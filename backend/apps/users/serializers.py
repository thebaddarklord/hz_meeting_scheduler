from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from .models import (
    User, Profile, Role, Permission, EmailVerificationToken, PasswordResetToken,
    Invitation, AuditLog, UserSession, MFADevice, SAMLConfiguration, OIDCConfiguration
)


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'codename', 'name', 'description', 'category']
        read_only_fields = ['id']
class RoleSerializer(serializers.ModelSerializer):
    role_permissions = PermissionSerializer(many=True, read_only=True)
    parent_name = serializers.CharField(source='parent.name', read_only=True)
    children_count = serializers.IntegerField(source='children.count', read_only=True)
    total_permissions = serializers.SerializerMethodField()
    
    class Meta:
        model = Role
        fields = ['id', 'name', 'role_type', 'description', 'parent', 'parent_name', 
                 'children_count', 'role_permissions', 'total_permissions', 'is_system_role']
        read_only_fields = ['id']
    
    def get_total_permissions(self, obj):
        return len(obj.get_all_permissions())


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = [
            'organizer_slug', 'display_name', 'bio', 'profile_picture',
            'phone', 'website', 'company', 'job_title', 'timezone_name',
            'language', 'date_format', 'time_format', 'brand_color',
            'brand_logo', 'public_profile', 'show_phone', 'show_email',
            'reasonable_hours_start', 'reasonable_hours_end'
        ]
        read_only_fields = ['organizer_slug']


class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)
    roles = RoleSerializer(many=True, read_only=True)
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'is_organizer', 'is_email_verified', 'is_phone_verified',
            'is_mfa_enabled', 'account_status', 'roles', 'profile',
            'last_login', 'date_joined'
        ]
        read_only_fields = [
            'id', 'is_email_verified', 'is_phone_verified', 'is_mfa_enabled',
            'last_login', 'date_joined'
        ]
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    terms_accepted = serializers.BooleanField(write_only=True)
    
    class Meta:
        model = User
        fields = [
            'email', 'first_name', 'last_name',
            'password', 'password_confirm', 'terms_accepted'
        ]
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        if not attrs.get('terms_accepted'):
            raise serializers.ValidationError("You must accept the terms and conditions")
        
        # Validate password strength
        try:
            validate_password(attrs['password'])
        except ValidationError as e:
            raise serializers.ValidationError({'password': e.messages})
        
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        validated_data.pop('terms_accepted')
        
        # Set username to email since our User model uses email as USERNAME_FIELD
        validated_data['username'] = validated_data['email']
        
        user = User.objects.create_user(**validated_data)
        user.password_changed_at = timezone.now()
        user.save(update_fields=['password_changed_at'])
        
        # Assign default role
        default_role, created = Role.objects.get_or_create(
            name='organizer',
            defaults={
                'role_type': 'organizer',
                'is_system_role': True
            }
        )
        
        # Add permissions to the role if it was just created
        if created:
            # Get or create the required permissions
            create_events_perm, _ = Permission.objects.get_or_create(
                codename='can_create_events',
                defaults={
                    'name': 'Create Events',
                    'description': 'Can create event types',
                    'category': 'event_management'
                }
            )
            manage_bookings_perm, _ = Permission.objects.get_or_create(
                codename='can_manage_bookings',
                defaults={
                    'name': 'Manage Bookings',
                    'description': 'Can manage all bookings',
                    'category': 'event_management'
                }
            )
            
            # Add permissions to the role
            default_role.role_permissions.add(create_events_perm, manage_bookings_perm)
        
        
        # Add permissions to the role if it was just created
        if created:
            # Get or create the required permissions
            create_events_perm, _ = Permission.objects.get_or_create(
                codename='can_create_events',
                defaults={
                    'name': 'Create Events',
                    'description': 'Can create event types',
                    'category': 'event_management'
                }
            )
            manage_bookings_perm, _ = Permission.objects.get_or_create(
                codename='can_manage_bookings',
                defaults={
                    'name': 'Manage Bookings',
                    'description': 'Can manage all bookings',
                    'category': 'event_management'
                }
            )
            
            # Add permissions to the role
            default_role.role_permissions.add(create_events_perm, manage_bookings_perm)
        
        user.roles.add(default_role)
        
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    remember_me = serializers.BooleanField(default=False)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            # Check if user exists
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise serializers.ValidationError('Invalid credentials')
            
            # Check if account is locked
            if user.is_account_locked():
                raise serializers.ValidationError('Account is temporarily locked due to multiple failed login attempts')
            
            # Check account status
            if user.account_status != 'active':
                if user.account_status == 'pending_verification':
                    raise serializers.ValidationError('Please verify your email address before logging in')
                elif user.account_status == 'suspended':
                    raise serializers.ValidationError('Your account has been suspended')
                else:
                    raise serializers.ValidationError('Your account is not active')
            
            # Authenticate user
            user = authenticate(username=email, password=password)
            if not user:
                # Increment failed login attempts
                try:
                    user_obj = User.objects.get(email=email)
                    user_obj.failed_login_attempts += 1
                    if user_obj.failed_login_attempts >= 5:
                        user_obj.lock_account()
                    user_obj.save(update_fields=['failed_login_attempts'])
                except User.DoesNotExist:
                    pass
                
                raise serializers.ValidationError('Invalid credentials')
            
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled')
            
            # Reset failed login attempts on successful login
            if user.failed_login_attempts > 0:
                user.failed_login_attempts = 0
                user.save(update_fields=['failed_login_attempts'])
            
            attrs['user'] = user
        else:
            raise serializers.ValidationError('Must include email and password')
        
        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField(min_length=8)
    new_password_confirm = serializers.CharField()
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        
        # Validate new password strength
        try:
            validate_password(attrs['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': e.messages})
        
        return attrs
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect")
        return value


class ForcedPasswordChangeSerializer(serializers.Serializer):
    """Serializer for forced password change (no old password required)."""
    new_password = serializers.CharField(min_length=8)
    new_password_confirm = serializers.CharField()
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        
        # Validate new password strength
        try:
            validate_password(attrs['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': e.messages})
        
        # Check password history to prevent reuse
        user = self.context['request'].user
        from django.contrib.auth.hashers import check_password
        
        recent_passwords = user.password_history.order_by('-created_at')[:5]
        for old_password in recent_passwords:
            if check_password(attrs['new_password'], old_password.password_hash):
                raise serializers.ValidationError({'new_password': ['Cannot reuse recent passwords']})
        
        return attrs
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate_email(self, value):
        try:
            User.objects.get(email=value, is_active=True)
        except User.DoesNotExist:
            # Don't reveal if email exists or not for security
            pass
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)
    new_password_confirm = serializers.CharField()
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        # Validate password strength
        try:
            validate_password(attrs['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': e.messages})
        
        # Validate token
        try:
            token = PasswordResetToken.objects.get(token=attrs['token'])
            if not token.is_valid():
                raise serializers.ValidationError("Token is invalid or expired")
            attrs['reset_token'] = token
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError("Token is invalid or expired")
        
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()
    
    def validate_token(self, value):
        try:
            token = EmailVerificationToken.objects.get(token=value)
            if not token.is_valid():
                raise serializers.ValidationError("Token is invalid or expired")
            return token
        except EmailVerificationToken.DoesNotExist:
            raise serializers.ValidationError("Token is invalid or expired")


class ResendVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = [
            'display_name', 'bio', 'profile_picture', 'phone', 'website',
            'company', 'job_title', 'timezone_name', 'language',
            'date_format', 'time_format', 'brand_color', 'brand_logo',
            'public_profile', 'show_phone', 'show_email'
        ]


class InvitationSerializer(serializers.ModelSerializer):
    invited_by_name = serializers.CharField(source='invited_by.get_full_name', read_only=True)
    role_name = serializers.CharField(source='role.name', read_only=True)
    
    class Meta:
        model = Invitation
        fields = [
            'id', 'invited_email', 'role', 'role_name', 'message',
            'status', 'invited_by_name', 'created_at', 'expires_at'
        ]
        read_only_fields = ['id', 'status', 'created_at', 'expires_at']


class InvitationCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invitation
        fields = ['invited_email', 'role', 'message']
    
    def validate_invited_email(self, value):
        # Check if user already exists
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists")
        
        # Check if there's already a pending invitation
        if Invitation.objects.filter(
            invited_email=value,
            invited_by=self.context['request'].user,
            status='pending'
        ).exists():
            raise serializers.ValidationError("A pending invitation already exists for this email")
        
        return value


class InvitationResponseSerializer(serializers.Serializer):
    token = serializers.CharField()
    action = serializers.ChoiceField(choices=['accept', 'decline'])
    
    # Fields for new user registration (if accepting and user doesn't exist)
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    password = serializers.CharField(required=False, min_length=8)
    password_confirm = serializers.CharField(required=False)
    
    def validate(self, attrs):
        # Validate token
        try:
            invitation = Invitation.objects.get(token=attrs['token'])
            if not invitation.is_valid():
                raise serializers.ValidationError("Invitation is invalid or expired")
            attrs['invitation'] = invitation
        except Invitation.DoesNotExist:
            raise serializers.ValidationError("Invitation is invalid or expired")
        
        # If accepting and user doesn't exist, validate registration fields
        if attrs['action'] == 'accept':
            try:
                User.objects.get(email=invitation.invited_email)
            except User.DoesNotExist:
                # User doesn't exist, validate registration fields
                required_fields = ['first_name', 'last_name', 'password', 'password_confirm']
                for field in required_fields:
                    if not attrs.get(field):
                        raise serializers.ValidationError(f"{field} is required for new users")
                
                if attrs['password'] != attrs['password_confirm']:
                    raise serializers.ValidationError("Passwords don't match")
                
                try:
                    validate_password(attrs['password'])
                except ValidationError as e:
                    raise serializers.ValidationError({'password': e.messages})
        
        return attrs


class AuditLogSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'user_email', 'action', 'action_display', 'description',
            'ip_address', 'user_agent', 'metadata', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class UserSessionSerializer(serializers.ModelSerializer):
    is_current = serializers.SerializerMethodField()
    is_expired = serializers.BooleanField(source='is_expired', read_only=True)
    location = serializers.SerializerMethodField()
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'session_key', 'ip_address', 'country', 'city', 'location', 
            'user_agent', 'device_info',
            'created_at', 'last_activity', 'expires_at', 'is_active',
            'is_current', 'is_expired'
        ]
        read_only_fields = ['id', 'created_at', 'last_activity']
    
    def get_is_current(self, obj):
        request = self.context.get('request')
        if request and hasattr(request, 'session'):
            return obj.session_key == request.session.session_key
        return False
    
    def get_location(self, obj):
        if obj.country and obj.city:
            return f"{obj.city}, {obj.country}"
        elif obj.country:
            return obj.country
        return "Unknown"


class PublicProfileSerializer(serializers.ModelSerializer):
    """Serializer for public profile view (limited fields)."""
    organizer_name = serializers.CharField(source='display_name', read_only=True)
    
    class Meta:
        model = Profile
        fields = [
            'organizer_slug', 'organizer_name', 'bio', 'profile_picture',
            'website', 'company', 'timezone_name', 'brand_color'
        ]
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        
        # Only show fields that user has made public
        if not instance.public_profile:
            return {'organizer_slug': data['organizer_slug']}
        
        # Filter based on privacy settings
        if not instance.show_email and 'email' in data:
            data.pop('email')
        
        return data


class MFADeviceSerializer(serializers.ModelSerializer):
    device_type_display = serializers.CharField(source='get_device_type_display', read_only=True)
    
    class Meta:
        model = MFADevice
        fields = [
            'id', 'device_type', 'device_type_display', 'name', 'phone_number',
            'is_active', 'is_primary', 'last_used_at', 'created_at'
        ]
        read_only_fields = ['id', 'last_used_at', 'created_at']


class MFASetupSerializer(serializers.Serializer):
    """Serializer for MFA setup initiation."""
    device_type = serializers.ChoiceField(choices=MFADevice.DEVICE_TYPES)
    device_name = serializers.CharField(max_length=100)
    phone_number = serializers.CharField(max_length=20, required=False)
    
    def validate(self, attrs):
        if attrs['device_type'] == 'sms' and not attrs.get('phone_number'):
            raise serializers.ValidationError("Phone number is required for SMS devices")
        
        # Validate phone number format if provided
        if attrs.get('phone_number'):
            from .utils import validate_phone_number
            if not validate_phone_number(attrs['phone_number']):
                raise serializers.ValidationError("Invalid phone number format")
        
        return attrs


class MFAVerificationSerializer(serializers.Serializer):
    """Serializer for MFA token verification."""
    otp_code = serializers.CharField(max_length=10)
    device_id = serializers.UUIDField(required=False)
    
    def validate_otp_code(self, value):
        """Validate OTP code format."""
        if not value.isdigit():
            raise serializers.ValidationError("OTP code must contain only digits")
        if len(value) != 6:
            raise serializers.ValidationError("OTP code must be 6 digits")
        return value


class SAMLConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = SAMLConfiguration
        fields = [
            'id', 'organization_name', 'organization_domain', 'entity_id',
            'sso_url', 'slo_url', 'email_attribute', 'first_name_attribute',
            'last_name_attribute', 'role_attribute', 'is_active',
            'auto_provision_users', 'default_role', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
        extra_kwargs = {
            'x509_cert': {'write_only': True}
        }


class OIDCConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = OIDCConfiguration
        fields = [
            'id', 'organization_name', 'organization_domain', 'issuer',
            'client_id', 'scopes', 'email_claim', 'first_name_claim',
            'last_name_claim', 'role_claim', 'is_active',
            'auto_provision_users', 'default_role', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
        extra_kwargs = {
            'client_secret': {'write_only': True}
        }


class SSOInitiateSerializer(serializers.Serializer):
    """Serializer for SSO initiation."""
    sso_type = serializers.ChoiceField(choices=['saml', 'oidc'])
    organization_domain = serializers.CharField(max_length=100)
    redirect_url = serializers.URLField(required=False)