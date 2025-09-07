from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from django.contrib.auth import login
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.hashers import make_password
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from .models import (
    User, Profile, Role, Permission, EmailVerificationToken, PasswordResetToken,
    Invitation, AuditLog, UserSession, PasswordHistory, MFADevice,
    SAMLConfiguration, OIDCConfiguration, SSOSession
)
from .serializers import (
    UserSerializer, UserRegistrationSerializer, LoginSerializer, PermissionSerializer,
    ProfileSerializer, ProfileUpdateSerializer, ChangePasswordSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    EmailVerificationSerializer, ResendVerificationSerializer,
    InvitationSerializer, InvitationCreateSerializer, InvitationResponseSerializer,
    AuditLogSerializer, UserSessionSerializer, PublicProfileSerializer,
    RoleSerializer, MFADeviceSerializer, MFASetupSerializer, MFAVerificationSerializer,
    SAMLConfigurationSerializer, OIDCConfigurationSerializer, SSOInitiateSerializer,
    ForcedPasswordChangeSerializer
)
from .tasks import (
    send_welcome_email, send_verification_email, send_password_reset_email, send_invitation_email,
    send_sms_verification, send_sms_mfa_code
)
from .utils import get_client_ip, get_user_agent, create_audit_log, get_geolocation_from_ip


class RegistrationThrottle(AnonRateThrottle):
    scope = 'registration'


class LoginThrottle(AnonRateThrottle):
    scope = 'login'


class PasswordResetThrottle(AnonRateThrottle):
    scope = 'password_reset'


@method_decorator(ratelimit(key='ip', rate='5/m', method='POST'), name='post')
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [RegistrationThrottle]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        with transaction.atomic():
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)
            
            # Create audit log
            create_audit_log(
                user=user,
                action='registration',
                description=f"User registered with email {user.email}",
                request=request
            )
            
            # Send verification email
            send_verification_email.delay(user.id)
            
            # Send welcome email
            send_welcome_email.delay(user.id)
        
        return Response({
            'user': UserSerializer(user).data,
            'token': token.key,
            'message': 'Registration successful. Please check your email to verify your account.'
        }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@throttle_classes([LoginThrottle])
@ratelimit(key='ip', rate='10/m', method='POST')
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.validated_data['user']
    remember_me = serializer.validated_data.get('remember_me', False)
    
    # Check if password has expired
    if user.password_expires_at and user.password_expires_at <= timezone.now():
        user.account_status = 'password_expired'
        user.save(update_fields=['account_status'])
        
        # Trigger password reset email
        send_password_reset_email.delay(user.id, "Your password has expired. Please reset it to continue.")
        
        return Response({
            'error': 'Password has expired. A password reset email has been sent.',
            'code': 'password_expired'
        }, status=status.HTTP_403_FORBIDDEN)
    
    # Update last login IP
    user.last_login_ip = get_client_ip(request)
    user.save(update_fields=['last_login_ip'])
    
    # Create or get token
    token, created = Token.objects.get_or_create(user=user)
    
    # Create user session
    session_key = request.session.session_key
    if not session_key:
        request.session.create()
        session_key = request.session.session_key
    
    # Get geolocation data
    ip_address = get_client_ip(request)
    geo_data = get_geolocation_from_ip(ip_address)
    
    # Set session expiry based on remember_me
    if remember_me:
        request.session.set_expiry(30 * 24 * 60 * 60)  # 30 days
    else:
        request.session.set_expiry(0)  # Browser session
    
    # Create session record
    UserSession.objects.update_or_create(
        user=user,
        session_key=session_key,
        defaults={
            'ip_address': ip_address,
            'country': geo_data['country'],
            'city': geo_data['city'],
            'user_agent': get_user_agent(request),
            'expires_at': timezone.now() + timezone.timedelta(days=30 if remember_me else 1),
            'is_active': True
        }
    )
    
    # Create audit log
    create_audit_log(
        user=user,
        action='login',
        description=f"User logged in from {get_client_ip(request)}",
        request=request
    )
    
    login(request, user)
    
    return Response({
        'user': UserSerializer(user).data,
        'token': token.key
    })


@api_view(['POST'])
def logout_view(request):
    user = request.user if request.user.is_authenticated else None
    
    # Revoke token
    if user:
        try:
            request.user.auth_token.delete()
        except:
            pass
        
        # Delete Django session
        if hasattr(request, 'session') and request.session.session_key:
            request.session.delete()
        
        # Deactivate session
        session_key = request.session.session_key
        if session_key:
            UserSession.objects.filter(
                user=user,
                session_key=session_key
            ).update(is_active=False)
        
        # Create audit log
        create_audit_log(
            user=user,
            action='logout',
            description=f"User logged out from {get_client_ip(request)}",
            request=request
        )
    
    return Response({'message': 'Successfully logged out'})


class ProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        profile, created = Profile.objects.get_or_create(user=self.request.user)
        return profile
    
    def get_serializer_class(self):
        if self.request.method in ['PATCH', 'PUT']:
            return ProfileUpdateSerializer
        return ProfileSerializer
    
    def perform_update(self, serializer):
        serializer.save()
        
        # Create audit log
        create_audit_log(
            user=self.request.user,
            action='profile_updated',
            description="User updated their profile",
            request=self.request,
            content_object=serializer.instance
        )


class PublicProfileView(generics.RetrieveAPIView):
    """Public view for user profiles by organizer slug."""
    serializer_class = PublicProfileSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'organizer_slug'
    lookup_url_kwarg = 'organizer_slug'
    
    def get_queryset(self):
        return Profile.objects.filter(
            user__is_organizer=True,
            user__is_active=True,
            user__account_status='active'
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def change_password(request):
    serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
    serializer.is_valid(raise_exception=True)
    
    user = request.user
    new_password = serializer.validated_data['new_password']
    
    # Check password history
    password_hash = make_password(new_password)
    recent_passwords = PasswordHistory.objects.filter(user=user).order_by('-created_at')[:5]
    
    for old_password in recent_passwords:
        if user.check_password(new_password):
            return Response(
                {'error': 'Cannot reuse recent passwords'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    # Update password
    user.set_password(new_password)
    user.password_changed_at = timezone.now()
    user.save(update_fields=['password', 'password_changed_at'])
    
    # Save to password history
    PasswordHistory.objects.create(user=user, password_hash=password_hash)
    
    # Revoke all existing tokens
    Token.objects.filter(user=user).delete()
    
    # Deactivate all sessions except current
    current_session = request.session.session_key
    UserSession.objects.filter(user=user).exclude(session_key=current_session).update(is_active=False)
    
    # Create new token
    token = Token.objects.create(user=user)
    
    # Create audit log
    create_audit_log(
        user=user,
        action='password_changed',
        description="User changed their password",
        request=request,
        content_object=user
    )
    
    return Response({
        'message': 'Password changed successfully',
        'token': token.key
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def force_password_change(request):
    """Force password change for users in grace period."""
    user = request.user
    
    # Only allow if user is in password expired grace period
    if user.account_status != 'password_expired_grace_period':
        return Response(
            {'error': 'Forced password change is only available during grace period'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    serializer = ForcedPasswordChangeSerializer(data=request.data, context={'request': request})
    serializer.is_valid(raise_exception=True)
    
    new_password = serializer.validated_data['new_password']
    
    # Update password (this will also update password_changed_at and password_expires_at)
    user.set_password(new_password)
    user.account_status = 'active'  # Restore active status
    user.save()
    
    # Save to password history
    from django.contrib.auth.hashers import make_password
    password_hash = make_password(new_password)
    PasswordHistory.objects.create(user=user, password_hash=password_hash)
    
    # Revoke all existing tokens except current
    current_token = getattr(request.auth, 'key', None)
    Token.objects.filter(user=user).exclude(key=current_token).delete()
    
    # Deactivate all sessions except current
    current_session = request.session.session_key
    UserSession.objects.filter(user=user).exclude(session_key=current_session).update(is_active=False)
    
    # Create new token if current one was revoked
    token, created = Token.objects.get_or_create(user=user)
    
    # Create audit log
    create_audit_log(
        user=user,
        action='forced_password_change',
        description="User completed forced password change during grace period",
        request=request,
        content_object=user
    )
    
    return Response({
        'message': 'Password changed successfully. Your account is now active.',
        'token': token.key
    })
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@throttle_classes([PasswordResetThrottle])
@ratelimit(key='ip', rate='3/h', method='POST')
def request_password_reset(request):
    serializer = PasswordResetRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    email = serializer.validated_data['email']
    
    try:
        user = User.objects.get(email=email, is_active=True)
        
        # Invalidate existing tokens
        PasswordResetToken.objects.filter(user=user, used_at__isnull=True).update(
            used_at=timezone.now()
        )
        
        # Create new token
        reset_token = PasswordResetToken.objects.create(
            user=user,
            created_ip=get_client_ip(request)
        )
        
        # Send reset email
        send_password_reset_email.delay(user.id, reset_token.token)
        
        # Create audit log
        create_audit_log(
            user=user,
            action='password_reset_requested',
            description=f"Password reset requested from {get_client_ip(request)}",
            request=request,
            content_object=user
        )
        
    except User.DoesNotExist:
        # Don't reveal if email exists
        pass
    
    return Response({
        'message': 'If an account with that email exists, a password reset link has been sent.'
    })


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def confirm_password_reset(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    reset_token = serializer.validated_data['reset_token']
    new_password = serializer.validated_data['new_password']
    
    user = reset_token.user
    
    # Update password
    user.set_password(new_password)
    user.password_changed_at = timezone.now()
    user.failed_login_attempts = 0
    user.locked_until = None
    user.save(update_fields=['password', 'password_changed_at', 'failed_login_attempts', 'locked_until'])
    
    # Mark token as used
    reset_token.mark_as_used(get_client_ip(request))
    
    # Save to password history
    password_hash = make_password(new_password)
    PasswordHistory.objects.create(user=user, password_hash=password_hash)
    
    # Revoke all tokens and sessions
    Token.objects.filter(user=user).delete()
    UserSession.objects.filter(user=user).update(is_active=False)
    
    # Create audit log
    create_audit_log(
        user=user,
        action='password_reset_completed',
        description=f"Password reset completed from {get_client_ip(request)}",
        request=request,
        content_object=user
    )
    
    return Response({'message': 'Password reset successfully'})


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def verify_email(request):
    serializer = EmailVerificationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    token = serializer.validated_data['token']
    user = token.user
    
    # Update user
    if token.token_type == 'email_verification':
        user.is_email_verified = True
        user.account_status = 'active'
    elif token.token_type == 'email_change':
        user.email = token.email
        user.is_email_verified = True
    
    user.save()
    
    # Mark token as used
    token.mark_as_used()
    
    # Create audit log
    create_audit_log(
        user=user,
        action='email_verified',
        description=f"Email verified: {token.email}",
        request=request,
        content_object=user
    )
    
    return Response({'message': 'Email verified successfully'})


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@throttle_classes([PasswordResetThrottle])
def resend_verification(request):
    serializer = ResendVerificationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    email = serializer.validated_data['email']
    
    try:
        user = User.objects.get(email=email, is_active=True)
        if not user.is_email_verified:
            send_verification_email.delay(user.id)
    except User.DoesNotExist:
        pass
    
    return Response({
        'message': 'If an unverified account with that email exists, a verification email has been sent.'
    })


# Role Management Views
class PermissionListView(generics.ListAPIView):
    serializer_class = PermissionSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = Permission.objects.all()


class RoleListView(generics.ListAPIView):
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        # Show all roles for now - in production, you might want to filter based on user permissions
        return Role.objects.all()


# Invitation Views
class InvitationListCreateView(generics.ListCreateAPIView):
    serializer_class = InvitationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Invitation.objects.filter(invited_by=self.request.user)
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return InvitationCreateSerializer
        return InvitationSerializer
    
    def perform_create(self, serializer):
        invitation = serializer.save(invited_by=self.request.user)
        
        # Send invitation email
        send_invitation_email.delay(invitation.id)
        
        # Create audit log
        create_audit_log(
            user=self.request.user,
            action='invitation_sent',
            description=f"Invitation sent to {invitation.invited_email}",
            request=self.request,
            content_object=invitation
        )


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def respond_to_invitation(request):
    serializer = InvitationResponseSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    invitation = serializer.validated_data['invitation']
    action = serializer.validated_data['action']
    
    if action == 'decline':
        invitation.decline()
        return Response({'message': 'Invitation declined'})
    
    # Accept invitation
    try:
        user = User.objects.get(email=invitation.invited_email)
    except User.DoesNotExist:
        # Create new user
        user_data = {
            'email': invitation.invited_email,
            'username': invitation.invited_email,
            'first_name': serializer.validated_data['first_name'],
            'last_name': serializer.validated_data['last_name'],
            'is_email_verified': True,
            'account_status': 'active'
        }
        user = User.objects.create_user(**user_data)
        user.set_password(serializer.validated_data['password'])
        user.password_changed_at = timezone.now()
        user.save()
    
    # Accept invitation
    invitation.accept(user)
    
    # Create token
    token, created = Token.objects.get_or_create(user=user)
    
    # Create audit log
    create_audit_log(
        user=user,
        action='invitation_accepted',
        description=f"Accepted invitation from {invitation.invited_by.email}",
        request=request,
        content_object=invitation
    )
    
    return Response({
        'message': 'Invitation accepted successfully',
        'user': UserSerializer(user).data,
        'token': token.key
    })


# Session Management Views
class UserSessionListView(generics.ListAPIView):
    serializer_class = UserSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return UserSession.objects.filter(
            user=self.request.user,
            is_active=True
        ).order_by('-last_activity')


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def revoke_session(request, session_id):
    session = get_object_or_404(
        UserSession,
        id=session_id,
        user=request.user,
        is_active=True
    )
    
    session.revoke()
    
    # Create audit log
    create_audit_log(
        user=request.user,
        action='session_revoked',
        description=f"Session revoked: {session.ip_address}",
        request=request,
        content_object=session
    )
    
    return Response({'message': 'Session revoked successfully'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def revoke_all_sessions(request):
    current_session = request.session.session_key
    
    # Revoke all sessions except current
    UserSession.objects.filter(
        user=request.user,
        is_active=True
    ).exclude(session_key=current_session).update(is_active=False)
    
    # Revoke all tokens except current
    current_token = getattr(request.auth, 'key', None)
    Token.objects.filter(user=request.user).exclude(key=current_token).delete()
    
    # Create audit log
    create_audit_log(
        user=request.user,
        action='all_sessions_revoked',
        description="All sessions revoked except current",
        request=request,
        content_object=request.user
    )
    
    return Response({'message': 'All other sessions revoked successfully'})


# Audit Log Views
class AuditLogListView(generics.ListAPIView):
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return AuditLog.objects.filter(user=self.request.user).order_by('-created_at')


# MFA Management Views
class MFADeviceListView(generics.ListAPIView):
    serializer_class = MFADeviceSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return MFADevice.objects.filter(user=self.request.user)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def setup_mfa(request):
    """Initiate MFA setup for user."""
    serializer = MFASetupSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    device_type = serializer.validated_data['device_type']
    device_name = serializer.validated_data['device_name']
    phone_number = serializer.validated_data.get('phone_number')
    
    user = request.user
    
    if device_type == 'totp':
        # Generate TOTP secret and QR code
        secret = user.generate_mfa_secret()
        totp_uri = user.get_totp_uri()
        
        # Generate QR code
        import qrcode
        from io import BytesIO
        import base64
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        
        return Response({
            'secret': secret,
            'qr_code': f"data:image/png;base64,{qr_code_data}",
            'manual_entry_key': secret,
            'message': 'Scan the QR code with your authenticator app'
        })
    
    elif device_type == 'sms':
        # Send SMS verification code
        from .tasks import send_sms_verification
        send_sms_verification.delay(user.id, phone_number)
        
        return Response({
            'message': 'SMS verification code sent',
            'phone_number': phone_number
        })
    
    return Response({'error': 'Invalid device type'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def verify_mfa_setup(request):
    """Verify and activate MFA setup."""
    serializer = MFAVerificationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    token = serializer.validated_data['token']
    user = request.user
    
    # Verify TOTP token
    if user.verify_totp(token):
        # Enable MFA
        user.is_mfa_enabled = True
        user.save(update_fields=['is_mfa_enabled'])
        
        # Generate backup codes
        backup_codes = user.generate_backup_codes()
        
        # Create MFA device record
        MFADevice.objects.create(
            user=user,
            device_type='totp',
            name='Authenticator App',
            is_active=True,
            is_primary=True
        )
        
        # Create audit log
        create_audit_log(
            user=user,
            action='mfa_enabled',
            description="User enabled MFA",
            request=request,
            content_object=user
        )
        
        return Response({
            'message': 'MFA enabled successfully',
            'backup_codes': backup_codes
        })
    
    return Response({'error': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def disable_mfa(request):
    """Disable MFA for user."""
    password = request.data.get('password')
    
    if not password or not request.user.check_password(password):
        return Response({'error': 'Password required to disable MFA'}, status=status.HTTP_400_BAD_REQUEST)
    
    user = request.user
    user.disable_mfa()
    
    # Remove MFA devices
    MFADevice.objects.filter(user=user).delete()
    
    # Create audit log
    create_audit_log(
        user=user,
        action='mfa_disabled',
        description="User disabled MFA",
        request=request,
        content_object=user
    )
    
    return Response({'message': 'MFA disabled successfully'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def regenerate_backup_codes(request):
    """Regenerate MFA backup codes."""
    password = request.data.get('password')
    
    if not password or not request.user.check_password(password):
        return Response({'error': 'Password required'}, status=status.HTTP_400_BAD_REQUEST)
    
    if not request.user.is_mfa_enabled:
        return Response({'error': 'MFA is not enabled'}, status=status.HTTP_400_BAD_REQUEST)
    
    backup_codes = request.user.generate_backup_codes()
    
    # Create audit log
    create_audit_log(
        user=request.user,
        action='backup_codes_regenerated',
        description="User regenerated MFA backup codes",
        request=request,
        content_object=request.user
    )
    
    return Response({
        'message': 'Backup codes regenerated',
        'backup_codes': backup_codes
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def resend_sms_otp(request):
    """Resend SMS verification code for MFA setup."""
    user = request.user
    
    try:
        # Find the user's active SMS MFA device
        sms_device = MFADevice.objects.get(user=user, device_type='sms', is_active=True)
        
        # Call the task to send the SMS verification
        send_sms_verification.delay(user.id, sms_device.phone_number)
        
        return Response({'message': 'SMS verification code sent successfully'})
    except MFADevice.DoesNotExist:
        return Response(
            {'error': 'No active SMS MFA device found for this user.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': f'Failed to resend SMS verification code: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def send_sms_mfa_code_view(request):
    """Send SMS MFA code during login (used for existing MFA devices)."""
    user = request.user
    device_id = request.data.get('device_id')

    if not device_id:
        return Response({'error': 'Device ID is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Ensure the device belongs to the user and is an active SMS device
        MFADevice.objects.get(id=device_id, user=user, device_type='sms', is_active=True)
        send_sms_mfa_code.delay(user.id, device_id)
        return Response({'message': 'SMS MFA code sent successfully'})
    except MFADevice.DoesNotExist:
        return Response({'error': 'MFA device not found or not active for this user.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': f'Failed to send SMS MFA code: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def verify_sms_mfa_login(request):
    """Verify SMS MFA code during login."""
    # This view would typically be part of the login flow,
    # where the user provides the OTP received via SMS.
    # The actual verification logic would be handled by the LoginSerializer
    # or a dedicated MFA verification serializer.
    # For now, it's a placeholder as the login serializer handles the actual verification.
    return Response({'message': 'SMS MFA login verification endpoint (implementation in serializer)'})


# SSO Configuration Views (Admin only)
class SAMLConfigurationListCreateView(generics.ListCreateAPIView):
    serializer_class = SAMLConfigurationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        # Only allow admins to view/manage SAML configs
        if self.request.user.has_permission('can_manage_sso'):
            return SAMLConfiguration.objects.all()
        return SAMLConfiguration.objects.none()


class SAMLConfigurationDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = SAMLConfigurationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.has_permission('can_manage_sso'):
            return SAMLConfiguration.objects.all()
        return SAMLConfiguration.objects.none()


class OIDCConfigurationListCreateView(generics.ListCreateAPIView):
    serializer_class = OIDCConfigurationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.has_permission('can_manage_sso'):
            return OIDCConfiguration.objects.all()
        return OIDCConfiguration.objects.none()


class OIDCConfigurationDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = OIDCConfigurationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.has_permission('can_manage_sso'):
            return OIDCConfiguration.objects.all()
        return OIDCConfiguration.objects.none()


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def initiate_sso(request):
    """Initiate SSO login flow."""
    serializer = SSOInitiateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    sso_type = serializer.validated_data['sso_type']
    organization_domain = serializer.validated_data['organization_domain']
    redirect_url = serializer.validated_data.get('redirect_url', '/')
    
    if sso_type == 'saml':
        try:
            saml_config = SAMLConfiguration.objects.get(
                organization_domain=organization_domain,
                is_active=True
            )
            
            # Validate SAML configuration
            from .utils import validate_saml_configuration
            errors = validate_saml_configuration(saml_config)
            if errors:
                return Response(
                    {'error': f'SAML configuration invalid: {", ".join(errors)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Store SAML config ID in session for the authentication process
            request.session['saml_config_id'] = str(saml_config.id)
            request.session['sso_redirect_url'] = redirect_url
            
            # Generate SAML AuthnRequest URL
            from djangosaml2.views import LoginView
            from django.urls import reverse
            
            # Create SAML login URL
            auth_url = reverse('saml2_login')
            if redirect_url != '/':
                auth_url += f"?next={redirect_url}"
            
            return Response({
                'auth_url': auth_url,
                'sso_type': 'saml',
                'organization': saml_config.organization_name
            })
            
        except SAMLConfiguration.DoesNotExist:
            return Response(
                {'error': 'SAML configuration not found for this domain'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    elif sso_type == 'oidc':
        try:
            oidc_config = OIDCConfiguration.objects.get(
                organization_domain=organization_domain,
                is_active=True
            )
            
            # Validate OIDC configuration
            from .utils import validate_oidc_configuration
            errors = validate_oidc_configuration(oidc_config)
            if errors:
                return Response(
                    {'error': f'OIDC configuration invalid: {", ".join(errors)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Store OIDC config info in session
            request.session['oidc_organization_domain'] = organization_domain
            request.session['sso_redirect_url'] = redirect_url
            
            # Generate OIDC authorization URL
            from django.urls import reverse
            auth_url = reverse('oidc_authentication_init')
            if redirect_url != '/':
                auth_url += f"?next={redirect_url}"
            
            return Response({
                'auth_url': auth_url,
                'sso_type': 'oidc',
                'organization': oidc_config.organization_name
            })
            
        except OIDCConfiguration.DoesNotExist:
            return Response(
                {'error': 'OIDC configuration not found for this domain'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    return Response({'error': 'Invalid SSO type'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def sso_logout(request):
    """Handle SSO logout with proper SLO."""
    user = request.user
    
    # Get active SSO sessions
    sso_sessions = SSOSession.objects.filter(
        user=user,
        is_active=True
    )
    
    logout_urls = []
    
    for sso_session in sso_sessions:
        try:
            if sso_session.sso_type == 'saml':
                # Get SAML configuration
                saml_config = SAMLConfiguration.objects.get(
                    organization_name=sso_session.provider_name,
                    is_active=True
                )
                
                if saml_config.slo_url:
                    # Generate SAML SLO URL
                    from django.urls import reverse
                    slo_url = reverse('saml2_logout')
                    logout_urls.append({
                        'type': 'saml',
                        'url': slo_url,
                        'provider': sso_session.provider_name
                    })
            
            elif sso_session.sso_type == 'oidc':
                # Get OIDC configuration
                oidc_config = OIDCConfiguration.objects.get(
                    organization_name=sso_session.provider_name,
                    is_active=True
                )
                
                # Generate OIDC logout URL
                logout_url = f"{oidc_config.issuer}/logout"
                logout_urls.append({
                    'type': 'oidc',
                    'url': logout_url,
                    'provider': sso_session.provider_name
                })
            
            # Deactivate SSO session
            sso_session.is_active = False
            sso_session.save()
            
        except (SAMLConfiguration.DoesNotExist, OIDCConfiguration.DoesNotExist):
            # Configuration no longer exists, just deactivate session
            sso_session.is_active = False
            sso_session.save()
    
    # Create audit log
    create_audit_log(
        user=user,
        action='sso_logout',
        description=f"User initiated SSO logout from {len(sso_sessions)} providers",
        request=request,
        metadata={'logout_urls': logout_urls}
    )
    
    return Response({
        'message': 'SSO logout initiated',
        'logout_urls': logout_urls
    })


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def sso_discovery(request):
    """Discover available SSO providers for a domain."""
    domain = request.GET.get('domain')
    if not domain:
        return Response(
            {'error': 'Domain parameter is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    providers = []
    
    # Check for SAML configurations
    saml_configs = SAMLConfiguration.objects.filter(
        organization_domain=domain,
        is_active=True
    )
    
    for config in saml_configs:
        providers.append({
            'type': 'saml',
            'organization': config.organization_name,
            'domain': config.organization_domain
        })
    
    # Check for OIDC configurations
    oidc_configs = OIDCConfiguration.objects.filter(
        organization_domain=domain,
        is_active=True
    )
    
    for config in oidc_configs:
        providers.append({
            'type': 'oidc',
            'organization': config.organization_name,
            'domain': config.organization_domain
        })
    
    return Response({
        'domain': domain,
        'providers': providers
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def sso_sessions(request):
    """Get user's active SSO sessions."""
    sessions = SSOSession.objects.filter(
        user=request.user,
        is_active=True
    ).order_by('-created_at')
    
    session_data = []
    for session in sessions:
        session_data.append({
            'id': session.id,
            'sso_type': session.sso_type,
            'provider_name': session.provider_name,
            'ip_address': session.ip_address,
            'created_at': session.created_at,
            'last_activity': session.last_activity,
            'expires_at': session.expires_at
        })
    
    return Response({
        'sessions': session_data
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def revoke_sso_session(request, session_id):
    """Revoke a specific SSO session."""
    try:
        session = SSOSession.objects.get(
            id=session_id,
            user=request.user,
            is_active=True
        )
        
        session.is_active = False
        session.save()
        
        # Create audit log
        create_audit_log(
            user=request.user,
            action='sso_session_revoked',
            description=f"SSO session revoked: {session.provider_name}",
            request=request,
            content_object=session
        )
        
        return Response({'message': 'SSO session revoked successfully'})
        
    except SSOSession.DoesNotExist:
        return Response(
            {'error': 'SSO session not found'},
            status=status.HTTP_404_NOT_FOUND
        )