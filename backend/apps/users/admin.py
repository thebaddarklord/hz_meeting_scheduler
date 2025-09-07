from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import (
    User, Profile, Role, Permission, EmailVerificationToken, PasswordResetToken,
    Invitation, AuditLog, UserSession, PasswordHistory, MFADevice, SAMLConfiguration, OIDCConfiguration, SSOSession
)


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ('name', 'codename', 'category', 'role_count', 'created_at')
    list_filter = ('category', 'created_at')
    search_fields = ('name', 'codename', 'description')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Permission Information', {
            'fields': ('codename', 'name', 'description', 'category')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def role_count(self, obj):
        return obj.roles.count()
    role_count.short_description = 'Roles'
@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('name', 'role_type', 'parent', 'permission_count', 'is_system_role', 'user_count', 'created_at')
    list_filter = ('role_type', 'is_system_role', 'created_at')
    search_fields = ('name', 'description')
    readonly_fields = ('created_at', 'updated_at')
    filter_horizontal = ('role_permissions',)
    
    fieldsets = (
        ('Role Information', {
            'fields': ('name', 'role_type', 'parent', 'description', 'is_system_role')
        }),
        ('Permissions', {
            'fields': ('role_permissions',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def user_count(self, obj):
        return obj.users.count()
    user_count.short_description = 'Users'
    
    def permission_count(self, obj):
        return len(obj.get_all_permissions())
    permission_count.short_description = 'Total Permissions'
    
    def get_readonly_fields(self, request, obj=None):
        readonly_fields = list(self.readonly_fields)
        if obj and obj.is_system_role:
            readonly_fields.extend(['name', 'role_type', 'is_system_role'])
        return readonly_fields


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = 'Profile'
    fields = (
        'organizer_slug', 'display_name', 'bio', 'profile_picture',
        'phone', 'website', 'company', 'job_title', 'timezone_name',
        'language', 'brand_color', 'public_profile'
    )
    readonly_fields = ('organizer_slug',)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    inlines = (ProfileInline,)
    list_display = (
        'email', 'first_name', 'last_name', 'account_status',
        'is_email_verified', 'is_mfa_enabled', 'role_list',
        'last_login', 'date_joined'
    )
    list_filter = (
        'account_status', 'is_email_verified', 'is_mfa_enabled',
        'is_organizer', 'is_active', 'is_staff', 'date_joined'
    )
    search_fields = ('email', 'first_name', 'last_name', 'username')
    ordering = ('-date_joined',)
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Account Status', {
            'fields': (
                'is_organizer', 'is_email_verified', 'is_phone_verified',
                'is_mfa_enabled', 'account_status'
            )
        }),
        ('Security', {
            'fields': (
                'password_changed_at', 'password_expires_at',
                'failed_login_attempts', 'locked_until', 'last_login_ip'
            ),
            'classes': ('collapse',)
        }),
        ('Roles', {
            'fields': ('roles',)
        }),
    )
    
    readonly_fields = BaseUserAdmin.readonly_fields + (
        'password_changed_at', 'failed_login_attempts', 'last_login_ip'
    )
    
    filter_horizontal = ('roles', 'groups', 'user_permissions')
    
    def role_list(self, obj):
        roles = obj.roles.all()[:3]  # Show first 3 roles
        role_names = [role.name for role in roles]
        if obj.roles.count() > 3:
            role_names.append(f'... +{obj.roles.count() - 3} more')
        return ', '.join(role_names) if role_names else 'No roles'
    role_list.short_description = 'Roles'
    
    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related('roles')


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = (
        'user_email', 'organizer_slug', 'display_name',
        'company', 'timezone_name', 'public_profile', 'created_at'
    )
    list_filter = ('public_profile', 'timezone_name', 'language', 'created_at')
    search_fields = ('user__email', 'organizer_slug', 'display_name', 'company')
    readonly_fields = ('organizer_slug', 'created_at', 'updated_at')
    
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Profile Information', {
            'fields': (
                'organizer_slug', 'display_name', 'bio', 'profile_picture',
                'phone', 'website', 'company', 'job_title'
            )
        }),
        ('Localization', {
            'fields': ('timezone_name', 'language', 'date_format', 'time_format')
        }),
        ('Branding', {
            'fields': ('brand_color', 'brand_logo')
        }),
        ('Privacy', {
            'fields': ('public_profile', 'show_phone', 'show_email')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'Email'
    user_email.admin_order_field = 'user__email'


@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'email', 'token_type', 'is_used', 'created_at', 'expires_at')
    list_filter = ('token_type', 'created_at', 'expires_at')
    search_fields = ('user__email', 'email', 'token')
    readonly_fields = ('token', 'created_at', 'used_at')
    
    fieldsets = (
        ('Token Information', {
            'fields': ('user', 'email', 'token_type', 'token')
        }),
        ('Status', {
            'fields': ('created_at', 'expires_at', 'used_at')
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    
    def is_used(self, obj):
        return obj.used_at is not None
    is_used.boolean = True
    is_used.short_description = 'Used'


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'is_used', 'created_at', 'expires_at', 'created_ip')
    list_filter = ('created_at', 'expires_at')
    search_fields = ('user__email', 'token', 'created_ip')
    readonly_fields = ('token', 'created_at', 'used_at')
    
    fieldsets = (
        ('Token Information', {
            'fields': ('user', 'token')
        }),
        ('Status', {
            'fields': ('created_at', 'expires_at', 'used_at')
        }),
        ('Security', {
            'fields': ('created_ip', 'used_ip')
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    
    def is_used(self, obj):
        return obj.used_at is not None
    is_used.boolean = True
    is_used.short_description = 'Used'


@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('user__email',)
    readonly_fields = ('user', 'password_hash', 'created_at')
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = (
        'invited_email', 'invited_by_email', 'role_name',
        'status', 'created_at', 'expires_at'
    )
    list_filter = ('status', 'role', 'created_at', 'expires_at')
    search_fields = ('invited_email', 'invited_by__email', 'message')
    readonly_fields = ('token', 'created_at', 'responded_at')
    
    fieldsets = (
        ('Invitation Details', {
            'fields': ('invited_by', 'invited_email', 'role', 'message')
        }),
        ('Status', {
            'fields': ('status', 'token', 'created_at', 'expires_at', 'responded_at')
        }),
        ('Response', {
            'fields': ('accepted_by',)
        }),
    )
    
    def invited_by_email(self, obj):
        return obj.invited_by.email
    invited_by_email.short_description = 'Invited By'
    
    def role_name(self, obj):
        return obj.role.name
    role_name.short_description = 'Role'


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        'user_email', 'action_display', 'related_object_info', 'ip_address',
        'created_at'
    )
    list_filter = ('action', 'created_at')
    search_fields = ('user__email', 'description', 'ip_address')
    readonly_fields = ('user', 'action', 'description', 'ip_address', 'user_agent', 'session_key', 
                      'content_type', 'object_id', 'related_object', 'metadata', 'created_at')
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Log Information', {
            'fields': ('user', 'action', 'description', 'content_type', 'object_id', 'related_object')
        }),
        ('Context', {
            'fields': ('ip_address', 'user_agent', 'session_key')
        }),
        ('Additional Data', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
        ('Timestamp', {
            'fields': ('created_at',)
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email if obj.user else 'Anonymous'
    user_email.short_description = 'User'
    
    def action_display(self, obj):
        return obj.get_action_display()
    action_display.short_description = 'Action'
    
    def related_object_info(self, obj):
        if obj.related_object:
            return f"{obj.content_type.model}: {obj.related_object}"
        return "-"
    related_object_info.short_description = 'Related Object'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = (
        'user_email', 'ip_address', 'location', 'is_active',
        'created_at', 'last_activity', 'expires_at'
    )
    list_filter = ('is_active', 'created_at', 'last_activity')
    search_fields = ('user__email', 'ip_address', 'session_key', 'country', 'city')
    readonly_fields = ('user', 'session_key', 'ip_address', 'user_agent', 'country', 'city', 'device_info', 'created_at', 'last_activity')
    
    fieldsets = (
        ('Session Information', {
            'fields': ('user', 'session_key', 'is_active')
        }),
        ('Client Information', {
            'fields': ('ip_address', 'country', 'city', 'user_agent', 'device_info')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'last_activity', 'expires_at')
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User'
    
    def location(self, obj):
        if obj.country and obj.city:
            return f"{obj.city}, {obj.country}"
        elif obj.country:
            return obj.country
        return "-"
    location.short_description = 'Location'
    
    actions = ['revoke_sessions']
    
    def revoke_sessions(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"Revoked {queryset.count()} sessions.")
    revoke_sessions.short_description = "Revoke selected sessions"


@admin.register(MFADevice)
class MFADeviceAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'device_type', 'name', 'phone_number_masked', 'is_active', 'is_primary', 'verification_attempts', 'last_used_at', 'created_at')
    list_filter = ('device_type', 'is_active', 'is_primary', 'created_at')
    search_fields = ('user__email', 'name', 'phone_number')
    readonly_fields = ('created_at', 'updated_at', 'last_used_at', 'verification_attempts', 'last_verification_attempt')
    
    fieldsets = (
        ('Device Information', {
            'fields': ('user', 'device_type', 'name', 'phone_number')
        }),
        ('Settings', {
            'fields': ('is_active', 'is_primary')
        }),
        ('Security', {
            'fields': ('verification_attempts', 'last_verification_attempt')
        }),
        ('Usage', {
            'fields': ('last_used_at',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    
    def phone_number_masked(self, obj):
        if obj.phone_number:
            return obj.phone_number[-4:].rjust(len(obj.phone_number), '*')
        return '-'
    phone_number_masked.short_description = 'Phone Number'


@admin.register(SAMLConfiguration)
class SAMLConfigurationAdmin(admin.ModelAdmin):
    list_display = ('organization_name', 'organization_domain', 'is_active', 'auto_provision_users', 'created_at')
    list_filter = ('is_active', 'auto_provision_users', 'created_at')
    search_fields = ('organization_name', 'organization_domain', 'entity_id')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Organization', {
            'fields': ('organization_name', 'organization_domain')
        }),
        ('SAML Configuration', {
            'fields': ('entity_id', 'sso_url', 'slo_url', 'x509_cert')
        }),
        ('Attribute Mapping', {
            'fields': ('email_attribute', 'first_name_attribute', 'last_name_attribute', 'role_attribute')
        }),
        ('Settings', {
            'fields': ('is_active', 'auto_provision_users', 'default_role')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def save_model(self, request, obj, form, change):
        # Validate configuration before saving
        from .utils import validate_saml_configuration
        errors = validate_saml_configuration(obj)
        if errors:
            from django.contrib import messages
            messages.warning(request, f"Configuration warnings: {', '.join(errors)}")
        super().save_model(request, obj, form, change)


@admin.register(OIDCConfiguration)
class OIDCConfigurationAdmin(admin.ModelAdmin):
    list_display = ('organization_name', 'organization_domain', 'issuer', 'is_active', 'auto_provision_users', 'created_at')
    list_filter = ('is_active', 'auto_provision_users', 'created_at')
    search_fields = ('organization_name', 'organization_domain', 'issuer', 'client_id')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Organization', {
            'fields': ('organization_name', 'organization_domain')
        }),
        ('OIDC Configuration', {
            'fields': ('issuer', 'client_id', 'client_secret')
        }),
        ('Endpoints', {
            'fields': ('authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'),
            'classes': ('collapse',)
        }),
        ('Claims Mapping', {
            'fields': ('scopes', 'email_claim', 'first_name_claim', 'last_name_claim', 'role_claim')
        }),
        ('Settings', {
            'fields': ('is_active', 'auto_provision_users', 'default_role')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def save_model(self, request, obj, form, change):
        # Validate configuration before saving
        from .utils import validate_oidc_configuration
        errors = validate_oidc_configuration(obj)
        if errors:
            from django.contrib import messages
            messages.warning(request, f"Configuration warnings: {', '.join(errors)}")
        super().save_model(request, obj, form, change)


@admin.register(SSOSession)
class SSOSessionAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'sso_type', 'provider_name', 'ip_address', 'is_active', 'created_at', 'expires_at')
    list_filter = ('sso_type', 'is_active', 'created_at')
    search_fields = ('user__email', 'provider_name', 'ip_address', 'external_session_id')
    readonly_fields = ('created_at', 'last_activity')
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Session Information', {
            'fields': ('user', 'sso_type', 'provider_name', 'external_session_id')
        }),
        ('Client Information', {
            'fields': ('session_key', 'ip_address', 'user_agent')
        }),
        ('Status', {
            'fields': ('is_active', 'created_at', 'last_activity', 'expires_at')
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'