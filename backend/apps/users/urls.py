from django.urls import path
from . import views

app_name = 'users'

urlpatterns = [
    # Authentication
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Profile Management
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('public/<str:organizer_slug>/', views.PublicProfileView.as_view(), name='public-profile'),
    
    # Password Management
    path('change-password/', views.change_password, name='change-password'),
    path('force-password-change/', views.force_password_change, name='force-password-change'),
    path('request-password-reset/', views.request_password_reset, name='request-password-reset'),
    path('confirm-password-reset/', views.confirm_password_reset, name='confirm-password-reset'),
    
    # Email Verification
    path('verify-email/', views.verify_email, name='verify-email'),
    path('resend-verification/', views.resend_verification, name='resend-verification'),
    
    # Role Management
    path('permissions/', views.PermissionListView.as_view(), name='permission-list'),
    path('roles/', views.RoleListView.as_view(), name='role-list'),
    
    # Invitations
    path('invitations/', views.InvitationListCreateView.as_view(), name='invitation-list'),
    path('invitations/respond/', views.respond_to_invitation, name='respond-invitation'),
    
    # Session Management
    path('sessions/', views.UserSessionListView.as_view(), name='session-list'),
    path('sessions/<uuid:session_id>/revoke/', views.revoke_session, name='revoke-session'),
    path('sessions/revoke-all/', views.revoke_all_sessions, name='revoke-all-sessions'),
    
    # Audit Logs
    path('audit-logs/', views.AuditLogListView.as_view(), name='audit-logs'),
    
    # MFA Management
    path('mfa/devices/', views.MFADeviceListView.as_view(), name='mfa-devices'),
    path('mfa/setup/', views.setup_mfa, name='setup-mfa'),
    path('mfa/verify/', views.verify_mfa_setup, name='verify-mfa'),
    path('mfa/resend-sms/', views.resend_sms_otp, name='resend-sms-otp'),
    path('mfa/send-sms-code/', views.send_sms_mfa_code_view, name='send-sms-mfa-code'),
    path('mfa/verify-sms/', views.verify_sms_mfa_login, name='verify-sms-mfa'),
    path('mfa/disable/', views.disable_mfa, name='disable-mfa'),
    path('mfa/backup-codes/regenerate/', views.regenerate_backup_codes, name='regenerate-backup-codes'),
    
    # SSO Configuration (Admin)
    path('sso/saml/', views.SAMLConfigurationListCreateView.as_view(), name='saml-config-list'),
    path('sso/saml/<uuid:pk>/', views.SAMLConfigurationDetailView.as_view(), name='saml-config-detail'),
    path('sso/oidc/', views.OIDCConfigurationListCreateView.as_view(), name='oidc-config-list'),
    path('sso/oidc/<uuid:pk>/', views.OIDCConfigurationDetailView.as_view(), name='oidc-config-detail'),
    path('sso/initiate/', views.initiate_sso, name='initiate-sso'),
    path('sso/logout/', views.sso_logout, name='sso-logout'),
    path('sso/discovery/', views.sso_discovery, name='sso-discovery'),
    path('sso/sessions/', views.sso_sessions, name='sso-sessions'),
    path('sso/sessions/<uuid:session_id>/revoke/', views.revoke_sso_session, name='revoke-sso-session'),
]