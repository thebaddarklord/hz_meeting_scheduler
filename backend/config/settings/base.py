"""
Base settings for calendly_clone project.
"""
import os
from pathlib import Path
from decouple import config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('DJANGO_SECRET_KEY', default='django-insecure-change-me-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=lambda v: [s.strip() for s in v.split(',')])

# Application definition
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'rest_framework.authtoken',
    'corsheaders',
    'django_ratelimit',
    'django_otp',
    'django_otp.plugins.otp_totp',
    'django_otp.plugins.otp_static',
    'guardian',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'allauth.socialaccount.providers.microsoft',
    'djangosaml2',
    'mozilla_django_oidc',
    'django_celery_beat',
    'django_celery_results',
]

LOCAL_APPS = [
    'apps.users',
    'apps.events',
    'apps.availability',
    'apps.integrations',
    'apps.workflows',
    'apps.notifications',
    'apps.contacts',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# Custom User Model
AUTH_USER_MODEL = 'users.User'

# Site ID for django.contrib.sites
SITE_ID = 1

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django_ratelimit.middleware.RatelimitMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_otp.middleware.OTPMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME', default='calendly_clone'),
        'USER': config('DB_USER', default='postgres'),
        'PASSWORD': config('DB_PASSWORD', default='postgres'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Django REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'booking': '10/minute',
        'login': '5/minute',
        'registration': '3/minute',
        'password_reset': '3/hour',
    }
}

# Django Guardian (Object-level permissions)
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'guardian.backends.ObjectPermissionBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
    'apps.users.backends.CustomSAMLBackend',
    'apps.users.backends.CustomOIDCBackend',
)

# Django Allauth Configuration
ACCOUNT_LOGIN_METHODS = ["email"]

ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_SIGNUP_FIELDS = ["email*", "first_name", "last_name"]
ACCOUNT_USER_MODEL_EMAIL_FIELD = 'email'
ACCOUNT_EMAIL_VERIFICATION = 'mandatory'
ACCOUNT_RATE_LIMITS = {
    'login_failed': '5/5m'  # 5 attempts per 5 minutes
}
ACCOUNT_LOGOUT_ON_GET = True
ACCOUNT_SESSION_REMEMBER = True
SOCIALACCOUNT_AUTO_SIGNUP = True

# Social Account Providers
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': [
            'profile',
            'email',
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',
        }
    },
    'microsoft': {
        'tenant': 'common',
    }
}

# Password Validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'apps.users.validators.CustomPasswordValidator',
    },
]

# CORS settings
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default='http://localhost:3000,http://127.0.0.1:3000',
    cast=lambda v: [s.strip() for s in v.split(',')]
)

CORS_ALLOW_CREDENTIALS = True

# Cache configuration (Redis)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': config('REDIS_URL', default='redis://127.0.0.1:6379/1'),
        'OPTIONS': {
            # 'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': 'calendly_clone',
        'TIMEOUT': 300,  # 5 minutes default timeout
    }
}

# Celery Configuration
CELERY_BROKER_URL = config('CELERY_BROKER_URL', default='redis://127.0.0.1:6379/0')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default='redis://127.0.0.1:6379/0')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'
CELERY_ENABLE_UTC = True
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes
CELERY_TASK_SOFT_TIME_LIMIT = 25 * 60  # 25 minutes
CELERY_WORKER_SEND_TASK_EVENTS = True
CELERY_RESULT_EXPIRES = 3600  # 1 hour

# Celery Beat (Periodic Tasks)
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# Availability Module Settings
AVAILABILITY_CACHE_DAYS_AHEAD = config('AVAILABILITY_CACHE_DAYS_AHEAD', default=14, cast=int)
AVAILABILITY_CACHE_TIMEOUT = config('AVAILABILITY_CACHE_TIMEOUT', default=3600, cast=int)  # 1 hour
AVAILABILITY_REASONABLE_HOURS_START = config('AVAILABILITY_REASONABLE_HOURS_START', default=7, cast=int)
AVAILABILITY_REASONABLE_HOURS_END = config('AVAILABILITY_REASONABLE_HOURS_END', default=22, cast=int)
AVAILABILITY_SLOT_INTERVAL_MINUTES = config('AVAILABILITY_SLOT_INTERVAL_MINUTES', default=15, cast=int)
AVAILABILITY_CACHE_DEBOUNCE_SECONDS = config('AVAILABILITY_CACHE_DEBOUNCE_SECONDS', default=300, cast=int)  # 5 minutes

# Twilio Configuration (for SMS)
TWILIO_ACCOUNT_SID = config('TWILIO_ACCOUNT_SID', default='')
TWILIO_AUTH_TOKEN = config('TWILIO_AUTH_TOKEN', default='')
TWILIO_PHONE_NUMBER = config('TWILIO_PHONE_NUMBER', default='')

# Notification Settings
ADMIN_NOTIFICATION_EMAILS = config(
    'ADMIN_NOTIFICATION_EMAILS',
    default='',
    cast=lambda v: [email.strip() for email in v.split(',') if email.strip()]
)
BASE_URL = config('BASE_URL', default='http://localhost:8000')
SITE_NAME = config('SITE_NAME', default='Calendly Clone')

# Notification Rate Limiting
NOTIFICATION_RATE_LIMIT_EMAIL = config('NOTIFICATION_RATE_LIMIT_EMAIL', default=100, cast=int)  # per hour
NOTIFICATION_RATE_LIMIT_SMS = config('NOTIFICATION_RATE_LIMIT_SMS', default=50, cast=int)  # per hour
NOTIFICATION_MAX_RETRIES = config('NOTIFICATION_MAX_RETRIES', default=3, cast=int)
NOTIFICATION_RETRY_DELAY_BASE = config('NOTIFICATION_RETRY_DELAY_BASE', default=30, cast=int)  # seconds

# Google API Configuration
GOOGLE_OAUTH_CLIENT_ID = config('GOOGLE_OAUTH_CLIENT_ID', default='')
GOOGLE_OAUTH_CLIENT_SECRET = config('GOOGLE_OAUTH_CLIENT_SECRET', default='')
GOOGLE_OAUTH_REDIRECT_URI = config('GOOGLE_OAUTH_REDIRECT_URI', default='http://localhost:8000/api/v1/integrations/oauth/callback/')

# Microsoft Graph API Configuration
MICROSOFT_CLIENT_ID = config('MICROSOFT_CLIENT_ID', default='')
MICROSOFT_CLIENT_SECRET = config('MICROSOFT_CLIENT_SECRET', default='')
MICROSOFT_TENANT_ID = config('MICROSOFT_TENANT_ID', default='common')
MICROSOFT_REDIRECT_URI = config('MICROSOFT_REDIRECT_URI', default='http://localhost:8000/api/v1/integrations/oauth/callback/')

# Zoom API Configuration
ZOOM_CLIENT_ID = config('ZOOM_CLIENT_ID', default='')
ZOOM_CLIENT_SECRET = config('ZOOM_CLIENT_SECRET', default='')
ZOOM_REDIRECT_URI = config('ZOOM_REDIRECT_URI', default='http://localhost:8000/api/v1/integrations/oauth/callback/')

# Apple Calendar Configuration
APPLE_CLIENT_ID = config('APPLE_CLIENT_ID', default='')
APPLE_CLIENT_SECRET = config('APPLE_CLIENT_SECRET', default='')
APPLE_REDIRECT_URI = config('APPLE_REDIRECT_URI', default='http://localhost:8000/api/v1/integrations/oauth/callback/')

# Webex API Configuration
WEBEX_CLIENT_ID = config('WEBEX_CLIENT_ID', default='')
WEBEX_CLIENT_SECRET = config('WEBEX_CLIENT_SECRET', default='')
WEBEX_REDIRECT_URI = config('WEBEX_REDIRECT_URI', default='http://localhost:8000/api/v1/integrations/oauth/callback/')

# Integration Rate Limiting
INTEGRATION_RATE_LIMIT_GOOGLE = config('INTEGRATION_RATE_LIMIT_GOOGLE', default=100, cast=int)  # requests per minute
INTEGRATION_RATE_LIMIT_MICROSOFT = config('INTEGRATION_RATE_LIMIT_MICROSOFT', default=60, cast=int)
INTEGRATION_RATE_LIMIT_ZOOM = config('INTEGRATION_RATE_LIMIT_ZOOM', default=80, cast=int)

# Integration Sync Settings
CALENDAR_SYNC_DAYS_AHEAD = config('CALENDAR_SYNC_DAYS_AHEAD', default=90, cast=int)
CALENDAR_SYNC_DAYS_BEHIND = config('CALENDAR_SYNC_DAYS_BEHIND', default=7, cast=int)
CALENDAR_SYNC_BATCH_SIZE = config('CALENDAR_SYNC_BATCH_SIZE', default=50, cast=int)

# SAML Configuration
SAML_CONFIG = {
    'debug': DEBUG,
    'xmlsec_binary': '/usr/bin/xmlsec1',
    'entityid': config('SAML_ENTITY_ID', default='http://localhost:8000/saml/metadata/'),
    'description': 'Calendly Clone SAML SP',
    'service': {
        'sp': {
            'endpoints': {
                'assertion_consumer_service': [
                    ('http://localhost:8000/saml/acs/', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                ],
                'single_logout_service': [
                    ('http://localhost:8000/saml/sls/', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                ],
            },
            'allow_unsolicited': True,
            'authn_requests_signed': False,
            'logout_requests_signed': True,
            'want_assertions_signed': True,
            'want_response_signed': False,
        },
    },
}

# OIDC Configuration
OIDC_RP_CLIENT_ID = config('OIDC_RP_CLIENT_ID', default='')
OIDC_RP_CLIENT_SECRET = config('OIDC_RP_CLIENT_SECRET', default='')
OIDC_OP_AUTHORIZATION_ENDPOINT = config('OIDC_OP_AUTHORIZATION_ENDPOINT', default='')
OIDC_OP_TOKEN_ENDPOINT = config('OIDC_OP_TOKEN_ENDPOINT', default='')
OIDC_OP_USER_ENDPOINT = config('OIDC_OP_USER_ENDPOINT', default='')
OIDC_OP_JWKS_ENDPOINT = config('OIDC_OP_JWKS_ENDPOINT', default='')

# MFA Settings
OTP_TOTP_ISSUER = 'Calendly Clone'
OTP_LOGIN_URL = '/login/'

# Password Expiry Settings
PASSWORD_EXPIRY_DAYS = config('PASSWORD_EXPIRY_DAYS', default=90, cast=int)  # Password expires after 90 days
PASSWORD_EXPIRY_WARNING_DAYS = config('PASSWORD_EXPIRY_WARNING_DAYS', default=7, cast=int)  # Start warning 7 days before expiry
PASSWORD_EXPIRY_GRACE_PERIOD_HOURS = config('PASSWORD_EXPIRY_GRACE_PERIOD_HOURS', default=24, cast=int)  # 24-hour grace period after expiry

# SAML Configuration
SAML_CONFIG = {
    'debug': DEBUG,
    'xmlsec_binary': '/usr/bin/xmlsec1',
    'entityid': config('SAML_ENTITY_ID', default='http://localhost:8000/saml/metadata/'),
    'description': 'Calendly Clone SAML SP',
    'service': {
        'sp': {
            'endpoints': {
                'assertion_consumer_service': [
                    ('http://localhost:8000/saml/acs/', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                ],
                'single_logout_service': [
                    ('http://localhost:8000/saml/sls/', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
                ],
            },
            'allow_unsolicited': True,
            'authn_requests_signed': False,
            'logout_requests_signed': True,
            'want_assertions_signed': True,
            'want_response_signed': False,
        },
    },
}

# OIDC Configuration
OIDC_AUTHENTICATION_CALLBACK_URL = 'oidc_authentication_callback'
OIDC_RP_SIGN_ALGO = 'RS256'
OIDC_RP_SCOPES = 'openid email profile'

# SSO URLs
LOGIN_URL = '/login/'
LOGOUT_URL = '/logout/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'
# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default=EMAIL_HOST_USER)

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'django.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'celery': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Security Settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'