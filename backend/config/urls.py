"""
URL configuration for calendly_clone project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # API endpoints
    path('api/v1/users/', include('apps.users.urls')),
    path('api/v1/events/', include('apps.events.urls')),
    path('api/v1/availability/', include('apps.availability.urls')),
    path('api/v1/integrations/', include('apps.integrations.urls')),
    path('api/v1/workflows/', include('apps.workflows.urls')),
    path('api/v1/notifications/', include('apps.notifications.urls')),
    path('api/v1/contacts/', include('apps.contacts.urls')),
    
    # SSO URLs
    path('saml/', include('djangosaml2.urls')),
    path('oidc/', include('mozilla_django_oidc.urls')),
    
    # Public booking URLs - these should be last to avoid conflicts
    path('', include('apps.events.public_urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Django Debug Toolbar
if settings.DEBUG:
    try:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns
    except ImportError:
        pass