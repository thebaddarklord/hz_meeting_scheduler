from django.urls import path
from . import views

app_name = 'integrations'

urlpatterns = [
    # Calendar Integrations
    path('calendar/', views.CalendarIntegrationListView.as_view(), name='calendar-list'),
    path('calendar/<uuid:pk>/', views.CalendarIntegrationDetailView.as_view(), name='calendar-detail'),
    path('calendar/<uuid:pk>/refresh/', views.refresh_calendar_sync, name='calendar-refresh'),
    
    # Video Conference Integrations
    path('video/', views.VideoConferenceIntegrationListView.as_view(), name='video-list'),
    path('video/<uuid:pk>/', views.VideoConferenceIntegrationDetailView.as_view(), name='video-detail'),
    
    # Webhook Integrations
    path('webhooks/', views.WebhookIntegrationListCreateView.as_view(), name='webhook-list'),
    path('webhooks/<uuid:pk>/', views.WebhookIntegrationDetailView.as_view(), name='webhook-detail'),
    path('webhooks/<uuid:pk>/test/', views.test_webhook, name='webhook-test'),
    
    # Integration Logs
    path('logs/', views.IntegrationLogListView.as_view(), name='log-list'),
    
    # OAuth
    path('oauth/initiate/', views.initiate_oauth, name='oauth-initiate'),
    path('oauth/callback/', views.oauth_callback, name='oauth-callback'),
    
    # Health and Monitoring
    path('health/', views.integration_health, name='integration-health'),
    path('calendar/<uuid:pk>/force-sync/', views.force_calendar_sync, name='force-calendar-sync'),
    path('calendar/conflicts/', views.calendar_conflicts, name='calendar-conflicts'),
]