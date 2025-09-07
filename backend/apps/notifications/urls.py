from django.urls import path
from . import views

app_name = 'notifications'

urlpatterns = [
    # Notification Templates
    path('templates/', views.NotificationTemplateListCreateView.as_view(), name='template-list'),
    path('templates/<uuid:pk>/', views.NotificationTemplateDetailView.as_view(), name='template-detail'),
    path('templates/<uuid:pk>/test/', views.test_template, name='template-test'),
    
    # Notification Logs
    path('logs/', views.NotificationLogListView.as_view(), name='log-list'),
    
    # Notification Preferences
    path('preferences/', views.NotificationPreferenceView.as_view(), name='preferences'),
    
    # Scheduled Notifications
    path('scheduled/', views.NotificationScheduleListView.as_view(), name='scheduled-list'),
    path('scheduled/<uuid:pk>/cancel/', views.cancel_scheduled_notification, name='scheduled-cancel'),
    
    # Manual Notifications
    path('send/', views.send_notification, name='send-notification'),
    
    # Statistics
    path('stats/', views.notification_stats, name='stats'),
    
    # Health and Monitoring
    path('health/', views.notification_health, name='health'),
    path('<uuid:pk>/resend/', views.resend_failed_notification, name='resend'),
    
    # Webhooks and Callbacks
    path('sms-status-callback/', views.sms_status_callback, name='sms-status-callback'),
]