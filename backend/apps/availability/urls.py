from django.urls import path
from . import views

app_name = 'availability'

urlpatterns = [
    # Availability Rules
    path('rules/', views.AvailabilityRuleListCreateView.as_view(), name='rule-list'),
    path('rules/<uuid:pk>/', views.AvailabilityRuleDetailView.as_view(), name='rule-detail'),
    
    # Date Override Rules
    path('overrides/', views.DateOverrideRuleListCreateView.as_view(), name='override-list'),
    path('overrides/<uuid:pk>/', views.DateOverrideRuleDetailView.as_view(), name='override-detail'),
    
    # Recurring Blocked Times
    path('recurring-blocks/', views.RecurringBlockedTimeListCreateView.as_view(), name='recurring-block-list'),
    path('recurring-blocks/<uuid:pk>/', views.RecurringBlockedTimeDetailView.as_view(), name='recurring-block-detail'),
    
    # Blocked Times
    path('blocked/', views.BlockedTimeListCreateView.as_view(), name='blocked-list'),
    path('blocked/<uuid:pk>/', views.BlockedTimeDetailView.as_view(), name='blocked-detail'),
    
    # Buffer Time Settings
    path('buffer/', views.BufferTimeView.as_view(), name='buffer-settings'),
    
    # Calculated Slots (Public endpoint)
    path('calculated-slots/<str:organizer_slug>/', views.calculated_slots, name='calculated-slots'),
    
    # Statistics and Management
    path('stats/', views.availability_stats, name='availability-stats'),
    path('cache/clear/', views.clear_availability_cache_manual, name='clear-cache'),
    path('cache/precompute/', views.precompute_availability_cache_manual, name='precompute-cache'),
    
    # Testing and Debugging
    path('test/timezone/', views.test_timezone_handling, name='test-timezone'),
]