from django.urls import path
from . import views

app_name = 'events'

urlpatterns = [
    # Event Types
    path('event-types/', views.EventTypeListCreateView.as_view(), name='event-type-list'),
    path('event-types/<uuid:pk>/', views.EventTypeDetailView.as_view(), name='event-type-detail'),
    
    # Public Pages
    path('public/<str:organizer_slug>/', views.public_organizer_page, name='public-organizer-page'),
    path('public/<str:organizer_slug>/<str:event_type_slug>/', views.public_event_type_page, name='public-event-type-page'),
    
    # Available Slots API
    path('slots/<str:organizer_slug>/<str:event_type_slug>/', views.get_available_slots_api, name='available-slots'),
    
    # Bookings
    path('bookings/', views.BookingListView.as_view(), name='booking-list'),
    path('bookings/<uuid:pk>/', views.BookingDetailView.as_view(), name='booking-detail'),
    path('bookings/create/', views.create_booking, name='create-booking'),
    path('bookings/<uuid:booking_id>/cancel/', views.cancel_booking_legacy, name='cancel-booking-legacy'),
    
    # Booking Management (Public)
    path('booking/<uuid:access_token>/manage/', views.booking_management, name='booking-management'),
    
    # Group Event Management
    path('bookings/<uuid:booking_id>/attendees/add/', views.add_attendee_to_booking, name='add-attendee'),
    path('bookings/<uuid:booking_id>/attendees/<uuid:attendee_id>/remove/', views.remove_attendee_from_booking, name='remove-attendee'),
    
    # Analytics and Audit
    path('analytics/', views.booking_analytics, name='booking-analytics'),
    path('bookings/<uuid:booking_id>/audit/', views.booking_audit_logs, name='booking-audit-logs'),
]