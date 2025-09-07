from django.urls import path
from . import views

# These URLs are for the public booking pages
# They are included at the root level to match Calendly-style URLs

urlpatterns = [
    # Public organizer page
    path('<str:organizer_slug>/', views.public_organizer_page, name='public-organizer'),
    
    # Public event type booking page
    path('<str:organizer_slug>/<str:event_type_slug>/', views.public_event_type_page, name='public-booking'),
]