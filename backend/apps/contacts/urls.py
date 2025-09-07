from django.urls import path
from . import views

app_name = 'contacts'

urlpatterns = [
    # Contacts
    path('', views.ContactListCreateView.as_view(), name='contact-list'),
    path('<uuid:pk>/', views.ContactDetailView.as_view(), name='contact-detail'),
    path('<uuid:contact_id>/interactions/', views.ContactInteractionListView.as_view(), name='contact-interactions'),
    path('<uuid:contact_id>/interactions/add/', views.add_contact_interaction, name='add-interaction'),
    
    # Contact Groups
    path('groups/', views.ContactGroupListCreateView.as_view(), name='group-list'),
    path('groups/<uuid:pk>/', views.ContactGroupDetailView.as_view(), name='group-detail'),
    path('<uuid:contact_id>/groups/<uuid:group_id>/add/', views.add_contact_to_group, name='add-to-group'),
    path('<uuid:contact_id>/groups/<uuid:group_id>/remove/', views.remove_contact_from_group, name='remove-from-group'),
    
    # Statistics and Analytics
    path('stats/', views.contact_stats, name='contact-stats'),
    
    # Import/Export
    path('import/', views.import_contacts, name='import-contacts'),
    path('export/', views.export_contacts, name='export-contacts'),
    
    # Contact Management
    path('merge/', views.merge_contacts, name='merge-contacts'),
    
    # All Interactions
    path('interactions/', views.ContactInteractionListView.as_view(), name='all-interactions'),
]