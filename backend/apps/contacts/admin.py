from django.contrib import admin
from .models import Contact, ContactGroup, ContactInteraction


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'email', 'company', 'total_bookings', 'last_booking_date', 'organizer', 'is_active')
    list_filter = ('is_active', 'company', 'created_at', 'last_booking_date')
    search_fields = ('first_name', 'last_name', 'email', 'company', 'organizer__email')
    readonly_fields = ('total_bookings', 'last_booking_date', 'created_at', 'updated_at')
    
    fieldsets = (
        ('Contact Information', {
            'fields': ('organizer', 'first_name', 'last_name', 'email', 'phone')
        }),
        ('Professional Information', {
            'fields': ('company', 'job_title')
        }),
        ('Additional Information', {
            'fields': ('notes', 'tags', 'is_active')
        }),
        ('Statistics', {
            'fields': ('total_bookings', 'last_booking_date'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(ContactGroup)
class ContactGroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'organizer', 'contact_count', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('name', 'organizer__email', 'description')
    readonly_fields = ('created_at', 'updated_at')
    filter_horizontal = ('contacts',)
    
    fieldsets = (
        ('Group Information', {
            'fields': ('organizer', 'name', 'description', 'color')
        }),
        ('Contacts', {
            'fields': ('contacts',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(ContactInteraction)
class ContactInteractionAdmin(admin.ModelAdmin):
    list_display = ('contact', 'interaction_type', 'organizer', 'booking', 'created_at')
    list_filter = ('interaction_type', 'created_at')
    search_fields = ('contact__first_name', 'contact__last_name', 'contact__email', 'description')
    readonly_fields = ('created_at',)
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Interaction Details', {
            'fields': ('contact', 'organizer', 'interaction_type', 'description')
        }),
        ('Related Objects', {
            'fields': ('booking',)
        }),
        ('Additional Data', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
        ('Timestamp', {
            'fields': ('created_at',)
        }),
    )