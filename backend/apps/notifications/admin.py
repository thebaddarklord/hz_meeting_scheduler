from django.contrib import admin
from .models import NotificationTemplate, NotificationLog, NotificationPreference, NotificationSchedule


@admin.register(NotificationTemplate)
class NotificationTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'organizer', 'template_type', 'notification_type', 'is_active', 'is_default')
    list_filter = ('template_type', 'notification_type', 'is_active', 'is_default', 'created_at')
    search_fields = ('name', 'organizer__email', 'subject')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Template Information', {
            'fields': ('organizer', 'name', 'template_type', 'notification_type')
        }),
        ('Content', {
            'fields': ('subject', 'message')
        }),
        ('Settings', {
            'fields': ('is_active', 'is_default')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(NotificationLog)
class NotificationLogAdmin(admin.ModelAdmin):
    list_display = ('recipient_display', 'notification_type', 'status', 'delivery_status', 'retry_count', 'sent_at', 'organizer', 'created_at')
    list_filter = ('notification_type', 'status', 'delivery_status', 'sent_at', 'created_at')
    search_fields = ('recipient_email', 'recipient_phone', 'subject', 'organizer__email')
    readonly_fields = ('created_at', 'updated_at')
    date_hierarchy = 'created_at'
    actions = ['retry_failed_notifications', 'mark_as_delivered']
    
    fieldsets = (
        ('Notification Details', {
            'fields': ('organizer', 'booking', 'template', 'notification_type')
        }),
        ('Recipients', {
            'fields': ('recipient_email', 'recipient_phone')
        }),
        ('Content', {
            'fields': ('subject', 'message')
        }),
        ('Status Tracking', {
            'fields': ('status', 'delivery_status', 'sent_at', 'delivered_at', 'opened_at', 'clicked_at')
        }),
        ('Error Tracking', {
            'fields': ('error_message', 'retry_count', 'max_retries', 'external_id', 'provider_response')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def recipient_display(self, obj):
        if obj.recipient_email:
            return obj.recipient_email
        elif obj.recipient_phone:
            return obj.recipient_phone
        return 'No recipient'
    recipient_display.short_description = 'Recipient'
    
    def retry_failed_notifications(self, request, queryset):
        """Admin action to retry failed notifications."""
        failed_notifications = queryset.filter(status='failed')
        retry_count = 0
        
        for notification in failed_notifications:
            if notification.can_retry():
                from .tasks import send_notification_task
                send_notification_task.delay(notification.id)
                retry_count += 1
        
        self.message_user(request, f"Queued {retry_count} notifications for retry.")
    retry_failed_notifications.short_description = "Retry failed notifications"
    
    def mark_as_delivered(self, request, queryset):
        """Admin action to manually mark notifications as delivered."""
        updated = queryset.filter(status='sent').update(
            status='delivered',
            delivered_at=timezone.now()
        )
        self.message_user(request, f"Marked {updated} notifications as delivered.")
    mark_as_delivered.short_description = "Mark as delivered"


@admin.register(NotificationPreference)
class NotificationPreferenceAdmin(admin.ModelAdmin):
    list_display = ('organizer', 'preferred_notification_method', 'booking_reminders_email', 'daily_agenda_email', 'dnd_enabled', 'exclude_weekends_reminders')
    list_filter = ('preferred_notification_method', 'dnd_enabled', 'exclude_weekends_reminders', 'exclude_weekends_agenda')
    search_fields = ('organizer__email', 'organizer__first_name', 'organizer__last_name')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Organizer', {
            'fields': ('organizer',)
        }),
        ('General Preferences', {
            'fields': ('preferred_notification_method', 'max_reminders_per_day')
        }),
        ('Email Preferences', {
            'fields': ('booking_confirmations_email', 'booking_reminders_email', 
                      'booking_cancellations_email', 'daily_agenda_email')
        }),
        ('SMS Preferences', {
            'fields': ('booking_confirmations_sms', 'booking_reminders_sms', 'booking_cancellations_sms')
        }),
        ('Timing Preferences', {
            'fields': ('reminder_minutes_before', 'daily_agenda_time')
        }),
        ('Do-Not-Disturb Settings', {
            'fields': ('dnd_enabled', 'dnd_start_time', 'dnd_end_time')
        }),
        ('Weekend Preferences', {
            'fields': ('exclude_weekends_reminders', 'exclude_weekends_agenda')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(NotificationSchedule)
class NotificationScheduleAdmin(admin.ModelAdmin):
    list_display = ('schedule_type', 'recipient_email', 'scheduled_for', 'status', 'organizer')
    list_filter = ('schedule_type', 'notification_type', 'status', 'scheduled_for')
    search_fields = ('recipient_email', 'recipient_phone', 'subject', 'organizer__email')
    readonly_fields = ('created_at', 'updated_at')
    date_hierarchy = 'scheduled_for'
    
    fieldsets = (
        ('Schedule Information', {
            'fields': ('organizer', 'booking', 'schedule_type', 'notification_type')
        }),
        ('Scheduling', {
            'fields': ('scheduled_for', 'status')
        }),
        ('Recipients', {
            'fields': ('recipient_email', 'recipient_phone')
        }),
        ('Content', {
            'fields': ('subject', 'message')
        }),
        ('Execution', {
            'fields': ('sent_at', 'error_message')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )