from django.contrib import admin
from django.utils.html import format_html
from .models import EventType, Booking, Attendee, WaitlistEntry, CustomQuestion, BookingAuditLog


class CustomQuestionInline(admin.TabularInline):
    model = CustomQuestion
    extra = 0
    fields = ('question_text', 'question_type', 'is_required', 'order')
    ordering = ['order']


@admin.register(EventType)
class EventTypeAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'organizer', 'duration', 'max_attendees', 'is_group_event_display',
        'is_active', 'is_private', 'booking_count', 'created_at'
    )
    list_filter = (
        'duration', 'is_active', 'is_private', 'location_type', 
        'recurrence_type', 'enable_waitlist', 'created_at'
    )
    search_fields = ('name', 'organizer__email', 'event_type_slug')
    readonly_fields = ('event_type_slug', 'created_at', 'updated_at')
    inlines = [CustomQuestionInline]
    filter_horizontal = []
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('organizer', 'name', 'event_type_slug', 'description', 'duration', 'max_attendees')
        }),
        ('Availability Settings', {
            'fields': (
                'is_active', 'is_private', 'min_scheduling_notice', 'max_scheduling_horizon',
                'buffer_time_before', 'buffer_time_after', 'max_bookings_per_day',
                'slot_interval_minutes'
            )
        }),
        ('Group Event Settings', {
            'fields': ('enable_waitlist',),
            'classes': ('collapse',)
        }),
        ('Recurrence Settings', {
            'fields': (
                'recurrence_type', 'recurrence_rule', 'max_occurrences', 'recurrence_end_date'
            ),
            'classes': ('collapse',)
        }),
        ('Location & Meeting', {
            'fields': ('location_type', 'location_details', 'redirect_url_after_booking')
        }),
        ('Workflow Integration', {
            'fields': ('confirmation_workflow', 'reminder_workflow', 'cancellation_workflow'),
            'classes': ('collapse',)
        }),
        ('Legacy Custom Questions', {
            'fields': ('custom_questions',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def is_group_event_display(self, obj):
        return obj.is_group_event()
    is_group_event_display.boolean = True
    is_group_event_display.short_description = 'Group Event'
    
    def booking_count(self, obj):
        return obj.bookings.filter(status='confirmed').count()
    booking_count.short_description = 'Active Bookings'


class AttendeeInline(admin.TabularInline):
    model = Attendee
    extra = 0
    fields = ('name', 'email', 'phone', 'status', 'joined_at')
    readonly_fields = ('joined_at',)


class BookingAuditLogInline(admin.TabularInline):
    model = BookingAuditLog
    extra = 0
    fields = ('action', 'actor_type', 'actor_name', 'description', 'created_at')
    readonly_fields = ('action', 'actor_type', 'actor_name', 'description', 'created_at')
    can_delete = False
    
    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = (
        'invitee_name', 'invitee_email', 'event_type', 'organizer',
        'start_time', 'status', 'attendee_count', 'calendar_sync_status',
        'is_recurring_display', 'created_at'
    )
    list_filter = (
        'status', 'calendar_sync_status', 'event_type__name', 
        'cancelled_by', 'is_recurring_exception', 'start_time', 'created_at'
    )
    search_fields = (
        'invitee_name', 'invitee_email', 'organizer__email', 
        'access_token', 'external_calendar_event_id'
    )
    readonly_fields = (
        'id', 'access_token', 'duration_minutes', 'calendar_sync_attempts',
        'last_calendar_sync_attempt', 'created_at', 'updated_at'
    )
    date_hierarchy = 'start_time'
    inlines = [AttendeeInline, BookingAuditLogInline]
    actions = ['mark_completed', 'retry_calendar_sync', 'regenerate_access_tokens']
    
    fieldsets = (
        ('Booking Information', {
            'fields': ('id', 'event_type', 'organizer', 'status', 'attendee_count')
        }),
        ('Invitee Details', {
            'fields': (
                'invitee_name', 'invitee_email', 'invitee_phone', 'invitee_timezone'
            )
        }),
        ('Schedule', {
            'fields': ('start_time', 'end_time')
        }),
        ('Recurrence', {
            'fields': (
                'recurrence_id', 'is_recurring_exception', 'recurrence_sequence'
            ),
            'classes': ('collapse',)
        }),
        ('Security', {
            'fields': ('access_token', 'access_token_expires_at'),
            'classes': ('collapse',)
        }),
        ('Meeting Details', {
            'fields': ('meeting_link', 'meeting_id', 'meeting_password'),
            'classes': ('collapse',)
        }),
        ('Calendar Integration', {
            'fields': (
                'external_calendar_event_id', 'calendar_sync_status', 
                'calendar_sync_error', 'calendar_sync_attempts', 'last_calendar_sync_attempt'
            ),
            'classes': ('collapse',)
        }),
        ('Custom Data', {
            'fields': ('custom_answers',),
            'classes': ('collapse',)
        }),
        ('Cancellation', {
            'fields': ('cancelled_at', 'cancelled_by', 'cancellation_reason'),
            'classes': ('collapse',)
        }),
        ('Rescheduling', {
            'fields': ('rescheduled_from', 'rescheduled_at'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def is_recurring_display(self, obj):
        return bool(obj.recurrence_id)
    is_recurring_display.boolean = True
    is_recurring_display.short_description = 'Recurring'
    
    def mark_completed(self, request, queryset):
        """Mark selected bookings as completed."""
        updated = queryset.filter(status='confirmed').update(status='completed')
        self.message_user(request, f"Marked {updated} bookings as completed.")
    mark_completed.short_description = "Mark as completed"
    
    def retry_calendar_sync(self, request, queryset):
        """Retry calendar sync for failed bookings."""
        failed_bookings = queryset.filter(calendar_sync_status='failed')
        
        for booking in failed_bookings:
            from .tasks import sync_booking_to_external_calendars
            sync_booking_to_external_calendars.delay(booking.id)
        
        self.message_user(request, f"Queued {failed_bookings.count()} bookings for calendar sync retry.")
    retry_calendar_sync.short_description = "Retry calendar sync"
    
    def regenerate_access_tokens(self, request, queryset):
        """Regenerate access tokens for selected bookings."""
        count = 0
        for booking in queryset:
            booking.regenerate_access_token()
            count += 1
        
        self.message_user(request, f"Regenerated access tokens for {count} bookings.")
    regenerate_access_tokens.short_description = "Regenerate access tokens"


@admin.register(Attendee)
class AttendeeAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'booking_event_type', 'booking_organizer', 'status', 'joined_at')
    list_filter = ('status', 'joined_at', 'cancelled_at')
    search_fields = ('name', 'email', 'booking__invitee_name')
    readonly_fields = ('joined_at', 'created_at', 'updated_at')
    
    fieldsets = (
        ('Attendee Information', {
            'fields': ('booking', 'name', 'email', 'phone', 'status')
        }),
        ('Custom Answers', {
            'fields': ('custom_answers',),
            'classes': ('collapse',)
        }),
        ('Cancellation', {
            'fields': ('cancelled_at', 'cancellation_reason'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('joined_at', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def booking_event_type(self, obj):
        return obj.booking.event_type.name
    booking_event_type.short_description = 'Event Type'
    
    def booking_organizer(self, obj):
        return obj.booking.organizer.email
    booking_organizer.short_description = 'Organizer'


@admin.register(WaitlistEntry)
class WaitlistEntryAdmin(admin.ModelAdmin):
    list_display = (
        'invitee_name', 'invitee_email', 'event_type', 'organizer',
        'desired_start_time', 'status', 'is_expired_display', 'created_at'
    )
    list_filter = ('status', 'notify_when_available', 'created_at', 'expires_at')
    search_fields = ('invitee_name', 'invitee_email', 'organizer__email')
    readonly_fields = ('created_at', 'updated_at', 'notified_at')
    date_hierarchy = 'desired_start_time'
    actions = ['notify_availability', 'extend_expiration']
    
    fieldsets = (
        ('Waitlist Information', {
            'fields': ('event_type', 'organizer', 'status')
        }),
        ('Desired Booking', {
            'fields': ('desired_start_time', 'desired_end_time')
        }),
        ('Invitee Details', {
            'fields': ('invitee_name', 'invitee_email', 'invitee_phone', 'invitee_timezone')
        }),
        ('Settings', {
            'fields': ('notify_when_available', 'expires_at')
        }),
        ('Custom Answers', {
            'fields': ('custom_answers',),
            'classes': ('collapse',)
        }),
        ('Status Tracking', {
            'fields': ('notified_at', 'converted_booking'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def is_expired_display(self, obj):
        return obj.is_expired()
    is_expired_display.boolean = True
    is_expired_display.short_description = 'Expired'
    
    def notify_availability(self, request, queryset):
        """Manually notify waitlist entries of availability."""
        active_entries = queryset.filter(status='active')
        
        for entry in active_entries:
            entry.notify_availability()
        
        self.message_user(request, f"Notified {active_entries.count()} waitlist entries.")
    notify_availability.short_description = "Notify of availability"
    
    def extend_expiration(self, request, queryset):
        """Extend expiration for selected waitlist entries."""
        from datetime import timedelta
        
        updated = queryset.filter(status='active').update(
            expires_at=timezone.now() + timedelta(days=7)
        )
        
        self.message_user(request, f"Extended expiration for {updated} waitlist entries.")
    extend_expiration.short_description = "Extend expiration by 7 days"


@admin.register(CustomQuestion)
class CustomQuestionAdmin(admin.ModelAdmin):
    list_display = ('question_text_short', 'event_type', 'question_type', 'is_required', 'order')
    list_filter = ('question_type', 'is_required', 'event_type__organizer')
    search_fields = ('question_text', 'event_type__name')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Question Details', {
            'fields': ('event_type', 'question_text', 'question_type', 'is_required', 'order')
        }),
        ('Options (for select/radio)', {
            'fields': ('options',),
            'classes': ('collapse',)
        }),
        ('Conditional Logic', {
            'fields': ('conditions',),
            'classes': ('collapse',)
        }),
        ('Validation Rules', {
            'fields': ('validation_rules',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def question_text_short(self, obj):
        return obj.question_text[:50] + '...' if len(obj.question_text) > 50 else obj.question_text
    question_text_short.short_description = 'Question'


@admin.register(BookingAuditLog)
class BookingAuditLogAdmin(admin.ModelAdmin):
    list_display = (
        'booking_display', 'action', 'actor_type', 'actor_name', 
        'description_short', 'created_at'
    )
    list_filter = ('action', 'actor_type', 'created_at')
    search_fields = ('booking__invitee_name', 'actor_email', 'description')
    readonly_fields = ('created_at',)
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Log Information', {
            'fields': ('booking', 'action', 'description')
        }),
        ('Actor Information', {
            'fields': ('actor_type', 'actor_email', 'actor_name')
        }),
        ('Context', {
            'fields': ('ip_address', 'user_agent')
        }),
        ('Data Changes', {
            'fields': ('old_values', 'new_values', 'metadata'),
            'classes': ('collapse',)
        }),
        ('Timestamp', {
            'fields': ('created_at',)
        }),
    )
    
    def booking_display(self, obj):
        return f"{obj.booking.invitee_name} - {obj.booking.event_type.name}"
    booking_display.short_description = 'Booking'
    
    def description_short(self, obj):
        return obj.description[:100] + '...' if len(obj.description) > 100 else obj.description
    description_short.short_description = 'Description'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False