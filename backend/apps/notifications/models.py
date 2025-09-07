from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from datetime import time
import uuid


class NotificationTemplate(models.Model):
    """Email/SMS templates for notifications."""
    TEMPLATE_TYPES = [
        ('booking_confirmation', 'Booking Confirmation'),
        ('booking_reminder', 'Booking Reminder'),
        ('booking_cancellation', 'Booking Cancellation'),
        ('booking_rescheduled', 'Booking Rescheduled'),
        ('follow_up', 'Follow-up'),
        ('custom', 'Custom'),
    ]
    
    NOTIFICATION_TYPES = [
        ('email', 'Email'),
        ('sms', 'SMS'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='notification_templates')
    
    name = models.CharField(max_length=200)
    template_type = models.CharField(max_length=30, choices=TEMPLATE_TYPES)
    notification_type = models.CharField(max_length=10, choices=NOTIFICATION_TYPES)
    
    # Email fields
    subject = models.CharField(max_length=200, blank=True)
    
    # Content
    message = models.TextField()
    
    # Settings
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)
    
    # Template validation
    required_placeholders = models.JSONField(
        default=list, 
        blank=True, 
        help_text="List of required placeholders for this template"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'notification_templates'
        unique_together = ['organizer', 'template_type', 'notification_type', 'is_default']
        verbose_name = 'Notification Template'
        verbose_name_plural = 'Notification Templates'
    
    def __str__(self):
        return f"{self.organizer.email} - {self.name}"
    
    def validate_placeholders(self, context_data):
        """Validate that all required placeholders have data."""
        missing_placeholders = []
        for placeholder in self.required_placeholders:
            if placeholder not in context_data or not context_data[placeholder]:
                missing_placeholders.append(placeholder)
        return missing_placeholders
    
    def render_content(self, context_data):
        """Safely render template content with fallbacks."""
        from .utils import render_template_with_fallbacks
        
        rendered_subject = render_template_with_fallbacks(self.subject, context_data)
        rendered_message = render_template_with_fallbacks(self.message, context_data)
        
        return {
            'subject': rendered_subject,
            'message': rendered_message
        }


class NotificationLog(models.Model):
    """Log of sent notifications."""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('failed', 'Failed'),
        ('bounced', 'Bounced'),
        ('delivered', 'Delivered'),
        ('opened', 'Opened'),
        ('clicked', 'Clicked'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='notification_logs')
    booking = models.ForeignKey('events.Booking', on_delete=models.CASCADE, related_name='notifications', null=True, blank=True)
    template = models.ForeignKey(NotificationTemplate, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Notification details
    notification_type = models.CharField(max_length=10, choices=NotificationTemplate.NOTIFICATION_TYPES)
    recipient_email = models.EmailField(blank=True)
    recipient_phone = models.CharField(max_length=20, blank=True)
    
    # Content
    subject = models.CharField(max_length=200, blank=True)
    message = models.TextField()
    
    # Status tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    sent_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    opened_at = models.DateTimeField(null=True, blank=True)
    clicked_at = models.DateTimeField(null=True, blank=True)
    
    # Error tracking
    error_message = models.TextField(blank=True)
    retry_count = models.IntegerField(default=0)
    max_retries = models.IntegerField(default=3)
    
    # External service tracking
    external_id = models.CharField(max_length=200, blank=True, help_text="ID from email/SMS service")
    
    # Delivery tracking
    delivery_status = models.CharField(
        max_length=20,
        choices=[
            ('unknown', 'Unknown'),
            ('queued', 'Queued'),
            ('sending', 'Sending'),
            ('sent', 'Sent'),
            ('delivered', 'Delivered'),
            ('failed', 'Failed'),
            ('bounced', 'Bounced'),
            ('undelivered', 'Undelivered'),
        ],
        default='unknown'
    )
    
    # Provider-specific data
    provider_response = models.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'notification_logs'
        verbose_name = 'Notification Log'
        verbose_name_plural = 'Notification Logs'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.notification_type} to {self.recipient_email or self.recipient_phone} - {self.status}"
    
    def can_retry(self):
        """Check if notification can be retried."""
        return self.retry_count < self.max_retries and self.status in ['pending', 'failed']
    
    def mark_retry(self, error_message=None):
        """Mark a retry attempt."""
        self.retry_count += 1
        if error_message:
            self.error_message = error_message
        if self.retry_count >= self.max_retries:
            self.status = 'failed'
        self.save(update_fields=['retry_count', 'error_message', 'status'])


class NotificationPreference(models.Model):
    """User preferences for notifications."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.OneToOneField('users.User', on_delete=models.CASCADE, related_name='notification_preferences')
    
    # Email preferences
    booking_confirmations_email = models.BooleanField(default=True)
    booking_reminders_email = models.BooleanField(default=True)
    booking_cancellations_email = models.BooleanField(default=True)
    daily_agenda_email = models.BooleanField(default=True)
    
    # SMS preferences
    booking_confirmations_sms = models.BooleanField(default=False)
    booking_reminders_sms = models.BooleanField(default=False)
    booking_cancellations_sms = models.BooleanField(default=False)
    
    # Timing preferences
    reminder_minutes_before = models.IntegerField(default=60, help_text="Minutes before meeting to send reminder")
    daily_agenda_time = models.TimeField(default='08:00', help_text="Time to send daily agenda")
    
    # Do-Not-Disturb settings
    dnd_enabled = models.BooleanField(default=False, help_text="Enable do-not-disturb hours")
    dnd_start_time = models.TimeField(
        default=time(22, 0), 
        help_text="Start of do-not-disturb period (local time)"
    )
    dnd_end_time = models.TimeField(
        default=time(7, 0), 
        help_text="End of do-not-disturb period (local time)"
    )
    
    # Weekend preferences
    exclude_weekends_reminders = models.BooleanField(
        default=False, 
        help_text="Don't send reminders on weekends"
    )
    exclude_weekends_agenda = models.BooleanField(
        default=True, 
        help_text="Don't send daily agenda on weekends"
    )
    
    # Communication preferences
    preferred_notification_method = models.CharField(
        max_length=10,
        choices=[
            ('email', 'Email Only'),
            ('sms', 'SMS Only'),
            ('both', 'Both Email and SMS'),
        ],
        default='email'
    )
    
    # Rate limiting preferences
    max_reminders_per_day = models.IntegerField(
        default=10,
        validators=[MinValueValidator(1), MaxValueValidator(50)],
        help_text="Maximum reminders to send per day"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'notification_preferences'
        verbose_name = 'Notification Preference'
        verbose_name_plural = 'Notification Preferences'
    
    def __str__(self):
        return f"Notification preferences for {self.organizer.email}"
    
    def is_in_dnd_period(self, check_time=None):
        """Check if current time is within do-not-disturb period."""
        if not self.dnd_enabled:
            return False
        
        if check_time is None:
            from django.utils import timezone
            # Convert to organizer's timezone
            organizer_tz = self.organizer.profile.timezone_name
            from zoneinfo import ZoneInfo
            check_time = timezone.now().astimezone(ZoneInfo(organizer_tz)).time()
        
        # Handle DND periods that span midnight
        if self.dnd_start_time <= self.dnd_end_time:
            # Normal period (e.g., 10 PM - 7 AM next day)
            return self.dnd_start_time <= check_time <= self.dnd_end_time
        else:
            # Midnight-spanning period (e.g., 10 PM - 7 AM)
            return check_time >= self.dnd_start_time or check_time <= self.dnd_end_time
    
    def should_exclude_weekend(self, notification_type, check_date=None):
        """Check if weekends should be excluded for this notification type."""
        if check_date is None:
            from django.utils import timezone
            check_date = timezone.now().date()
        
        is_weekend = check_date.weekday() >= 5  # Saturday=5, Sunday=6
        
        if notification_type == 'reminder':
            return is_weekend and self.exclude_weekends_reminders
        elif notification_type == 'daily_agenda':
            return is_weekend and self.exclude_weekends_agenda
        
        return False
    
    def get_daily_reminder_count(self):
        """Get count of reminders sent today."""
        from django.utils import timezone
        today = timezone.now().date()
        
        return NotificationLog.objects.filter(
            organizer=self.organizer,
            notification_type__in=['email', 'sms'],
            created_at__date=today,
            status__in=['sent', 'delivered']
        ).count()
    
    def can_send_reminder(self):
        """Check if organizer can receive more reminders today."""
        return self.get_daily_reminder_count() < self.max_reminders_per_day


class NotificationSchedule(models.Model):
    """Scheduled notifications (reminders, follow-ups, etc.)."""
    SCHEDULE_TYPES = [
        ('reminder', 'Reminder'),
        ('follow_up', 'Follow-up'),
        ('daily_agenda', 'Daily Agenda'),
    ]
    
    STATUS_CHOICES = [
        ('scheduled', 'Scheduled'),
        ('sent', 'Sent'),
        ('cancelled', 'Cancelled'),
        ('failed', 'Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='scheduled_notifications')
    booking = models.ForeignKey('events.Booking', on_delete=models.CASCADE, related_name='scheduled_notifications', null=True, blank=True)
    
    schedule_type = models.CharField(max_length=20, choices=SCHEDULE_TYPES)
    notification_type = models.CharField(max_length=10, choices=NotificationTemplate.NOTIFICATION_TYPES)
    
    # Scheduling
    scheduled_for = models.DateTimeField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
    
    # Content
    recipient_email = models.EmailField(blank=True)
    recipient_phone = models.CharField(max_length=20, blank=True)
    subject = models.CharField(max_length=200, blank=True)
    message = models.TextField()
    
    # Execution tracking
    sent_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'notification_schedules'
        verbose_name = 'Notification Schedule'
        verbose_name_plural = 'Notification Schedules'
        ordering = ['scheduled_for']
    
    def __str__(self):
        return f"{self.schedule_type} for {self.recipient_email or self.recipient_phone} at {self.scheduled_for}"
    
    def should_send_now(self, tolerance_minutes=5):
        """Check if notification should be sent now (within tolerance)."""
        from django.utils import timezone
        now = timezone.now()
        
        # Check if scheduled time is within tolerance window
        time_diff = abs((self.scheduled_for - now).total_seconds() / 60)
        return time_diff <= tolerance_minutes
    
    def calculate_next_send_time(self, preferences):
        """Calculate next appropriate send time based on preferences."""
        from django.utils import timezone
        from datetime import timedelta
        
        send_time = self.scheduled_for
        
        # Check DND period
        if preferences.is_in_dnd_period():
            # Schedule for end of DND period
            organizer_tz = preferences.organizer.profile.timezone_name
            from zoneinfo import ZoneInfo
            
            # Convert to organizer timezone
            local_time = send_time.astimezone(ZoneInfo(organizer_tz))
            
            # Set to DND end time
            next_send = local_time.replace(
                hour=preferences.dnd_end_time.hour,
                minute=preferences.dnd_end_time.minute,
                second=0,
                microsecond=0
            )
            
            # If DND end is earlier in the day, move to next day
            if next_send.time() <= local_time.time():
                next_send += timedelta(days=1)
            
            send_time = next_send.astimezone(timezone.utc)
        
        # Check weekend exclusion
        if preferences.should_exclude_weekend(self.schedule_type, send_time.date()):
            # Move to next Monday
            days_until_monday = (7 - send_time.weekday()) % 7
            if days_until_monday == 0:  # Already Monday
                days_until_monday = 7
            send_time += timedelta(days=days_until_monday)
        
        return send_time