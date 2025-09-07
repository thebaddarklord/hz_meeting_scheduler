from django.db import models
from django.utils.text import slugify
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
import uuid
import json
import secrets


class EventType(models.Model):
    """Enhanced event type model with enterprise features."""
    DURATION_CHOICES = [
        (15, '15 minutes'),
        (30, '30 minutes'),
        (45, '45 minutes'),
        (60, '1 hour'),
        (90, '1.5 hours'),
        (120, '2 hours'),
        (180, '3 hours'),
        (240, '4 hours'),
    ]
    
    LOCATION_TYPE_CHOICES = [
        ('video_call', 'Video Call'),
        ('phone_call', 'Phone Call'),
        ('in_person', 'In Person'),
        ('custom', 'Custom'),
    ]
    
    RECURRENCE_TYPE_CHOICES = [
        ('none', 'No Recurrence'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='event_types')
    name = models.CharField(max_length=200)
    event_type_slug = models.SlugField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    duration = models.IntegerField(choices=DURATION_CHOICES, default=30)
    
    # Group event settings
    max_attendees = models.IntegerField(
        default=1, 
        validators=[MinValueValidator(1), MaxValueValidator(100)], 
        help_text="Maximum number of attendees for this event type"
    )
    enable_waitlist = models.BooleanField(
        default=False,
        help_text="Allow waitlist when event is full"
    )
    
    # Booking constraints
    is_active = models.BooleanField(default=True)
    is_private = models.BooleanField(
        default=False,
        help_text="Private events are only accessible via direct link"
    )
    
    # Scheduling rules
    min_scheduling_notice = models.IntegerField(
        default=60, 
        validators=[MinValueValidator(0)],
        help_text="Minimum booking notice (minutes)"
    )
    max_scheduling_horizon = models.IntegerField(
        default=43200, 
        validators=[MinValueValidator(60)],
        help_text="Maximum booking advance (minutes)"
    )
    
    # Buffer times
    buffer_time_before = models.IntegerField(
        default=0, 
        validators=[MinValueValidator(0), MaxValueValidator(120)],
        help_text="Buffer time before meeting (minutes)"
    )
    buffer_time_after = models.IntegerField(
        default=0, 
        validators=[MinValueValidator(0), MaxValueValidator(120)],
        help_text="Buffer time after meeting (minutes)"
    )
    
    # Daily limits
    max_bookings_per_day = models.IntegerField(
        null=True, 
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(50)],
        help_text="Maximum bookings per day for this event type"
    )
    
    # Slot generation settings
    slot_interval_minutes = models.IntegerField(
        default=0, 
        validators=[MinValueValidator(0), MaxValueValidator(60)],
        help_text="Slot interval for this event type (minutes). 0 uses organizer's default."
    )
    
    # Recurrence settings
    recurrence_type = models.CharField(
        max_length=20,
        choices=RECURRENCE_TYPE_CHOICES,
        default='none'
    )
    recurrence_rule = models.TextField(
        blank=True,
        help_text="RRULE string for complex recurrence patterns"
    )
    max_occurrences = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(365)],
        help_text="Maximum number of recurring occurrences"
    )
    recurrence_end_date = models.DateField(
        null=True,
        blank=True,
        help_text="End date for recurring events"
    )
    
    # Location settings
    location_type = models.CharField(
        max_length=20, 
        choices=LOCATION_TYPE_CHOICES,
        default='video_call'
    )
    location_details = models.TextField(
        blank=True,
        help_text="Location details (address, phone number, or custom instructions)"
    )
    
    # Post-booking settings
    redirect_url_after_booking = models.URLField(
        blank=True,
        help_text="URL to redirect invitee after successful booking"
    )
    
    # Workflow integration
    confirmation_workflow = models.ForeignKey(
        'workflows.Workflow',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='confirmation_event_types',
        help_text="Workflow to trigger on booking confirmation"
    )
    reminder_workflow = models.ForeignKey(
        'workflows.Workflow',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reminder_event_types',
        help_text="Workflow to trigger for reminders"
    )
    cancellation_workflow = models.ForeignKey(
        'workflows.Workflow',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='cancellation_event_types',
        help_text="Workflow to trigger on cancellation"
    )
    
    # Custom questions (stored as JSON)
    custom_questions = models.JSONField(default=list, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'event_types'
        unique_together = ['organizer', 'event_type_slug']
        verbose_name = 'Event Type'
        verbose_name_plural = 'Event Types'
        indexes = [
            models.Index(fields=['organizer', 'is_active', 'is_private']),
            models.Index(fields=['event_type_slug']),
        ]
    
    def __str__(self):
        return f"{self.organizer.email} - {self.name}"
    
    def save(self, *args, **kwargs):
        if not self.event_type_slug:
            base_slug = slugify(self.name)
            slug = base_slug
            counter = 1
            
            # Ensure uniqueness within organizer's event types
            while EventType.objects.filter(
                organizer=self.organizer, 
                event_type_slug=slug
            ).exclude(id=self.id).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            
            self.event_type_slug = slug
        
        super().save(*args, **kwargs)
    
    def clean(self):
        """Validate event type configuration."""
        super().clean()
        
        # Validate recurrence settings
        if self.recurrence_type != 'none':
            if not self.max_occurrences and not self.recurrence_end_date:
                raise ValidationError("Recurring events must have either max_occurrences or recurrence_end_date")
        
        # Validate scheduling horizon
        if self.max_scheduling_horizon < self.min_scheduling_notice:
            raise ValidationError("Maximum scheduling horizon must be greater than minimum notice")
        
        # Validate buffer times don't exceed duration
        total_buffer = self.buffer_time_before + self.buffer_time_after
        if total_buffer >= self.duration:
            raise ValidationError("Total buffer time cannot exceed event duration")
    
    def get_total_duration_with_buffers(self):
        """Get total time blocked including buffers."""
        return self.duration + self.buffer_time_before + self.buffer_time_after
    
    def is_group_event(self):
        """Check if this is a group event."""
        return self.max_attendees > 1
    
    def can_book_on_date(self, date):
        """Check if this event type can be booked on a specific date."""
        if not self.is_active:
            return False
        
        # Check scheduling horizon
        max_date = timezone.now().date() + timedelta(minutes=self.max_scheduling_horizon)
        if date > max_date:
            return False
        
        # Check minimum notice
        min_date = timezone.now().date() + timedelta(minutes=self.min_scheduling_notice)
        if date < min_date:
            return False
        
        return True


class CustomQuestion(models.Model):
    """Custom questions for event types with conditional logic."""
    QUESTION_TYPES = [
        ('text', 'Text Input'),
        ('textarea', 'Long Text'),
        ('select', 'Single Select'),
        ('multiselect', 'Multiple Select'),
        ('checkbox', 'Checkbox'),
        ('radio', 'Radio Buttons'),
        ('email', 'Email'),
        ('phone', 'Phone Number'),
        ('number', 'Number'),
        ('date', 'Date'),
        ('time', 'Time'),
        ('url', 'URL'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.ForeignKey(EventType, on_delete=models.CASCADE, related_name='questions')
    
    question_text = models.CharField(max_length=500)
    question_type = models.CharField(max_length=20, choices=QUESTION_TYPES, default='text')
    is_required = models.BooleanField(default=False)
    order = models.IntegerField(default=0)
    
    # Options for select/radio questions
    options = models.JSONField(
        default=list,
        blank=True,
        help_text="List of options for select/radio questions"
    )
    
    # Conditional logic
    conditions = models.JSONField(
        default=list,
        blank=True,
        help_text="Conditions for showing this question based on previous answers"
    )
    
    # Validation rules
    validation_rules = models.JSONField(
        default=dict,
        blank=True,
        help_text="Validation rules (min_length, max_length, pattern, etc.)"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'custom_questions'
        verbose_name = 'Custom Question'
        verbose_name_plural = 'Custom Questions'
        ordering = ['order']
        unique_together = ['event_type', 'order']
    
    def __str__(self):
        return f"{self.event_type.name} - {self.question_text[:50]}"
    
    def clean(self):
        """Validate question configuration."""
        super().clean()
        
        # Validate options for select/radio questions
        if self.question_type in ['select', 'multiselect', 'radio']:
            if not self.options or len(self.options) < 2:
                raise ValidationError("Select/radio questions must have at least 2 options")
    
    def should_show_for_answers(self, previous_answers):
        """Check if this question should be shown based on previous answers."""
        if not self.conditions:
            return True
        
        from apps.workflows.utils import evaluate_conditions
        return evaluate_conditions(self.conditions, previous_answers)


class Booking(models.Model):
    """Enhanced booking model with enterprise features."""
    STATUS_CHOICES = [
        ('confirmed', 'Confirmed'),
        ('cancelled', 'Cancelled'),
        ('rescheduled', 'Rescheduled'),
        ('completed', 'Completed'),
        ('no_show', 'No Show'),
    ]
    
    CALENDAR_SYNC_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('succeeded', 'Succeeded'),
        ('failed', 'Failed'),
        ('not_required', 'Not Required'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.ForeignKey(EventType, on_delete=models.CASCADE, related_name='bookings')
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='organized_bookings')
    
    # Primary invitee information
    invitee_name = models.CharField(max_length=200)
    invitee_email = models.EmailField()
    invitee_phone = models.CharField(max_length=20, blank=True)
    invitee_timezone = models.CharField(max_length=50, default='UTC')
    
    # Booking details
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='confirmed')
    
    # Group booking settings
    attendee_count = models.IntegerField(
        default=1, 
        validators=[MinValueValidator(1)], 
        help_text="Number of attendees for this specific booking"
    )
    
    # Recurrence tracking
    recurrence_id = models.UUIDField(
        null=True,
        blank=True,
        help_text="Links recurring bookings together"
    )
    is_recurring_exception = models.BooleanField(
        default=False,
        help_text="True if this booking is an exception to a recurring series"
    )
    recurrence_sequence = models.IntegerField(
        null=True,
        blank=True,
        help_text="Sequence number in recurring series"
    )
    
    # Security and access
    access_token = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        help_text="Secure token for invitee booking management"
    )
    access_token_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Expiration time for access token"
    )
    
    # Custom question answers
    custom_answers = models.JSONField(default=dict, blank=True)
    
    # Meeting details
    meeting_link = models.URLField(blank=True)
    meeting_id = models.CharField(max_length=100, blank=True)
    meeting_password = models.CharField(max_length=50, blank=True)
    
    # External calendar integration
    external_calendar_event_id = models.CharField(
        max_length=200, 
        blank=True, 
        help_text="ID from external calendar system"
    )
    calendar_sync_status = models.CharField(
        max_length=20,
        choices=CALENDAR_SYNC_STATUS_CHOICES,
        default='pending'
    )
    calendar_sync_error = models.TextField(blank=True)
    calendar_sync_attempts = models.IntegerField(default=0)
    last_calendar_sync_attempt = models.DateTimeField(null=True, blank=True)
    
    # Tracking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Cancellation details
    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancelled_by = models.CharField(
        max_length=20,
        choices=[
            ('organizer', 'Organizer'),
            ('invitee', 'Invitee'),
            ('system', 'System'),
        ],
        blank=True
    )
    cancellation_reason = models.TextField(blank=True)
    
    # Rescheduling tracking
    rescheduled_from = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='rescheduled_to_bookings'
    )
    rescheduled_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'bookings'
        verbose_name = 'Booking'
        verbose_name_plural = 'Bookings'
        indexes = [
            models.Index(fields=['organizer', 'start_time', 'end_time']),
            models.Index(fields=['status', 'start_time']),
            models.Index(fields=['access_token']),
            models.Index(fields=['recurrence_id']),
            models.Index(fields=['calendar_sync_status']),
        ]
    
    def __str__(self):
        return f"{self.invitee_name} - {self.event_type.name} - {self.start_time}"
    
    def save(self, *args, **kwargs):
        # Set access token expiration (30 days from creation)
        if not self.access_token_expires_at:
            self.access_token_expires_at = timezone.now() + timedelta(days=30)
        
        super().save(*args, **kwargs)
    
    def clean(self):
        """Validate booking data."""
        super().clean()
        
        # Validate time range
        if self.start_time and self.end_time:
            if self.start_time >= self.end_time:
                raise ValidationError("End time must be after start time")
            
            # Validate duration matches event type
            expected_duration = timedelta(minutes=self.event_type.duration)
            actual_duration = self.end_time - self.start_time
            if actual_duration != expected_duration:
                raise ValidationError("Booking duration must match event type duration")
        
        # Validate attendee count
        if self.attendee_count > self.event_type.max_attendees:
            raise ValidationError("Attendee count exceeds event type maximum")
    
    @property
    def duration_minutes(self):
        """Calculate booking duration in minutes."""
        return int((self.end_time - self.start_time).total_seconds() / 60)
    
    def is_access_token_valid(self):
        """Check if access token is still valid."""
        if not self.access_token_expires_at:
            return True
        return timezone.now() < self.access_token_expires_at
    
    def regenerate_access_token(self):
        """Generate new access token and extend expiration."""
        self.access_token = uuid.uuid4()
        self.access_token_expires_at = timezone.now() + timedelta(days=30)
        self.save(update_fields=['access_token', 'access_token_expires_at'])
    
    def can_be_cancelled(self):
        """Check if booking can be cancelled."""
        if self.status in ['cancelled', 'completed']:
            return False
        
        # Check if within cancellation window
        min_notice = timedelta(minutes=self.event_type.min_scheduling_notice)
        return timezone.now() + min_notice < self.start_time
    
    def can_be_rescheduled(self):
        """Check if booking can be rescheduled."""
        return self.can_be_cancelled()  # Same rules for now
    
    def cancel(self, cancelled_by='invitee', reason=''):
        """Cancel the booking."""
        if not self.can_be_cancelled():
            raise ValidationError("Booking cannot be cancelled at this time")
        
        self.status = 'cancelled'
        self.cancelled_at = timezone.now()
        self.cancelled_by = cancelled_by
        self.cancellation_reason = reason
        self.save(update_fields=[
            'status', 'cancelled_at', 'cancelled_by', 'cancellation_reason'
        ])
    
    def mark_calendar_sync_success(self, external_event_id=None):
        """Mark calendar sync as successful."""
        self.calendar_sync_status = 'succeeded'
        self.calendar_sync_error = ''
        if external_event_id:
            self.external_calendar_event_id = external_event_id
        self.save(update_fields=[
            'calendar_sync_status', 'calendar_sync_error', 'external_calendar_event_id'
        ])
    
    def mark_calendar_sync_failed(self, error_message):
        """Mark calendar sync as failed."""
        self.calendar_sync_status = 'failed'
        self.calendar_sync_error = error_message
        self.calendar_sync_attempts += 1
        self.last_calendar_sync_attempt = timezone.now()
        self.save(update_fields=[
            'calendar_sync_status', 'calendar_sync_error', 
            'calendar_sync_attempts', 'last_calendar_sync_attempt'
        ])


class Attendee(models.Model):
    """Individual attendees for group bookings."""
    STATUS_CHOICES = [
        ('confirmed', 'Confirmed'),
        ('cancelled', 'Cancelled'),
        ('no_show', 'No Show'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='attendees')
    
    name = models.CharField(max_length=200)
    email = models.EmailField()
    phone = models.CharField(max_length=20, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='confirmed')
    
    # Custom answers specific to this attendee
    custom_answers = models.JSONField(default=dict, blank=True)
    
    # Tracking
    joined_at = models.DateTimeField(auto_now_add=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancellation_reason = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'booking_attendees'
        verbose_name = 'Attendee'
        verbose_name_plural = 'Attendees'
        unique_together = ['booking', 'email']
    
    def __str__(self):
        return f"{self.name} - {self.booking.event_type.name}"
    
    def cancel(self, reason=''):
        """Cancel this attendee's participation."""
        self.status = 'cancelled'
        self.cancelled_at = timezone.now()
        self.cancellation_reason = reason
        self.save(update_fields=['status', 'cancelled_at', 'cancellation_reason'])


class WaitlistEntry(models.Model):
    """Waitlist entries for full group events."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.ForeignKey(EventType, on_delete=models.CASCADE, related_name='waitlist_entries')
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='waitlist_entries')
    
    # Desired booking details
    desired_start_time = models.DateTimeField()
    desired_end_time = models.DateTimeField()
    
    # Invitee information
    invitee_name = models.CharField(max_length=200)
    invitee_email = models.EmailField()
    invitee_phone = models.CharField(max_length=20, blank=True)
    invitee_timezone = models.CharField(max_length=50, default='UTC')
    
    # Waitlist settings
    notify_when_available = models.BooleanField(default=True)
    expires_at = models.DateTimeField(
        help_text="When this waitlist entry expires"
    )
    
    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ('active', 'Active'),
            ('notified', 'Notified'),
            ('converted', 'Converted to Booking'),
            ('expired', 'Expired'),
            ('cancelled', 'Cancelled'),
        ],
        default='active'
    )
    
    # Custom answers
    custom_answers = models.JSONField(default=dict, blank=True)
    
    # Tracking
    notified_at = models.DateTimeField(null=True, blank=True)
    converted_booking = models.ForeignKey(
        Booking,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='converted_from_waitlist'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'waitlist_entries'
        verbose_name = 'Waitlist Entry'
        verbose_name_plural = 'Waitlist Entries'
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['event_type', 'status', 'desired_start_time']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"Waitlist: {self.invitee_name} - {self.event_type.name}"
    
    def save(self, *args, **kwargs):
        # Set expiration if not set (7 days from creation)
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(days=7)
        
        super().save(*args, **kwargs)
    
    def is_expired(self):
        """Check if waitlist entry has expired."""
        return timezone.now() > self.expires_at
    
    def notify_availability(self):
        """Notify invitee that a slot is available."""
        if self.status != 'active':
            return False
        
        self.status = 'notified'
        self.notified_at = timezone.now()
        self.save(update_fields=['status', 'notified_at'])
        
        # Trigger notification
        from apps.notifications.tasks import send_waitlist_notification
        send_waitlist_notification.delay(self.id)
        
        return True


class RecurringEventException(models.Model):
    """Exceptions to recurring event series."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.ForeignKey(EventType, on_delete=models.CASCADE, related_name='recurrence_exceptions')
    recurrence_id = models.UUIDField(help_text="Links to the recurring series")
    
    # Exception details
    exception_date = models.DateField()
    exception_type = models.CharField(
        max_length=20,
        choices=[
            ('cancelled', 'Cancelled'),
            ('rescheduled', 'Rescheduled'),
            ('modified', 'Modified'),
        ]
    )
    
    # Rescheduled details (if applicable)
    new_start_time = models.DateTimeField(null=True, blank=True)
    new_end_time = models.DateTimeField(null=True, blank=True)
    
    # Modification details (if applicable)
    modified_fields = models.JSONField(
        default=dict,
        blank=True,
        help_text="Fields that were modified for this occurrence"
    )
    
    reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'recurring_event_exceptions'
        verbose_name = 'Recurring Event Exception'
        verbose_name_plural = 'Recurring Event Exceptions'
        unique_together = ['event_type', 'recurrence_id', 'exception_date']
    
    def __str__(self):
        return f"Exception: {self.event_type.name} on {self.exception_date}"


class BookingAuditLog(models.Model):
    """Comprehensive audit trail for booking-related actions."""
    ACTION_CHOICES = [
        ('booking_created', 'Booking Created'),
        ('booking_cancelled', 'Booking Cancelled'),
        ('booking_rescheduled', 'Booking Rescheduled'),
        ('booking_completed', 'Booking Completed'),
        ('attendee_added', 'Attendee Added'),
        ('attendee_cancelled', 'Attendee Cancelled'),
        ('waitlist_added', 'Added to Waitlist'),
        ('waitlist_converted', 'Waitlist Converted'),
        ('calendar_sync_success', 'Calendar Sync Success'),
        ('calendar_sync_failed', 'Calendar Sync Failed'),
        ('workflow_triggered', 'Workflow Triggered'),
        ('notification_sent', 'Notification Sent'),
        ('access_token_regenerated', 'Access Token Regenerated'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='audit_logs')
    
    # Action details
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    description = models.TextField()
    
    # Actor information
    actor_type = models.CharField(
        max_length=20,
        choices=[
            ('organizer', 'Organizer'),
            ('invitee', 'Invitee'),
            ('attendee', 'Attendee'),
            ('system', 'System'),
            ('integration', 'Integration'),
        ]
    )
    actor_email = models.EmailField(blank=True)
    actor_name = models.CharField(max_length=200, blank=True)
    
    # Context information
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Additional data
    metadata = models.JSONField(
        default=dict, 
        blank=True, 
        help_text="Additional context data"
    )
    
    # Changes tracking
    old_values = models.JSONField(default=dict, blank=True)
    new_values = models.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'booking_audit_logs'
        verbose_name = 'Booking Audit Log'
        verbose_name_plural = 'Booking Audit Logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['booking', '-created_at']),
            models.Index(fields=['action', '-created_at']),
            models.Index(fields=['actor_type', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.booking.id} - {self.get_action_display()} by {self.actor_type}"


class EventTypeAvailabilityCache(models.Model):
    """Cache for computed availability to improve performance."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='availability_cache')
    event_type = models.ForeignKey(EventType, on_delete=models.CASCADE, related_name='availability_cache')
    
    # Cache key components
    date = models.DateField()
    timezone_name = models.CharField(max_length=50)
    attendee_count = models.IntegerField(default=1)
    
    # Cached data
    available_slots = models.JSONField(help_text="Serialized available slots")
    
    # Cache metadata
    computed_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_dirty = models.BooleanField(
        default=False,
        help_text="True if cache needs recomputation"
    )
    
    # Performance tracking
    computation_time_ms = models.IntegerField(
        null=True,
        blank=True,
        help_text="Time taken to compute this cache entry"
    )
    
    class Meta:
        db_table = 'event_type_availability_cache'
        verbose_name = 'Availability Cache'
        verbose_name_plural = 'Availability Cache'
        unique_together = ['organizer', 'event_type', 'date', 'timezone_name', 'attendee_count']
        indexes = [
            models.Index(fields=['expires_at']),
            models.Index(fields=['is_dirty']),
            models.Index(fields=['organizer', 'date']),
        ]
    
    def __str__(self):
        return f"Cache: {self.organizer.email} - {self.event_type.name} - {self.date}"
    
    def is_expired(self):
        """Check if cache entry has expired."""
        return timezone.now() > self.expires_at
    
    def mark_dirty(self):
        """Mark cache as dirty for recomputation."""
        self.is_dirty = True
        self.save(update_fields=['is_dirty'])