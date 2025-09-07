from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from datetime import time
import uuid


class AvailabilityRule(models.Model):
    """Recurring availability rules for organizers."""
    WEEKDAY_CHOICES = [
        (0, 'Monday'),
        (1, 'Tuesday'),
        (2, 'Wednesday'),
        (3, 'Thursday'),
        (4, 'Friday'),
        (5, 'Saturday'),
        (6, 'Sunday'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='availability_rules')
    
    # Day of week (0=Monday, 6=Sunday)
    day_of_week = models.IntegerField(choices=WEEKDAY_CHOICES)
    
    # Time range
    start_time = models.TimeField()
    end_time = models.TimeField()
    
    # Event type specificity
    event_types = models.ManyToManyField(
        'events.EventType', 
        blank=True, 
        related_name='availability_rules',
        help_text="Leave empty to apply to all event types"
    )
    
    # Active status
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'availability_rules'
        verbose_name = 'Availability Rule'
        verbose_name_plural = 'Availability Rules'
        unique_together = ['organizer', 'day_of_week', 'start_time', 'end_time']
    
    def __str__(self):
        return f"{self.organizer.email} - {self.get_day_of_week_display()} {self.start_time}-{self.end_time}"
    
    def spans_midnight(self):
        """Check if this rule spans across midnight."""
        return self.end_time < self.start_time
    
    def applies_to_event_type(self, event_type):
        """Check if this rule applies to the given event type."""
        if not self.event_types.exists():
            return True  # Applies to all event types
        return self.event_types.filter(id=event_type.id).exists()


class DateOverrideRule(models.Model):
    """Date-specific availability overrides."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='date_overrides')
    
    # Specific date
    date = models.DateField()
    
    # Override settings
    is_available = models.BooleanField(default=True, help_text="If False, entire day is blocked")
    start_time = models.TimeField(null=True, blank=True, help_text="Required if is_available is True")
    end_time = models.TimeField(null=True, blank=True, help_text="Required if is_available is True")
    
    # Event type specificity
    event_types = models.ManyToManyField(
        'events.EventType', 
        blank=True, 
        related_name='date_overrides',
        help_text="Leave empty to apply to all event types"
    )
    
    # Optional description
    reason = models.CharField(max_length=200, blank=True)
    
    # Active status
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'date_override_rules'
        verbose_name = 'Date Override Rule'
        verbose_name_plural = 'Date Override Rules'
        unique_together = ['organizer', 'date']
    
    def __str__(self):
        status = "Available" if self.is_available else "Blocked"
        return f"{self.organizer.email} - {self.date} ({status})"
    
    def clean(self):
        """Validate that start_time and end_time are set when is_available is True."""
        from django.core.exceptions import ValidationError
        if self.is_available and (self.start_time is None or self.end_time is None):
            raise ValidationError("start_time and end_time must be set if is_available is True")
        
        if self.start_time and self.end_time and self.start_time == self.end_time:
            raise ValidationError("Start time and end time cannot be the same")
    
    def spans_midnight(self):
        """
        Check if this override spans across midnight.
        Note: If start_time equals end_time, this returns False (zero-duration slot).
        """
        if not self.start_time or not self.end_time:
            return False
        return self.end_time < self.start_time
    
    def applies_to_event_type(self, event_type):
        """Check if this override applies to the given event type."""
        if not self.event_types.exists():
            return True  # Applies to all event types
        return self.event_types.filter(id=event_type.id).exists()


class RecurringBlockedTime(models.Model):
    """Recurring blocked time periods (e.g., weekly team meetings)."""
    WEEKDAY_CHOICES = [
        (0, 'Monday'),
        (1, 'Tuesday'),
        (2, 'Wednesday'),
        (3, 'Thursday'),
        (4, 'Friday'),
        (5, 'Saturday'),
        (6, 'Sunday'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='recurring_blocks')
    
    # Block details
    name = models.CharField(max_length=200, help_text="Name of the recurring block (e.g., 'Weekly Team Meeting')")
    day_of_week = models.IntegerField(choices=WEEKDAY_CHOICES)
    
    # Time range (can span midnight)
    start_time = models.TimeField()
    end_time = models.TimeField(help_text="Can be earlier than start_time to span midnight")
    
    # Date range for when this recurring block is active
    start_date = models.DateField(null=True, blank=True, help_text="When this recurring block starts (None = indefinite start)")
    end_date = models.DateField(null=True, blank=True, help_text="When this recurring block ends (None = indefinite end)")
    
    # Active status
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'recurring_blocked_times'
        verbose_name = 'Recurring Blocked Time'
        verbose_name_plural = 'Recurring Blocked Times'
    
    def __str__(self):
        return f"{self.organizer.email} - {self.name} ({self.get_day_of_week_display()} {self.start_time}-{self.end_time})"
    
    def spans_midnight(self):
        """
        Check if this recurring block spans across midnight.
        Note: If start_time equals end_time, this returns False (zero-duration block).
        """
        return self.end_time < self.start_time
    
    def applies_to_date(self, date):
        """
        Check if this recurring block applies to the given date.
        
        Args:
            date: datetime.date object to check
            
        Returns:
            bool: True if the recurring block applies to this date
            
        Note:
            - start_date=None means the block has been active since the beginning of time
            - end_date=None means the block continues indefinitely
        """
        # Check day of week
        if date.weekday() != self.day_of_week:
            return False
        
        # Check date range
        if self.start_date and date < self.start_date:
            return False
        if self.end_date and date > self.end_date:
            return False
        
        return True


class BlockedTime(models.Model):
    """One-off blocked time periods for organizers."""
    SOURCE_CHOICES = [
        ('manual', 'Manual'),
        ('google_calendar', 'Google Calendar'),
        ('outlook_calendar', 'Outlook Calendar'),
        ('apple_calendar', 'Apple Calendar'),
        ('external_sync', 'External Sync'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='blocked_times')
    
    # Blocked time period
    start_datetime = models.DateTimeField()
    end_datetime = models.DateTimeField()
    
    # Optional description
    reason = models.CharField(max_length=200, blank=True)
    
    # Source tracking for conflict resolution
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default='manual')
    external_id = models.CharField(max_length=200, blank=True, help_text="ID from external calendar system")
    external_updated_at = models.DateTimeField(null=True, blank=True, help_text="Last updated time from external system")
    
    # Active status
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'blocked_times'
        verbose_name = 'Blocked Time'
        verbose_name_plural = 'Blocked Times'
        indexes = [
            models.Index(fields=['organizer', 'source', 'external_id']),
            models.Index(fields=['organizer', 'start_datetime', 'end_datetime']),
        ]
    
    def __str__(self):
        return f"{self.organizer.email} - Blocked {self.start_datetime} to {self.end_datetime}"


class BufferTime(models.Model):
    """
    Buffer time settings for organizers.
    
    Note: These are global defaults. Individual EventType instances can override
    these values with their own buffer_time_before and buffer_time_after fields.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.OneToOneField('users.User', on_delete=models.CASCADE, related_name='buffer_settings')
    
    # Default buffer times (in minutes)
    default_buffer_before = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(120)],
        help_text="Default buffer time before meetings (minutes)"
    )
    default_buffer_after = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(120)],
        help_text="Default buffer time after meetings (minutes)"
    )
    
    # Minimum time between bookings
    minimum_gap = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(60)],
        help_text="Minimum gap between bookings (minutes)"
    )
    
    # Slot generation granularity (future enhancement)
    slot_interval_minutes = models.IntegerField(
        default=15,
        validators=[MinValueValidator(5), MaxValueValidator(60)],
        help_text="Interval for generating time slots (minutes)"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'buffer_times'
        verbose_name = 'Buffer Time Settings'
        verbose_name_plural = 'Buffer Time Settings'
    
    def __str__(self):
        return f"Buffer settings for {self.organizer.email}"