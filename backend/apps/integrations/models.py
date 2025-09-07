from django.db import models
from django.utils import timezone
import uuid


class CalendarIntegration(models.Model):
    """Calendar integration model for storing OAuth tokens."""
    PROVIDER_CHOICES = [
        ('google', 'Google Calendar'),
        ('outlook', 'Microsoft Outlook'),
        ('apple', 'Apple Calendar'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='calendar_integrations')
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
    
    # OAuth tokens
    access_token = models.TextField()
    refresh_token = models.TextField(blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)
    
    # Provider-specific data
    provider_user_id = models.CharField(max_length=200, blank=True)
    provider_email = models.EmailField(blank=True)
    calendar_id = models.CharField(max_length=200, blank=True)
    
    # Sync tracking
    last_sync_at = models.DateTimeField(null=True, blank=True)
    sync_token = models.TextField(blank=True, help_text="Token for incremental sync")
    sync_errors = models.IntegerField(default=0, help_text="Consecutive sync error count")
    
    # Settings
    is_active = models.BooleanField(default=True)
    sync_enabled = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'calendar_integrations'
        unique_together = ['organizer', 'provider']
        verbose_name = 'Calendar Integration'
        verbose_name_plural = 'Calendar Integrations'
        indexes = [
            models.Index(fields=['is_active', 'sync_enabled']),
            models.Index(fields=['last_sync_at']),
        ]
    
    def __str__(self):
        return f"{self.organizer.email} - {self.get_provider_display()}"
    
    @property
    def is_token_expired(self):
        """Check if the access token is expired."""
        if not self.token_expires_at:
            return False
        return timezone.now() >= self.token_expires_at
    
    def mark_sync_error(self):
        """Mark a sync error and disable if too many consecutive errors."""
        self.sync_errors += 1
        if self.sync_errors >= 5:  # Disable after 5 consecutive errors
            self.is_active = False
        self.save(update_fields=['sync_errors', 'is_active'])
    
    def mark_sync_success(self):
        """Mark successful sync and reset error count."""
        self.sync_errors = 0
        self.last_sync_at = timezone.now()
        self.save(update_fields=['sync_errors', 'last_sync_at'])


class VideoConferenceIntegration(models.Model):
    """Video conference integration model."""
    PROVIDER_CHOICES = [
        ('zoom', 'Zoom'),
        ('google_meet', 'Google Meet'),
        ('microsoft_teams', 'Microsoft Teams'),
        ('webex', 'Cisco Webex'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='video_integrations')
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
    
    # OAuth tokens or API keys
    access_token = models.TextField()
    refresh_token = models.TextField(blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)
    
    # Provider-specific data
    provider_user_id = models.CharField(max_length=200, blank=True)
    provider_email = models.EmailField(blank=True)
    
    # Rate limiting tracking
    last_api_call = models.DateTimeField(null=True, blank=True)
    api_calls_today = models.IntegerField(default=0)
    rate_limit_reset_at = models.DateTimeField(null=True, blank=True)
    
    # Settings
    is_active = models.BooleanField(default=True)
    auto_generate_links = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'video_integrations'
        unique_together = ['organizer', 'provider']
        verbose_name = 'Video Conference Integration'
        verbose_name_plural = 'Video Conference Integrations'
        indexes = [
            models.Index(fields=['is_active', 'auto_generate_links']),
            models.Index(fields=['rate_limit_reset_at']),
        ]
    
    def __str__(self):
        return f"{self.organizer.email} - {self.get_provider_display()}"
    
    @property
    def is_token_expired(self):
        """Check if the access token is expired."""
        if not self.token_expires_at:
            return False
        return timezone.now() >= self.token_expires_at
    
    def can_make_api_call(self):
        """Check if we can make an API call without hitting rate limits."""
        now = timezone.now()
        
        # Reset daily counter if needed
        if self.rate_limit_reset_at and now >= self.rate_limit_reset_at:
            self.api_calls_today = 0
            self.rate_limit_reset_at = None
            self.save(update_fields=['api_calls_today', 'rate_limit_reset_at'])
        
        # Check daily limits (conservative estimates)
        daily_limits = {
            'zoom': 1000,
            'google_meet': 1000,
            'microsoft_teams': 500,
        }
        
        limit = daily_limits.get(self.provider, 100)
        return self.api_calls_today < limit
    
    def record_api_call(self):
        """Record an API call for rate limiting."""
        now = timezone.now()
        self.api_calls_today += 1
        self.last_api_call = now
        
        # Set reset time if not set (midnight next day)
        if not self.rate_limit_reset_at:
            from datetime import time
            tomorrow = now.date() + timezone.timedelta(days=1)
            self.rate_limit_reset_at = timezone.datetime.combine(tomorrow, time.min).replace(tzinfo=now.tzinfo)
        
        self.save(update_fields=['api_calls_today', 'last_api_call', 'rate_limit_reset_at'])


class WebhookIntegration(models.Model):
    """Webhook integration model for external services."""
    EVENT_CHOICES = [
        ('booking_created', 'Booking Created'),
        ('booking_cancelled', 'Booking Cancelled'),
        ('booking_rescheduled', 'Booking Rescheduled'),
        ('booking_completed', 'Booking Completed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='webhook_integrations')
    
    name = models.CharField(max_length=100)
    webhook_url = models.URLField()
    events = models.JSONField(default=list, help_text="List of events to trigger webhook")
    
    # Authentication
    secret_key = models.CharField(max_length=200, blank=True)
    headers = models.JSONField(default=dict, blank=True, help_text="Additional headers to send")
    
    # Settings
    is_active = models.BooleanField(default=True)
    retry_failed = models.BooleanField(default=True)
    max_retries = models.IntegerField(default=3)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'webhook_integrations'
        verbose_name = 'Webhook Integration'
        verbose_name_plural = 'Webhook Integrations'
    
    def __str__(self):
        return f"{self.organizer.email} - {self.name}"


class IntegrationLog(models.Model):
    """Log model for tracking integration activities."""
    LOG_TYPES = [
        ('calendar_sync', 'Calendar Sync'),
        ('video_link_created', 'Video Link Created'),
        ('webhook_sent', 'Webhook Sent'),
        ('error', 'Error'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='integration_logs')
    log_type = models.CharField(max_length=30, choices=LOG_TYPES)
    
    # Related objects
    booking = models.ForeignKey('events.Booking', on_delete=models.CASCADE, null=True, blank=True)
    integration_type = models.CharField(max_length=50, blank=True)  # e.g., 'google', 'zoom'
    
    # Log details
    message = models.TextField()
    details = models.JSONField(default=dict, blank=True)
    
    # Status
    success = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'integration_logs'
        verbose_name = 'Integration Log'
        verbose_name_plural = 'Integration Logs'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.organizer.email} - {self.get_log_type_display()} - {self.created_at}"