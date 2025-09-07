from django.db import models
from django.core.exceptions import ValidationError
import json
import uuid


class Workflow(models.Model):
    """Workflow model for automated sequences."""
    TRIGGER_CHOICES = [
        ('booking_created', 'Booking Created'),
        ('booking_cancelled', 'Booking Cancelled'),
        ('booking_completed', 'Booking Completed'),
        ('before_meeting', 'Before Meeting'),
        ('after_meeting', 'After Meeting'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='workflows')
    
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    trigger = models.CharField(max_length=30, choices=TRIGGER_CHOICES)
    
    # Trigger conditions
    event_types = models.ManyToManyField('events.EventType', blank=True, help_text="Leave empty for all event types")
    
    # Timing
    delay_minutes = models.IntegerField(default=0, help_text="Delay before executing actions (minutes)")
    
    # Status
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Execution statistics
    total_executions = models.IntegerField(default=0)
    successful_executions = models.IntegerField(default=0)
    failed_executions = models.IntegerField(default=0)
    last_executed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'workflows'
        verbose_name = 'Workflow'
        verbose_name_plural = 'Workflows'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.organizer.email} - {self.name}"
    
    def get_success_rate(self):
        """Calculate workflow success rate."""
        if self.total_executions == 0:
            return 0
        return round((self.successful_executions / self.total_executions) * 100, 2)
    
    def increment_execution_stats(self, success=True):
        """Update execution statistics."""
        self.total_executions += 1
        if success:
            self.successful_executions += 1
        else:
            self.failed_executions += 1
        self.last_executed_at = timezone.now()
        self.save(update_fields=['total_executions', 'successful_executions', 'failed_executions', 'last_executed_at'])


class WorkflowAction(models.Model):
    """Individual actions within a workflow."""
    ACTION_CHOICES = [
        ('send_email', 'Send Email'),
        ('send_sms', 'Send SMS'),
        ('webhook', 'Trigger Webhook'),
        ('update_booking', 'Update Booking'),
    ]
    
    RECIPIENT_CHOICES = [
        ('organizer', 'Organizer'),
        ('invitee', 'Invitee'),
        ('both', 'Both'),
        ('custom', 'Custom Email'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workflow = models.ForeignKey(Workflow, on_delete=models.CASCADE, related_name='actions')
    
    name = models.CharField(max_length=200)
    action_type = models.CharField(max_length=20, choices=ACTION_CHOICES)
    order = models.IntegerField(default=0, help_text="Execution order within workflow")
    
    # Action configuration
    recipient = models.CharField(max_length=20, choices=RECIPIENT_CHOICES, default='invitee')
    custom_email = models.EmailField(blank=True, help_text="Used when recipient is 'custom'")
    
    # Email/SMS content
    subject = models.CharField(max_length=200, blank=True)
    message = models.TextField(blank=True)
    
    # Webhook configuration
    webhook_url = models.URLField(blank=True)
    webhook_data = models.JSONField(default=dict, blank=True)
    
    # Conditions
    conditions = models.JSONField(default=dict, blank=True, help_text="Additional conditions for action execution")
    
    # Update booking configuration (for update_booking actions)
    update_booking_fields = models.JSONField(
        default=dict, 
        blank=True, 
        help_text="Fields to update on booking (for update_booking action type)"
    )
    
    # Execution tracking
    total_executions = models.IntegerField(default=0)
    successful_executions = models.IntegerField(default=0)
    failed_executions = models.IntegerField(default=0)
    last_executed_at = models.DateTimeField(null=True, blank=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'workflow_actions'
        verbose_name = 'Workflow Action'
        verbose_name_plural = 'Workflow Actions'
        ordering = ['order']
    
    def __str__(self):
        return f"{self.workflow.name} - {self.name}"
    
    def clean(self):
        """Validate action configuration."""
        super().clean()
        
        # Validate conditions JSON structure
        if self.conditions:
            try:
                self._validate_conditions_structure(self.conditions)
            except ValueError as e:
                raise ValidationError(f"Invalid conditions structure: {str(e)}")
        
        # Validate update_booking_fields for update_booking actions
        if self.action_type == 'update_booking' and self.update_booking_fields:
            try:
                self._validate_update_booking_fields(self.update_booking_fields)
            except ValueError as e:
                raise ValidationError(f"Invalid update_booking_fields: {str(e)}")
        
        # Validate recipient configuration
        if self.action_type in ['send_email', 'send_sms']:
            if self.recipient == 'custom' and not self.custom_email:
                raise ValidationError("custom_email is required when recipient is 'custom'")
    
    def _validate_conditions_structure(self, conditions):
        """Validate the structure of conditions JSON."""
        if not isinstance(conditions, list):
            raise ValueError("Conditions must be a list of condition groups")
        
        valid_operators = ['equals', 'not_equals', 'greater_than', 'less_than', 'contains', 
                          'not_contains', 'starts_with', 'ends_with', 'is_empty', 'is_not_empty']
        valid_group_operators = ['AND', 'OR']
        
        for group in conditions:
            if not isinstance(group, dict):
                raise ValueError("Each condition group must be a dictionary")
            
            if 'operator' not in group or group['operator'] not in valid_group_operators:
                raise ValueError(f"Each group must have a valid operator: {valid_group_operators}")
            
            if 'rules' not in group or not isinstance(group['rules'], list):
                raise ValueError("Each group must have a 'rules' list")
            
            for rule in group['rules']:
                if not isinstance(rule, dict):
                    raise ValueError("Each rule must be a dictionary")
                
                required_fields = ['field', 'operator']
                for field in required_fields:
                    if field not in rule:
                        raise ValueError(f"Rule missing required field: {field}")
                
                if rule['operator'] not in valid_operators:
                    raise ValueError(f"Invalid rule operator: {rule['operator']}")
                
                # Value is required for most operators except is_empty/is_not_empty
                if rule['operator'] not in ['is_empty', 'is_not_empty'] and 'value' not in rule:
                    raise ValueError(f"Rule with operator '{rule['operator']}' requires a 'value'")
    
    def _validate_update_booking_fields(self, update_fields):
        """Validate update_booking_fields structure."""
        if not isinstance(update_fields, dict):
            raise ValueError("update_booking_fields must be a dictionary")
        
        # Define allowed fields that can be updated
        allowed_fields = [
            'status', 'cancellation_reason', 'meeting_link', 'meeting_id', 
            'meeting_password', 'custom_answers'
        ]
        
        for field_name in update_fields.keys():
            if field_name not in allowed_fields:
                raise ValueError(f"Field '{field_name}' is not allowed for booking updates. Allowed fields: {allowed_fields}")
    
    def get_success_rate(self):
        """Calculate action success rate."""
        if self.total_executions == 0:
            return 0
        return round((self.successful_executions / self.total_executions) * 100, 2)
    
    def increment_execution_stats(self, success=True):
        """Update execution statistics."""
        self.total_executions += 1
        if success:
            self.successful_executions += 1
        else:
            self.failed_executions += 1
        self.last_executed_at = timezone.now()
        self.save(update_fields=['total_executions', 'successful_executions', 'failed_executions', 'last_executed_at'])


class WorkflowExecution(models.Model):
    """Log of workflow executions."""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workflow = models.ForeignKey(Workflow, on_delete=models.CASCADE, related_name='executions')
    booking = models.ForeignKey('events.Booking', on_delete=models.CASCADE, related_name='workflow_executions')
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Execution details
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    # Results
    actions_executed = models.IntegerField(default=0)
    actions_failed = models.IntegerField(default=0)
    execution_log = models.JSONField(default=list, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'workflow_executions'
        verbose_name = 'Workflow Execution'
        verbose_name_plural = 'Workflow Executions'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.workflow.name} - {self.booking.invitee_name} - {self.status}"


class WorkflowTemplate(models.Model):
    """Pre-built workflow templates."""
    CATEGORY_CHOICES = [
        ('booking', 'Booking Management'),
        ('follow_up', 'Follow-up'),
        ('reminder', 'Reminders'),
        ('feedback', 'Feedback Collection'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    name = models.CharField(max_length=200)
    description = models.TextField()
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    
    # Template configuration
    template_data = models.JSONField(help_text="Workflow and actions configuration")
    
    # Metadata
    is_public = models.BooleanField(default=True)
    usage_count = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'workflow_templates'
        verbose_name = 'Workflow Template'
        verbose_name_plural = 'Workflow Templates'
    
    def __str__(self):
        return self.name