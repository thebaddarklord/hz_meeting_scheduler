from django.contrib import admin
from .models import Workflow, WorkflowAction, WorkflowExecution, WorkflowTemplate


class WorkflowActionInline(admin.TabularInline):
    model = WorkflowAction
    extra = 1
    fields = ('name', 'action_type', 'order', 'recipient', 'is_active')


@admin.register(Workflow)
class WorkflowAdmin(admin.ModelAdmin):
    list_display = ('name', 'organizer', 'trigger', 'is_active', 'success_rate_display', 'total_executions', 'last_executed_at', 'created_at')
    list_filter = ('trigger', 'is_active', 'created_at')
    search_fields = ('name', 'organizer__email')
    readonly_fields = ('created_at', 'updated_at', 'total_executions', 'successful_executions', 'failed_executions', 'last_executed_at')
    inlines = [WorkflowActionInline]
    actions = ['test_selected_workflows', 'validate_selected_workflows']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('organizer', 'name', 'description', 'trigger')
        }),
        ('Configuration', {
            'fields': ('event_types', 'delay_minutes', 'is_active')
        }),
        ('Execution Statistics', {
            'fields': ('total_executions', 'successful_executions', 'failed_executions', 'last_executed_at'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def success_rate_display(self, obj):
        return f"{obj.get_success_rate()}%"
    success_rate_display.short_description = 'Success Rate'
    
    def test_selected_workflows(self, request, queryset):
        """Admin action to test selected workflows."""
        from .tasks import bulk_execute_workflows
        
        workflow_ids = [str(workflow.id) for workflow in queryset]
        booking_ids = [None] * len(workflow_ids)  # Mock data
        
        bulk_execute_workflows.delay(workflow_ids, booking_ids, test_mode=True)
        
        self.message_user(request, f"Test initiated for {len(workflow_ids)} workflows.")
    test_selected_workflows.short_description = "Test selected workflows"
    
    def validate_selected_workflows(self, request, queryset):
        """Admin action to validate selected workflows."""
        from .tasks import validate_all_workflow_configurations
        
        validate_all_workflow_configurations.delay()
        
        self.message_user(request, f"Validation initiated for {queryset.count()} workflows.")
    validate_selected_workflows.short_description = "Validate selected workflows"


@admin.register(WorkflowAction)
class WorkflowActionAdmin(admin.ModelAdmin):
    list_display = ('name', 'workflow', 'action_type', 'recipient', 'order', 'success_rate_display', 'total_executions', 'is_active')
    list_filter = ('action_type', 'recipient', 'is_active')
    search_fields = ('name', 'workflow__name')
    readonly_fields = ('created_at', 'updated_at', 'total_executions', 'successful_executions', 'failed_executions', 'last_executed_at')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('workflow', 'name', 'action_type', 'order', 'is_active')
        }),
        ('Recipients', {
            'fields': ('recipient', 'custom_email')
        }),
        ('Email/SMS Content', {
            'fields': ('subject', 'message'),
            'classes': ('collapse',)
        }),
        ('Webhook Configuration', {
            'fields': ('webhook_url', 'webhook_data')
        }),
        ('Booking Update Configuration', {
            'fields': ('update_booking_fields',),
            'classes': ('collapse',)
        }),
        ('Advanced', {
            'fields': ('conditions',),
            'classes': ('collapse',)
        }),
        ('Execution Statistics', {
            'fields': ('total_executions', 'successful_executions', 'failed_executions', 'last_executed_at'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def success_rate_display(self, obj):
        return f"{obj.get_success_rate()}%"
    success_rate_display.short_description = 'Success Rate'


@admin.register(WorkflowExecution)
class WorkflowExecutionAdmin(admin.ModelAdmin):
    list_display = ('workflow', 'booking_display', 'status', 'actions_executed', 'actions_failed', 'execution_time_display', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('workflow__name', 'booking__invitee_name')
    readonly_fields = ('created_at', 'updated_at')
    date_hierarchy = 'created_at'
    actions = ['retry_failed_executions']
    
    fieldsets = (
        ('Execution Information', {
            'fields': ('workflow', 'booking', 'status')
        }),
        ('Timing', {
            'fields': ('started_at', 'completed_at')
        }),
        ('Results', {
            'fields': ('actions_executed', 'actions_failed', 'error_message')
        }),
        ('Execution Log', {
            'fields': ('execution_log',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def booking_display(self, obj):
        if obj.booking:
            return f"{obj.booking.invitee_name} - {obj.booking.event_type.name}"
        return "Test Execution"
    booking_display.short_description = 'Booking'
    
    def execution_time_display(self, obj):
        if obj.started_at and obj.completed_at:
            duration = obj.completed_at - obj.started_at
            return f"{duration.total_seconds():.1f}s"
        return "-"
    execution_time_display.short_description = 'Duration'
    
    def retry_failed_executions(self, request, queryset):
        """Admin action to retry failed workflow executions."""
        failed_executions = queryset.filter(status='failed')
        retry_count = 0
        
        for execution in failed_executions:
            if execution.booking:  # Only retry if we have a booking
                from .tasks import execute_workflow
                execute_workflow.delay(execution.workflow.id, execution.booking.id)
                retry_count += 1
        
        self.message_user(request, f"Queued {retry_count} workflow executions for retry.")
    retry_failed_executions.short_description = "Retry failed executions"


@admin.register(WorkflowTemplate)
class WorkflowTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'is_public', 'usage_count', 'created_at')
    list_filter = ('category', 'is_public', 'created_at')
    search_fields = ('name', 'description')
    readonly_fields = ('usage_count', 'created_at', 'updated_at')
    
    fieldsets = (
        ('Template Information', {
            'fields': ('name', 'description', 'category')
        }),
        ('Configuration', {
            'fields': ('template_data',)
        }),
        ('Settings', {
            'fields': ('is_public', 'usage_count')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )