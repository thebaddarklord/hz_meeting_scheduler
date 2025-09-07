from rest_framework import serializers
from django.utils import timezone
from .models import Workflow, WorkflowAction, WorkflowExecution, WorkflowTemplate


class WorkflowActionSerializer(serializers.ModelSerializer):
    action_type_display = serializers.CharField(source='get_action_type_display', read_only=True)
    recipient_display = serializers.CharField(source='get_recipient_display', read_only=True)
    success_rate = serializers.ReadOnlyField(source='get_success_rate')
    execution_stats = serializers.SerializerMethodField()
    
    class Meta:
        model = WorkflowAction
        fields = [
            'id', 'name', 'action_type', 'action_type_display', 'order',
            'recipient', 'recipient_display', 'custom_email', 'subject', 'message',
            'webhook_url', 'webhook_data', 'conditions', 'update_booking_fields',
            'is_active', 'success_rate', 'execution_stats', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_execution_stats(self, obj):
        return {
            'total_executions': obj.total_executions,
            'successful_executions': obj.successful_executions,
            'failed_executions': obj.failed_executions,
            'last_executed_at': obj.last_executed_at
        }


class WorkflowSerializer(serializers.ModelSerializer):
    trigger_display = serializers.CharField(source='get_trigger_display', read_only=True)
    actions = WorkflowActionSerializer(many=True, read_only=True)
    event_types_count = serializers.IntegerField(source='event_types.count', read_only=True)
    success_rate = serializers.ReadOnlyField(source='get_success_rate')
    execution_stats = serializers.SerializerMethodField()
    
    class Meta:
        model = Workflow
        fields = [
            'id', 'name', 'description', 'trigger', 'trigger_display',
            'event_types_count', 'delay_minutes', 'is_active', 'success_rate',
            'execution_stats', 'actions', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_execution_stats(self, obj):
        return {
            'total_executions': obj.total_executions,
            'successful_executions': obj.successful_executions,
            'failed_executions': obj.failed_executions,
            'last_executed_at': obj.last_executed_at
        }


class WorkflowCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Workflow
        fields = [
            'name', 'description', 'trigger', 'event_types',
            'delay_minutes', 'is_active'
        ]


class WorkflowActionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkflowAction
        fields = [
            'name', 'action_type', 'order', 'recipient', 'custom_email',
            'subject', 'message', 'webhook_url', 'webhook_data',
            'conditions', 'update_booking_fields', 'is_active'
        ]
    
    def validate_conditions(self, value):
        """Validate conditions JSON structure."""
        if value:
            try:
                # Use the model's validation method
                from .models import WorkflowAction
                temp_action = WorkflowAction()
                temp_action._validate_conditions_structure(value)
            except ValueError as e:
                raise serializers.ValidationError(str(e))
        return value
    
    def validate_update_booking_fields(self, value):
        """Validate update_booking_fields structure."""
        if value:
            try:
                from .models import WorkflowAction
                temp_action = WorkflowAction()
                temp_action._validate_update_booking_fields(value)
            except ValueError as e:
                raise serializers.ValidationError(str(e))
        return value
    
    def validate(self, attrs):
        """Cross-field validation."""
        action_type = attrs.get('action_type')
        recipient = attrs.get('recipient')
        custom_email = attrs.get('custom_email')
        webhook_url = attrs.get('webhook_url')
        update_booking_fields = attrs.get('update_booking_fields')
        
        # Validate recipient configuration
        if action_type in ['send_email', 'send_sms'] and recipient == 'custom' and not custom_email:
            raise serializers.ValidationError("custom_email is required when recipient is 'custom'")
        
        # Validate webhook configuration
        if action_type == 'webhook' and not webhook_url:
            raise serializers.ValidationError("webhook_url is required for webhook actions")
        
        # Validate update_booking configuration
        if action_type == 'update_booking' and not update_booking_fields:
            raise serializers.ValidationError("update_booking_fields is required for update_booking actions")
        
        return attrs


class WorkflowExecutionSerializer(serializers.ModelSerializer):
    workflow_name = serializers.CharField(source='workflow.name', read_only=True)
    booking_invitee = serializers.CharField(source='booking.invitee_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    execution_summary = serializers.SerializerMethodField()
    execution_time_seconds = serializers.SerializerMethodField()
    
    class Meta:
        model = WorkflowExecution
        fields = [
            'id', 'workflow_name', 'booking_invitee', 'status', 'status_display',
            'started_at', 'completed_at', 'error_message', 'actions_executed',
            'actions_failed', 'execution_log', 'execution_summary', 
            'execution_time_seconds', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_execution_summary(self, obj):
        from .utils import get_workflow_execution_summary
        return get_workflow_execution_summary(obj)
    
    def get_execution_time_seconds(self, obj):
        if obj.started_at and obj.completed_at:
            return round((obj.completed_at - obj.started_at).total_seconds(), 2)
        return None


class WorkflowTemplateSerializer(serializers.ModelSerializer):
    category_display = serializers.CharField(source='get_category_display', read_only=True)
    
    class Meta:
        model = WorkflowTemplate
        fields = [
            'id', 'name', 'description', 'category', 'category_display',
            'template_data', 'is_public', 'usage_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'usage_count', 'created_at', 'updated_at']


class WorkflowFromTemplateSerializer(serializers.Serializer):
    """Serializer for creating workflow from template."""
    template_id = serializers.UUIDField()
    name = serializers.CharField(max_length=200, required=False)
    customize_actions = serializers.BooleanField(default=False)


class WorkflowTestSerializer(serializers.Serializer):
    """Serializer for workflow testing options."""
    test_type = serializers.ChoiceField(
        choices=['mock_data', 'real_data', 'live_test'],
        default='mock_data'
    )
    booking_id = serializers.UUIDField(required=False)
    live_test = serializers.BooleanField(default=False)
    
    def validate(self, attrs):
        test_type = attrs.get('test_type')
        booking_id = attrs.get('booking_id')
        live_test = attrs.get('live_test')
        
        if test_type in ['real_data', 'live_test'] and not booking_id:
            raise serializers.ValidationError("booking_id is required for real_data and live_test")
        
        if test_type == 'live_test' and not live_test:
            raise serializers.ValidationError("live_test must be True for live_test type")
        
        return attrs


class WorkflowValidationSerializer(serializers.Serializer):
    """Serializer for workflow validation results."""
    valid = serializers.BooleanField()
    warnings = serializers.ListField(child=serializers.CharField())
    errors = serializers.ListField(child=serializers.CharField())
    runtime_checks = serializers.ListField(child=serializers.CharField())
    overall_status = serializers.CharField()