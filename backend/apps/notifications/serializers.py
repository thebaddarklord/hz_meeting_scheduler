from rest_framework import serializers
from .models import NotificationTemplate, NotificationLog, NotificationPreference, NotificationSchedule


class NotificationTemplateSerializer(serializers.ModelSerializer):
    template_type_display = serializers.CharField(source='get_template_type_display', read_only=True)
    notification_type_display = serializers.CharField(source='get_notification_type_display', read_only=True)
    
    class Meta:
        model = NotificationTemplate
        fields = [
            'id', 'name', 'template_type', 'template_type_display',
            'notification_type', 'notification_type_display', 'subject', 'message',
            'is_active', 'is_default', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class NotificationLogSerializer(serializers.ModelSerializer):
    notification_type_display = serializers.CharField(source='get_notification_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    booking_id = serializers.UUIDField(source='booking.id', read_only=True)
    template_name = serializers.CharField(source='template.name', read_only=True)
    
    class Meta:
        model = NotificationLog
        fields = [
            'id', 'booking_id', 'template_name', 'notification_type', 'notification_type_display',
            'recipient_email', 'recipient_phone', 'subject', 'status', 'status_display',
            'sent_at', 'delivered_at', 'opened_at', 'clicked_at', 'error_message',
            'retry_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class NotificationPreferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationPreference
        fields = [
            'booking_confirmations_email', 'booking_reminders_email', 'booking_cancellations_email',
            'daily_agenda_email', 'booking_confirmations_sms', 'booking_reminders_sms',
            'booking_cancellations_sms', 'reminder_minutes_before', 'daily_agenda_time',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


class NotificationScheduleSerializer(serializers.ModelSerializer):
    schedule_type_display = serializers.CharField(source='get_schedule_type_display', read_only=True)
    notification_type_display = serializers.CharField(source='get_notification_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    booking_id = serializers.UUIDField(source='booking.id', read_only=True)
    
    class Meta:
        model = NotificationSchedule
        fields = [
            'id', 'booking_id', 'schedule_type', 'schedule_type_display',
            'notification_type', 'notification_type_display', 'scheduled_for',
            'status', 'status_display', 'recipient_email', 'recipient_phone',
            'subject', 'sent_at', 'error_message', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class SendNotificationSerializer(serializers.Serializer):
    """Serializer for manually sending notifications."""
    notification_type = serializers.ChoiceField(choices=NotificationTemplate.NOTIFICATION_TYPES)
    template_id = serializers.UUIDField(required=False)
    recipient_email = serializers.EmailField(required=False)
    recipient_phone = serializers.CharField(max_length=20, required=False)
    subject = serializers.CharField(max_length=200, required=False)
    message = serializers.CharField()
    booking_id = serializers.UUIDField(required=False)
    send_immediately = serializers.BooleanField(default=True)
    scheduled_for = serializers.DateTimeField(required=False)
    
    def validate(self, attrs):
        notification_type = attrs.get('notification_type')
        recipient_email = attrs.get('recipient_email')
        recipient_phone = attrs.get('recipient_phone')
        send_immediately = attrs.get('send_immediately', True)
        scheduled_for = attrs.get('scheduled_for')
        
        if notification_type == 'email' and not recipient_email:
            raise serializers.ValidationError("recipient_email is required for email notifications")
        
        if notification_type == 'sms' and not recipient_phone:
            raise serializers.ValidationError("recipient_phone is required for SMS notifications")
        
        if not send_immediately and not scheduled_for:
            raise serializers.ValidationError("scheduled_for is required when send_immediately is False")
        
        if scheduled_for and scheduled_for <= timezone.now():
            raise serializers.ValidationError("scheduled_for must be in the future")
        
        # Validate phone number format for SMS
        if notification_type == 'sms' and recipient_phone:
            from .utils import validate_phone_number
            phone_validation = validate_phone_number(recipient_phone)
            if not phone_validation['valid']:
                raise serializers.ValidationError(f"Invalid phone number: {phone_validation['error']}")
        
        return attrs


class NotificationStatsSerializer(serializers.Serializer):
    """Serializer for notification statistics."""
    total_notifications = serializers.IntegerField()
    total_sent = serializers.IntegerField()
    total_failed = serializers.IntegerField()
    total_pending = serializers.IntegerField()
    total_delivered = serializers.IntegerField()
    total_opened = serializers.IntegerField()
    total_clicked = serializers.IntegerField()
    email_count = serializers.IntegerField()
    sms_count = serializers.IntegerField()
    email_delivery_rate = serializers.FloatField()
    email_open_rate = serializers.FloatField()
    email_click_rate = serializers.FloatField()
    sms_delivery_rate = serializers.FloatField()
    recent_activity = serializers.DictField()
    top_templates = serializers.ListField()
    preferences = serializers.DictField()