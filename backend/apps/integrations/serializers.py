from rest_framework import serializers
from .models import CalendarIntegration, VideoConferenceIntegration, WebhookIntegration, IntegrationLog


class CalendarIntegrationSerializer(serializers.ModelSerializer):
    provider_display = serializers.CharField(source='get_provider_display', read_only=True)
    is_token_expired = serializers.ReadOnlyField()
    
    class Meta:
        model = CalendarIntegration
        fields = [
            'id', 'provider', 'provider_display', 'provider_email', 'calendar_id',
            'is_active', 'sync_enabled', 'is_token_expired', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'provider_email', 'calendar_id']


class VideoConferenceIntegrationSerializer(serializers.ModelSerializer):
    provider_display = serializers.CharField(source='get_provider_display', read_only=True)
    is_token_expired = serializers.ReadOnlyField()
    
    class Meta:
        model = VideoConferenceIntegration
        fields = [
            'id', 'provider', 'provider_display', 'provider_email',
            'is_active', 'auto_generate_links', 'is_token_expired', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'provider_email']


class WebhookIntegrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebhookIntegration
        fields = [
            'id', 'name', 'webhook_url', 'events', 'secret_key', 'headers',
            'is_active', 'retry_failed', 'max_retries', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
        extra_kwargs = {
            'secret_key': {'write_only': True}
        }


class IntegrationLogSerializer(serializers.ModelSerializer):
    log_type_display = serializers.CharField(source='get_log_type_display', read_only=True)
    booking_id = serializers.UUIDField(source='booking.id', read_only=True)
    
    class Meta:
        model = IntegrationLog
        fields = [
            'id', 'log_type', 'log_type_display', 'integration_type',
            'booking_id', 'message', 'details', 'success', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class OAuthInitiateSerializer(serializers.Serializer):
    """Serializer for initiating OAuth flow."""
    provider = serializers.ChoiceField(choices=['google', 'outlook', 'zoom', 'microsoft_teams'])
    integration_type = serializers.ChoiceField(choices=['calendar', 'video'])
    redirect_uri = serializers.URLField()


class OAuthCallbackSerializer(serializers.Serializer):
    """Serializer for OAuth callback."""
    provider = serializers.CharField()
    integration_type = serializers.CharField()
    code = serializers.CharField()
    state = serializers.CharField(required=False)