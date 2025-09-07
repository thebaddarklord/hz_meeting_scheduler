from rest_framework import serializers
from django.utils import timezone
from django.forms.models import model_to_dict
from .models import EventType, Booking, Attendee, WaitlistEntry, CustomQuestion
from apps.users.serializers import UserSerializer


class CustomQuestionSerializer(serializers.ModelSerializer):
    question_type_display = serializers.CharField(source='get_question_type_display', read_only=True)
    
    class Meta:
        model = CustomQuestion
        fields = [
            'id', 'question_text', 'question_type', 'question_type_display',
            'is_required', 'order', 'options', 'conditions', 'validation_rules'
        ]
        read_only_fields = ['id']
class EventTypeSerializer(serializers.ModelSerializer):
    organizer = UserSerializer(read_only=True)
    questions = CustomQuestionSerializer(many=True, read_only=True)
    is_group_event = serializers.BooleanField(read_only=True)
    total_duration_with_buffers = serializers.IntegerField(source='get_total_duration_with_buffers', read_only=True)
    
    class Meta:
        model = EventType
        fields = [
            'id', 'organizer', 'name', 'event_type_slug', 'description', 'duration',
            'max_attendees', 'enable_waitlist', 'is_active', 'is_private',
            'min_scheduling_notice', 'max_scheduling_horizon',
            'buffer_time_before', 'buffer_time_after', 'max_bookings_per_day',
            'slot_interval_minutes', 'recurrence_type', 'recurrence_rule',
            'max_occurrences', 'recurrence_end_date', 'location_type',
            'location_details', 'redirect_url_after_booking',
            'confirmation_workflow', 'reminder_workflow', 'cancellation_workflow',
            'questions', 'is_group_event',
            'total_duration_with_buffers', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'event_type_slug', 'created_at', 'updated_at']


class EventTypeCreateSerializer(serializers.ModelSerializer):
    questions_data = serializers.ListField(
        child=serializers.DictField(),
        write_only=True,
        required=False,
        help_text="List of custom questions to create"
    )
    
    class Meta:
        model = EventType
        fields = [
            'name', 'description', 'duration', 'max_attendees', 'enable_waitlist',
            'is_active', 'is_private', 'min_scheduling_notice', 'max_scheduling_horizon',
            'buffer_time_before', 'buffer_time_after', 'max_bookings_per_day',
            'slot_interval_minutes', 'recurrence_type', 'recurrence_rule',
            'max_occurrences', 'recurrence_end_date', 'location_type',
            'location_details', 'redirect_url_after_booking',
            'confirmation_workflow', 'reminder_workflow', 'cancellation_workflow',
            'questions_data'
        ]
    
    def create(self, validated_data):
        questions_data = validated_data.pop('questions_data', [])
        event_type = super().create(validated_data)
        
        # Create custom questions
        for i, question_data in enumerate(questions_data):
            CustomQuestion.objects.create(
                event_type=event_type,
                order=i,
                **question_data
            )
        
        return event_type


class PublicEventTypeSerializer(serializers.ModelSerializer):
    """Serializer for public event type details (no sensitive info)."""
    organizer_name = serializers.CharField(source='organizer.profile.display_name', read_only=True)
    organizer_bio = serializers.CharField(source='organizer.profile.bio', read_only=True)
    organizer_picture = serializers.ImageField(source='organizer.profile.profile_picture', read_only=True)
    organizer_company = serializers.CharField(source='organizer.profile.company', read_only=True)
    organizer_timezone = serializers.CharField(source='organizer.profile.timezone_name', read_only=True)
    questions = CustomQuestionSerializer(many=True, read_only=True)
    is_group_event = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = EventType
        fields = [
            'name', 'event_type_slug', 'description', 'duration', 'max_attendees',
            'enable_waitlist', 'location_type', 'location_details',
            'min_scheduling_notice', 'max_scheduling_horizon',
            'organizer_name', 'organizer_bio', 'organizer_picture',
            'organizer_company', 'organizer_timezone', 'questions',
            'is_group_event'
        ]


class AttendeeSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = Attendee
        fields = [
            'id', 'name', 'email', 'phone', 'status', 'status_display',
            'custom_answers', 'joined_at', 'cancelled_at', 'cancellation_reason'
        ]
        read_only_fields = ['id', 'joined_at', 'cancelled_at']
class BookingSerializer(serializers.ModelSerializer):
    event_type = EventTypeSerializer(read_only=True)
    organizer = UserSerializer(read_only=True)
    duration_minutes = serializers.ReadOnlyField()
    attendees = AttendeeSerializer(many=True, read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    can_cancel = serializers.BooleanField(source='can_be_cancelled', read_only=True)
    can_reschedule = serializers.BooleanField(source='can_be_rescheduled', read_only=True)
    is_access_token_valid = serializers.BooleanField(source='is_access_token_valid', read_only=True)
    
    class Meta:
        model = Booking
        fields = [
            'id', 'event_type', 'organizer', 'invitee_name', 'invitee_email',
            'invitee_phone', 'invitee_timezone', 'attendee_count',
            'start_time', 'end_time', 'status', 'status_display',
            'recurrence_id', 'is_recurring_exception', 'recurrence_sequence',
            'custom_answers', 'meeting_link', 'meeting_id', 'meeting_password',
            'calendar_sync_status', 'attendees', 'duration_minutes',
            'can_cancel', 'can_reschedule', 'is_access_token_valid',
            'cancelled_at', 'cancelled_by', 'cancellation_reason',
            'rescheduled_at', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'duration_minutes', 'calendar_sync_status', 'attendees',
            'can_cancel', 'can_reschedule', 'is_access_token_valid',
            'cancelled_at', 'cancelled_by', 'rescheduled_at',
            'created_at', 'updated_at', 'meeting_link', 'meeting_id', 'meeting_password'
        ]


class BookingCreateSerializer(serializers.ModelSerializer):
    organizer_slug = serializers.CharField(write_only=True)
    event_type_slug = serializers.CharField(write_only=True)
    attendees_data = serializers.ListField(
        child=serializers.DictField(),
        write_only=True,
        required=False,
        help_text="List of additional attendees for group events"
    )
    
    class Meta:
        model = Booking
        fields = [
            'organizer_slug', 'event_type_slug', 'invitee_name', 'invitee_email',
            'invitee_phone', 'invitee_timezone', 'attendee_count',
            'start_time', 'custom_answers', 'attendees_data'
        ]
    
    def validate(self, attrs):
        # Validate that the start_time is in the future
        start_time = attrs.get('start_time')
        if start_time and start_time <= timezone.now():
            # Ensure timezone-aware comparison
            raise serializers.ValidationError("Start time must be in the future")
        
        # Validate attendee count
        attendee_count = attrs.get('attendee_count', 1)
        attendees_data = attrs.get('attendees_data', [])
        
        if attendee_count > 1 and len(attendees_data) != attendee_count - 1:
            raise serializers.ValidationError(
                "attendees_data must contain attendee_count - 1 entries (excluding primary invitee)"
            )
        
        return attrs
    
    # Note: create() method removed - handled by create_booking view function


class BookingManagementSerializer(serializers.ModelSerializer):
    """Serializer for public booking management page."""
    event_type_name = serializers.CharField(source='event_type.name', read_only=True)
    organizer_name = serializers.CharField(source='organizer.profile.display_name', read_only=True)
    duration_minutes = serializers.ReadOnlyField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = Booking
        fields = [
            'id', 'event_type_name', 'organizer_name', 'invitee_name',
            'invitee_email', 'invitee_phone', 'invitee_timezone',
            'start_time', 'end_time', 'duration_minutes', 'status',
            'status_display', 'meeting_link', 'meeting_id', 'meeting_password',
            'custom_answers', 'cancelled_at', 'cancellation_reason',
            'access_token_expires_at'
        ]
        read_only_fields = [
            'id', 'event_type_name', 'organizer_name', 'duration_minutes',
            'status', 'status_display', 'cancelled_at', 'cancellation_reason',
            'access_token_expires_at'
        ]
class BookingUpdateSerializer(serializers.ModelSerializer):
    """Serializer for organizer booking updates."""
    
    class Meta:
        model = Booking
        fields = [
            'status', 'cancellation_reason', 'meeting_link', 
            'meeting_id', 'meeting_password', 'custom_answers'
        ]
    
    def update(self, instance, validated_data):
        # Track old values for audit (full snapshot)
        old_values = model_to_dict(instance)
        
        # Update instance
        updated_instance = super().update(instance, validated_data)
        
        # Create audit log
        from .utils import create_booking_audit_log, get_client_ip_from_request, get_user_agent_from_request
        
        request = self.context.get('request')
        if request:
            create_booking_audit_log(
                booking=updated_instance,
                action='booking_updated',
                description=f"Booking updated by organizer",
                actor_type='organizer',
                actor_email=request.user.email,
                actor_name=request.user.get_full_name(),
                ip_address=get_client_ip_from_request(request),
                user_agent=get_user_agent_from_request(request),
                old_values=old_values,
                new_values=validated_data
            )
        
        # Handle status changes
        if validated_data.get('status') == 'cancelled':
            updated_instance.cancelled_at = timezone.now()
            updated_instance.cancelled_by = 'organizer'
            updated_instance.save(update_fields=['cancelled_at', 'cancelled_by'])
            return updated_instance
        
        
class WaitlistEntrySerializer(serializers.ModelSerializer):
    event_type_name = serializers.CharField(source='event_type.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_expired = serializers.BooleanField(source='is_expired', read_only=True)
    
    class Meta:
        model = WaitlistEntry
        fields = [
            'id', 'event_type_name', 'desired_start_time', 'desired_end_time',
            'invitee_name', 'invitee_email', 'invitee_phone', 'invitee_timezone',
            'notify_when_available', 'expires_at', 'status', 'status_display',
            'is_expired', 'custom_answers', 'notified_at', 'created_at'
        ]
        read_only_fields = [
            'id', 'event_type_name', 'status', 'status_display', 'is_expired',
            'notified_at', 'created_at'
        ]
class PublicBookingPageSerializer(serializers.Serializer):
    """Serializer for public booking page data."""
    event_type = PublicEventTypeSerializer()
    available_slots = serializers.ListField()
    custom_questions = CustomQuestionSerializer(many=True)
    cache_hit = serializers.BooleanField()
    total_slots = serializers.IntegerField()
    performance_metrics = serializers.DictField()
    search_params = serializers.DictField()
        