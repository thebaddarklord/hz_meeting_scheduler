from rest_framework import serializers
from .models import AvailabilityRule, BlockedTime, BufferTime, DateOverrideRule, RecurringBlockedTime
from .utils import validate_timezone


class AvailabilityRuleSerializer(serializers.ModelSerializer):
    day_of_week_display = serializers.CharField(source='get_day_of_week_display', read_only=True)
    event_types_count = serializers.IntegerField(source='event_types.count', read_only=True)
    spans_midnight = serializers.BooleanField(source='spans_midnight', read_only=True)
    
    class Meta:
        model = AvailabilityRule
        fields = [
            'id', 'day_of_week', 'day_of_week_display', 'start_time', 'end_time',
            'event_types', 'event_types_count', 'spans_midnight', 'is_active', 
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate(self, attrs):
        start_time = attrs.get('start_time')
        end_time = attrs.get('end_time')
        
        # Allow midnight-spanning rules, but validate they make sense
        if start_time and end_time:
            if start_time == end_time:
                raise serializers.ValidationError("Start time and end time cannot be the same")
        
        return attrs


class DateOverrideRuleSerializer(serializers.ModelSerializer):
    event_types_count = serializers.IntegerField(source='event_types.count', read_only=True)
    spans_midnight = serializers.BooleanField(source='spans_midnight', read_only=True)
    
    class Meta:
        model = DateOverrideRule
        fields = [
            'id', 'date', 'is_available', 'start_time', 'end_time',
            'event_types', 'event_types_count', 'spans_midnight', 'reason',
            'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate(self, attrs):
        is_available = attrs.get('is_available')
        start_time = attrs.get('start_time')
        end_time = attrs.get('end_time')
        
        if is_available:
            if not start_time or not end_time:
                raise serializers.ValidationError(
                    "start_time and end_time are required when is_available is True"
                )
            if start_time == end_time:
                raise serializers.ValidationError("Start time and end time cannot be the same")
        
        return attrs


class RecurringBlockedTimeSerializer(serializers.ModelSerializer):
    day_of_week_display = serializers.CharField(source='get_day_of_week_display', read_only=True)
    spans_midnight = serializers.BooleanField(source='spans_midnight', read_only=True)
    
    class Meta:
        model = RecurringBlockedTime
        fields = [
            'id', 'name', 'day_of_week', 'day_of_week_display', 'start_time', 'end_time',
            'start_date', 'end_date', 'spans_midnight', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate(self, attrs):
        start_time = attrs.get('start_time')
        end_time = attrs.get('end_time')
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')
        
        if start_time and end_time and start_time == end_time:
            raise serializers.ValidationError("Start time and end time cannot be the same")
        
        if start_date and end_date and start_date > end_date:
            raise serializers.ValidationError("Start date must be before or equal to end date")
        
        return attrs


class BlockedTimeSerializer(serializers.ModelSerializer):
    source_display = serializers.CharField(source='get_source_display', read_only=True)
    
    class Meta:
        model = BlockedTime
        fields = [
            'id', 'start_datetime', 'end_datetime', 'reason', 'source', 'source_display',
            'external_id', 'external_updated_at', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'source_display', 'external_id', 'external_updated_at', 'created_at', 'updated_at']
    
    def validate(self, attrs):
        start_datetime = attrs.get('start_datetime')
        end_datetime = attrs.get('end_datetime')
        
        if start_datetime and end_datetime and start_datetime >= end_datetime:
            raise serializers.ValidationError("End datetime must be after start datetime")
        
        # Prevent manual modification of synced blocks
        source = attrs.get('source', 'manual')
        if source != 'manual' and self.instance is None:  # Creating new
            raise serializers.ValidationError("Cannot manually create synced blocked times")
        
        if self.instance and self.instance.source != 'manual' and source != self.instance.source:
            raise serializers.ValidationError("Cannot change source of synced blocked times")
        
        return attrs


class BufferTimeSerializer(serializers.ModelSerializer):
    class Meta:
        model = BufferTime
        fields = [
            'default_buffer_before', 'default_buffer_after', 'minimum_gap', 'slot_interval_minutes',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


class AvailableSlotSerializer(serializers.Serializer):
    """Serializer for available time slots."""
    start_time = serializers.DateTimeField()
    end_time = serializers.DateTimeField()
    duration_minutes = serializers.IntegerField()
    
    # Optional localized times for display
    local_start_time = serializers.DateTimeField(required=False)
    local_end_time = serializers.DateTimeField(required=False)
    
    # Multi-invitee timezone information
    invitee_times = serializers.DictField(required=False)
    fairness_score = serializers.FloatField(required=False)


class CalculatedSlotsRequestSerializer(serializers.Serializer):
    """Serializer for validating calculated slots request parameters."""
    event_type_slug = serializers.CharField()
    start_date = serializers.DateField()
    end_date = serializers.DateField()
    invitee_timezone = serializers.CharField(default='UTC')
    attendee_count = serializers.IntegerField(default=1, min_value=1)
    invitee_timezones = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="List of IANA timezone strings for multi-invitee scheduling"
    )
    
    def validate_invitee_timezone(self, value):
        if not validate_timezone(value):
            raise serializers.ValidationError(f"Invalid timezone: {value}")
        return value
    
    def validate_invitee_timezones(self, value):
        if value:
            for tz in value:
                if not validate_timezone(tz):
                    raise serializers.ValidationError(f"Invalid timezone in list: {tz}")
        return value
    
    def validate(self, attrs):
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')
        
        if start_date and end_date and start_date > end_date:
            raise serializers.ValidationError("start_date must be before or equal to end_date")
        
        # Limit date range to prevent abuse
        if start_date and end_date:
            date_diff = (end_date - start_date).days
            if date_diff > 90:  # 3 months max
                raise serializers.ValidationError("Date range cannot exceed 90 days")
        
        return attrs


class AvailabilityStatsSerializer(serializers.Serializer):
    """Serializer for availability statistics."""
    total_rules = serializers.IntegerField()
    active_rules = serializers.IntegerField()
    total_overrides = serializers.IntegerField()
    total_blocks = serializers.IntegerField()
    total_recurring_blocks = serializers.IntegerField()
    average_weekly_hours = serializers.FloatField()
    busiest_day = serializers.CharField()
    daily_hours = serializers.DictField()
    cache_hit_rate = serializers.FloatField()
    performance_summary = serializers.DictField(required=False)