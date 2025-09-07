from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.core.cache import cache
from django.db.models import Count, Q
from datetime import datetime, timedelta
from .models import AvailabilityRule, BlockedTime, BufferTime, DateOverrideRule, RecurringBlockedTime
from .serializers import (
    AvailabilityRuleSerializer, BlockedTimeSerializer, BufferTimeSerializer,
    DateOverrideRuleSerializer, RecurringBlockedTimeSerializer,
    AvailableSlotSerializer, CalculatedSlotsRequestSerializer, AvailabilityStatsSerializer
)
from .utils import calculate_available_slots, get_cache_key_for_availability, get_weekly_cache_keys_for_date_range
from apps.users.models import User
import logging

logger = logging.getLogger(__name__)


class AvailabilityRuleListCreateView(generics.ListCreateAPIView):
    serializer_class = AvailabilityRuleSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return AvailabilityRule.objects.filter(organizer=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(organizer=self.request.user)


class AvailabilityRuleDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = AvailabilityRuleSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return AvailabilityRule.objects.filter(organizer=self.request.user)


class DateOverrideRuleListCreateView(generics.ListCreateAPIView):
    serializer_class = DateOverrideRuleSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return DateOverrideRule.objects.filter(organizer=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(organizer=self.request.user)


class DateOverrideRuleDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DateOverrideRuleSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return DateOverrideRule.objects.filter(organizer=self.request.user)


class RecurringBlockedTimeListCreateView(generics.ListCreateAPIView):
    serializer_class = RecurringBlockedTimeSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return RecurringBlockedTime.objects.filter(organizer=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(organizer=self.request.user)


class RecurringBlockedTimeDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = RecurringBlockedTimeSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return RecurringBlockedTime.objects.filter(organizer=self.request.user)


class BlockedTimeListCreateView(generics.ListCreateAPIView):
    serializer_class = BlockedTimeSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return BlockedTime.objects.filter(organizer=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(organizer=self.request.user)


class BlockedTimeDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = BlockedTimeSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return BlockedTime.objects.filter(organizer=self.request.user)


class BufferTimeView(generics.RetrieveUpdateAPIView):
    serializer_class = BufferTimeSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        buffer_time, created = BufferTime.objects.get_or_create(
            organizer=self.request.user
        )
        return buffer_time


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def calculated_slots(request, organizer_slug):
    """
    Calculate and return available time slots for an organizer with advanced caching.
    
    Query parameters:
    - event_type_slug: Required. The event type slug to determine duration.
    - start_date: Required. Start date for availability search (YYYY-MM-DD).
    - end_date: Required. End date for availability search (YYYY-MM-DD).
    - invitee_timezone: Optional. IANA timezone string for the invitee.
    - attendee_count: Optional. Number of attendees (default: 1).
    - invitee_timezones: Optional. Comma-separated list of IANA timezones for multi-invitee scheduling.
    """
    import time as time_module
    request_start_time = time_module.time()
    
    # Validate request parameters
    request_serializer = CalculatedSlotsRequestSerializer(data=request.GET)
    if not request_serializer.is_valid():
        return Response(
            {'error': 'Invalid parameters', 'details': request_serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    validated_data = request_serializer.validated_data
    event_type_slug = validated_data['event_type_slug']
    start_date = validated_data['start_date']
    end_date = validated_data['end_date']
    invitee_timezone = validated_data['invitee_timezone']
    attendee_count = validated_data['attendee_count']
    invitee_timezones = validated_data.get('invitee_timezones')
    
    try:
        # Get organizer and event type
        organizer = get_object_or_404(
            User,
            profile__organizer_slug=organizer_slug,
            is_active=True
        )
        
        from apps.events.models import EventType
        event_type = get_object_or_404(
            EventType,
            organizer=organizer,
            event_type_slug=event_type_slug,
            is_active=True
        )
        
        # Check cache first
        cache_key = f"availability:{organizer.id}:{event_type.id}:{start_date}:{end_date}:{invitee_timezone}:{attendee_count}"
        
        # For multi-invitee requests, create a specialized cache key
        if invitee_timezones and len(invitee_timezones) > 1:
            timezones_hash = hash(tuple(sorted(invitee_timezones)))
            cache_key = f"availability_multi:{organizer.id}:{event_type.id}:{start_date}:{end_date}:{timezones_hash}:{attendee_count}"
        
        cached_slots = cache.get(cache_key)
        cache_hit = cached_slots is not None
        
        if cached_slots is not None:
            logger.info(f"Cache HIT for {organizer_slug}/{event_type_slug}")
            available_slots = cached_slots
        else:
            logger.info(f"Cache MISS for {organizer_slug}/{event_type_slug}")
            
            # Calculate available slots
            slot_calculation_start = time_module.time()
            available_slots = calculate_available_slots(
                organizer=organizer,
                event_type=event_type,
                start_date=start_date,
                end_date=end_date,
                invitee_timezone=invitee_timezone,
                attendee_count=attendee_count,
                invitee_timezones=invitee_timezones
            )
            slot_calculation_time = time_module.time() - slot_calculation_start
            
            # Log computation time for performance monitoring
            logger.info(f"Slot calculation took {slot_calculation_time:.3f}s for {organizer_slug}/{event_type_slug}")
            
            # Cache the result for 15 minutes
            cache.set(cache_key, available_slots, timeout=900)
        
        # Serialize the slots
        response_serializer = AvailableSlotSerializer(available_slots, many=True)
        
        # Calculate total request time
        total_request_time = time_module.time() - request_start_time
        
        response_data = {
            'organizer_slug': organizer_slug,
            'event_type_slug': event_type_slug,
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'invitee_timezone': invitee_timezone,
            'attendee_count': attendee_count,
            'available_slots': response_serializer.data,
            'cache_hit': cache_hit,
            'total_slots': len(available_slots),
            'computation_time_ms': round(total_request_time * 1000, 2)
        }
        
        # Add multi-invitee information if applicable
        if invitee_timezones:
            response_data['invitee_timezones'] = invitee_timezones
            response_data['multi_invitee_mode'] = True
        
    except ValueError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        logger.error(f"Error calculating availability for {organizer_slug}/{event_type_slug}: {str(e)}")
        return Response(
            {'error': 'Failed to calculate availability'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def availability_stats(request):
    """Get availability statistics for the organizer."""
    organizer = request.user
    
    # Get counts
    total_rules = AvailabilityRule.objects.filter(organizer=organizer).count()
    active_rules = AvailabilityRule.objects.filter(organizer=organizer, is_active=True).count()
    total_overrides = DateOverrideRule.objects.filter(organizer=organizer).count()
    total_blocks = BlockedTime.objects.filter(organizer=organizer).count()
    total_recurring_blocks = RecurringBlockedTime.objects.filter(organizer=organizer).count()
    
    # Calculate average weekly hours and find busiest day by duration
    active_availability_rules = AvailabilityRule.objects.filter(organizer=organizer, is_active=True)
    total_weekly_minutes = 0
    daily_minutes = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0}  # Monday=0 to Sunday=6
    
    for rule in active_availability_rules:
        if rule.spans_midnight():
            # Calculate duration for midnight-spanning rule
            start_minutes = rule.start_time.hour * 60 + rule.start_time.minute
            end_minutes = rule.end_time.hour * 60 + rule.end_time.minute
            duration_minutes = (24 * 60 - start_minutes) + end_minutes
        else:
            # Normal rule within same day
            start_minutes = rule.start_time.hour * 60 + rule.start_time.minute
            end_minutes = rule.end_time.hour * 60 + rule.end_time.minute
            duration_minutes = end_minutes - start_minutes
        
        total_weekly_minutes += duration_minutes
        daily_minutes[rule.day_of_week] += duration_minutes
    
    average_weekly_hours = total_weekly_minutes / 60.0
    
    # Find busiest day by total duration (more meaningful than rule count)
    day_mapping = {0: 'Monday', 1: 'Tuesday', 2: 'Wednesday', 3: 'Thursday', 
                  4: 'Friday', 5: 'Saturday', 6: 'Sunday'}
    
    busiest_day = 'None'
    if daily_minutes:
        busiest_day_num = max(daily_minutes, key=daily_minutes.get)
        if daily_minutes[busiest_day_num] > 0:
            busiest_day = day_mapping[busiest_day_num]
    
    # Calculate cache hit rate (simplified - would need more sophisticated tracking in production)
    cache_hit_rate = 0.85  # Placeholder - in production, track this via Redis metrics
    
    stats = {
        'total_rules': total_rules,
        'active_rules': active_rules,
        'total_overrides': total_overrides,
        'total_blocks': total_blocks,
        'total_recurring_blocks': total_recurring_blocks,
        'average_weekly_hours': round(average_weekly_hours, 2),
        'busiest_day': busiest_day,
        'daily_hours': {day_mapping[k]: round(v / 60.0, 2) for k, v in daily_minutes.items()},
        'cache_hit_rate': cache_hit_rate
    }
    
    response_serializer = AvailabilityStatsSerializer(stats)
    return Response(response_serializer.data)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def clear_availability_cache_manual(request):
    """Manually clear availability cache for the organizer."""
    organizer = request.user
    
    # Clear all cache entries for this organizer
    from .tasks import clear_availability_cache
    clear_availability_cache.delay(organizer.id, cache_type='manual_clear')
    
    return Response({'message': 'Cache clearing initiated'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def precompute_availability_cache_manual(request):
    """Manually trigger availability cache precomputation."""
    organizer = request.user
    days_ahead = request.data.get('days_ahead', 14)
    
    # Validate days_ahead
    if not isinstance(days_ahead, int) or days_ahead < 1 or days_ahead > 90:
        return Response(
            {'error': 'days_ahead must be an integer between 1 and 90'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Trigger precomputation
    from .tasks import precompute_availability_cache
    precompute_availability_cache.delay(organizer.id, days_ahead)
    
    return Response({
        'message': f'Cache precomputation initiated for {days_ahead} days ahead'
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def test_timezone_handling(request):
    """Test endpoint for timezone handling and DST transitions."""
    organizer = request.user
    test_timezone = request.GET.get('timezone', 'America/New_York')
    test_date = request.GET.get('date')
    
    if test_date:
        try:
            test_date_obj = datetime.strptime(test_date, '%Y-%m-%d').date()
        except ValueError:
            return Response(
                {'error': 'Invalid date format. Use YYYY-MM-DD'},
                status=status.HTTP_400_BAD_REQUEST
            )
    else:
        test_date_obj = timezone.now().date()
    
    from .utils import calculate_timezone_offset_hours, validate_timezone
    
    if not validate_timezone(test_timezone):
        return Response(
            {'error': f'Invalid timezone: {test_timezone}'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Calculate timezone information
    organizer_timezone = organizer.profile.timezone_name
    offset_hours = calculate_timezone_offset_hours(organizer_timezone, test_timezone, test_date_obj)
    
    # Check if the test date is in DST for the test timezone
    try:
        test_tz = ZoneInfo(test_timezone)
        test_datetime = datetime.combine(test_date_obj, time(12, 0)).replace(tzinfo=test_tz)
        is_dst = bool(test_datetime.dst())
        dst_offset_hours = test_datetime.dst().total_seconds() / 3600 if test_datetime.dst() else 0
        
        # Check if this is a DST transition date
        is_dst_transition = False
        try:
            # Check if the day before or after has different DST status
            day_before = test_datetime - timedelta(days=1)
            day_after = test_datetime + timedelta(days=1)
            
            is_dst_transition = (
                bool(day_before.dst()) != is_dst or 
                bool(day_after.dst()) != is_dst
            )
        except Exception:
            pass
    except Exception:
        is_dst = False
        dst_offset_hours = 0
        is_dst_transition = False
    
    return Response({
        'organizer_timezone': organizer_timezone,
        'test_timezone': test_timezone,
        'test_date': test_date_obj.isoformat(),
        'offset_hours': offset_hours,
        'timezone_valid': True,
        'is_dst': is_dst,
        'dst_offset_hours': dst_offset_hours,
        'is_dst_transition_date': is_dst_transition
    })