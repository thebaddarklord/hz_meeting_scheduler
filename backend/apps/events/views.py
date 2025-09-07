from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.utils import timezone
from django.core.cache import cache
from .models import EventType, Booking, Attendee, WaitlistEntry, CustomQuestion
from .serializers import (
    EventTypeSerializer, EventTypeCreateSerializer, PublicEventTypeSerializer,
    BookingSerializer, BookingCreateSerializer, BookingUpdateSerializer,
    PublicBookingPageSerializer, AttendeeSerializer, WaitlistEntrySerializer,
    BookingManagementSerializer, CustomQuestionSerializer
)
from .tasks import process_booking_confirmation, trigger_event_type_workflows
from .utils import (
    get_available_time_slots, create_booking_with_validation, 
    handle_booking_cancellation, handle_booking_rescheduling,
    get_booking_by_access_token, get_client_ip_from_request,
    get_user_agent_from_request, create_booking_audit_log
)
import logging

logger = logging.getLogger(__name__)


class EventTypeListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return EventType.objects.filter(organizer=self.request.user)
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return EventTypeCreateSerializer
        return EventTypeSerializer
    
    def perform_create(self, serializer):
        serializer.save(organizer=self.request.user)


class EventTypeDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = EventTypeSerializer
    
    def get_queryset(self):
        return EventType.objects.filter(organizer=self.request.user)


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def public_organizer_page(request, organizer_slug):
    """Public organizer page showing all available event types."""
    try:
        # Get organizer by slug
        from apps.users.models import User
        organizer = get_object_or_404(
            User,
            profile__organizer_slug=organizer_slug,
            is_active=True,
            is_organizer=True
        )
        
        # Check cache first
        cache_key = f"public_organizer:{organizer_slug}"
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return Response(cached_data)
        
        # Get public event types
        event_types = EventType.objects.filter(
            organizer=organizer,
            is_active=True,
            is_private=False
        ).order_by('name')
        
        # Serialize data
        organizer_data = {
            'organizer_slug': organizer.profile.organizer_slug,
            'display_name': organizer.profile.display_name,
            'bio': organizer.profile.bio,
            'profile_picture': organizer.profile.profile_picture.url if organizer.profile.profile_picture else None,
            'company': organizer.profile.company,
            'website': organizer.profile.website,
            'timezone': organizer.profile.timezone_name,
            'brand_color': organizer.profile.brand_color,
            'event_types': []
        }
        
        for event_type in event_types:
            organizer_data['event_types'].append({
                'name': event_type.name,
                'event_type_slug': event_type.event_type_slug,
                'description': event_type.description,
                'duration': event_type.duration,
                'location_type': event_type.location_type,
                'max_attendees': event_type.max_attendees,
                'is_group_event': event_type.is_group_event()
            })
        
        # Cache for 15 minutes
        cache.set(cache_key, organizer_data, timeout=900)
        
        return Response(organizer_data)
        
    except Exception as e:
        logger.error(f"Error loading public organizer page: {str(e)}")
        return Response(
            {'error': 'Organizer not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def public_event_type_page(request, organizer_slug, event_type_slug):
    """Public event type page with availability and booking form."""
    try:
        # Get event type
        event_type = get_object_or_404(
            EventType,
            organizer__profile__organizer_slug=organizer_slug,
            event_type_slug=event_type_slug,
            is_active=True
        )
        
        # Get query parameters
        start_date_str = request.GET.get('start_date')
        end_date_str = request.GET.get('end_date')
        invitee_timezone = request.GET.get('timezone', 'UTC')
        attendee_count = int(request.GET.get('attendee_count', 1))
        
        # Default to next 7 days if no dates provided
        if not start_date_str or not end_date_str:
            from datetime import date, timedelta
            start_date = date.today()
            end_date = start_date + timedelta(days=7)
        else:
            from datetime import datetime
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        
        # Validate timezone
        from .utils import validate_timezone_for_booking
        timezone_valid, timezone_error = validate_timezone_for_booking(invitee_timezone)
        if not timezone_valid:
            return Response(
                {'error': timezone_error},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get available slots
        availability_result = get_available_time_slots(
            organizer=event_type.organizer,
            event_type=event_type,
            start_date=start_date,
            end_date=end_date,
            invitee_timezone=invitee_timezone,
            attendee_count=attendee_count
        )
        
        # Get custom questions
        custom_questions = CustomQuestion.objects.filter(
            event_type=event_type,
            is_active=True
        ).order_by('order')
        
        # Serialize event type data
        event_type_data = PublicEventTypeSerializer(event_type).data
        
        # Add availability and questions
        event_type_data.update({
            'available_slots': availability_result.get('slots', []),
            'custom_questions': CustomQuestionSerializer(custom_questions, many=True).data,
            'cache_hit': availability_result.get('cache_hit', False),
            'total_slots': availability_result.get('total_slots', 0),
            'performance_metrics': availability_result.get('performance_metrics', {}),
            'search_params': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'invitee_timezone': invitee_timezone,
                'attendee_count': attendee_count
            }
        })
        
        return Response(event_type_data)
        
    except ValueError as e:
        return Response(
            {'error': f'Invalid parameter: {str(e)}'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        logger.error(f"Error loading public event type page: {str(e)}")
        return Response(
            {'error': 'Event type not found'},
            status=status.HTTP_404_NOT_FOUND
        )


class PublicEventTypeView(generics.RetrieveAPIView):
    """Legacy public view - redirects to new endpoint."""
    serializer_class = PublicEventTypeSerializer
    permission_classes = [permissions.AllowAny]
    
    def get_object(self):
        organizer_slug = self.kwargs['organizer_slug']
        event_type_slug = self.kwargs['event_type_slug']
        
        return get_object_or_404(
            EventType,
            organizer__profile__organizer_slug=organizer_slug,
            event_type_slug=event_type_slug,
            is_active=True
        )


class BookingListView(generics.ListAPIView):
    serializer_class = BookingSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = Booking.objects.filter(organizer=self.request.user).order_by('-start_time')
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            try:
                from datetime import datetime
                start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
                queryset = queryset.filter(start_time__date__gte=start_date_obj)
            except ValueError:
                pass
        
        if end_date:
            try:
                from datetime import datetime
                end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
                queryset = queryset.filter(start_time__date__lte=end_date_obj)
            except ValueError:
                pass
        
        return queryset


class BookingDetailView(generics.RetrieveUpdateAPIView):
    serializer_class = BookingSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Booking.objects.filter(organizer=self.request.user)
    
    def get_serializer_class(self):
        if self.request.method in ['PATCH', 'PUT']:
            return BookingUpdateSerializer
        return BookingSerializer


class BookingThrottle(AnonRateThrottle):
    scope = 'booking'


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@throttle_classes([BookingThrottle])
def create_booking(request):
    """Enhanced public endpoint for creating bookings with comprehensive validation."""
    serializer = BookingCreateSerializer(data=request.data)
    
    if serializer.is_valid():
        try:
            # Extract validated data
            organizer_slug = serializer.validated_data['organizer_slug']
            event_type_slug = serializer.validated_data['event_type_slug']
            custom_answers = serializer.validated_data.get('custom_answers', {})
            
            # Get event type
            event_type = get_object_or_404(
                EventType,
                organizer__profile__organizer_slug=organizer_slug,
                event_type_slug=event_type_slug,
                is_active=True
            )
            
            # Check if slot is full and handle waitlist
            attendee_count = serializer.validated_data.get('attendee_count', 1)
            start_time = serializer.validated_data['start_time']
            
            # Check availability
            availability_result = get_available_time_slots(
                organizer=event_type.organizer,
                event_type=event_type,
                start_date=start_time.date(),
                end_date=start_time.date(),
                attendee_count=attendee_count,
                use_cache=False  # Don't use cache for booking validation
            )
            
            available_slots = availability_result.get('slots', [])
            slot_available = any(
                slot['start_time'] == start_time for slot in available_slots
            )
            
            if not slot_available:
                # Check if waitlist is enabled
                if event_type.enable_waitlist:
                    return handle_waitlist_request(request, event_type, serializer.validated_data)
                else:
                    return Response(
                        {'error': 'This time slot is no longer available'},
                        status=status.HTTP_409_CONFLICT
                    )
            
            # Create booking with comprehensive validation
            booking, created, errors = create_booking_with_validation(
                event_type=event_type,
                organizer=event_type.organizer,
                booking_data=serializer.validated_data,
                custom_answers=custom_answers
            )
            
            if errors:
                return Response(
                    {'errors': errors},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not booking:
                return Response(
                    {'error': 'Failed to create booking'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Trigger async post-booking tasks
            process_booking_confirmation.delay(booking.id)
            
            # Prepare response
            response_data = BookingSerializer(booking).data
            
            # Add redirect URL if configured
            if event_type.redirect_url_after_booking:
                response_data['redirect_url'] = event_type.redirect_url_after_booking
            
            # Add access token for booking management
            response_data['access_token'] = str(booking.access_token)
            response_data['management_url'] = f"/booking/{booking.access_token}/manage/"
            
            return Response(response_data, status=status.HTTP_201_CREATED)
                
        except EventType.DoesNotExist:
            return Response(
                {'error': 'Event type not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error creating booking: {str(e)}")
            return Response(
                {'error': 'Failed to create booking', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def handle_waitlist_request(request, event_type, booking_data):
    """Handle waitlist request when event is full."""
    try:
        # Create waitlist entry
        start_time = booking_data['start_time']
        end_time = start_time + timezone.timedelta(minutes=event_type.duration)
        
        waitlist_entry = WaitlistEntry.objects.create(
            event_type=event_type,
            organizer=event_type.organizer,
            desired_start_time=start_time,
            desired_end_time=end_time,
            invitee_name=booking_data['invitee_name'],
            invitee_email=booking_data['invitee_email'],
            invitee_phone=booking_data.get('invitee_phone', ''),
            invitee_timezone=booking_data.get('invitee_timezone', 'UTC'),
            custom_answers=booking_data.get('custom_answers', {})
        )
        
        # Send waitlist confirmation
        from apps.notifications.tasks import send_waitlist_confirmation
        send_waitlist_confirmation.delay(waitlist_entry.id)
        
        return Response({
            'message': 'Added to waitlist',
            'waitlist_entry_id': str(waitlist_entry.id),
            'position': get_waitlist_position(waitlist_entry),
            'estimated_notification_time': waitlist_entry.expires_at
        }, status=status.HTTP_202_ACCEPTED)
        
    except Exception as e:
        logger.error(f"Error handling waitlist request: {str(e)}")
        return Response(
            {'error': 'Failed to add to waitlist'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


def get_waitlist_position(waitlist_entry):
    """Get position in waitlist for a specific entry."""
    earlier_entries = WaitlistEntry.objects.filter(
        event_type=waitlist_entry.event_type,
        desired_start_time=waitlist_entry.desired_start_time,
        status='active',
        created_at__lt=waitlist_entry.created_at
    ).count()
    
    return earlier_entries + 1


@api_view(['GET', 'POST'])
@permission_classes([permissions.AllowAny])
def booking_management(request, access_token):
    """Booking management page for invitees."""
    booking = get_booking_by_access_token(access_token)
    
    if not booking:
        return Response(
            {'error': 'Invalid or expired access token'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    if request.method == 'GET':
        # Return booking details and management options
        serializer = BookingManagementSerializer(booking)
        data = serializer.data
        
        # Add management capabilities
        data['can_cancel'] = booking.can_be_cancelled()
        data['can_reschedule'] = booking.can_be_rescheduled()
        
        # Add attendee information for group bookings
        if booking.event_type.is_group_event():
            attendees = Attendee.objects.filter(booking=booking, status='confirmed')
            data['attendees'] = AttendeeSerializer(attendees, many=True).data
            data['available_spots'] = booking.event_type.max_attendees - attendees.count()
        
        return Response(data)
    
    elif request.method == 'POST':
        # Handle booking management actions
        action = request.data.get('action')
        ip_address = get_client_ip_from_request(request)
        user_agent = get_user_agent_from_request(request)
        
        if action == 'cancel':
            reason = request.data.get('reason', '')
            success, errors = handle_booking_cancellation(
                booking=booking,
                cancelled_by='invitee',
                reason=reason,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            if success:
                # Trigger cancellation workflows
                trigger_event_type_workflows.delay(booking.id, 'booking_cancelled')
                
                return Response({'message': 'Booking cancelled successfully'})
            else:
                return Response(
                    {'errors': errors},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        elif action == 'reschedule':
            new_start_time_str = request.data.get('new_start_time')
            if not new_start_time_str:
                return Response(
                    {'error': 'new_start_time is required for rescheduling'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                from datetime import datetime
                new_start_time = datetime.fromisoformat(new_start_time_str.replace('Z', '+00:00'))
                
                success, errors = handle_booking_rescheduling(
                    booking=booking,
                    new_start_time=new_start_time,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                if success:
                    # Trigger rescheduling workflows
                    trigger_event_type_workflows.delay(booking.id, 'booking_rescheduled')
                    
                    return Response({'message': 'Booking rescheduled successfully'})
                else:
                    return Response(
                        {'errors': errors},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                    
            except ValueError:
                return Response(
                    {'error': 'Invalid datetime format for new_start_time'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        elif action == 'regenerate_token':
            # Regenerate access token
            booking.regenerate_access_token()
            
            create_booking_audit_log(
                booking=booking,
                action='access_token_regenerated',
                description="Access token regenerated by invitee",
                actor_type='invitee',
                actor_email=booking.invitee_email,
                actor_name=booking.invitee_name,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            return Response({
                'message': 'Access token regenerated',
                'new_token': str(booking.access_token),
                'expires_at': booking.access_token_expires_at
            })
        
        else:
            return Response(
                {'error': f'Unknown action: {action}'},
                status=status.HTTP_400_BAD_REQUEST
            )


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def cancel_booking_legacy(request, booking_id):
    """Legacy endpoint for cancelling bookings - use booking management instead."""
    try:
        booking = Booking.objects.get(id=booking_id, status='confirmed')
        
        reason = request.data.get('reason', '')
        ip_address = get_client_ip_from_request(request)
        user_agent = get_user_agent_from_request(request)
        
        success, errors = handle_booking_cancellation(
            booking=booking,
            cancelled_by='invitee',
            reason=reason,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        if success:
            # Trigger cancellation workflows
            trigger_event_type_workflows.delay(booking.id, 'booking_cancelled')
            
            return Response({'message': 'Booking cancelled successfully'})
        else:
            return Response(
                {'errors': errors},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    except Booking.DoesNotExist:
        return Response(
            {'error': 'Booking not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def get_available_slots_api(request, organizer_slug, event_type_slug):
    """API endpoint for getting available slots."""
    try:
        # Get event type
        event_type = get_object_or_404(
            EventType,
            organizer__profile__organizer_slug=organizer_slug,
            event_type_slug=event_type_slug,
            is_active=True
        )
        
        # Parse query parameters
        start_date_str = request.GET.get('start_date')
        end_date_str = request.GET.get('end_date')
        invitee_timezone = request.GET.get('timezone', 'UTC')
        attendee_count = int(request.GET.get('attendee_count', 1))
        
        if not start_date_str or not end_date_str:
            return Response(
                {'error': 'start_date and end_date are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            from datetime import datetime
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            return Response(
                {'error': 'Invalid date format. Use YYYY-MM-DD'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate timezone
        from .utils import validate_timezone_for_booking
        timezone_valid, timezone_error = validate_timezone_for_booking(invitee_timezone)
        if not timezone_valid:
            return Response(
                {'error': timezone_error},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get available slots
        availability_result = get_available_time_slots(
            organizer=event_type.organizer,
            event_type=event_type,
            start_date=start_date,
            end_date=end_date,
            invitee_timezone=invitee_timezone,
            attendee_count=attendee_count
        )
        
        return Response(availability_result)
        
    except Exception as e:
        logger.error(f"Error getting available slots: {str(e)}")
        return Response(
            {'error': 'Failed to get available slots'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def add_attendee_to_booking(request, booking_id):
    """Add attendee to existing group booking."""
    try:
        booking = get_object_or_404(
            Booking,
            id=booking_id,
            organizer=request.user,
            status='confirmed'
        )
        
        if not booking.event_type.is_group_event():
            return Response(
                {'error': 'This is not a group event'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check capacity
        current_attendees = booking.attendees.filter(status='confirmed').count()
        if current_attendees >= booking.event_type.max_attendees:
            return Response(
                {'error': 'Event is at maximum capacity'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create attendee
        attendee_data = {
            'name': request.data.get('name'),
            'email': request.data.get('email'),
            'phone': request.data.get('phone', ''),
            'custom_answers': request.data.get('custom_answers', {})
        }
        
        attendee = Attendee.objects.create(
            booking=booking,
            **attendee_data
        )
        
        # Update booking attendee count
        booking.attendee_count = booking.attendees.filter(status='confirmed').count()
        booking.save(update_fields=['attendee_count'])
        
        # Create audit log
        create_booking_audit_log(
            booking=booking,
            action='attendee_added',
            description=f"Added attendee {attendee.name} to group booking",
            actor_type='organizer',
            actor_email=request.user.email,
            actor_name=request.user.get_full_name(),
            ip_address=get_client_ip_from_request(request),
            user_agent=get_user_agent_from_request(request),
            metadata={'attendee_id': str(attendee.id)}
        )
        
        return Response(AttendeeSerializer(attendee).data, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"Error adding attendee: {str(e)}")
        return Response(
            {'error': 'Failed to add attendee'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def remove_attendee_from_booking(request, booking_id, attendee_id):
    """Remove attendee from group booking."""
    try:
        booking = get_object_or_404(
            Booking,
            id=booking_id,
            organizer=request.user,
            status='confirmed'
        )
        
        attendee = get_object_or_404(
            Attendee,
            id=attendee_id,
            booking=booking,
            status='confirmed'
        )
        
        # Cancel attendee
        reason = request.data.get('reason', 'Removed by organizer')
        attendee.cancel(reason)
        
        # Update booking attendee count
        booking.attendee_count = booking.attendees.filter(status='confirmed').count()
        booking.save(update_fields=['attendee_count'])
        
        # Create audit log
        create_booking_audit_log(
            booking=booking,
            action='attendee_cancelled',
            description=f"Removed attendee {attendee.name} from group booking",
            actor_type='organizer',
            actor_email=request.user.email,
            actor_name=request.user.get_full_name(),
            ip_address=get_client_ip_from_request(request),
            user_agent=get_user_agent_from_request(request),
            metadata={'attendee_id': str(attendee.id), 'reason': reason}
        )
        
        # Check waitlist for this spot
        from .tasks import process_waitlist_for_cancelled_booking
        process_waitlist_for_cancelled_booking.delay(booking.id)
        
        return Response({'message': 'Attendee removed successfully'})
        
    except Exception as e:
        logger.error(f"Error removing attendee: {str(e)}")
        return Response(
            {'error': 'Failed to remove attendee'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def booking_analytics(request):
    """Get booking analytics for the organizer."""
    from django.db.models import Count, Q
    from datetime import timedelta
    
    # Date range filter
    days = int(request.GET.get('days', 30))
    start_date = timezone.now() - timedelta(days=days)
    
    bookings = Booking.objects.filter(
        organizer=request.user,
        created_at__gte=start_date
    )
    
    analytics = {
        'total_bookings': bookings.count(),
        'confirmed_bookings': bookings.filter(status='confirmed').count(),
        'cancelled_bookings': bookings.filter(status='cancelled').count(),
        'completed_bookings': bookings.filter(status='completed').count(),
        'no_show_bookings': bookings.filter(status='no_show').count(),
        
        # Calendar sync health
        'calendar_sync_success': bookings.filter(calendar_sync_status='succeeded').count(),
        'calendar_sync_failed': bookings.filter(calendar_sync_status='failed').count(),
        'calendar_sync_pending': bookings.filter(calendar_sync_status='pending').count(),
        
        # Event type breakdown
        'bookings_by_event_type': list(
            bookings.values('event_type__name')
            .annotate(count=Count('id'))
            .order_by('-count')
        ),
        
        # Cancellation analysis
        'cancellations_by_actor': list(
            bookings.filter(status='cancelled')
            .values('cancelled_by')
            .annotate(count=Count('id'))
        ),
        
        # Group event statistics
        'group_event_stats': {
            'total_group_bookings': bookings.filter(event_type__max_attendees__gt=1).count(),
            'average_attendees': bookings.filter(
                event_type__max_attendees__gt=1
            ).aggregate(avg_attendees=models.Avg('attendee_count'))['avg_attendees'] or 0
        }
    }
    
    return Response(analytics)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def booking_audit_logs(request, booking_id):
    """Get audit logs for a specific booking."""
    booking = get_object_or_404(
        Booking,
        id=booking_id,
        organizer=request.user
    )
    
    audit_logs = booking.audit_logs.order_by('-created_at')
    
    # Serialize audit logs
    logs_data = []
    for log in audit_logs:
        logs_data.append({
            'id': str(log.id),
            'action': log.action,
            'action_display': log.get_action_display(),
            'description': log.description,
            'actor_type': log.actor_type,
            'actor_email': log.actor_email,
            'actor_name': log.actor_name,
            'ip_address': log.ip_address,
            'metadata': log.metadata,
            'old_values': log.old_values,
            'new_values': log.new_values,
            'created_at': log.created_at
        })
    
    return Response({
        'booking_id': str(booking.id),
        'audit_logs': logs_data,
        'total_logs': len(logs_data)
    })