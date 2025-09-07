from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from .models import Booking, WaitlistEntry, EventTypeAvailabilityCache
from .utils import create_booking_audit_log, invalidate_availability_cache
import logging

logger = logging.getLogger(__name__)


@shared_task
def process_booking_confirmation(booking_id):
    """Process all post-booking confirmation tasks."""
    try:
        booking = Booking.objects.get(id=booking_id)
        
        # Send confirmation emails
        send_booking_confirmation_to_invitee.delay(booking_id)
        send_booking_notification_to_organizer.delay(booking_id)
        
        # Create calendar events with retry logic
        sync_booking_to_external_calendars.delay(booking_id)
        
        # Generate meeting link if needed
        if booking.event_type.location_type == 'video_call':
            from apps.integrations.tasks import generate_meeting_link
            generate_meeting_link.delay(booking_id)
        
        # Trigger event-specific workflows
        trigger_event_type_workflows.delay(booking_id, 'booking_created')
        
        # Invalidate availability cache
        invalidate_availability_cache(booking.organizer, booking.start_time.date())
        
        return f"Processed booking confirmation for {booking_id}"
    
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        logger.error(f"Error processing booking confirmation: {str(e)}")
        return f"Error processing booking confirmation: {str(e)}"


@shared_task
def sync_booking_to_external_calendars(booking_id, retry_count=0):
    """
    Sync booking to external calendars with retry logic.
    
    Args:
        booking_id: Booking UUID
        retry_count: Current retry attempt
    """
    max_retries = 3
    retry_delays = [60, 300, 900]  # 1 min, 5 min, 15 min
    
    try:
        booking = Booking.objects.get(id=booking_id)
        
        # Skip if already synced successfully
        if booking.calendar_sync_status == 'succeeded':
            return f"Booking {booking_id} already synced to calendar"
        
        # Create calendar events
        from apps.integrations.tasks import create_calendar_event
        result = create_calendar_event(booking_id)
        
        if "successfully" in result.lower():
            booking.mark_calendar_sync_success()
            
            # Create audit log
            create_booking_audit_log(
                booking=booking,
                action='calendar_sync_success',
                description="Successfully synced booking to external calendar",
                actor_type='system',
                metadata={'sync_result': result, 'retry_count': retry_count}
            )
        else:
            raise Exception(f"Calendar sync failed: {result}")
        
        return result
        
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        error_message = str(e)
        logger.error(f"Calendar sync failed for booking {booking_id}: {error_message}")
        
        try:
            booking = Booking.objects.get(id=booking_id)
            booking.mark_calendar_sync_failed(error_message)
            
            # Create audit log
            create_booking_audit_log(
                booking=booking,
                action='calendar_sync_failed',
                description=f"Calendar sync failed: {error_message}",
                actor_type='system',
                metadata={'error': error_message, 'retry_count': retry_count}
            )
            
            # Retry if within limits
            if retry_count < max_retries:
                delay = retry_delays[min(retry_count, len(retry_delays) - 1)]
                sync_booking_to_external_calendars.apply_async(
                    args=[booking_id, retry_count + 1],
                    countdown=delay
                )
                return f"Calendar sync failed, scheduled retry {retry_count + 1} in {delay}s"
            else:
                return f"Calendar sync failed after {max_retries} retries: {error_message}"
                
        except Booking.DoesNotExist:
            pass
        
        return f"Calendar sync error: {error_message}"


@shared_task
def trigger_event_type_workflows(booking_id, trigger_type):
    """
    Trigger event-type-specific workflows.
    
    Args:
        booking_id: Booking UUID
        trigger_type: Type of trigger (booking_created, booking_cancelled, etc.)
    """
    try:
        booking = Booking.objects.get(id=booking_id)
        event_type = booking.event_type
        
        # Get workflow based on trigger type
        workflow = None
        if trigger_type == 'booking_created' and event_type.confirmation_workflow:
            workflow = event_type.confirmation_workflow
        elif trigger_type == 'booking_cancelled' and event_type.cancellation_workflow:
            workflow = event_type.cancellation_workflow
        elif trigger_type == 'reminder' and event_type.reminder_workflow:
            workflow = event_type.reminder_workflow
        
        if workflow and workflow.is_active:
            # Trigger the workflow
            from apps.workflows.tasks import execute_workflow
            execute_workflow.delay(workflow.id, booking_id)
            
            # Create audit log
            create_booking_audit_log(
                booking=booking,
                action='workflow_triggered',
                description=f"Triggered {workflow.name} workflow for {trigger_type}",
                actor_type='system',
                metadata={
                    'workflow_id': str(workflow.id),
                    'workflow_name': workflow.name,
                    'trigger_type': trigger_type
                }
            )
            
            return f"Triggered workflow {workflow.name} for booking {booking_id}"
        
        return f"No workflow configured for {trigger_type} on event type {event_type.name}"
        
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        logger.error(f"Error triggering event type workflows: {str(e)}")
        return f"Error triggering workflows: {str(e)}"


@shared_task
def process_waitlist_for_cancelled_booking(booking_id):
    """Process waitlist when a booking is cancelled."""
    try:
        booking = Booking.objects.get(id=booking_id, status='cancelled')
        
        # Find active waitlist entries for this exact time slot
        waitlist_entries = WaitlistEntry.objects.filter(
            event_type=booking.event_type,
            organizer=booking.organizer,
            desired_start_time=booking.start_time,
            desired_end_time=booking.end_time,
            status='active'
        ).order_by('created_at')
        
        if waitlist_entries.exists():
            first_entry = waitlist_entries.first()
            
            # Notify the first person on waitlist
            success = first_entry.notify_availability()
            
            if success:
                # Create audit log
                create_booking_audit_log(
                    booking=booking,
                    action='waitlist_converted',
                    description=f"Notified waitlist entry {first_entry.invitee_name} of available slot",
                    actor_type='system',
                    metadata={
                        'waitlist_entry_id': str(first_entry.id),
                        'waitlist_email': first_entry.invitee_email
                    }
                )
                
                return f"Notified {first_entry.invitee_name} from waitlist"
        
        return f"No active waitlist entries found for booking {booking_id}"
        
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        logger.error(f"Error processing waitlist: {str(e)}")
        return f"Error processing waitlist: {str(e)}"


@shared_task
def cleanup_expired_waitlist_entries():
    """Clean up expired waitlist entries."""
    expired_entries = WaitlistEntry.objects.filter(
        status='active',
        expires_at__lt=timezone.now()
    )
    
    count = expired_entries.count()
    expired_entries.update(status='expired')
    
    logger.info(f"Marked {count} waitlist entries as expired")
    return f"Cleaned up {count} expired waitlist entries"


@shared_task
def cleanup_expired_access_tokens():
    """Clean up expired booking access tokens."""
    expired_bookings = Booking.objects.filter(
        access_token_expires_at__lt=timezone.now(),
        status__in=['confirmed', 'rescheduled']
    )
    
    count = 0
    for booking in expired_bookings:
        # Regenerate token for active bookings
        if booking.start_time > timezone.now():
            booking.regenerate_access_token()
            count += 1
    
    logger.info(f"Regenerated {count} expired access tokens")
    return f"Regenerated {count} expired access tokens"


@shared_task
def recompute_dirty_availability_cache():
    """Recompute availability cache entries marked as dirty."""
    dirty_entries = EventTypeAvailabilityCache.objects.filter(
        is_dirty=True,
        expires_at__gt=timezone.now()  # Only recompute non-expired entries
    )
    
    recomputed_count = 0
    
    for entry in dirty_entries:
        try:
            from .utils import AvailabilityCalculator
            
            calculator = AvailabilityCalculator(
                entry.organizer, 
                entry.event_type, 
                entry.timezone_name
            )
            
            # Recompute availability
            result = calculator.get_available_slots(
                entry.date, 
                entry.date, 
                entry.attendee_count,
                use_cache=False  # Don't use cache when recomputing
            )
            
            # Update cache entry
            entry.available_slots = result['slots']
            entry.computed_at = timezone.now()
            entry.is_dirty = False
            entry.computation_time_ms = result.get('performance_metrics', {}).get('computation_time_ms')
            entry.save()
            
            recomputed_count += 1
            
        except Exception as e:
            logger.error(f"Error recomputing cache entry {entry.id}: {str(e)}")
            # Mark as expired to remove from active cache
            entry.expires_at = timezone.now()
            entry.save(update_fields=['expires_at'])
    
    return f"Recomputed {recomputed_count} dirty cache entries"


@shared_task
def cleanup_expired_cache_entries():
    """Clean up expired availability cache entries."""
    expired_entries = EventTypeAvailabilityCache.objects.filter(
        expires_at__lt=timezone.now()
    )
    
    count = expired_entries.count()
    expired_entries.delete()
    
    logger.info(f"Cleaned up {count} expired cache entries")
    return f"Cleaned up {count} expired cache entries"


@shared_task
def send_waitlist_notification(waitlist_entry_id):
    """Send notification to waitlist entry about available slot."""
    try:
        entry = WaitlistEntry.objects.get(id=waitlist_entry_id)
        
        if entry.status != 'notified':
            return f"Waitlist entry {waitlist_entry_id} is not in notified status"
        
        # Create notification
        from apps.notifications.models import NotificationLog
        from apps.notifications.tasks import send_notification_task
        
        subject = f"Spot Available: {entry.event_type.name}"
        message = f"""Hi {entry.invitee_name},

Great news! A spot has opened up for the time you requested:

Event: {entry.event_type.name}
Time: {entry.desired_start_time.strftime('%B %d, %Y at %I:%M %p')} ({entry.invitee_timezone})

This spot is available on a first-come, first-served basis. Please book soon to secure your spot.

Book now: [booking_link]

Best regards,
{entry.organizer.first_name}"""
        
        log = NotificationLog.objects.create(
            organizer=entry.organizer,
            notification_type='email',
            recipient_email=entry.invitee_email,
            subject=subject,
            message=message,
            status='pending'
        )
        
        send_notification_task.delay(log.id)
        
        return f"Waitlist notification sent to {entry.invitee_email}"
        
    except WaitlistEntry.DoesNotExist:
        return f"Waitlist entry {waitlist_entry_id} not found"
    except Exception as e:
        logger.error(f"Error sending waitlist notification: {str(e)}")
        return f"Error sending waitlist notification: {str(e)}"


@shared_task
def monitor_booking_system_health():
    """Monitor overall booking system health and performance."""
    from datetime import timedelta
    
    # Check recent booking creation rate
    recent_bookings = Booking.objects.filter(
        created_at__gte=timezone.now() - timedelta(hours=1)
    )
    
    # Check calendar sync health
    failed_syncs = Booking.objects.filter(
        calendar_sync_status='failed',
        calendar_sync_attempts__gte=3,
        created_at__gte=timezone.now() - timedelta(hours=24)
    )
    
    # Check cache performance
    total_cache_entries = EventTypeAvailabilityCache.objects.count()
    dirty_cache_entries = EventTypeAvailabilityCache.objects.filter(is_dirty=True).count()
    expired_cache_entries = EventTypeAvailabilityCache.objects.filter(
        expires_at__lt=timezone.now()
    ).count()
    
    # Check waitlist health
    active_waitlist_entries = WaitlistEntry.objects.filter(status='active').count()
    expired_waitlist_entries = WaitlistEntry.objects.filter(
        status='active',
        expires_at__lt=timezone.now()
    ).count()
    
    health_report = {
        'timestamp': timezone.now().isoformat(),
        'recent_bookings_count': recent_bookings.count(),
        'failed_calendar_syncs': failed_syncs.count(),
        'cache_stats': {
            'total_entries': total_cache_entries,
            'dirty_entries': dirty_cache_entries,
            'expired_entries': expired_cache_entries,
            'cache_hit_rate': round((total_cache_entries - dirty_cache_entries) / max(total_cache_entries, 1) * 100, 2)
        },
        'waitlist_stats': {
            'active_entries': active_waitlist_entries,
            'expired_entries': expired_waitlist_entries
        }
    }
    
    # Alert if issues detected
    if failed_syncs.count() > 10 or dirty_cache_entries > 100:
        alert_admins_of_booking_issues.delay(health_report)
    
    logger.info(f"Booking system health check: {health_report}")
    return f"Health check completed: {health_report}"


@shared_task
def alert_admins_of_booking_issues(health_report):
    """Alert administrators of booking system issues."""
    try:
        subject = "Booking System Health Alert"
        message = f"""
Booking system health issues detected:

Recent Bookings (1h): {health_report['recent_bookings_count']}
Failed Calendar Syncs (24h): {health_report['failed_calendar_syncs']}

Cache Performance:
- Total Entries: {health_report['cache_stats']['total_entries']}
- Dirty Entries: {health_report['cache_stats']['dirty_entries']}
- Expired Entries: {health_report['cache_stats']['expired_entries']}
- Hit Rate: {health_report['cache_stats']['cache_hit_rate']}%

Waitlist Status:
- Active Entries: {health_report['waitlist_stats']['active_entries']}
- Expired Entries: {health_report['waitlist_stats']['expired_entries']}

Please check the admin panel for detailed information.

Timestamp: {health_report['timestamp']}
        """
        
        admin_emails = getattr(settings, 'ADMIN_NOTIFICATION_EMAILS', [])
        if admin_emails:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                admin_emails,
                fail_silently=True,
            )
        
        return f"Health alert sent to {len(admin_emails)} administrators"
        
    except Exception as e:
        logger.error(f"Error sending health alert: {str(e)}")
        return f"Error sending health alert: {str(e)}"


@shared_task
def retry_failed_calendar_syncs():
    """Retry failed calendar syncs for recent bookings."""
    failed_bookings = Booking.objects.filter(
        calendar_sync_status='failed',
        calendar_sync_attempts__lt=3,
        created_at__gte=timezone.now() - timedelta(hours=24)
    )
    
    retry_count = 0
    
    for booking in failed_bookings:
        try:
            # Reset sync status and retry
            booking.calendar_sync_status = 'pending'
            booking.save(update_fields=['calendar_sync_status'])
            
            # Schedule retry with delay based on attempt count
            delay = 60 * (2 ** booking.calendar_sync_attempts)  # Exponential backoff
            sync_booking_to_external_calendars.apply_async(
                args=[booking.id, booking.calendar_sync_attempts],
                countdown=delay
            )
            
            retry_count += 1
            
        except Exception as e:
            logger.error(f"Error scheduling calendar sync retry for booking {booking.id}: {str(e)}")
    
    return f"Scheduled {retry_count} calendar sync retries"


@shared_task
def send_booking_confirmation_to_invitee(booking_id):
    """Send booking confirmation email to invitee."""
    try:
        booking = Booking.objects.get(id=booking_id)
        
        subject = f"Booking Confirmed: {booking.event_type.name}"
        message = f"""
        Hi {booking.invitee_name},
        
        Your booking has been confirmed!
        
        Event: {booking.event_type.name}
        Date & Time: {booking.start_time.strftime('%B %d, %Y at %I:%M %p')} ({booking.invitee_timezone})
        Duration: {booking.event_type.duration} minutes
        
        Organizer: {booking.organizer.profile.display_name}
        
        {"Meeting Link: " + booking.meeting_link if booking.meeting_link else ""}
        
        Best regards,
        The Calendly Clone Team
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [booking.invitee_email],
            fail_silently=False,
        )
        
        return f"Confirmation email sent to {booking.invitee_email}"
    
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        return f"Failed to send confirmation email: {str(e)}"


@shared_task
def send_booking_notification_to_organizer(booking_id):
    """Send booking notification email to organizer."""
    try:
        booking = Booking.objects.get(id=booking_id)
        
        subject = f"New Booking: {booking.event_type.name}"
        message = f"""
        Hi {booking.organizer.first_name},
        
        You have a new booking!
        
        Event: {booking.event_type.name}
        Invitee: {booking.invitee_name} ({booking.invitee_email})
        Date & Time: {booking.start_time.strftime('%B %d, %Y at %I:%M %p')}
        Duration: {booking.event_type.duration} minutes
        
        {"Meeting Link: " + booking.meeting_link if booking.meeting_link else ""}
        
        Best regards,
        The Calendly Clone Team
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [booking.organizer.email],
            fail_silently=False,
        )
        
        return f"Notification email sent to {booking.organizer.email}"
    
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        return f"Failed to send notification email: {str(e)}"


@shared_task
def process_booking_cancellation(booking_id):
    """Process booking cancellation tasks."""
    try:
        booking = Booking.objects.get(id=booking_id)
        
        # Send cancellation emails
        send_cancellation_email_to_invitee.delay(booking_id)
        send_cancellation_notification_to_organizer.delay(booking_id)
        
        # Remove from calendar
        from apps.integrations.tasks import remove_calendar_event
        remove_calendar_event.delay(booking_id)
        
        return f"Processed booking cancellation for {booking_id}"
    
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        return f"Error processing booking cancellation: {str(e)}"


@shared_task
def send_cancellation_email_to_invitee(booking_id):
    """Send cancellation email to invitee."""
    try:
        booking = Booking.objects.get(id=booking_id)
        
        subject = f"Booking Cancelled: {booking.event_type.name}"
        message = f"""
        Hi {booking.invitee_name},
        
        Your booking has been cancelled.
        
        Event: {booking.event_type.name}
        Date & Time: {booking.start_time.strftime('%B %d, %Y at %I:%M %p')} ({booking.invitee_timezone})
        
        {f"Reason: {booking.cancellation_reason}" if booking.cancellation_reason else ""}
        
        You can book a new time at any time.
        
        Best regards,
        The Calendly Clone Team
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [booking.invitee_email],
            fail_silently=False,
        )
        
        return f"Cancellation email sent to {booking.invitee_email}"
    
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        return f"Failed to send cancellation email: {str(e)}"


@shared_task
def send_cancellation_notification_to_organizer(booking_id):
    """Send cancellation notification to organizer."""
    try:
        booking = Booking.objects.get(id=booking_id)
        
        subject = f"Booking Cancelled: {booking.event_type.name}"
        message = f"""
        Hi {booking.organizer.first_name},
        
        A booking has been cancelled.
        
        Event: {booking.event_type.name}
        Invitee: {booking.invitee_name} ({booking.invitee_email})
        Date & Time: {booking.start_time.strftime('%B %d, %Y at %I:%M %p')}
        
        {f"Reason: {booking.cancellation_reason}" if booking.cancellation_reason else ""}
        
        Best regards,
        The Calendly Clone Team
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [booking.organizer.email],
            fail_silently=False,
        )
        
        return f"Cancellation notification sent to {booking.organizer.email}"
    
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        return f"Failed to send cancellation notification: {str(e)}"