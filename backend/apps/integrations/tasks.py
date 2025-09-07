from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
import requests
from datetime import datetime, timedelta
import json
import logging

logger = logging.getLogger(__name__)
from .models import CalendarIntegration, VideoConferenceIntegration, WebhookIntegration, IntegrationLog
from .utils import log_integration_activity, ensure_valid_token, detect_integration_conflicts
from .google_client import GoogleCalendarClient, GoogleMeetClient
from .outlook_client import OutlookCalendarClient
from .zoom_client import ZoomClient


@shared_task
def create_calendar_event(booking_id):
    """Create calendar event for a booking."""
    try:
        from apps.events.models import Booking
        booking = Booking.objects.get(id=booking_id)
        
        # Get calendar integrations for the organizer
        calendar_integrations = CalendarIntegration.objects.filter(
            organizer=booking.organizer,
            is_active=True,
            sync_enabled=True
        )
        
        external_event_id = None
        
        for integration in calendar_integrations:
            try:
                if integration.provider == 'google':
                    client = GoogleCalendarClient(integration)
                    external_event_id = client.create_event(booking)
                elif integration.provider == 'outlook':
                    client = OutlookCalendarClient(integration)
                    external_event_id = client.create_event(booking)
                else:
                    logger.warning(f"Calendar provider {integration.provider} not implemented")
                    continue
                
                # Store external event ID in booking
                if external_event_id:
                    booking.external_calendar_event_id = external_event_id
                    booking.save(update_fields=['external_calendar_event_id'])
                    break  # Successfully created, no need to try other providers
                    
            except Exception as e:
                logger.error(f"Error creating calendar event with {integration.provider}: {str(e)}")
                integration.mark_sync_error()
                continue
        
        return f"Calendar events created for booking {booking_id}"
    
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        return f"Error creating calendar event: {str(e)}"


@shared_task
def generate_meeting_link(booking_id):
    """Generate video conference link for a booking."""
    try:
        from apps.events.models import Booking
        booking = Booking.objects.get(id=booking_id)
        
        # Get video integrations for the organizer
        video_integrations = VideoConferenceIntegration.objects.filter(
            organizer=booking.organizer,
            is_active=True,
            auto_generate_links=True
        )
        
        for integration in video_integrations:
            try:
                meeting_details = None
                
                if integration.provider == 'zoom':
                    client = ZoomClient(integration)
                    meeting_details = client.create_meeting(booking)
                elif integration.provider == 'google_meet':
                    client = GoogleMeetClient(integration)
                    meeting_details = client.create_meeting(booking)
                else:
                    logger.warning(f"Video provider {integration.provider} not implemented")
                    continue
                
                # Update booking with meeting details
                if meeting_details:
                    booking.meeting_link = meeting_details.get('meeting_link', '')
                    booking.meeting_id = meeting_details.get('meeting_id', '')
                    booking.meeting_password = meeting_details.get('meeting_password', '')
                    booking.save(update_fields=['meeting_link', 'meeting_id', 'meeting_password'])
                    break  # Successfully created, no need to try other providers
                    
            except Exception as e:
                logger.error(f"Error generating meeting link with {integration.provider}: {str(e)}")
                continue
        
        return f"Video link generated for booking {booking_id}"
    
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        return f"Error generating video link: {str(e)}"


@shared_task
def remove_calendar_event(booking_id):
    """Remove calendar event for a cancelled booking."""
    try:
        from apps.events.models import Booking
        booking = Booking.objects.get(id=booking_id)
        
        # Get calendar integrations for the organizer
        calendar_integrations = CalendarIntegration.objects.filter(
            organizer=booking.organizer,
            is_active=True,
            sync_enabled=True
        )
        
        for integration in calendar_integrations:
            try:
                if integration.provider == 'google':
                    client = GoogleCalendarClient(integration)
                    client.delete_event(booking)
                elif integration.provider == 'outlook':
                    client = OutlookCalendarClient(integration)
                    client.delete_event(booking)
                else:
                    logger.warning(f"Calendar provider {integration.provider} not implemented")
                    continue
                    
            except Exception as e:
                logger.error(f"Error removing calendar event with {integration.provider}: {str(e)}")
                continue
        
        return f"Calendar events removed for booking {booking_id}"
    
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        return f"Error removing calendar event: {str(e)}"


@shared_task
def send_webhook(webhook_id, event_type, data):
    """Send webhook notification."""
    try:
        webhook = WebhookIntegration.objects.get(id=webhook_id, is_active=True)
        
        # Prepare payload
        payload = {
            'event': event_type,
            'timestamp': data.get('timestamp'),
            'data': data
        }
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Calendly-Clone-Webhook/1.0'
        }
        
        # Add custom headers
        if webhook.headers:
            headers.update(webhook.headers)
        
        # Add secret key if provided
        if webhook.secret_key:
            headers['X-Webhook-Secret'] = webhook.secret_key
        
        # Send webhook
        response = requests.post(
            webhook.webhook_url,
            json=payload,
            headers=headers,
            timeout=30
        )
        
        success = response.status_code == 200
        message = f"Webhook sent successfully (Status: {response.status_code})" if success else f"Webhook failed (Status: {response.status_code})"
        
        # Log the result
        IntegrationLog.objects.create(
            organizer=webhook.organizer,
            log_type='webhook_sent',
            integration_type='webhook',
            message=message,
            details={
                'webhook_url': webhook.webhook_url,
                'event_type': event_type,
                'status_code': response.status_code,
                'response_text': response.text[:500]  # Limit response text
            },
            success=success
        )
        
        return message
    
    except WebhookIntegration.DoesNotExist:
        return f"Webhook {webhook_id} not found"
    except Exception as e:
        return f"Error sending webhook: {str(e)}"


@shared_task
def sync_calendar_events(integration_id):
    """Sync events from external calendar."""
    try:
        integration = CalendarIntegration.objects.get(id=integration_id)
        
        if not integration.is_active or not integration.sync_enabled:
            return f"Sync disabled for {integration.provider} integration"
        
        # Calculate sync date range
        today = timezone.now().date()
        start_date = today - timedelta(days=getattr(settings, 'CALENDAR_SYNC_DAYS_BEHIND', 7))
        end_date = today + timedelta(days=getattr(settings, 'CALENDAR_SYNC_DAYS_AHEAD', 90))
        
        # Get external events
        external_events = []
        
        if integration.provider == 'google':
            client = GoogleCalendarClient(integration)
            external_events = client.get_busy_times(start_date, end_date)
        elif integration.provider == 'outlook':
            client = OutlookCalendarClient(integration)
            external_events = client.get_busy_times(start_date, end_date)
        else:
            logger.warning(f"Calendar sync not implemented for {integration.provider}")
            return f"Sync not implemented for {integration.provider}"
        
        # Reconcile with existing blocked times
        reconcile_calendar_events.delay(integration.id, external_events)
        
        # Mark successful sync
        integration.mark_sync_success()
        
        return f"Calendar sync completed for {integration.provider}"
    
    except CalendarIntegration.DoesNotExist:
        return f"Calendar integration {integration_id} not found"
    except Exception as e:
        try:
            integration = CalendarIntegration.objects.get(id=integration_id)
            integration.mark_sync_error()
        except:
            pass
        
        logger.error(f"Error syncing calendar: {str(e)}")
        return f"Error syncing calendar: {str(e)}"


@shared_task
def reconcile_calendar_events(integration_id, external_events):
    """
    Reconcile external calendar events with internal blocked times.
    
    Args:
        integration_id: CalendarIntegration ID
        external_events: List of external events from calendar API
    """
    try:
        integration = CalendarIntegration.objects.get(id=integration_id)
        organizer = integration.organizer
        
        from apps.availability.models import BlockedTime
        
        # Get existing synced blocked times for this provider
        source_name = f"{integration.provider}_calendar"
        existing_blocks = BlockedTime.objects.filter(
            organizer=organizer,
            source=source_name,
            is_active=True
        )
        
        # Create lookup for existing blocks by external_id
        existing_blocks_map = {
            block.external_id: block 
            for block in existing_blocks 
            if block.external_id
        }
        
        # Track what we've processed
        processed_external_ids = set()
        created_count = 0
        updated_count = 0
        
        # Process external events
        for event in external_events:
            external_id = event['external_id']
            processed_external_ids.add(external_id)
            
            # Skip transparent (free) events
            if event.get('transparency') == 'transparent':
                continue
            
            # Skip cancelled events
            if event.get('status') == 'cancelled':
                continue
            
            existing_block = existing_blocks_map.get(external_id)
            
            if existing_block:
                # Update existing block if changed
                needs_update = (
                    existing_block.start_datetime != event['start_datetime'] or
                    existing_block.end_datetime != event['end_datetime'] or
                    existing_block.reason != event['summary']
                )
                
                if needs_update:
                    existing_block.start_datetime = event['start_datetime']
                    existing_block.end_datetime = event['end_datetime']
                    existing_block.reason = event['summary']
                    existing_block.external_updated_at = event.get('updated')
                    existing_block.save()
                    updated_count += 1
            else:
                # Create new blocked time
                BlockedTime.objects.create(
                    organizer=organizer,
                    start_datetime=event['start_datetime'],
                    end_datetime=event['end_datetime'],
                    reason=event['summary'],
                    source=source_name,
                    external_id=external_id,
                    external_updated_at=event.get('updated'),
                    is_active=True
                )
                created_count += 1
        
        # Remove blocks that no longer exist externally
        blocks_to_remove = existing_blocks.exclude(external_id__in=processed_external_ids)
        removed_count = blocks_to_remove.count()
        blocks_to_remove.delete()
        
        # Detect conflicts with manual blocks
        manual_blocks = BlockedTime.objects.filter(
            organizer=organizer,
            source='manual',
            is_active=True
        )
        
        conflict_analysis = detect_integration_conflicts(
            organizer, external_events, manual_blocks
        )
        
        # Clear availability cache if changes were made
        if created_count > 0 or updated_count > 0 or removed_count > 0:
            from apps.availability.tasks import clear_availability_cache
            clear_availability_cache.delay(
                organizer.id,
                cache_type='calendar_sync',
                provider=integration.provider
            )
        
        log_integration_activity(
            organizer=organizer,
            log_type='calendar_reconciliation',
            integration_type=integration.provider,
            message=f"Reconciled calendar events: {created_count} created, {updated_count} updated, {removed_count} removed",
            success=True,
            details={
                'created_count': created_count,
                'updated_count': updated_count,
                'removed_count': removed_count,
                'conflict_analysis': conflict_analysis
            }
        )
        
        return f"Reconciled {integration.provider} calendar: {created_count} created, {updated_count} updated, {removed_count} removed"
        
    except CalendarIntegration.DoesNotExist:
        return f"Calendar integration {integration_id} not found"
    except Exception as e:
        logger.error(f"Error reconciling calendar events: {str(e)}")
        return f"Error reconciling calendar events: {str(e)}"


@shared_task
def sync_all_calendar_integrations():
    """Sync all active calendar integrations."""
    active_integrations = CalendarIntegration.objects.filter(
        is_active=True,
        sync_enabled=True
    )
    
    # Stagger sync tasks to avoid overwhelming APIs
    for i, integration in enumerate(active_integrations):
        # Add a small delay between each sync to spread the load
        sync_calendar_events.apply_async(
            args=[integration.id],
            countdown=i * 2  # 2 seconds between each sync
        )
    
    return f"Triggered sync for {active_integrations.count()} calendar integrations"


@shared_task
def refresh_expired_tokens():
    """Refresh expired tokens for all integrations."""
    from .utils import refresh_access_token
    
    # Find integrations with expired tokens
    expired_calendar_integrations = CalendarIntegration.objects.filter(
        is_active=True,
        token_expires_at__lte=timezone.now() + timedelta(minutes=10)  # Refresh 10 minutes before expiry
    )
    
    expired_video_integrations = VideoConferenceIntegration.objects.filter(
        is_active=True,
        token_expires_at__lte=timezone.now() + timedelta(minutes=10)
    )
    
    refreshed_count = 0
    failed_count = 0
    
    # Refresh calendar integration tokens
    for integration in expired_calendar_integrations:
        try:
            if refresh_access_token(integration):
                refreshed_count += 1
                logger.info(f"Refreshed token for {integration.provider} calendar integration")
            else:
                failed_count += 1
                integration.is_active = False
                integration.save(update_fields=['is_active'])
                
                # Notify organizer
                notify_integration_disconnected.delay(
                    integration.organizer.id,
                    integration.provider,
                    'calendar'
                )
        except Exception as e:
            logger.error(f"Error refreshing {integration.provider} token: {str(e)}")
            failed_count += 1
    
    # Refresh video integration tokens
    for integration in expired_video_integrations:
        try:
            if refresh_access_token(integration):
                refreshed_count += 1
                logger.info(f"Refreshed token for {integration.provider} video integration")
            else:
                failed_count += 1
                integration.is_active = False
                integration.save(update_fields=['is_active'])
                
                # Notify organizer
                notify_integration_disconnected.delay(
                    integration.organizer.id,
                    integration.provider,
                    'video'
                )
        except Exception as e:
            logger.error(f"Error refreshing {integration.provider} token: {str(e)}")
            failed_count += 1
    
    return f"Token refresh completed: {refreshed_count} successful, {failed_count} failed"


@shared_task
def notify_integration_disconnected(organizer_id, provider, integration_type):
    """Notify organizer that their integration has been disconnected."""
    try:
        from apps.users.models import User
        organizer = User.objects.get(id=organizer_id)
        
        subject = f"Your {provider.title()} {integration_type} integration needs attention"
        message = f"""
        Hi {organizer.first_name},
        
        Your {provider.title()} {integration_type} integration has been disconnected and needs to be reconnected.
        
        This could be due to:
        - Expired authentication tokens
        - Revoked permissions
        - Changes to your {provider.title()} account
        
        To restore functionality, please:
        1. Log into your Calendly Clone dashboard
        2. Go to Integrations settings
        3. Reconnect your {provider.title()} {integration_type}
        
        Until reconnected, your {integration_type} integration will not function properly.
        
        Best regards,
        The Calendly Clone Team
        """
        
        from django.core.mail import send_mail
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [organizer.email],
            fail_silently=False,
        )
        
        return f"Disconnection notification sent to {organizer.email}"
        
    except User.DoesNotExist:
        return f"Organizer {organizer_id} not found"
    except Exception as e:
        return f"Error sending disconnection notification: {str(e)}"


@shared_task
def cleanup_old_integration_logs():
    """Clean up old integration logs to prevent database bloat."""
    cutoff_date = timezone.now() - timedelta(days=90)  # Keep 90 days of logs
    
    old_logs = IntegrationLog.objects.filter(created_at__lt=cutoff_date)
    count = old_logs.count()
    old_logs.delete()
    
    return f"Cleaned up {count} old integration logs"


@shared_task
def update_calendar_event(booking_id):
    """Update calendar event for a rescheduled booking."""
    try:
        from apps.events.models import Booking
        booking = Booking.objects.get(id=booking_id)
        
        if not booking.external_calendar_event_id:
            # No external event to update, create new one
            return create_calendar_event(booking_id)
        
        # Get calendar integrations for the organizer
        calendar_integrations = CalendarIntegration.objects.filter(
            organizer=booking.organizer,
            is_active=True,
            sync_enabled=True
        )
        
        for integration in calendar_integrations:
            try:
                if integration.provider == 'google':
                    client = GoogleCalendarClient(integration)
                    client.update_event(booking)
                elif integration.provider == 'outlook':
                    client = OutlookCalendarClient(integration)
                    client.update_event(booking)
                else:
                    logger.warning(f"Calendar provider {integration.provider} not implemented")
                    continue
                
                break  # Successfully updated
                
            except Exception as e:
                logger.error(f"Error updating calendar event with {integration.provider}: {str(e)}")
                integration.mark_sync_error()
                continue
        
        return f"Calendar event updated for booking {booking_id}"
    
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        return f"Error updating calendar event: {str(e)}"

