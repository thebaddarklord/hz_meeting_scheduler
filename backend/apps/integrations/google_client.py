"""
Google Calendar and Google Meet integration client.
"""
import logging
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from .utils import make_api_request, ensure_valid_token, log_integration_activity, parse_google_calendar_event
from .models import IntegrationLog

logger = logging.getLogger(__name__)


class GoogleCalendarClient:
    """Client for Google Calendar API operations."""
    
    def __init__(self, integration):
        """
        Initialize Google Calendar client.
        
        Args:
            integration: CalendarIntegration instance
        """
        self.integration = integration
        self.organizer = integration.organizer
        
    def _get_service(self):
        """Get authenticated Google Calendar service."""
        if not ensure_valid_token(self.integration):
            raise Exception("Unable to refresh Google Calendar token")
        
        credentials = Credentials(
            token=self.integration.access_token,
            refresh_token=self.integration.refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=settings.GOOGLE_OAUTH_CLIENT_ID,
            client_secret=settings.GOOGLE_OAUTH_CLIENT_SECRET
        )
        
        return build('calendar', 'v3', credentials=credentials)
    
    def get_busy_times(self, start_date, end_date):
        """
        Get busy times from Google Calendar.
        
        Args:
            start_date: Start date for sync
            end_date: End date for sync
        
        Returns:
            list: List of parsed events
        """
        try:
            service = self._get_service()
            
            # Convert dates to RFC3339 format
            time_min = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=timezone.utc).isoformat()
            time_max = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=timezone.utc).isoformat()
            
            # Get calendar ID (primary by default)
            calendar_id = self.integration.calendar_id or 'primary'
            
            # Fetch events with pagination
            events = []
            page_token = None
            
            while True:
                events_result = service.events().list(
                    calendarId=calendar_id,
                    timeMin=time_min,
                    timeMax=time_max,
                    singleEvents=True,  # Expand recurring events
                    orderBy='startTime',
                    maxResults=250,  # Maximum allowed by Google
                    pageToken=page_token
                ).execute()
                
                batch_events = events_result.get('items', [])
                
                # Parse and filter events
                for event in batch_events:
                    # Skip events that don't block time
                    if event.get('transparency') == 'transparent':
                        continue
                    
                    # Skip cancelled events
                    if event.get('status') == 'cancelled':
                        continue
                    
                    # Skip events without start/end times
                    if 'start' not in event or 'end' not in event:
                        continue
                    
                    try:
                        parsed_event = parse_google_calendar_event(event)
                        events.append(parsed_event)
                    except Exception as e:
                        logger.warning(f"Error parsing Google Calendar event {event.get('id')}: {str(e)}")
                        continue
                
                # Check for next page
                page_token = events_result.get('nextPageToken')
                if not page_token:
                    break
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_sync',
                integration_type='google',
                message=f"Successfully fetched {len(events)} events from Google Calendar",
                success=True,
                details={'event_count': len(events), 'date_range': f"{start_date} to {end_date}"}
            )
            
            return events
            
        except Exception as e:
            logger.error(f"Error fetching Google Calendar events: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_sync',
                integration_type='google',
                message=f"Failed to fetch events: {str(e)}",
                success=False,
                details={'error': str(e)}
            )
            raise
    
    def create_event(self, booking):
        """
        Create an event in Google Calendar.
        
        Args:
            booking: Booking instance
        
        Returns:
            str: External event ID
        """
        try:
            service = self._get_service()
            
            # Prepare event data
            event_data = {
                'summary': f"{booking.event_type.name} with {booking.invitee_name}",
                'description': f"Booking created via Calendly Clone\n\nInvitee: {booking.invitee_name} ({booking.invitee_email})\nEvent Type: {booking.event_type.name}",
                'start': {
                    'dateTime': booking.start_time.isoformat(),
                    'timeZone': self.organizer.profile.timezone_name,
                },
                'end': {
                    'dateTime': booking.end_time.isoformat(),
                    'timeZone': self.organizer.profile.timezone_name,
                },
                'attendees': [
                    {'email': self.organizer.email, 'responseStatus': 'accepted'},
                    {'email': booking.invitee_email, 'responseStatus': 'needsAction'},
                ],
                'reminders': {
                    'useDefault': True
                },
                'source': {
                    'title': 'Calendly Clone',
                    'url': f"https://your-domain.com/bookings/{booking.id}"
                }
            }
            
            # Add meeting link if available
            if booking.meeting_link:
                event_data['description'] += f"\n\nMeeting Link: {booking.meeting_link}"
                event_data['conferenceData'] = {
                    'entryPoints': [{
                        'entryPointType': 'video',
                        'uri': booking.meeting_link
                    }]
                }
            
            # Create the event
            calendar_id = self.integration.calendar_id or 'primary'
            created_event = service.events().insert(
                calendarId=calendar_id,
                body=event_data,
                conferenceDataVersion=1 if booking.meeting_link else 0
            ).execute()
            
            external_event_id = created_event['id']
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_created',
                integration_type='google',
                message=f"Created Google Calendar event for booking {booking.id}",
                success=True,
                booking=booking,
                details={'external_event_id': external_event_id}
            )
            
            return external_event_id
            
        except Exception as e:
            logger.error(f"Error creating Google Calendar event: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_created',
                integration_type='google',
                message=f"Failed to create event: {str(e)}",
                success=False,
                booking=booking,
                details={'error': str(e)}
            )
            raise
    
    def update_event(self, booking):
        """
        Update an event in Google Calendar.
        
        Args:
            booking: Booking instance with external_calendar_event_id
        
        Returns:
            bool: True if successful
        """
        if not booking.external_calendar_event_id:
            raise ValueError("No external calendar event ID found")
        
        try:
            service = self._get_service()
            calendar_id = self.integration.calendar_id or 'primary'
            
            # Get existing event
            existing_event = service.events().get(
                calendarId=calendar_id,
                eventId=booking.external_calendar_event_id
            ).execute()
            
            # Update event data
            existing_event.update({
                'summary': f"{booking.event_type.name} with {booking.invitee_name}",
                'start': {
                    'dateTime': booking.start_time.isoformat(),
                    'timeZone': self.organizer.profile.timezone_name,
                },
                'end': {
                    'dateTime': booking.end_time.isoformat(),
                    'timeZone': self.organizer.profile.timezone_name,
                },
            })
            
            # Update the event
            service.events().update(
                calendarId=calendar_id,
                eventId=booking.external_calendar_event_id,
                body=existing_event
            ).execute()
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_updated',
                integration_type='google',
                message=f"Updated Google Calendar event for booking {booking.id}",
                success=True,
                booking=booking
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating Google Calendar event: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_updated',
                integration_type='google',
                message=f"Failed to update event: {str(e)}",
                success=False,
                booking=booking,
                details={'error': str(e)}
            )
            return False
    
    def delete_event(self, booking):
        """
        Delete an event from Google Calendar.
        
        Args:
            booking: Booking instance with external_calendar_event_id
        
        Returns:
            bool: True if successful
        """
        if not booking.external_calendar_event_id:
            return True  # Nothing to delete
        
        try:
            service = self._get_service()
            calendar_id = self.integration.calendar_id or 'primary'
            
            service.events().delete(
                calendarId=calendar_id,
                eventId=booking.external_calendar_event_id
            ).execute()
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_deleted',
                integration_type='google',
                message=f"Deleted Google Calendar event for booking {booking.id}",
                success=True,
                booking=booking
            )
            
            return True
            
        except Exception as e:
            # If event doesn't exist, consider it successful
            if '404' in str(e) or 'not found' in str(e).lower():
                logger.info(f"Google Calendar event already deleted for booking {booking.id}")
                return True
            
            logger.error(f"Error deleting Google Calendar event: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_deleted',
                integration_type='google',
                message=f"Failed to delete event: {str(e)}",
                success=False,
                booking=booking,
                details={'error': str(e)}
            )
            return False


class GoogleMeetClient:
    """Client for Google Meet integration via Calendar API."""
    
    def __init__(self, integration):
        """
        Initialize Google Meet client.
        
        Args:
            integration: VideoConferenceIntegration instance
        """
        self.integration = integration
        self.organizer = integration.organizer
    
    def create_meeting(self, booking):
        """
        Create a Google Meet meeting by creating a calendar event.
        
        Args:
            booking: Booking instance
        
        Returns:
            dict: Meeting details (link, id, etc.)
        """
        try:
            if not ensure_valid_token(self.integration):
                raise Exception("Unable to refresh Google Meet token")
            
            credentials = Credentials(
                token=self.integration.access_token,
                refresh_token=self.integration.refresh_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=settings.GOOGLE_OAUTH_CLIENT_ID,
                client_secret=settings.GOOGLE_OAUTH_CLIENT_SECRET
            )
            
            service = build('calendar', 'v3', credentials=credentials)
            
            # Create event with Google Meet
            event_data = {
                'summary': f"{booking.event_type.name} with {booking.invitee_name}",
                'start': {
                    'dateTime': booking.start_time.isoformat(),
                    'timeZone': self.organizer.profile.timezone_name,
                },
                'end': {
                    'dateTime': booking.end_time.isoformat(),
                    'timeZone': self.organizer.profile.timezone_name,
                },
                'conferenceData': {
                    'createRequest': {
                        'requestId': f"meet-{booking.id}",
                        'conferenceSolutionKey': {
                            'type': 'hangoutsMeet'
                        }
                    }
                },
                'attendees': [
                    {'email': booking.invitee_email}
                ]
            }
            
            # Record API call for rate limiting
            self.integration.record_api_call()
            
            created_event = service.events().insert(
                calendarId='primary',
                body=event_data,
                conferenceDataVersion=1
            ).execute()
            
            # Extract meeting details
            conference_data = created_event.get('conferenceData', {})
            entry_points = conference_data.get('entryPoints', [])
            
            meeting_link = None
            for entry_point in entry_points:
                if entry_point.get('entryPointType') == 'video':
                    meeting_link = entry_point.get('uri')
                    break
            
            if not meeting_link:
                meeting_link = created_event.get('hangoutLink')
            
            meeting_details = {
                'meeting_link': meeting_link,
                'meeting_id': conference_data.get('conferenceId', ''),
                'external_event_id': created_event['id']
            }
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='video_link_created',
                integration_type='google_meet',
                message=f"Created Google Meet link for booking {booking.id}",
                success=True,
                booking=booking,
                details=meeting_details
            )
            
            return meeting_details
            
        except Exception as e:
            logger.error(f"Error creating Google Meet: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='video_link_created',
                integration_type='google_meet',
                message=f"Failed to create Google Meet: {str(e)}",
                success=False,
                booking=booking,
                details={'error': str(e)}
            )
            raise