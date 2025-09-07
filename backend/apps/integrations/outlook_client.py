"""
Microsoft Outlook Calendar integration client.
"""
import logging
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
import requests
from .utils import make_api_request, ensure_valid_token, log_integration_activity, parse_outlook_calendar_event

logger = logging.getLogger(__name__)


class OutlookCalendarClient:
    """Client for Microsoft Graph Calendar API operations."""
    
    def __init__(self, integration):
        """
        Initialize Outlook Calendar client.
        
        Args:
            integration: CalendarIntegration instance
        """
        self.integration = integration
        self.organizer = integration.organizer
        self.base_url = "https://graph.microsoft.com/v1.0"
    
    def _get_headers(self):
        """Get authenticated headers for Microsoft Graph API."""
        if not ensure_valid_token(self.integration):
            raise Exception("Unable to refresh Outlook token")
        
        return {
            'Authorization': f'Bearer {self.integration.access_token}',
            'Content-Type': 'application/json'
        }
    
    def get_busy_times(self, start_date, end_date):
        """
        Get busy times from Outlook Calendar.
        
        Args:
            start_date: Start date for sync
            end_date: End date for sync
        
        Returns:
            list: List of parsed events
        """
        try:
            headers = self._get_headers()
            
            # Convert dates to ISO format
            start_time = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=timezone.utc).isoformat()
            end_time = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=timezone.utc).isoformat()
            
            # Use calendar view for better performance with large date ranges
            url = f"{self.base_url}/me/calendarView"
            params = {
                'startDateTime': start_time,
                'endDateTime': end_time,
                '$select': 'id,subject,start,end,lastModifiedDateTime,isCancelled,showAs,isAllDay',
                '$orderby': 'start/dateTime',
                '$top': 999  # Maximum allowed
            }
            
            events = []
            
            while url:
                response = make_api_request(
                    'GET', url, headers=headers, params=params,
                    provider='outlook', organizer_id=self.organizer.id
                )
                
                data = response.json()
                batch_events = data.get('value', [])
                
                # Parse and filter events
                for event in batch_events:
                    # Skip cancelled events
                    if event.get('isCancelled', False):
                        continue
                    
                    # Skip free time events
                    if event.get('showAs') == 'free':
                        continue
                    
                    try:
                        parsed_event = parse_outlook_calendar_event(event)
                        events.append(parsed_event)
                    except Exception as e:
                        logger.warning(f"Error parsing Outlook event {event.get('id')}: {str(e)}")
                        continue
                
                # Check for next page
                url = data.get('@odata.nextLink')
                params = None  # Next link includes all parameters
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_sync',
                integration_type='outlook',
                message=f"Successfully fetched {len(events)} events from Outlook Calendar",
                success=True,
                details={'event_count': len(events), 'date_range': f"{start_date} to {end_date}"}
            )
            
            return events
            
        except Exception as e:
            logger.error(f"Error fetching Outlook Calendar events: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_sync',
                integration_type='outlook',
                message=f"Failed to fetch events: {str(e)}",
                success=False,
                details={'error': str(e)}
            )
            raise
    
    def create_event(self, booking):
        """
        Create an event in Outlook Calendar.
        
        Args:
            booking: Booking instance
        
        Returns:
            str: External event ID
        """
        try:
            headers = self._get_headers()
            
            # Prepare event data
            event_data = {
                'subject': f"{booking.event_type.name} with {booking.invitee_name}",
                'body': {
                    'contentType': 'text',
                    'content': f"Booking created via Calendly Clone\n\nInvitee: {booking.invitee_name} ({booking.invitee_email})\nEvent Type: {booking.event_type.name}"
                },
                'start': {
                    'dateTime': booking.start_time.isoformat(),
                    'timeZone': self.organizer.profile.timezone_name
                },
                'end': {
                    'dateTime': booking.end_time.isoformat(),
                    'timeZone': self.organizer.profile.timezone_name
                },
                'attendees': [
                    {
                        'emailAddress': {
                            'address': booking.invitee_email,
                            'name': booking.invitee_name
                        },
                        'type': 'required'
                    }
                ],
                'reminderMinutesBeforeStart': 15
            }
            
            # Add meeting link if available
            if booking.meeting_link:
                event_data['body']['content'] += f"\n\nMeeting Link: {booking.meeting_link}"
                event_data['onlineMeeting'] = {
                    'joinUrl': booking.meeting_link
                }
            
            # Create the event
            url = f"{self.base_url}/me/events"
            response = make_api_request(
                'POST', url, headers=headers, json_data=event_data,
                provider='outlook', organizer_id=self.organizer.id
            )
            
            created_event = response.json()
            external_event_id = created_event['id']
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_created',
                integration_type='outlook',
                message=f"Created Outlook Calendar event for booking {booking.id}",
                success=True,
                booking=booking,
                details={'external_event_id': external_event_id}
            )
            
            return external_event_id
            
        except Exception as e:
            logger.error(f"Error creating Outlook Calendar event: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_created',
                integration_type='outlook',
                message=f"Failed to create event: {str(e)}",
                success=False,
                booking=booking,
                details={'error': str(e)}
            )
            raise
    
    def update_event(self, booking):
        """
        Update an event in Outlook Calendar.
        
        Args:
            booking: Booking instance with external_calendar_event_id
        
        Returns:
            bool: True if successful
        """
        if not booking.external_calendar_event_id:
            raise ValueError("No external calendar event ID found")
        
        try:
            headers = self._get_headers()
            
            # Prepare update data
            update_data = {
                'subject': f"{booking.event_type.name} with {booking.invitee_name}",
                'start': {
                    'dateTime': booking.start_time.isoformat(),
                    'timeZone': self.organizer.profile.timezone_name
                },
                'end': {
                    'dateTime': booking.end_time.isoformat(),
                    'timeZone': self.organizer.profile.timezone_name
                }
            }
            
            # Update the event
            url = f"{self.base_url}/me/events/{booking.external_calendar_event_id}"
            make_api_request(
                'PATCH', url, headers=headers, json_data=update_data,
                provider='outlook', organizer_id=self.organizer.id
            )
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_updated',
                integration_type='outlook',
                message=f"Updated Outlook Calendar event for booking {booking.id}",
                success=True,
                booking=booking
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating Outlook Calendar event: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_updated',
                integration_type='outlook',
                message=f"Failed to update event: {str(e)}",
                success=False,
                booking=booking,
                details={'error': str(e)}
            )
            return False
    
    def delete_event(self, booking):
        """
        Delete an event from Outlook Calendar.
        
        Args:
            booking: Booking instance with external_calendar_event_id
        
        Returns:
            bool: True if successful
        """
        if not booking.external_calendar_event_id:
            return True  # Nothing to delete
        
        try:
            headers = self._get_headers()
            
            url = f"{self.base_url}/me/events/{booking.external_calendar_event_id}"
            make_api_request(
                'DELETE', url, headers=headers,
                provider='outlook', organizer_id=self.organizer.id
            )
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_deleted',
                integration_type='outlook',
                message=f"Deleted Outlook Calendar event for booking {booking.id}",
                success=True,
                booking=booking
            )
            
            return True
            
        except Exception as e:
            # If event doesn't exist, consider it successful
            if '404' in str(e) or 'not found' in str(e).lower():
                logger.info(f"Outlook Calendar event already deleted for booking {booking.id}")
                return True
            
            logger.error(f"Error deleting Outlook Calendar event: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='calendar_event_deleted',
                integration_type='outlook',
                message=f"Failed to delete event: {str(e)}",
                success=False,
                booking=booking,
                details={'error': str(e)}
            )
            return False