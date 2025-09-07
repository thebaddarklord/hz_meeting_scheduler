"""
Zoom integration client for video conferencing.
"""
import logging
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
import requests
from .utils import make_api_request, ensure_valid_token, log_integration_activity

logger = logging.getLogger(__name__)


class ZoomClient:
    """Client for Zoom API operations."""
    
    def __init__(self, integration):
        """
        Initialize Zoom client.
        
        Args:
            integration: VideoConferenceIntegration instance
        """
        self.integration = integration
        self.organizer = integration.organizer
        self.base_url = "https://api.zoom.us/v2"
    
    def _get_headers(self):
        """Get authenticated headers for Zoom API."""
        if not ensure_valid_token(self.integration):
            raise Exception("Unable to refresh Zoom token")
        
        return {
            'Authorization': f'Bearer {self.integration.access_token}',
            'Content-Type': 'application/json'
        }
    
    def create_meeting(self, booking):
        """
        Create a Zoom meeting.
        
        Args:
            booking: Booking instance
        
        Returns:
            dict: Meeting details (link, id, password, etc.)
        """
        try:
            # Check rate limits
            if not self.integration.can_make_api_call():
                raise Exception("Daily API rate limit exceeded for Zoom")
            
            headers = self._get_headers()
            
            # Prepare meeting data
            meeting_data = {
                'topic': f"{booking.event_type.name} with {booking.invitee_name}",
                'type': 2,  # Scheduled meeting
                'start_time': booking.start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'duration': booking.event_type.duration,
                'timezone': self.organizer.profile.timezone_name,
                'agenda': f"Meeting with {booking.invitee_name} ({booking.invitee_email})",
                'settings': {
                    'host_video': True,
                    'participant_video': True,
                    'join_before_host': False,
                    'mute_upon_entry': True,
                    'watermark': False,
                    'use_pmi': False,
                    'approval_type': 0,  # Automatically approve
                    'audio': 'both',
                    'auto_recording': 'none',
                    'waiting_room': True
                }
            }
            
            # Create the meeting
            url = f"{self.base_url}/users/me/meetings"
            response = make_api_request(
                'POST', url, headers=headers, json_data=meeting_data,
                provider='zoom', organizer_id=self.organizer.id
            )
            
            # Record API call
            self.integration.record_api_call()
            
            meeting_response = response.json()
            
            meeting_details = {
                'meeting_link': meeting_response['join_url'],
                'meeting_id': str(meeting_response['id']),
                'meeting_password': meeting_response.get('password', ''),
                'host_link': meeting_response.get('start_url', ''),
                'external_meeting_id': str(meeting_response['id'])
            }
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='video_link_created',
                integration_type='zoom',
                message=f"Created Zoom meeting for booking {booking.id}",
                success=True,
                booking=booking,
                details=meeting_details
            )
            
            return meeting_details
            
        except Exception as e:
            logger.error(f"Error creating Zoom meeting: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='video_link_created',
                integration_type='zoom',
                message=f"Failed to create Zoom meeting: {str(e)}",
                success=False,
                booking=booking,
                details={'error': str(e)}
            )
            raise
    
    def update_meeting(self, booking, external_meeting_id):
        """
        Update a Zoom meeting.
        
        Args:
            booking: Booking instance
            external_meeting_id: Zoom meeting ID
        
        Returns:
            bool: True if successful
        """
        try:
            headers = self._get_headers()
            
            # Prepare update data
            update_data = {
                'topic': f"{booking.event_type.name} with {booking.invitee_name}",
                'start_time': booking.start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'duration': booking.event_type.duration,
                'timezone': self.organizer.profile.timezone_name
            }
            
            # Update the meeting
            url = f"{self.base_url}/meetings/{external_meeting_id}"
            make_api_request(
                'PATCH', url, headers=headers, json_data=update_data,
                provider='zoom', organizer_id=self.organizer.id
            )
            
            self.integration.record_api_call()
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='video_meeting_updated',
                integration_type='zoom',
                message=f"Updated Zoom meeting for booking {booking.id}",
                success=True,
                booking=booking
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating Zoom meeting: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='video_meeting_updated',
                integration_type='zoom',
                message=f"Failed to update Zoom meeting: {str(e)}",
                success=False,
                booking=booking,
                details={'error': str(e)}
            )
            return False
    
    def delete_meeting(self, external_meeting_id):
        """
        Delete a Zoom meeting.
        
        Args:
            external_meeting_id: Zoom meeting ID
        
        Returns:
            bool: True if successful
        """
        try:
            headers = self._get_headers()
            
            url = f"{self.base_url}/meetings/{external_meeting_id}"
            make_api_request(
                'DELETE', url, headers=headers,
                provider='zoom', organizer_id=self.organizer.id
            )
            
            self.integration.record_api_call()
            
            log_integration_activity(
                organizer=self.organizer,
                log_type='video_meeting_deleted',
                integration_type='zoom',
                message=f"Deleted Zoom meeting {external_meeting_id}",
                success=True,
                details={'external_meeting_id': external_meeting_id}
            )
            
            return True
            
        except Exception as e:
            # If meeting doesn't exist, consider it successful
            if '404' in str(e) or 'not found' in str(e).lower():
                logger.info(f"Zoom meeting {external_meeting_id} already deleted")
                return True
            
            logger.error(f"Error deleting Zoom meeting: {str(e)}")
            log_integration_activity(
                organizer=self.organizer,
                log_type='video_meeting_deleted',
                integration_type='zoom',
                message=f"Failed to delete Zoom meeting: {str(e)}",
                success=False,
                details={'error': str(e), 'external_meeting_id': external_meeting_id}
            )
            return False