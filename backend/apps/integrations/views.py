from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import CalendarIntegration, VideoConferenceIntegration, WebhookIntegration, IntegrationLog
from .serializers import (
    CalendarIntegrationSerializer, VideoConferenceIntegrationSerializer,
    WebhookIntegrationSerializer, IntegrationLogSerializer,
    OAuthInitiateSerializer, OAuthCallbackSerializer
)


class CalendarIntegrationListView(generics.ListAPIView):
    serializer_class = CalendarIntegrationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return CalendarIntegration.objects.filter(organizer=self.request.user)


class CalendarIntegrationDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CalendarIntegrationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return CalendarIntegration.objects.filter(organizer=self.request.user)


class VideoConferenceIntegrationListView(generics.ListAPIView):
    serializer_class = VideoConferenceIntegrationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return VideoConferenceIntegration.objects.filter(organizer=self.request.user)


class VideoConferenceIntegrationDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = VideoConferenceIntegrationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return VideoConferenceIntegration.objects.filter(organizer=self.request.user)


class WebhookIntegrationListCreateView(generics.ListCreateAPIView):
    serializer_class = WebhookIntegrationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return WebhookIntegration.objects.filter(organizer=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(organizer=self.request.user)


class WebhookIntegrationDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebhookIntegrationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return WebhookIntegration.objects.filter(organizer=self.request.user)


class IntegrationLogListView(generics.ListAPIView):
    serializer_class = IntegrationLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return IntegrationLog.objects.filter(organizer=self.request.user)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def initiate_oauth(request):
    """Initiate OAuth flow for calendar or video integrations."""
    serializer = OAuthInitiateSerializer(data=request.data)
    
    if serializer.is_valid():
        provider = serializer.validated_data['provider']
        integration_type = serializer.validated_data['integration_type']
        redirect_uri = serializer.validated_data['redirect_uri']
        
        from .utils import get_provider_scopes
        import urllib.parse
        import secrets
        
        # Generate state parameter for security
        state = secrets.token_urlsafe(32)
        request.session[f'oauth_state_{provider}_{integration_type}'] = state
        request.session[f'oauth_redirect_{provider}_{integration_type}'] = redirect_uri
        
        # Get required scopes
        scopes = get_provider_scopes(provider, integration_type)
        
        # Build authorization URL
        if provider == 'google':
            auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
                'client_id': settings.GOOGLE_OAUTH_CLIENT_ID,
                'redirect_uri': settings.GOOGLE_OAUTH_REDIRECT_URI,
                'scope': ' '.join(scopes),
                'response_type': 'code',
                'access_type': 'offline',
                'prompt': 'consent',
                'state': f"{provider}:{integration_type}:{state}"
            })
        elif provider == 'outlook':
            auth_url = f"https://login.microsoftonline.com/{settings.MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize?" + urllib.parse.urlencode({
                'client_id': settings.MICROSOFT_CLIENT_ID,
                'redirect_uri': settings.MICROSOFT_REDIRECT_URI,
                'scope': ' '.join(scopes),
                'response_type': 'code',
                'state': f"{provider}:{integration_type}:{state}"
            })
        elif provider == 'zoom':
            auth_url = "https://zoom.us/oauth/authorize?" + urllib.parse.urlencode({
                'client_id': settings.ZOOM_CLIENT_ID,
                'redirect_uri': settings.ZOOM_REDIRECT_URI,
                'response_type': 'code',
                'state': f"{provider}:{integration_type}:{state}"
            })
        else:
            return Response(
                {'error': f'Provider {provider} not supported'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return Response({
            'authorization_url': auth_url,
            'provider': provider,
            'integration_type': integration_type,
            'state': state
        })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def oauth_callback(request):
    """Handle OAuth callback and store tokens."""
    serializer = OAuthCallbackSerializer(data=request.data)
    
    if serializer.is_valid():
        provider = serializer.validated_data['provider']
        integration_type = serializer.validated_data['integration_type']
        code = serializer.validated_data['code']
        state = serializer.validated_data.get('state', '')
        
        # Verify state parameter
        expected_state = request.session.get(f'oauth_state_{provider}_{integration_type}')
        if not expected_state or not state.endswith(expected_state):
            return Response(
                {'error': 'Invalid state parameter'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Exchange code for tokens
            token_data = exchange_oauth_code(provider, code)
            
            # Get user info from provider
            user_info = get_provider_user_info(provider, token_data['access_token'])
            
            # Create or update integration
            if integration_type == 'calendar':
                integration, created = CalendarIntegration.objects.update_or_create(
                    organizer=request.user,
                    provider=provider,
                    defaults={
                        'access_token': token_data['access_token'],
                        'refresh_token': token_data.get('refresh_token', ''),
                        'token_expires_at': timezone.now() + timedelta(seconds=token_data.get('expires_in', 3600)),
                        'provider_user_id': user_info.get('id', ''),
                        'provider_email': user_info.get('email', ''),
                        'calendar_id': user_info.get('calendar_id', ''),
                        'is_active': True,
                        'sync_enabled': True,
                        'sync_errors': 0
                    }
                )
            else:  # video
                integration, created = VideoConferenceIntegration.objects.update_or_create(
                    organizer=request.user,
                    provider=provider,
                    defaults={
                        'access_token': token_data['access_token'],
                        'refresh_token': token_data.get('refresh_token', ''),
                        'token_expires_at': timezone.now() + timedelta(seconds=token_data.get('expires_in', 3600)),
                        'provider_user_id': user_info.get('id', ''),
                        'provider_email': user_info.get('email', ''),
                        'is_active': True,
                        'auto_generate_links': True
                    }
                )
            
            # Trigger initial sync for calendar integrations
            if integration_type == 'calendar':
                from .tasks import sync_calendar_events
                sync_calendar_events.delay(integration.id)
            
            # Clean up session
            request.session.pop(f'oauth_state_{provider}_{integration_type}', None)
            request.session.pop(f'oauth_redirect_{provider}_{integration_type}', None)
            
            action = "connected" if created else "reconnected"
            
            return Response({
                'message': f'{provider.title()} {integration_type} integration {action} successfully',
                'provider': provider,
                'integration_type': integration_type,
                'provider_email': user_info.get('email', ''),
                'created': created
            })
            
        except Exception as e:
            logger.error(f"OAuth callback error for {provider}: {str(e)}")
            return Response(
                {'error': f'Failed to complete {provider} integration: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        return Response({
            'message': f'{provider.title()} {integration_type} integration completed successfully',
            'provider': provider,
            'integration_type': integration_type
        })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def exchange_oauth_code(provider, code):
    """
    Exchange OAuth authorization code for access tokens.
    
    Args:
        provider: Provider name (google, outlook, zoom)
        code: Authorization code from OAuth callback
    
    Returns:
        dict: Token data
    """
    if provider == 'google':
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            'client_id': settings.GOOGLE_OAUTH_CLIENT_ID,
            'client_secret': settings.GOOGLE_OAUTH_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': settings.GOOGLE_OAUTH_REDIRECT_URI
        }
    elif provider == 'outlook':
        token_url = f"https://login.microsoftonline.com/{settings.MICROSOFT_TENANT_ID}/oauth2/v2.0/token"
        data = {
            'client_id': settings.MICROSOFT_CLIENT_ID,
            'client_secret': settings.MICROSOFT_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': settings.MICROSOFT_REDIRECT_URI
        }
    elif provider == 'zoom':
        token_url = "https://zoom.us/oauth/token"
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': settings.ZOOM_REDIRECT_URI
        }
        # Zoom uses Basic Auth
        auth = (settings.ZOOM_CLIENT_ID, settings.ZOOM_CLIENT_SECRET)
        response = requests.post(token_url, data=data, auth=auth, timeout=30)
    else:
        raise ValueError(f"Unsupported provider: {provider}")
    
    if provider != 'zoom':
        response = requests.post(token_url, data=data, timeout=30)
    
    if response.status_code != 200:
        raise Exception(f"Token exchange failed: {response.text}")
    
    return response.json()


def get_provider_user_info(provider, access_token):
    """
    Get user information from OAuth provider.
    
    Args:
        provider: Provider name
        access_token: Access token
    
    Returns:
        dict: User information
    """
    headers = {'Authorization': f'Bearer {access_token}'}
    
    if provider == 'google':
        response = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', headers=headers, timeout=30)
    elif provider == 'outlook':
        response = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers, timeout=30)
    elif provider == 'zoom':
        response = requests.get('https://api.zoom.us/v2/users/me', headers=headers, timeout=30)
    else:
        raise ValueError(f"Unsupported provider: {provider}")
    
    if response.status_code != 200:
        raise Exception(f"Failed to get user info: {response.text}")
    
    return response.json()


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def integration_health(request):
    """Get health status of all integrations for the organizer."""
    from .utils import create_integration_health_report
    
    health_report = create_integration_health_report(request.user)
    
    return Response(health_report)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def force_calendar_sync(request, pk):
    """Force immediate calendar sync for a specific integration."""
    integration = get_object_or_404(CalendarIntegration, pk=pk, organizer=request.user)
    
    if not integration.is_active:
        return Response(
            {'error': 'Integration is not active'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Trigger immediate sync
    from .tasks import sync_calendar_events
    sync_calendar_events.delay(integration.id)
    
    return Response({'message': 'Calendar sync initiated'})


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def calendar_conflicts(request):
    """Get calendar conflicts for the organizer."""
    from apps.availability.models import BlockedTime
    from .utils import detect_integration_conflicts
    
    # Get manual blocks
    manual_blocks = BlockedTime.objects.filter(
        organizer=request.user,
        source='manual',
        is_active=True,
        start_datetime__gte=timezone.now()
    )
    
    # Get synced blocks
    synced_blocks = BlockedTime.objects.filter(
        organizer=request.user,
        source__endswith='_calendar',
        is_active=True,
        start_datetime__gte=timezone.now()
    )
    
    # Convert synced blocks to external event format for conflict detection
    external_events = []
    for block in synced_blocks:
        external_events.append({
            'external_id': block.external_id,
            'summary': block.reason,
            'start_datetime': block.start_datetime,
            'end_datetime': block.end_datetime,
            'updated': block.external_updated_at or block.updated_at
        })
    
    conflicts = detect_integration_conflicts(request.user, external_events, manual_blocks)
    
    return Response({
        'conflicts': conflicts,
        'manual_blocks_count': manual_blocks.count(),
        'synced_blocks_count': synced_blocks.count()
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def test_webhook(request, pk):
    """Test a webhook integration."""
    webhook = get_object_or_404(WebhookIntegration, pk=pk, organizer=request.user)
    
    # Trigger test webhook
    from .tasks import send_webhook
    send_webhook.delay(
        webhook_id=webhook.id,
        event_type='test',
        data={'message': 'This is a test webhook'}
    )
    
    return Response({'message': 'Test webhook triggered'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def refresh_calendar_sync(request, pk):
    """Manually refresh calendar sync for a specific integration."""
    integration = get_object_or_404(CalendarIntegration, pk=pk, organizer=request.user)
    
    # Trigger calendar sync
    from .tasks import sync_calendar_events
    sync_calendar_events.delay(integration.id)
    
    return Response({'message': 'Calendar sync initiated'})