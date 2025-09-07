from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.shortcuts import get_object_or_404
from django.utils import timezone
from .models import NotificationTemplate, NotificationLog, NotificationPreference, NotificationSchedule
from .serializers import (
    NotificationTemplateSerializer, NotificationLogSerializer,
    NotificationPreferenceSerializer, NotificationScheduleSerializer,
    SendNotificationSerializer, NotificationStatsSerializer
)
import logging

logger = logging.getLogger(__name__)


class NotificationTemplateListCreateView(generics.ListCreateAPIView):
    serializer_class = NotificationTemplateSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return NotificationTemplate.objects.filter(organizer=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(organizer=self.request.user)


class NotificationTemplateDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = NotificationTemplateSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return NotificationTemplate.objects.filter(organizer=self.request.user)


class NotificationLogListView(generics.ListAPIView):
    serializer_class = NotificationLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return NotificationLog.objects.filter(organizer=self.request.user)


class NotificationPreferenceView(generics.RetrieveUpdateAPIView):
    serializer_class = NotificationPreferenceSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        preference, created = NotificationPreference.objects.get_or_create(
            organizer=self.request.user
        )
        return preference


class NotificationScheduleListView(generics.ListAPIView):
    serializer_class = NotificationScheduleSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return NotificationSchedule.objects.filter(organizer=self.request.user)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def send_notification(request):
    """Manually send a notification."""
    serializer = SendNotificationSerializer(data=request.data)
    
    if serializer.is_valid():
        notification_type = serializer.validated_data['notification_type']
        template_id = serializer.validated_data.get('template_id')
        recipient_email = serializer.validated_data.get('recipient_email')
        recipient_phone = serializer.validated_data.get('recipient_phone')
        subject = serializer.validated_data.get('subject', '')
        message = serializer.validated_data['message']
        booking_id = serializer.validated_data.get('booking_id')
        
        # Get template if provided
        template = None
        if template_id:
            try:
                template = NotificationTemplate.objects.get(
                    id=template_id,
                    organizer=request.user
                )
                if not subject:
                    subject = template.subject
                if not message:
                    message = template.message
            except NotificationTemplate.DoesNotExist:
                return Response(
                    {'error': 'Template not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        # Get booking if provided
        booking = None
        if booking_id:
            from apps.events.models import Booking
            try:
                booking = Booking.objects.get(
                    id=booking_id,
                    organizer=request.user
                )
            except Booking.DoesNotExist:
                return Response(
                    {'error': 'Booking not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        # Create notification log
        notification_log = NotificationLog.objects.create(
            organizer=request.user,
            booking=booking,
            template=template,
            notification_type=notification_type,
            recipient_email=recipient_email or '',
            recipient_phone=recipient_phone or '',
            subject=subject,
            message=message,
            status='pending'
        )
        
        # Send notification asynchronously
        from .tasks import send_notification_task
        send_notification_task.delay(notification_log.id)
        
        return Response({
            'message': 'Notification queued for sending',
            'notification_id': notification_log.id
        })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def test_template(request, pk):
    """Test a notification template."""
    template = get_object_or_404(NotificationTemplate, pk=pk, organizer=request.user)
    
    # Send test notification
    from .tasks import send_test_notification
    send_test_notification.delay(template.id, request.user.email)
    
    return Response({'message': 'Test notification sent'})


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def notification_stats(request):
    """Get comprehensive notification statistics for the organizer."""
    logs = NotificationLog.objects.filter(organizer=request.user)
    
    # Basic counts
    total_logs = logs.count()
    email_logs = logs.filter(notification_type='email')
    sms_logs = logs.filter(notification_type='sms')
    
    stats = {
        'total_notifications': total_logs,
        'total_sent': logs.filter(status__in=['sent', 'delivered']).count(),
        'total_failed': logs.filter(status='failed').count(),
        'total_pending': logs.filter(status='pending').count(),
        'total_delivered': logs.filter(status='delivered').count(),
        'total_opened': logs.filter(status='opened').count(),
        'total_clicked': logs.filter(status='clicked').count(),
        'email_count': email_logs.count(),
        'sms_count': sms_logs.count(),
    }
    
    # Calculate rates
    email_sent = email_logs.filter(status__in=['sent', 'delivered']).count()
    sms_sent = sms_logs.filter(status__in=['sent', 'delivered']).count()
    
    if email_sent > 0:
        stats['email_delivery_rate'] = round((email_logs.filter(status='delivered').count() / email_sent) * 100, 2)
        stats['email_open_rate'] = round((email_logs.filter(status='opened').count() / email_sent) * 100, 2)
        stats['email_click_rate'] = round((email_logs.filter(status='clicked').count() / email_sent) * 100, 2)
    else:
        stats['email_delivery_rate'] = 0
        stats['email_open_rate'] = 0
        stats['email_click_rate'] = 0
    
    if sms_sent > 0:
        stats['sms_delivery_rate'] = round((sms_logs.filter(status='delivered').count() / sms_sent) * 100, 2)
    else:
        stats['sms_delivery_rate'] = 0
    
    # Recent activity (last 7 days)
    recent_logs = logs.filter(created_at__gte=timezone.now() - timezone.timedelta(days=7))
    stats['recent_activity'] = {
        'total': recent_logs.count(),
        'sent': recent_logs.filter(status__in=['sent', 'delivered']).count(),
        'failed': recent_logs.filter(status='failed').count(),
    }
    
    # Template usage
    template_usage = list(
        logs.exclude(template__isnull=True)
        .values('template__name')
        .annotate(usage_count=models.Count('id'))
        .order_by('-usage_count')[:5]
    )
    stats['top_templates'] = template_usage
    
    # Get preferences
    preferences, _ = NotificationPreference.objects.get_or_create(organizer=request.user)
    stats['preferences'] = {
        'daily_reminder_count': preferences.get_daily_reminder_count(),
        'daily_reminder_limit': preferences.max_reminders_per_day,
        'can_send_more_reminders': preferences.can_send_reminder(),
        'preferred_method': preferences.preferred_notification_method,
        'dnd_enabled': preferences.dnd_enabled,
    }
    
    serializer = NotificationStatsSerializer(stats)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def cancel_scheduled_notification(request, pk):
    """Cancel a scheduled notification."""
    notification = get_object_or_404(
        NotificationSchedule,
        pk=pk,
        organizer=request.user,
        status='scheduled'
    )
    
    notification.status = 'cancelled'
    notification.save()
    
    return Response({'message': 'Scheduled notification cancelled'})


@csrf_exempt
@require_http_methods(["POST"])
def sms_status_callback(request):
    """Handle Twilio SMS status callbacks for delivery tracking."""
    try:
        # Get Twilio data from POST body
        message_sid = request.POST.get('MessageSid')
        message_status = request.POST.get('MessageStatus')
        error_code = request.POST.get('ErrorCode')
        error_message = request.POST.get('ErrorMessage')
        
        if not message_sid:
            return HttpResponse("Missing MessageSid", status=400)
        
        # Find notification log by external_id (Twilio SID)
        try:
            log = NotificationLog.objects.get(
                external_id=message_sid,
                notification_type='sms'
            )
        except NotificationLog.DoesNotExist:
            logger.warning(f"Notification log not found for Twilio SID: {message_sid}")
            return HttpResponse("Notification not found", status=404)
        
        # Update delivery status based on Twilio status
        status_mapping = {
            'queued': 'queued',
            'sending': 'sending',
            'sent': 'sent',
            'delivered': 'delivered',
            'undelivered': 'undelivered',
            'failed': 'failed',
        }
        
        new_status = status_mapping.get(message_status, 'unknown')
        
        # Update notification log
        update_fields = ['delivery_status', 'provider_response']
        log.delivery_status = new_status
        log.provider_response.update({
            'twilio_status': message_status,
            'error_code': error_code,
            'error_message': error_message,
            'updated_at': timezone.now().isoformat()
        })
        
        # Update timestamps based on status
        if message_status == 'delivered' and not log.delivered_at:
            log.delivered_at = timezone.now()
            update_fields.append('delivered_at')
        
        # Update main status if needed
        if message_status in ['delivered', 'failed', 'undelivered']:
            if message_status == 'delivered':
                log.status = 'delivered'
            elif message_status in ['failed', 'undelivered']:
                log.status = 'failed'
                if error_message:
                    log.error_message = error_message
                    update_fields.append('error_message')
            
            update_fields.append('status')
        
        log.save(update_fields=update_fields)
        
        logger.info(f"Updated SMS delivery status for {message_sid}: {message_status}")
        
        return HttpResponse("OK", status=200)
        
    except Exception as e:
        logger.error(f"Error processing SMS status callback: {str(e)}")
        return HttpResponse("Internal Server Error", status=500)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def resend_failed_notification(request, pk):
    """Manually resend a failed notification."""
    try:
        log = NotificationLog.objects.get(pk=pk, organizer=request.user)
        
        if log.status not in ['failed', 'pending']:
            return Response(
                {'error': 'Only failed or pending notifications can be resent'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not log.can_retry():
            return Response(
                {'error': 'Maximum retry attempts exceeded'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Reset status and send
        log.status = 'pending'
        log.save(update_fields=['status'])
        
        # Send immediately
        from .tasks import send_notification_task
        send_notification_task.delay(log.id)
        
        return Response({'message': 'Notification queued for resending'})
        
    except NotificationLog.DoesNotExist:
        return Response(
            {'error': 'Notification not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def notification_health(request):
    """Get notification system health for the organizer."""
    from datetime import timedelta
    
    # Get recent notification data
    recent_logs = NotificationLog.objects.filter(
        organizer=request.user,
        created_at__gte=timezone.now() - timedelta(days=7)
    )
    
    total_recent = recent_logs.count()
    failed_recent = recent_logs.filter(status='failed').count()
    
    health_data = {
        'overall_health': 'healthy',
        'recent_notifications': total_recent,
        'recent_failures': failed_recent,
        'failure_rate': round((failed_recent / total_recent * 100), 2) if total_recent > 0 else 0,
        'email_configured': bool(getattr(settings, 'EMAIL_HOST_USER', None)),
        'sms_configured': bool(getattr(settings, 'TWILIO_ACCOUNT_SID', None)),
    }
    
    # Determine overall health
    if health_data['failure_rate'] > 20:
        health_data['overall_health'] = 'unhealthy'
    elif health_data['failure_rate'] > 10:
        health_data['overall_health'] = 'degraded'
    
    # Check for recent failures
    recent_failures = recent_logs.filter(
        status='failed',
        created_at__gte=timezone.now() - timedelta(hours=1)
    )
    
    if recent_failures.exists():
        health_data['recent_failure_details'] = list(
            recent_failures.values('notification_type', 'error_message', 'created_at')[:5]
        )
    
    return Response(health_data)