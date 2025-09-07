from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.utils import timezone
from .models import Workflow, WorkflowAction, WorkflowExecution, WorkflowTemplate
from .serializers import (
    WorkflowSerializer, WorkflowCreateSerializer, WorkflowActionSerializer,
    WorkflowActionCreateSerializer, WorkflowExecutionSerializer,
    WorkflowTemplateSerializer, WorkflowFromTemplateSerializer,
    WorkflowTestSerializer, WorkflowValidationSerializer
)
from .utils import validate_workflow_configuration, get_workflow_execution_summary
import logging

logger = logging.getLogger(__name__)


class WorkflowListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Workflow.objects.filter(organizer=self.request.user)
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return WorkflowCreateSerializer
        return WorkflowSerializer
    
    def perform_create(self, serializer):
        serializer.save(organizer=self.request.user)


class WorkflowDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = WorkflowSerializer
    
    def get_queryset(self):
        return Workflow.objects.filter(organizer=self.request.user)


class WorkflowActionListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = WorkflowActionCreateSerializer
    
    def get_queryset(self):
        workflow_id = self.kwargs['workflow_id']
        return WorkflowAction.objects.filter(
            workflow_id=workflow_id,
            workflow__organizer=self.request.user
        )
    
    def perform_create(self, serializer):
        workflow_id = self.kwargs['workflow_id']
        workflow = get_object_or_404(
            Workflow,
            id=workflow_id,
            organizer=self.request.user
        )
        serializer.save(workflow=workflow)


class WorkflowActionDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = WorkflowActionSerializer
    
    def get_queryset(self):
        return WorkflowAction.objects.filter(
            workflow__organizer=self.request.user
        )


class WorkflowExecutionListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = WorkflowExecutionSerializer
    
    def get_queryset(self):
        return WorkflowExecution.objects.filter(
            workflow__organizer=self.request.user
        ).order_by('-created_at')


class WorkflowTemplateListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = WorkflowTemplateSerializer
    queryset = WorkflowTemplate.objects.filter(is_public=True)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def create_workflow_from_template(request):
    """Create a workflow from a template."""
    serializer = WorkflowFromTemplateSerializer(data=request.data)
    
    if serializer.is_valid():
        template_id = serializer.validated_data['template_id']
        custom_name = serializer.validated_data.get('name')
        
        try:
            template = WorkflowTemplate.objects.get(id=template_id, is_public=True)
            
            # Create workflow from template
            template_data = template.template_data
            workflow_data = template_data.get('workflow', {})
            
            workflow = Workflow.objects.create(
                organizer=request.user,
                name=custom_name or template.name,
                description=workflow_data.get('description', template.description),
                trigger=workflow_data.get('trigger', 'booking_created'),
                delay_minutes=workflow_data.get('delay_minutes', 0),
                is_active=True
            )
            
            # Create actions from template
            actions_data = template_data.get('actions', [])
            for action_data in actions_data:
                WorkflowAction.objects.create(
                    workflow=workflow,
                    name=action_data.get('name', ''),
                    action_type=action_data.get('action_type', 'send_email'),
                    order=action_data.get('order', 0),
                    recipient=action_data.get('recipient', 'invitee'),
                    subject=action_data.get('subject', ''),
                    message=action_data.get('message', ''),
                    webhook_url=action_data.get('webhook_url', ''),
                    webhook_data=action_data.get('webhook_data', {}),
                    conditions=action_data.get('conditions', {}),
                    is_active=True
                )
            
            # Increment usage count
            template.usage_count += 1
            template.save()
            
            return Response(
                WorkflowSerializer(workflow).data,
                status=status.HTTP_201_CREATED
            )
        
        except WorkflowTemplate.DoesNotExist:
            return Response(
                {'error': 'Template not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def test_workflow(request, pk):
    """Test a workflow with comprehensive options."""
    workflow = get_object_or_404(Workflow, pk=pk, organizer=request.user)
    
    serializer = WorkflowTestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    test_type = serializer.validated_data.get('test_type', 'mock_data')
    booking_id = serializer.validated_data.get('booking_id')
    live_test = serializer.validated_data.get('live_test', False)
    
    try:
        if test_type == 'mock_data':
            # Test with mock data
            from .tasks import execute_workflow
            task = execute_workflow.delay(
                workflow_id=workflow.id,
                booking_id=None,
                test_mode=True
            )
            
            return Response({
                'message': 'Workflow test initiated with mock data',
                'task_id': task.id,
                'test_type': 'mock_data'
            })
            
        elif test_type == 'real_data' and booking_id:
            # Test with real booking data
            from apps.events.models import Booking
            booking = get_object_or_404(
                Booking, 
                id=booking_id, 
                organizer=request.user
            )
            
            from .tasks import test_workflow_with_real_data
            task = test_workflow_with_real_data.delay(workflow.id, booking.id)
            
            return Response({
                'message': f'Workflow test initiated with booking {booking.id}',
                'task_id': task.id,
                'test_type': 'real_data',
                'booking_id': str(booking.id)
            })
            
        elif test_type == 'live_test' and booking_id and live_test:
            # Live test with real actions (use with caution)
            from apps.events.models import Booking
            booking = get_object_or_404(
                Booking, 
                id=booking_id, 
                organizer=request.user
            )
            
            # Execute workflow with real actions but mark as test
            from .tasks import execute_workflow
            task = execute_workflow.delay(
                workflow_id=workflow.id,
                booking_id=booking.id,
                test_mode=False  # Real execution
            )
            
            return Response({
                'message': 'Live workflow test initiated - real actions will be executed',
                'warning': 'This will send real emails/SMS and trigger real webhooks',
                'task_id': task.id,
                'test_type': 'live_test',
                'booking_id': str(booking.id)
            })
        
        else:
            return Response({
                'error': 'Invalid test configuration',
                'details': 'real_data and live_test require booking_id'
            }, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        logger.error(f"Error testing workflow {workflow.id}: {str(e)}")
        return Response({
            'error': 'Failed to initiate workflow test',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def validate_workflow(request, pk):
    """Validate workflow configuration and return detailed results."""
    workflow = get_object_or_404(Workflow, pk=pk, organizer=request.user)
    
    try:
        validation_results = validate_workflow_configuration(workflow)
        
        # Add additional runtime checks
        runtime_checks = []
        
        # Check if organizer has necessary integrations for actions
        actions = workflow.actions.filter(is_active=True)
        
        for action in actions:
            if action.action_type == 'send_sms':
                # Check if Twilio is configured
                if not all([
                    getattr(settings, 'TWILIO_ACCOUNT_SID', None),
                    getattr(settings, 'TWILIO_AUTH_TOKEN', None),
                    getattr(settings, 'TWILIO_PHONE_NUMBER', None)
                ]):
                    runtime_checks.append(f"SMS action '{action.name}' requires Twilio configuration")
            
            elif action.action_type == 'webhook':
                # Test webhook URL accessibility (basic check)
                try:
                    import requests
                    response = requests.head(action.webhook_url, timeout=5)
                    if response.status_code >= 400:
                        runtime_checks.append(f"Webhook URL for action '{action.name}' returned status {response.status_code}")
                except Exception:
                    runtime_checks.append(f"Webhook URL for action '{action.name}' is not accessible")
        
        validation_results['runtime_checks'] = runtime_checks
        validation_results['overall_status'] = 'valid' if validation_results['valid'] and not runtime_checks else 'issues_found'
        
        serializer = WorkflowValidationSerializer(validation_results)
        return Response(serializer.data)
        
    except Exception as e:
        logger.error(f"Error validating workflow {workflow.id}: {str(e)}")
        return Response({
            'error': 'Validation failed',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def workflow_execution_summary(request, pk):
    """Get detailed execution summary for a workflow."""
    workflow = get_object_or_404(Workflow, pk=pk, organizer=request.user)
    
    # Get recent executions
    recent_executions = WorkflowExecution.objects.filter(
        workflow=workflow
    ).order_by('-created_at')[:10]
    
    execution_summaries = []
    for execution in recent_executions:
        summary = get_workflow_execution_summary(execution)
        summary.update({
            'execution_id': str(execution.id),
            'booking_id': str(execution.booking.id) if execution.booking else None,
            'status': execution.status,
            'started_at': execution.started_at,
            'completed_at': execution.completed_at,
            'execution_time_seconds': (
                (execution.completed_at - execution.started_at).total_seconds()
                if execution.started_at and execution.completed_at else None
            )
        })
        execution_summaries.append(summary)
    
    # Calculate overall statistics
    total_executions = WorkflowExecution.objects.filter(workflow=workflow).count()
    successful_executions = WorkflowExecution.objects.filter(workflow=workflow, status='completed').count()
    
    overall_stats = {
        'workflow_id': str(workflow.id),
        'workflow_name': workflow.name,
        'total_executions': total_executions,
        'successful_executions': successful_executions,
        'failed_executions': total_executions - successful_executions,
        'success_rate': workflow.get_success_rate(),
        'last_executed_at': workflow.last_executed_at,
        'recent_executions': execution_summaries
    }
    
    return Response(overall_stats)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def bulk_test_workflows(request):
    """Test multiple workflows in bulk."""
    workflow_ids = request.data.get('workflow_ids', [])
    test_type = request.data.get('test_type', 'mock_data')
    
    if not workflow_ids:
        return Response({
            'error': 'workflow_ids is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Verify all workflows belong to the user
    workflows = Workflow.objects.filter(
        id__in=workflow_ids,
        organizer=request.user,
        is_active=True
    )
    
    if workflows.count() != len(workflow_ids):
        return Response({
            'error': 'Some workflows not found or not accessible'
        }, status=status.HTTP_404_NOT_FOUND)
    
    # Trigger bulk testing
    from .tasks import bulk_execute_workflows
    
    if test_type == 'mock_data':
        # Use None for booking_ids in mock mode
        booking_ids = [None] * len(workflow_ids)
        task = bulk_execute_workflows.delay(workflow_ids, booking_ids, test_mode=True)
    else:
        return Response({
            'error': 'Only mock_data test_type is supported for bulk testing'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response({
        'message': f'Bulk test initiated for {len(workflow_ids)} workflows',
        'task_id': task.id,
        'workflow_count': len(workflow_ids)
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def workflow_performance_stats(request):
    """Get comprehensive workflow performance statistics."""
    from datetime import timedelta
    from django.db.models import Avg, Count, Q
    
    # Get user's workflows
    workflows = Workflow.objects.filter(organizer=request.user)
    
    # Calculate overall statistics
    total_workflows = workflows.count()
    active_workflows = workflows.filter(is_active=True).count()
    
    # Get execution statistics for the last 30 days
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_executions = WorkflowExecution.objects.filter(
        workflow__organizer=request.user,
        created_at__gte=thirty_days_ago
    )
    
    execution_stats = recent_executions.aggregate(
        total_executions=Count('id'),
        successful_executions=Count('id', filter=Q(status='completed')),
        failed_executions=Count('id', filter=Q(status='failed')),
        avg_execution_time=Avg('completed_at') - Avg('started_at')
    )
    
    # Calculate success rate
    total_recent = execution_stats['total_executions'] or 0
    successful_recent = execution_stats['successful_executions'] or 0
    success_rate = (successful_recent / total_recent * 100) if total_recent > 0 else 0
    
    # Get top performing and problematic workflows
    workflow_performance = []
    for workflow in workflows:
        workflow_executions = recent_executions.filter(workflow=workflow)
        total = workflow_executions.count()
        successful = workflow_executions.filter(status='completed').count()
        
        if total > 0:
            workflow_performance.append({
                'workflow_id': str(workflow.id),
                'workflow_name': workflow.name,
                'total_executions': total,
                'successful_executions': successful,
                'success_rate': round((successful / total * 100), 2),
                'last_executed': workflow.last_executed_at
            })
    
    # Sort by success rate
    workflow_performance.sort(key=lambda x: x['success_rate'], reverse=True)
    
    stats = {
        'total_workflows': total_workflows,
        'active_workflows': active_workflows,
        'inactive_workflows': total_workflows - active_workflows,
        'execution_stats_30_days': {
            'total_executions': total_recent,
            'successful_executions': successful_recent,
            'failed_executions': execution_stats['failed_executions'] or 0,
            'success_rate': round(success_rate, 2)
        },
        'top_performing_workflows': workflow_performance[:5],
        'problematic_workflows': [w for w in workflow_performance if w['success_rate'] < 80][:5]
    }
    
    return Response(stats)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def duplicate_workflow(request, pk):
    """Duplicate an existing workflow."""
    original_workflow = get_object_or_404(Workflow, pk=pk, organizer=request.user)
    
    # Create duplicate workflow
    duplicate = Workflow.objects.create(
        organizer=request.user,
        name=f"{original_workflow.name} (Copy)",
        description=original_workflow.description,
        trigger=original_workflow.trigger,
        delay_minutes=original_workflow.delay_minutes,
        is_active=False  # Start as inactive
    )
    
    # Copy event types
    duplicate.event_types.set(original_workflow.event_types.all())
    
    # Copy actions
    for action in original_workflow.actions.all():
        WorkflowAction.objects.create(
            workflow=duplicate,
            name=action.name,
            action_type=action.action_type,
            order=action.order,
            recipient=action.recipient,
            custom_email=action.custom_email,
            subject=action.subject,
            message=action.message,
            webhook_url=action.webhook_url,
            webhook_data=action.webhook_data,
            conditions=action.conditions,
            is_active=action.is_active
        )
    
    return Response(
        WorkflowSerializer(duplicate).data,
        status=status.HTTP_201_CREATED
    )