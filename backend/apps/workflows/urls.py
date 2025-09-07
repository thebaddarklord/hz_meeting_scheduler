from django.urls import path
from . import views

app_name = 'workflows'

urlpatterns = [
    # Workflows
    path('', views.WorkflowListCreateView.as_view(), name='workflow-list'),
    path('<uuid:pk>/', views.WorkflowDetailView.as_view(), name='workflow-detail'),
    path('<uuid:pk>/test/', views.test_workflow, name='workflow-test'),
    path('<uuid:pk>/validate/', views.validate_workflow, name='workflow-validate'),
    path('<uuid:pk>/execution-summary/', views.workflow_execution_summary, name='workflow-execution-summary'),
    path('<uuid:pk>/duplicate/', views.duplicate_workflow, name='workflow-duplicate'),
    
    # Workflow Actions
    path('<uuid:workflow_id>/actions/', views.WorkflowActionListCreateView.as_view(), name='action-list'),
    path('actions/<uuid:pk>/', views.WorkflowActionDetailView.as_view(), name='action-detail'),
    
    # Workflow Executions
    path('executions/', views.WorkflowExecutionListView.as_view(), name='execution-list'),
    
    # Workflow Templates
    path('templates/', views.WorkflowTemplateListView.as_view(), name='template-list'),
    path('templates/create-from/', views.create_workflow_from_template, name='create-from-template'),
    
    # Bulk Operations and Analytics
    path('bulk-test/', views.bulk_test_workflows, name='bulk-test'),
    path('performance-stats/', views.workflow_performance_stats, name='performance-stats'),
]