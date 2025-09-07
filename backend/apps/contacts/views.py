from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db.models import Q, Count
from .models import Contact, ContactGroup, ContactInteraction
from .serializers import (
    ContactSerializer, ContactCreateSerializer, ContactGroupSerializer,
    ContactGroupCreateSerializer, ContactInteractionSerializer,
    ContactStatsSerializer, ContactImportSerializer
)


class ContactListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = Contact.objects.filter(organizer=self.request.user)
        
        # Filter by search query
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(email__icontains=search) |
                Q(company__icontains=search)
            )
        
        # Filter by group
        group_id = self.request.query_params.get('group')
        if group_id:
            queryset = queryset.filter(groups__id=group_id)
        
        # Filter by tags
        tags = self.request.query_params.get('tags')
        if tags:
            tag_list = [tag.strip() for tag in tags.split(',')]
            for tag in tag_list:
                queryset = queryset.filter(tags__contains=[tag])
        
        # Filter by active status
        is_active = self.request.query_params.get('is_active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        return queryset.order_by('first_name', 'last_name')
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return ContactCreateSerializer
        return ContactSerializer
    
    def perform_create(self, serializer):
        serializer.save(organizer=self.request.user)


class ContactDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ContactSerializer
    
    def get_queryset(self):
        return Contact.objects.filter(organizer=self.request.user)


class ContactGroupListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return ContactGroup.objects.filter(organizer=self.request.user)
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return ContactGroupCreateSerializer
        return ContactGroupSerializer
    
    def perform_create(self, serializer):
        serializer.save(organizer=self.request.user)


class ContactGroupDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ContactGroupSerializer
    
    def get_queryset(self):
        return ContactGroup.objects.filter(organizer=self.request.user)


class ContactInteractionListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ContactInteractionSerializer
    
    def get_queryset(self):
        contact_id = self.kwargs.get('contact_id')
        if contact_id:
            return ContactInteraction.objects.filter(
                contact_id=contact_id,
                organizer=self.request.user
            )
        return ContactInteraction.objects.filter(organizer=self.request.user)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def contact_stats(request):
    """Get contact statistics."""
    contacts = Contact.objects.filter(organizer=request.user)
    groups = ContactGroup.objects.filter(organizer=request.user)
    interactions = ContactInteraction.objects.filter(organizer=request.user)
    
    # Calculate statistics
    stats = {
        'total_contacts': contacts.count(),
        'active_contacts': contacts.filter(is_active=True).count(),
        'total_groups': groups.count(),
        'recent_interactions': interactions.filter(
            created_at__gte=timezone.now() - timedelta(days=30)
        ).count(),
    }
    
    # Top companies
    top_companies = list(
        contacts.exclude(company='')
        .values('company')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )
    stats['top_companies'] = top_companies
    
    # Booking frequency
    from django.utils import timezone
    from datetime import timedelta
    
    booking_frequency = {
        'this_month': contacts.filter(
            last_booking_date__gte=timezone.now() - timedelta(days=30)
        ).count(),
        'last_month': contacts.filter(
            last_booking_date__gte=timezone.now() - timedelta(days=60),
            last_booking_date__lt=timezone.now() - timedelta(days=30)
        ).count(),
        'this_year': contacts.filter(
            last_booking_date__gte=timezone.now() - timedelta(days=365)
        ).count(),
    }
    stats['booking_frequency'] = booking_frequency
    
    serializer = ContactStatsSerializer(stats)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def add_contact_to_group(request, contact_id, group_id):
    """Add a contact to a group."""
    contact = get_object_or_404(Contact, id=contact_id, organizer=request.user)
    group = get_object_or_404(ContactGroup, id=group_id, organizer=request.user)
    
    group.contacts.add(contact)
    
    return Response({'message': f'Contact added to {group.name}'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def remove_contact_from_group(request, contact_id, group_id):
    """Remove a contact from a group."""
    contact = get_object_or_404(Contact, id=contact_id, organizer=request.user)
    group = get_object_or_404(ContactGroup, id=group_id, organizer=request.user)
    
    group.contacts.remove(contact)
    
    return Response({'message': f'Contact removed from {group.name}'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def add_contact_interaction(request, contact_id):
    """Add an interaction to a contact."""
    contact = get_object_or_404(Contact, id=contact_id, organizer=request.user)
    
    interaction_type = request.data.get('interaction_type', 'manual_entry')
    description = request.data.get('description', '')
    metadata = request.data.get('metadata', {})
    
    interaction = ContactInteraction.objects.create(
        contact=contact,
        organizer=request.user,
        interaction_type=interaction_type,
        description=description,
        metadata=metadata
    )
    
    serializer = ContactInteractionSerializer(interaction)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def import_contacts(request):
    """Import contacts from CSV file."""
    serializer = ContactImportSerializer(data=request.data)
    
    if serializer.is_valid():
        csv_file = serializer.validated_data['csv_file']
        skip_duplicates = serializer.validated_data['skip_duplicates']
        update_existing = serializer.validated_data['update_existing']
        
        # Process CSV import
        from .tasks import process_contact_import
        task = process_contact_import.delay(
            organizer_id=request.user.id,
            csv_content=csv_file.read().decode('utf-8'),
            skip_duplicates=skip_duplicates,
            update_existing=update_existing
        )
        
        return Response({
            'message': 'Contact import started',
            'task_id': task.id
        })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def export_contacts(request):
    """Export contacts to CSV."""
    from django.http import HttpResponse
    import csv
    
    contacts = Contact.objects.filter(organizer=request.user)
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="contacts.csv"'
    
    writer = csv.writer(response)
    writer.writerow([
        'First Name', 'Last Name', 'Email', 'Phone', 'Company',
        'Job Title', 'Notes', 'Tags', 'Total Bookings', 'Last Booking Date'
    ])
    
    for contact in contacts:
        writer.writerow([
            contact.first_name,
            contact.last_name,
            contact.email,
            contact.phone,
            contact.company,
            contact.job_title,
            contact.notes,
            ','.join(contact.tags) if contact.tags else '',
            contact.total_bookings,
            contact.last_booking_date.strftime('%Y-%m-%d') if contact.last_booking_date else ''
        ])
    
    return response


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def merge_contacts(request):
    """Merge duplicate contacts."""
    primary_contact_id = request.data.get('primary_contact_id')
    duplicate_contact_ids = request.data.get('duplicate_contact_ids', [])
    
    if not primary_contact_id or not duplicate_contact_ids:
        return Response(
            {'error': 'primary_contact_id and duplicate_contact_ids are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        primary_contact = Contact.objects.get(id=primary_contact_id, organizer=request.user)
        duplicate_contacts = Contact.objects.filter(
            id__in=duplicate_contact_ids,
            organizer=request.user
        )
        
        # Merge contact data
        from .tasks import merge_contact_data
        merge_contact_data.delay(primary_contact.id, list(duplicate_contacts.values_list('id', flat=True)))
        
        return Response({'message': 'Contact merge initiated'})
    
    except Contact.DoesNotExist:
        return Response(
            {'error': 'Primary contact not found'},
            status=status.HTTP_404_NOT_FOUND
        )