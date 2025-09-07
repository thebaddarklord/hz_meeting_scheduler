from rest_framework import serializers
from .models import Contact, ContactGroup, ContactInteraction


class ContactSerializer(serializers.ModelSerializer):
    full_name = serializers.ReadOnlyField()
    groups_count = serializers.IntegerField(source='groups.count', read_only=True)
    
    class Meta:
        model = Contact
        fields = [
            'id', 'first_name', 'last_name', 'full_name', 'email', 'phone',
            'company', 'job_title', 'notes', 'tags', 'total_bookings',
            'last_booking_date', 'groups_count', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'total_bookings', 'last_booking_date', 'created_at', 'updated_at']


class ContactCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = [
            'first_name', 'last_name', 'email', 'phone', 'company',
            'job_title', 'notes', 'tags', 'is_active'
        ]


class ContactGroupSerializer(serializers.ModelSerializer):
    contact_count = serializers.ReadOnlyField()
    contacts = ContactSerializer(many=True, read_only=True)
    
    class Meta:
        model = ContactGroup
        fields = [
            'id', 'name', 'description', 'color', 'contact_count',
            'contacts', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ContactGroupCreateSerializer(serializers.ModelSerializer):
    contact_ids = serializers.ListField(
        child=serializers.UUIDField(),
        write_only=True,
        required=False
    )
    
    class Meta:
        model = ContactGroup
        fields = ['name', 'description', 'color', 'contact_ids']
    
    def create(self, validated_data):
        contact_ids = validated_data.pop('contact_ids', [])
        group = ContactGroup.objects.create(**validated_data)
        
        if contact_ids:
            contacts = Contact.objects.filter(
                id__in=contact_ids,
                organizer=group.organizer
            )
            group.contacts.set(contacts)
        
        return group


class ContactInteractionSerializer(serializers.ModelSerializer):
    interaction_type_display = serializers.CharField(source='get_interaction_type_display', read_only=True)
    contact_name = serializers.CharField(source='contact.full_name', read_only=True)
    booking_id = serializers.UUIDField(source='booking.id', read_only=True)
    
    class Meta:
        model = ContactInteraction
        fields = [
            'id', 'contact_name', 'interaction_type', 'interaction_type_display',
            'description', 'booking_id', 'metadata', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class ContactStatsSerializer(serializers.Serializer):
    """Serializer for contact statistics."""
    total_contacts = serializers.IntegerField()
    active_contacts = serializers.IntegerField()
    total_groups = serializers.IntegerField()
    recent_interactions = serializers.IntegerField()
    top_companies = serializers.ListField()
    booking_frequency = serializers.DictField()


class ContactImportSerializer(serializers.Serializer):
    """Serializer for importing contacts."""
    csv_file = serializers.FileField()
    skip_duplicates = serializers.BooleanField(default=True)
    update_existing = serializers.BooleanField(default=False)