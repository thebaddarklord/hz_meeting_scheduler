from django.db import models
import uuid


class Contact(models.Model):
    """Contact model for organizer's contact list."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='contacts')
    
    # Contact information
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100, blank=True)
    email = models.EmailField()
    phone = models.CharField(max_length=20, blank=True)
    company = models.CharField(max_length=200, blank=True)
    job_title = models.CharField(max_length=200, blank=True)
    
    # Additional information
    notes = models.TextField(blank=True)
    tags = models.JSONField(default=list, blank=True, help_text="List of tags for categorization")
    
    # Tracking
    total_bookings = models.IntegerField(default=0)
    last_booking_date = models.DateTimeField(null=True, blank=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'contacts'
        unique_together = ['organizer', 'email']
        verbose_name = 'Contact'
        verbose_name_plural = 'Contacts'
        ordering = ['first_name', 'last_name']
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()


class ContactGroup(models.Model):
    """Contact groups for organizing contacts."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='contact_groups')
    
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    color = models.CharField(max_length=7, default='#0066cc', help_text="Hex color code")
    
    # Contacts in this group
    contacts = models.ManyToManyField(Contact, blank=True, related_name='groups')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'contact_groups'
        unique_together = ['organizer', 'name']
        verbose_name = 'Contact Group'
        verbose_name_plural = 'Contact Groups'
        ordering = ['name']
    
    def __str__(self):
        return f"{self.organizer.email} - {self.name}"
    
    @property
    def contact_count(self):
        return self.contacts.count()


class ContactInteraction(models.Model):
    """Log of interactions with contacts."""
    INTERACTION_TYPES = [
        ('booking_created', 'Booking Created'),
        ('booking_completed', 'Booking Completed'),
        ('booking_cancelled', 'Booking Cancelled'),
        ('email_sent', 'Email Sent'),
        ('note_added', 'Note Added'),
        ('manual_entry', 'Manual Entry'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE, related_name='interactions')
    organizer = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='contact_interactions')
    
    interaction_type = models.CharField(max_length=30, choices=INTERACTION_TYPES)
    description = models.TextField()
    
    # Related objects
    booking = models.ForeignKey('events.Booking', on_delete=models.SET_NULL, null=True, blank=True)
    
    # Additional data
    metadata = models.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'contact_interactions'
        verbose_name = 'Contact Interaction'
        verbose_name_plural = 'Contact Interactions'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.contact.full_name} - {self.get_interaction_type_display()}"