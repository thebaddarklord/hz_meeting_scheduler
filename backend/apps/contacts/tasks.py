from celery import shared_task
from django.utils import timezone
from .models import Contact, ContactInteraction
import csv
import io


@shared_task
def process_contact_import(organizer_id, csv_content, skip_duplicates=True, update_existing=False):
    """Process contact import from CSV."""
    try:
        from apps.users.models import User
        organizer = User.objects.get(id=organizer_id)
        
        # Parse CSV
        csv_file = io.StringIO(csv_content)
        reader = csv.DictReader(csv_file)
        
        created_count = 0
        updated_count = 0
        skipped_count = 0
        
        for row in reader:
            email = row.get('email', '').strip().lower()
            if not email:
                skipped_count += 1
                continue
            
            # Check if contact exists
            existing_contact = Contact.objects.filter(
                organizer=organizer,
                email=email
            ).first()
            
            if existing_contact:
                if update_existing:
                    # Update existing contact
                    existing_contact.first_name = row.get('first_name', existing_contact.first_name)
                    existing_contact.last_name = row.get('last_name', existing_contact.last_name)
                    existing_contact.phone = row.get('phone', existing_contact.phone)
                    existing_contact.company = row.get('company', existing_contact.company)
                    existing_contact.job_title = row.get('job_title', existing_contact.job_title)
                    existing_contact.notes = row.get('notes', existing_contact.notes)
                    
                    # Handle tags
                    tags_str = row.get('tags', '')
                    if tags_str:
                        tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()]
                        existing_contact.tags = tags
                    
                    existing_contact.save()
                    updated_count += 1
                elif skip_duplicates:
                    skipped_count += 1
                    continue
            else:
                # Create new contact
                tags_str = row.get('tags', '')
                tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()] if tags_str else []
                
                contact = Contact.objects.create(
                    organizer=organizer,
                    first_name=row.get('first_name', ''),
                    last_name=row.get('last_name', ''),
                    email=email,
                    phone=row.get('phone', ''),
                    company=row.get('company', ''),
                    job_title=row.get('job_title', ''),
                    notes=row.get('notes', ''),
                    tags=tags
                )
                created_count += 1
        
        return f"Import completed: {created_count} created, {updated_count} updated, {skipped_count} skipped"
    
    except User.DoesNotExist:
        return f"Organizer {organizer_id} not found"
    except Exception as e:
        return f"Error importing contacts: {str(e)}"


@shared_task
def merge_contact_data(primary_contact_id, duplicate_contact_ids):
    """Merge duplicate contacts into primary contact."""
    try:
        primary_contact = Contact.objects.get(id=primary_contact_id)
        duplicate_contacts = Contact.objects.filter(id__in=duplicate_contact_ids)
        
        # Merge booking data
        from apps.events.models import Booking
        total_bookings = 0
        latest_booking_date = primary_contact.last_booking_date
        
        for duplicate in duplicate_contacts:
            # Update bookings to reference primary contact (if needed in future)
            # For now, just aggregate the statistics
            total_bookings += duplicate.total_bookings
            
            if duplicate.last_booking_date:
                if not latest_booking_date or duplicate.last_booking_date > latest_booking_date:
                    latest_booking_date = duplicate.last_booking_date
            
            # Merge interactions
            ContactInteraction.objects.filter(contact=duplicate).update(contact=primary_contact)
            
            # Merge tags
            if duplicate.tags:
                primary_tags = set(primary_contact.tags or [])
                duplicate_tags = set(duplicate.tags)
                primary_contact.tags = list(primary_tags.union(duplicate_tags))
            
            # Merge notes
            if duplicate.notes and duplicate.notes not in (primary_contact.notes or ''):
                if primary_contact.notes:
                    primary_contact.notes += f"\n\n--- Merged from {duplicate.email} ---\n{duplicate.notes}"
                else:
                    primary_contact.notes = duplicate.notes
        
        # Update primary contact
        primary_contact.total_bookings += total_bookings
        if latest_booking_date:
            primary_contact.last_booking_date = latest_booking_date
        primary_contact.save()
        
        # Delete duplicate contacts
        duplicate_contacts.delete()
        
        return f"Merged {len(duplicate_contact_ids)} contacts into {primary_contact.email}"
    
    except Contact.DoesNotExist:
        return f"Primary contact {primary_contact_id} not found"
    except Exception as e:
        return f"Error merging contacts: {str(e)}"


@shared_task
def update_contact_booking_stats():
    """Update contact booking statistics."""
    from apps.events.models import Booking
    
    # Get all contacts
    contacts = Contact.objects.all()
    updated_count = 0
    
    for contact in contacts:
        # Get bookings for this contact
        bookings = Booking.objects.filter(
            organizer=contact.organizer,
            invitee_email=contact.email,
            status='confirmed'
        )
        
        # Update statistics
        total_bookings = bookings.count()
        last_booking = bookings.order_by('-start_time').first()
        
        if contact.total_bookings != total_bookings or (
            last_booking and contact.last_booking_date != last_booking.start_time
        ):
            contact.total_bookings = total_bookings
            contact.last_booking_date = last_booking.start_time if last_booking else None
            contact.save()
            updated_count += 1
    
    return f"Updated booking stats for {updated_count} contacts"


@shared_task
def create_contact_from_booking(booking_id):
    """Create or update contact from booking."""
    try:
        from apps.events.models import Booking
        booking = Booking.objects.get(id=booking_id)
        
        # Check if contact already exists
        contact, created = Contact.objects.get_or_create(
            organizer=booking.organizer,
            email=booking.invitee_email,
            defaults={
                'first_name': booking.invitee_name.split(' ')[0] if booking.invitee_name else '',
                'last_name': ' '.join(booking.invitee_name.split(' ')[1:]) if booking.invitee_name and len(booking.invitee_name.split(' ')) > 1 else '',
                'phone': booking.invitee_phone,
            }
        )
        
        # Update booking statistics
        contact.total_bookings = Booking.objects.filter(
            organizer=booking.organizer,
            invitee_email=booking.invitee_email,
            status='confirmed'
        ).count()
        
        contact.last_booking_date = booking.start_time
        contact.save()
        
        # Create interaction record
        ContactInteraction.objects.create(
            contact=contact,
            organizer=booking.organizer,
            interaction_type='booking_created',
            description=f"Booked {booking.event_type.name} for {booking.start_time.strftime('%B %d, %Y at %I:%M %p')}",
            booking=booking,
            metadata={
                'event_type': booking.event_type.name,
                'duration': booking.event_type.duration,
                'start_time': booking.start_time.isoformat()
            }
        )
        
        action = "Created" if created else "Updated"
        return f"{action} contact for {booking.invitee_email}"
    
    except Booking.DoesNotExist:
        return f"Booking {booking_id} not found"
    except Exception as e:
        return f"Error creating contact from booking: {str(e)}"