from django.contrib import admin
from .models import CalendarIntegration, VideoConferenceIntegration, WebhookIntegration, IntegrationLog


@admin.register(CalendarIntegration)
class CalendarIntegrationAdmin(admin.ModelAdmin):
    list_display = ('organizer', 'provider', 'provider_email', 'is_active', 'sync_enabled', 'created_at')
    list_filter = ('provider', 'is_active', 'sync_enabled', 'created_at')
    search_fields = ('organizer__email', 'provider_email')
    readonly_fields = ('created_at', 'updated_at', 'token_expires_at')
    
    fieldsets = (
        ('Integration Details', {
            'fields': ('organizer', 'provider', 'is_active', 'sync_enabled')
        }),
        ('Provider Information', {
            'fields': ('provider_user_id', 'provider_email', 'calendar_id')
        }),
        ('OAuth Tokens', {
            'fields': ('access_token', 'refresh_token', 'token_expires_at'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(VideoConferenceIntegration)
class VideoConferenceIntegrationAdmin(admin.ModelAdmin):
    list_display = ('organizer', 'provider', 'provider_email', 'is_active', 'auto_generate_links', 'api_calls_today', 'created_at')
    list_filter = ('provider', 'is_active', 'auto_generate_links', 'created_at')
    search_fields = ('organizer__email', 'provider_email')
    readonly_fields = ('created_at', 'updated_at', 'token_expires_at', 'last_api_call', 'api_calls_today', 'rate_limit_reset_at')
    
    fieldsets = (
        ('Integration Details', {
            'fields': ('organizer', 'provider', 'is_active', 'auto_generate_links')
        }),
        ('Provider Information', {
            'fields': ('provider_user_id', 'provider_email')
        }),
        ('Rate Limiting', {
            'fields': ('last_api_call', 'api_calls_today', 'rate_limit_reset_at')
        }),
        ('OAuth Tokens', {
            'fields': ('access_token', 'refresh_token', 'token_expires_at'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(WebhookIntegration)
class WebhookIntegrationAdmin(admin.ModelAdmin):
    list_display = ('organizer', 'name', 'webhook_url', 'is_active', 'created_at')
    list_filter = ('is_active', 'retry_failed', 'created_at')
    search_fields = ('organizer__email', 'name', 'webhook_url')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Webhook Details', {
            'fields': ('organizer', 'name', 'webhook_url', 'events')
        }),
        ('Authentication', {
            'fields': ('secret_key', 'headers')
        }),
        ('Settings', {
            'fields': ('is_active', 'retry_failed', 'max_retries')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(IntegrationLog)
class IntegrationLogAdmin(admin.ModelAdmin):
    list_display = ('organizer', 'log_type', 'integration_type', 'success', 'created_at')
    list_filter = ('log_type', 'integration_type', 'success', 'created_at')
    search_fields = ('organizer__email', 'message')
    readonly_fields = ('created_at',)
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Log Information', {
            'fields': ('organizer', 'log_type', 'integration_type', 'booking', 'success')
        }),
        ('Details', {
            'fields': ('message', 'details')
        }),
        ('Timestamp', {
            'fields': ('created_at',)
        }),
    )