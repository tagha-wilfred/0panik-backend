from django.contrib import admin
from .models import Device, LocationPing

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('serial_number', 'owner', 'nickname', 'is_active', 'last_seen')
    search_fields = ('serial_number', 'owner__email', 'nickname')
    readonly_fields = ('api_key',)  # show but not editable
    fields = ('serial_number', 'api_key', 'owner', 'nickname', 'is_active', 'battery_level', 'last_seen')

@admin.register(LocationPing)
class LocationPingAdmin(admin.ModelAdmin):
    list_display = ('device', 'latitude', 'longitude', 'recorded_at', 'received_at')
    list_filter = ('device',)
    search_fields = ('device__serial_number',)
    ordering = ('-recorded_at',)