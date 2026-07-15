from rest_framework import serializers
from .models import Device, LocationPing

class LocationPingSerializer(serializers.ModelSerializer):
    class Meta:
        model = LocationPing
        fields = ['id', 'latitude', 'longitude', 'battery_level', 'recorded_at', 'received_at']

class DeviceSerializer(serializers.ModelSerializer):
    latest_location = serializers.SerializerMethodField()
    last_seen = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Device
        fields = ['id', 'serial_number', 'nickname', 'is_active', 'battery_level', 'last_seen', 'created_at', 'latest_location']
        read_only_fields = ['id', 'serial_number', 'is_active', 'battery_level', 'last_seen', 'created_at']

    def get_latest_location(self, obj):
        latest = obj.locations.order_by('-recorded_at').first()
        if latest:
            return LocationPingSerializer(latest).data
        return None