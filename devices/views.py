from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import Device, LocationPing
from .serializers import DeviceSerializer, LocationPingSerializer
from .permissions import IsDeviceOwner  # custom permission (see below)
from rest_framework.views import APIView
from rest_framework.throttling import ScopedRateThrottle
from .authentication import DeviceAPIKeyAuthentication
from rest_framework import serializers

class ClaimDeviceView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.Serializer  # dummy

    def post(self, request):
        serial_number = request.data.get('serial_number')
        if not serial_number:
            return Response({'serial_number': ['This field is required.']}, status=status.HTTP_400_BAD_REQUEST)
        try:
            device = Device.objects.get(serial_number=serial_number)
        except Device.DoesNotExist:
            return Response({'detail': 'Device not found.'}, status=status.HTTP_404_NOT_FOUND)
        if device.owner and device.owner != request.user:
            return Response({'detail': 'Device already claimed.'}, status=status.HTTP_409_CONFLICT)
        if device.owner is None:
            device.owner = request.user
            device.save()
        # If already owned by user, return ok
        return Response(DeviceSerializer(device).data, status=status.HTTP_200_OK)

class DeviceListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = DeviceSerializer

    def get_queryset(self):
        return Device.objects.filter(owner=self.request.user)

class DeviceDetailView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated, IsDeviceOwner]
    serializer_class = DeviceSerializer

    def get_queryset(self):
        return Device.objects.filter(owner=self.request.user)

    def update(self, request, *args, **kwargs):
        # Only allow nickname update
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        # Ensure only nickname is updated (fields other than nickname are ignored)
        instance.nickname = serializer.validated_data.get('nickname', instance.nickname)
        instance.save()
        return Response(DeviceSerializer(instance).data)

class ReleaseDeviceView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated, IsDeviceOwner]

    def post(self, request, pk=None):
        device = get_object_or_404(Device, pk=pk, owner=request.user)
        device.owner = None
        device.save()
        return Response({'detail': 'Device released successfully.'}, status=status.HTTP_200_OK)

class DeviceHistoryView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated, IsDeviceOwner]
    serializer_class = LocationPingSerializer

    def get_queryset(self):
        device_id = self.kwargs['pk']
        device = get_object_or_404(Device, pk=device_id, owner=self.request.user)
        qs = device.locations.all()
        since = self.request.query_params.get('since')
        if since:
            from django.utils import dateparse
            dt = dateparse.parse_datetime(since)
            if dt:
                qs = qs.filter(recorded_at__gte=dt)
        limit = self.request.query_params.get('limit', 100)
        try:
            limit = int(limit)
            if limit > 1000:
                limit = 1000
        except ValueError:
            limit = 100
        return qs[:limit]
    


class DeviceIngestView(APIView):
    authentication_classes = [DeviceAPIKeyAuthentication]
    permission_classes = []  # no user permission required
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'device_ingest'

    def post(self, request):
        # The authenticated device is the request.user (we set it to device object)
        device = request.user  # because we returned (device, None) in authentication
        data = request.data
        # Validate required fields
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        if latitude is None or longitude is None:
            return Response({'detail': 'latitude and longitude required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            lat = float(latitude)
            lon = float(longitude)
            if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
                raise ValueError
        except (TypeError, ValueError):
            return Response({'detail': 'latitude must be -90..90, longitude -180..180'}, status=status.HTTP_400_BAD_REQUEST)

        recorded_at = data.get('recorded_at')
        if recorded_at:
            try:
                from django.utils import dateparse
                recorded_at = dateparse.parse_datetime(recorded_at)
                if not recorded_at:
                    raise ValueError
            except:
                return Response({'detail': 'recorded_at must be ISO 8601 datetime'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            from django.utils import timezone
            recorded_at = timezone.now()

        # Create location ping
        location = LocationPing.objects.create(
            device=device,
            latitude=lat,
            longitude=lon,
            battery_level=data.get('battery_level'),
            recorded_at=recorded_at
        )
        # Update device last_seen and battery_level
        device.last_seen = location.recorded_at
        if data.get('battery_level') is not None:
            device.battery_level = data.get('battery_level')
        device.save(update_fields=['last_seen', 'battery_level'])

        return Response({'status': 'ok'}, status=status.HTTP_201_CREATED)