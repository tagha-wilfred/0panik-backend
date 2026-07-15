from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import Device

class DeviceAPIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        api_key = request.headers.get('X-Device-Key')
        serial_number = request.data.get('serial_number')
        if not api_key or not serial_number:
            return None
        try:
            device = Device.objects.get(api_key=api_key, serial_number=serial_number)
        except Device.DoesNotExist:
            raise AuthenticationFailed('Invalid device credentials')
        return (device, None)  # user=None, auth=Device