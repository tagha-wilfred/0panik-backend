from rest_framework.throttling import SimpleRateThrottle

class DeviceIngestRateThrottle(SimpleRateThrottle):
    """
    Rate limit for device location ingestion.
    Uses the device's API key as the throttle key for per-device limiting.
    """
    scope = 'device_ingest'
    
    def get_cache_key(self, request, view):
        """
        Generate a unique cache key for the request.
        Uses device API key if available, otherwise falls back to IP.
        """
        # Try to get device from request
        if hasattr(request, 'user'):
            # If user is a Device object with api_key
            if hasattr(request.user, 'api_key'):
                return self.cache_format % {
                    'scope': self.scope,
                    'ident': request.user.api_key
                }
            # If user has an id (fallback)
            elif hasattr(request.user, 'id'):
                return self.cache_format % {
                    'scope': self.scope,
                    'ident': f"device_{request.user.id}"
                }
        
        # Fallback to IP address
        return self.cache_format % {
            'scope': self.scope,
            'ident': self.get_ident(request)
        }