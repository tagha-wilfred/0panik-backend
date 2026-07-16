
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from accounts.views import RegisterView, LoginView, LogoutView, UserProfileView
from devices.views import (
    ClaimDeviceView, DeviceListView, DeviceDetailView, 
    ReleaseDeviceView, DeviceHistoryView, DeviceIngestView
)
from chatbot.views import ChatbotCheckView, ChatbotHistoryView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework.response import Response

urlpatterns = [
    path('admin/', admin.site.urls),

    # API version prefix
    path('api/v1/', include([
        # Auth
        path('auth/register/', RegisterView.as_view(), name='register'),
        path('auth/login/', LoginView.as_view(), name='login'),
        path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
        path('auth/logout/', LogoutView.as_view(), name='logout'),
        path('auth/me/', UserProfileView.as_view(), name='user_profile'),

        # Devices
        path('devices/claim/', ClaimDeviceView.as_view(), name='claim_device'),
        path('devices/', DeviceListView.as_view(), name='device_list'),
        path('devices/<uuid:pk>/', DeviceDetailView.as_view(), name='device_detail'),
        path('devices/<uuid:pk>/release/', ReleaseDeviceView.as_view(), name='device_release'),
        path('devices/<uuid:pk>/history/', DeviceHistoryView.as_view(), name='device_history'),

        # Location ingestion (device-facing)
        path('devices/ingest/location/', DeviceIngestView.as_view(), name='device_ingest'),

        # Chatbot
        path('chatbot/check/', ChatbotCheckView.as_view(), name='chatbot_check'),
        path('chatbot/history/', ChatbotHistoryView.as_view(), name='chatbot_history'),

        # Health check
        path('health/', lambda request: Response({'status': 'ok'}), name='health_check'),
    ])),

    # OpenAPI documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]