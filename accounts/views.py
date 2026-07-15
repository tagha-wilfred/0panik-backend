from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from .serializers import RegisterSerializer, UserSerializer
from rest_framework.throttling import ScopedRateThrottle
from rest_framework import serializers

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'register'

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)

class LoginView(TokenObtainPairView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'login'
    # Use default SimpleJWT view, but we customize response to include user data
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            user = User.objects.get(email=request.data['email'])
            response.data['user'] = UserSerializer(user).data
        return response

class TokenRefreshView(TokenRefreshView):
    pass  # default

class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.Serializer  # dummy

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({'detail': 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'detail': 'Logged out successfully'}, status=status.HTTP_205_RESET_CONTENT)
        except TokenError:
            return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user