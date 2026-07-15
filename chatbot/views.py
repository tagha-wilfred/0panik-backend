import re
import requests
from django.conf import settings
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from .models import ScamCheck
from .serializers import ScamCheckSerializer
from rest_framework import serializers

class ChatbotCheckView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.Serializer  # custom

    def post(self, request):
        text = request.data.get('text', '').strip()
        if not text:
            return Response({'detail': 'text field is required'}, status=status.HTTP_400_BAD_REQUEST)
        if len(text) > 5000:
            return Response({'detail': 'text too long (max 5000)'}, status=status.HTTP_400_BAD_REQUEST)

        # 1. Extract URLs
        urls = re.findall(r'https?://[^\s]+', text)

        verdict = 'unknown'
        source = 'combined'
        reason = ''

        # 2. Check Safe Browsing if API key present and URLs found
        safe_browsing_available = bool(settings.GOOGLE_SAFE_BROWSING_API_KEY)
        safe_browsing_flagged = False
        if urls and safe_browsing_available:
            try:
                # Google Safe Browsing API v4
                api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
                payload = {
                    "client": {"clientId": "0panik", "clientVersion": "1.0.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url} for url in urls]
                    }
                }
                response = requests.post(
                    f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}',
                    json=payload,
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('matches'):
                        safe_browsing_flagged = True
                        reason = "Flagged by Google Safe Browsing."
                else:
                    # Log error but continue
                    pass
            except Exception:
                # Timeout or other error; fall back to heuristics
                safe_browsing_available = False  # treat as unavailable

        if safe_browsing_flagged:
            verdict = 'risky'
            source = 'safe_browsing'
            if not reason:
                reason = 'Malicious URL detected.'
        else:
            # 3. Heuristics
            heuristics_flagged = False
            heuristic_reason = ''
            # Suspicious TLDs / IP-based URLs
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', text):
                heuristics_flagged = True
                heuristic_reason = 'IP-based URL detected.'
            # Common phishing keywords
            phishing_keywords = ['urgent', 'verify your account', 'you have won', 'send otp', 'password reset']
            for kw in phishing_keywords:
                if kw.lower() in text.lower():
                    heuristics_flagged = True
                    heuristic_reason = f'Contains suspicious phrase: "{kw}"'
                    break
            # Lookalike domains (simplified)
            if re.search(r'https?://[a-z0-9-]+\.(com|org|net)\.[a-z]{2,}', text):
                heuristics_flagged = True
                heuristic_reason = 'Suspicious domain structure.'

            if heuristics_flagged:
                verdict = 'risky'
                source = 'heuristic'
                reason = heuristic_reason
            else:
                # If no URL and no heuristics -> safe
                if not urls:
                    # No URL present, and heuristics didn't flag -> safe
                    verdict = 'safe'
                    source = 'combined'
                    reason = 'No suspicious content detected.'
                else:
                    # URLs present but Safe Browsing didn't flag and heuristics didn't flag -> safe
                    verdict = 'safe'
                    source = 'combined'
                    reason = 'No threat detected.'

        # If Safe Browsing unavailable and we couldn't decide, fallback unknown
        if not safe_browsing_available and not heuristics_flagged and urls:
            # We had URLs but could not check and heuristics didn't flag -> unknown
            verdict = 'unknown'
            source = 'heuristic'
            reason = 'External check unavailable; heuristics found no clear threat.'

        # Log the check
        ScamCheck.objects.create(
            user=request.user,
            submitted_text=text,
            verdict=verdict,
            reason=reason,
            source=source
        )

        return Response({
            'verdict': verdict,
            'reason': reason,
            'checked_at': request.timestamp  # we'll set in middleware? not critical
        }, status=status.HTTP_200_OK)
    

class ChatbotHistoryView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ScamCheckSerializer

    def get_queryset(self):
        return ScamCheck.objects.filter(user=self.request.user).order_by('-created_at')