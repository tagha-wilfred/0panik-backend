import logging
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.conf import settings
from django.utils import timezone
from .models import ScamCheck
from .serializers import ScamCheckSerializer, ChatbotCheckSerializer
from .utils import (
    extract_urls, 
    check_phishing_keywords, 
    check_suspicious_patterns,
    check_short_urls
)
from .safe_browsing import SafeBrowsingChecker

logger = logging.getLogger(__name__)

class ChatbotCheckView(generics.GenericAPIView):
    """
    Check a message or URL for scams/phishing/fake news.
    Accepts either 'text' or 'submitted_text' as the input field.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChatbotCheckSerializer
    
    # def post(self, request):
    #     # Accept either 'text' or 'submitted_text' from frontend
    #     if 'submitted_text' in request.data and 'text' not in request.data:
    #         request.data['text'] = request.data['submitted_text']
        
    #     # Log incoming data for debugging (remove in production)
    #     logger.debug(f"Received data: {request.data}")
        
    #     # Validate with serializer
    #     serializer = self.get_serializer(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #     text = serializer.validated_data['text']
        
    #     # Extract URLs
    #     urls = extract_urls(text)
    #     url_checked = urls[0] if urls else None
        
    #     verdict = 'unknown'
    #     source = 'combined'
    #     reason = ''
    #     safe_browsing_data = None
        
    #     # --- Stage 1: Google Safe Browsing ---
    #     safe_browsing_available = bool(getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', ''))
    #     safe_browsing_flagged = False
        
    #     if urls and safe_browsing_available:
    #         logger.info(f"Checking URL against Safe Browsing: {urls[0]}")
    #         try:
    #             result = SafeBrowsingChecker.check_url(urls[0])
    #             safe_browsing_data = result.get('response')
                
    #             if result['is_flagged']:
    #                 safe_browsing_flagged = True
    #                 reason = result['reason']
    #                 source = 'safe_browsing'
    #                 verdict = 'risky'
    #                 logger.info(f"Safe Browsing flagged URL: {urls[0]}")
    #         except Exception as e:
    #             logger.error(f"Safe Browsing check failed: {str(e)}")
    #             # Continue to heuristics
        
    #     # --- Stage 2: Heuristics (if not flagged by Safe Browsing) ---
    #     if not safe_browsing_flagged:
    #         heuristics_flagged = False
    #         heuristic_reasons = []
            
    #         # Check text for phishing keywords
    #         is_flagged, keyword_reason = check_phishing_keywords(text)
    #         if is_flagged:
    #             heuristics_flagged = True
    #             heuristic_reasons.append(keyword_reason)
            
    #         # Check URL patterns
    #         if urls:
    #             url = urls[0]
    #             is_flagged, url_reason = check_suspicious_patterns(url, text)
    #             if is_flagged:
    #                 heuristics_flagged = True
    #                 heuristic_reasons.append(url_reason)
                
    #             # Check short URLs
    #             is_short, short_reason = check_short_urls(url)
    #             if is_short:
    #                 heuristics_flagged = True
    #                 heuristic_reasons.append(short_reason)
            
    #         if heuristics_flagged:
    #             verdict = 'risky'
    #             source = 'heuristic'
    #             reason = ' | '.join(heuristic_reasons)
    #             logger.info(f"Heuristics flagged content: {reason}")
    #         else:
    #             # No threats detected
    #             if not urls:
    #                 # No URL present and no heuristics -> safe
    #                 verdict = 'safe'
    #                 source = 'combined'
    #                 reason = 'No suspicious content detected'
    #             else:
    #                 # URLs present but no flags
    #                 if safe_browsing_available:
    #                     verdict = 'safe'
    #                     source = 'combined'
    #                     reason = 'No threat detected by Safe Browsing or heuristics'
    #                 else:
    #                     # Safe Browsing unavailable, heuristics found nothing
    #                     verdict = 'unknown'
    #                     source = 'heuristic'
    #                     reason = 'Safe Browsing unavailable; heuristics found no clear threat'
        
    #     # --- Stage 3: Fallback for unknown ---
    #     if verdict == 'unknown' and not safe_browsing_available:
    #         # If we couldn't check and heuristics didn't flag
    #         if urls:
    #             reason = 'Could not verify URL safety (external check unavailable)'
    #         else:
    #             reason = 'Could not determine safety (no URL found for external check)'
        
    #     # --- Log the check ---
    #     try:
    #         scam_check = ScamCheck.objects.create(
    #             user=request.user,
    #             submitted_text=text,
    #             verdict=verdict,
    #             reason=reason,
    #             source=source,
    #             url_checked=url_checked,
    #             safe_browsing_response=safe_browsing_data
    #         )
    #     except Exception as e:
    #         logger.error(f"Failed to save ScamCheck: {str(e)}")
    #         # Still return the result even if logging fails
    #         # Create a mock object for the response
    #         class MockScamCheck:
    #             created_at = timezone.now()
    #         scam_check = MockScamCheck()
        
    #     # --- Return response ---
    #     return Response({
    #         'verdict': verdict,
    #         'reason': reason,
    #         'source': source,
    #         'checked_at': scam_check.created_at.isoformat(),
    #         'url_checked': url_checked,
    #         'submitted_text': text,  # Include original text for frontend display
    #         'message': 'Analysis complete'
    #     }, status=status.HTTP_200_OK)
def post(self, request):
    # Accept either 'text' or 'submitted_text' from frontend
    if 'submitted_text' in request.data and 'text' not in request.data:
        request.data['text'] = request.data['submitted_text']
    
    # Log incoming data
    logger.info(f"Chatbot request from user {request.user.email}: {request.data.get('text', '')[:100]}...")
    
    # Validate with serializer
    serializer = self.get_serializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    text = serializer.validated_data['text']
    
    # Extract URLs
    urls = extract_urls(text)
    url_checked = urls[0] if urls else None
    
    logger.info(f"Extracted URLs: {urls}")
    
    verdict = 'unknown'
    source = 'combined'
    reason = ''
    safe_browsing_data = None
    
    # --- Stage 1: Google Safe Browsing ---
    safe_browsing_available = bool(getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', ''))
    safe_browsing_flagged = False
    
    logger.info(f"Safe Browsing available: {safe_browsing_available}")
    logger.info(f"URLs to check: {urls}")
    
    if urls and safe_browsing_available:
        logger.info(f"Checking URL against Safe Browsing: {urls[0]}")
        try:
            result = SafeBrowsingChecker.check_url(urls[0])
            logger.info(f"Safe Browsing result: {result}")
            safe_browsing_data = result.get('response')
            
            if result['is_flagged']:
                safe_browsing_flagged = True
                reason = result['reason']
                source = 'safe_browsing'
                verdict = 'risky'
                logger.info(f"✅ Safe Browsing flagged URL: {urls[0]}")
            else:
                logger.info(f"❌ Safe Browsing did NOT flag URL: {urls[0]}")
                logger.info(f"Reason: {result.get('reason')}")
                if result.get('error'):
                    logger.warning(f"Safe Browsing error: {result.get('error')}")
        except Exception as e:
            logger.error(f"Safe Browsing check failed: {str(e)}", exc_info=True)
            # Continue to heuristics
    else:
        if not safe_browsing_available:
            logger.warning("Safe Browsing API key not configured")
        if not urls:
            logger.info("No URLs found to check")
    
    # --- Stage 2: Heuristics (if not flagged by Safe Browsing) ---
    if not safe_browsing_flagged:
        heuristics_flagged = False
        heuristic_reasons = []
        
        # Check text for phishing keywords
        is_flagged, keyword_reason = check_phishing_keywords(text)
        if is_flagged:
            heuristics_flagged = True
            heuristic_reasons.append(keyword_reason)
            logger.info(f"Phishing keyword found: {keyword_reason}")
        
        # Check URL patterns
        if urls:
            url = urls[0]
            is_flagged, url_reason = check_suspicious_patterns(url, text)
            if is_flagged:
                heuristics_flagged = True
                heuristic_reasons.append(url_reason)
                logger.info(f"Suspicious URL pattern: {url_reason}")
            
            # Check short URLs
            is_short, short_reason = check_short_urls(url)
            if is_short:
                heuristics_flagged = True
                heuristic_reasons.append(short_reason)
                logger.info(f"Short URL detected: {short_reason}")
        
        if heuristics_flagged:
            verdict = 'risky'
            source = 'heuristic'
            reason = ' | '.join(heuristic_reasons)
            logger.info(f"Heuristics flagged content: {reason}")
        else:
            # No threats detected
            if not urls:
                verdict = 'safe'
                source = 'combined'
                reason = 'No suspicious content detected'
            else:
                if safe_browsing_available:
                    verdict = 'safe'
                    source = 'combined'
                    reason = 'No threat detected by Safe Browsing or heuristics'
                else:
                    verdict = 'unknown'
                    source = 'heuristic'
                    reason = 'Safe Browsing unavailable; heuristics found no clear threat'
    
    # --- Stage 3: Fallback for unknown ---
    if verdict == 'unknown' and not safe_browsing_available:
        if urls:
            reason = 'Could not verify URL safety (external check unavailable)'
        else:
            reason = 'Could not determine safety (no URL found for external check)'
    
    # --- Log the check ---
    try:
        scam_check = ScamCheck.objects.create(
            user=request.user,
            submitted_text=text,
            verdict=verdict,
            reason=reason,
            source=source,
            url_checked=url_checked,
            safe_browsing_response=safe_browsing_data
        )
    except Exception as e:
        logger.error(f"Failed to save ScamCheck: {str(e)}")
        class MockScamCheck:
            created_at = timezone.now()
        scam_check = MockScamCheck()
    
    # Log final verdict
    logger.info(f"Final verdict: {verdict} - {reason}")
    
    # --- Return response ---
    return Response({
        'verdict': verdict,
        'reason': reason,
        'source': source,
        'checked_at': scam_check.created_at.isoformat(),
        'url_checked': url_checked,
        'submitted_text': text,
        'message': 'Analysis complete'
    }, status=status.HTTP_200_OK)

class ChatbotHistoryView(generics.ListAPIView):
    """
    Get the user's past scam check history.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ScamCheckSerializer
    
    def get_queryset(self):
        return ScamCheck.objects.filter(user=self.request.user)