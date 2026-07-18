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
from .url_analyzer import URLSecurityAnalyzer

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
        
    #     # Log incoming data
    #     logger.info(f"Chatbot request from user {request.user.email}")
        
    #     # Validate with serializer
    #     serializer = self.get_serializer(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #     text = serializer.validated_data['text']
        
    #     # Extract URLs
    #     urls = extract_urls(text)
    #     url_checked = urls[0] if urls else None
        
    #     logger.info(f"Extracted URLs: {urls}")
        
    #     # --- Initialize all variables ---
    #     verdict = 'unknown'
    #     source = 'combined'
    #     reason = ''
    #     safe_browsing_data = None
    #     safe_browsing_available = False
    #     safe_browsing_flagged = False
    #     advanced_findings = []
        
    #     # --- Stage 1: Google Safe Browsing ---
    #     safe_browsing_available = bool(getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', ''))
        
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
    #             else:
    #                 if result.get('error'):
    #                     logger.warning(f"Safe Browsing error: {result.get('error')}")
    #         except Exception as e:
    #             logger.error(f"Safe Browsing check failed: {str(e)}", exc_info=True)
        
    #     # --- Stage 1.5: Advanced URL Analysis ---
    #     if urls and not safe_browsing_flagged and getattr(settings, 'ENABLE_ADVANCED_URL_ANALYSIS', True):
    #         logger.info(f"Running advanced URL analysis on: {urls[0]}")
    #         try:
    #             analysis = URLSecurityAnalyzer.analyze_url(urls[0])
    #             advanced_findings = analysis.get('findings', [])
                
    #             # If advanced analysis found something suspicious
    #             if analysis.get('is_suspicious', False):
    #                 if verdict == 'safe' or verdict == 'unknown':
    #                     verdict = 'unknown'
                    
    #                 finding_messages = [f.get('message', '') for f in advanced_findings if f.get('severity') in ['critical', 'high']]
    #                 if finding_messages:
    #                     if reason:
    #                         reason += ' | Advanced analysis: ' + ' | '.join(finding_messages[:2])
    #                     else:
    #                         reason = 'Advanced analysis: ' + ' | '.join(finding_messages[:2])
    #                     source = 'combined'
    #                     logger.info(f"Advanced URL analysis found issues: {finding_messages}")
    #         except Exception as e:
    #             logger.error(f"Advanced URL analysis failed: {str(e)}")
        
    #     # --- Stage 2: Heuristics (if not flagged by Safe Browsing) ---
    #     if not safe_browsing_flagged:
    #         heuristics_flagged = False
    #         heuristic_reasons = []
            
    #         # Check text for phishing keywords
    #         is_flagged, keyword_reason = check_phishing_keywords(text)
    #         if is_flagged:
    #             heuristics_flagged = True
    #             heuristic_reasons.append(keyword_reason)
    #             logger.info(f"Phishing keyword found: {keyword_reason}")
            
    #         # Check URL patterns
    #         if urls:
    #             url = urls[0]
    #             is_flagged, url_reason = check_suspicious_patterns(url, text)
    #             if is_flagged:
    #                 heuristics_flagged = True
    #                 heuristic_reasons.append(url_reason)
    #                 logger.info(f"Suspicious URL pattern: {url_reason}")
                
    #             is_short, short_reason = check_short_urls(url)
    #             if is_short:
    #                 heuristics_flagged = True
    #                 heuristic_reasons.append(short_reason)
    #                 logger.info(f"Short URL detected: {short_reason}")
            
    #         if heuristics_flagged:
    #             verdict = 'risky'
    #             source = 'heuristic'
    #             reason = ' | '.join(heuristic_reasons)
    #             logger.info(f"Heuristics flagged content: {reason}")
    #         else:
    #             if not urls:
    #                 verdict = 'safe'
    #                 source = 'combined'
    #                 reason = 'No suspicious content detected'
    #             else:
    #                 if safe_browsing_available:
    #                     verdict = 'safe'
    #                     source = 'combined'
    #                     reason = 'No threat detected by Safe Browsing or heuristics'
    #                 else:
    #                     verdict = 'unknown'
    #                     source = 'heuristic'
    #                     reason = 'Safe Browsing unavailable; heuristics found no clear threat'
        
    #     # --- Stage 3: Fallback for unknown ---
    #     if verdict == 'unknown' and not safe_browsing_available:
    #         if urls:
    #             reason = 'Could not verify URL safety (external check unavailable)'
    #         else:
    #             reason = 'Could not determine safety (no URL found for external check)'
        
    #     # --- Log the check ---
    #     try:
    #         combined_response = {
    #             'safe_browsing': safe_browsing_data,
    #             'advanced_findings': advanced_findings
    #         }
            
    #         scam_check = ScamCheck.objects.create(
    #             user=request.user,
    #             submitted_text=text,
    #             verdict=verdict,
    #             reason=reason,
    #             source=source,
    #             url_checked=url_checked,
    #             safe_browsing_response=combined_response if combined_response else None
    #         )
    #     except Exception as e:
    #         logger.error(f"Failed to save ScamCheck: {str(e)}")
    #         class MockScamCheck:
    #             created_at = timezone.now()
    #         scam_check = MockScamCheck()
        
    #     # Log final verdict
    #     logger.info(f"Final verdict: {verdict} - {reason}")
        
    #     # --- Return response ---
    #     return Response({
    #         'verdict': verdict,
    #         'reason': reason,
    #         'source': source,
    #         'checked_at': scam_check.created_at.isoformat(),
    #         'url_checked': url_checked,
    #         'submitted_text': text,
    #         'advanced_findings_count': len(advanced_findings),
    #         'message': 'Analysis complete'
    #     }, status=status.HTTP_200_OK)
    def post(self, request):
        # Accept either 'text' or 'submitted_text' from frontend
        if 'submitted_text' in request.data and 'text' not in request.data:
            request.data['text'] = request.data['submitted_text']
        
        # Log incoming data
        logger.info(f"Chatbot request from user {request.user.email}")
        
        # Validate with serializer
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        text = serializer.validated_data['text']
        
        # Extract URLs
        urls = extract_urls(text)
        url_checked = urls[0] if urls else None
        
        logger.info(f"Extracted URLs: {urls}")
        
        # --- Initialize all variables ---
        verdict = 'unknown'
        source = 'combined'
        reason = ''
        safe_browsing_data = None
        safe_browsing_available = False
        safe_browsing_flagged = False
        advanced_findings = []
        
        # --- Stage 1: Google Safe Browsing ---
        safe_browsing_available = bool(getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', ''))
        
        if urls and safe_browsing_available:
            logger.info(f"Checking URL against Safe Browsing: {urls[0]}")
            try:
                result = SafeBrowsingChecker.check_url(urls[0])
                safe_browsing_data = result.get('response')
                
                if result['is_flagged']:
                    safe_browsing_flagged = True
                    reason = result['reason']
                    source = 'safe_browsing'
                    verdict = 'risky'
                    logger.info(f"✅ Safe Browsing flagged URL: {urls[0]}")
                else:
                    logger.info(f"❌ Safe Browsing did NOT flag URL: {urls[0]}")
                    if result.get('error'):
                        logger.warning(f"Safe Browsing error: {result.get('error')}")
            except Exception as e:
                logger.error(f"Safe Browsing check failed: {str(e)}", exc_info=True)
        
        # --- Stage 1.5: Advanced URL Analysis ---
        logger.info("=" * 60)
        logger.info("🔍 ADVANCED URL ANALYSIS DEBUG")
        logger.info(f"  urls: {urls}")
        logger.info(f"  safe_browsing_flagged: {safe_browsing_flagged}")
        logger.info(f"  ENABLE_ADVANCED_URL_ANALYSIS: {getattr(settings, 'ENABLE_ADVANCED_URL_ANALYSIS', True)}")
        logger.info("=" * 60)
        
        if urls and not safe_browsing_flagged and getattr(settings, 'ENABLE_ADVANCED_URL_ANALYSIS', True):
            logger.info(f"🔍 Running advanced URL analysis on: {urls[0]}")
            try:
                # Test the analyzer directly and log everything
                analysis = URLSecurityAnalyzer.analyze_url(urls[0])
                logger.info(f"🔍 Full analysis result: {analysis}")
                
                advanced_findings = analysis.get('findings', [])
                logger.info(f"🔍 Findings: {advanced_findings}")
                
                # If advanced analysis found something suspicious
                if analysis.get('is_suspicious', False):
                    logger.info("🔍 ✅ Analysis says URL IS SUSPICIOUS")
                    if verdict == 'safe' or verdict == 'unknown':
                        verdict = 'unknown'
                    
                    finding_messages = [f.get('message', '') for f in advanced_findings if f.get('severity') in ['critical', 'high']]
                    if finding_messages:
                        if reason:
                            reason += ' | Advanced analysis: ' + ' | '.join(finding_messages[:2])
                        else:
                            reason = 'Advanced analysis: ' + ' | '.join(finding_messages[:2])
                        source = 'combined'
                        logger.info(f"🔍 Setting reason to: {reason}")
                else:
                    logger.info("🔍 ❌ Analysis says URL is NOT suspicious")
                    
            except Exception as e:
                logger.error(f"Advanced URL analysis failed: {str(e)}", exc_info=True)
        else:
            logger.info("🔍 Advanced analysis skipped:")
            if not urls:
                logger.info("  - No URLs found")
            if safe_browsing_flagged:
                logger.info("  - Safe Browsing already flagged")
            if not getattr(settings, 'ENABLE_ADVANCED_URL_ANALYSIS', True):
                logger.info("  - Feature disabled")
        
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
            combined_response = {
                'safe_browsing': safe_browsing_data,
                'advanced_findings': advanced_findings
            }
            
            scam_check = ScamCheck.objects.create(
                user=request.user,
                submitted_text=text,
                verdict=verdict,
                reason=reason,
                source=source,
                url_checked=url_checked,
                safe_browsing_response=combined_response if combined_response else None
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
            'advanced_findings_count': len(advanced_findings),
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