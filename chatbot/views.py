import logging
import re
import urllib.parse
import socket
import ssl
import whois
from datetime import datetime, timedelta
from urllib.parse import urlparse
from difflib import SequenceMatcher

from rest_framework import generics, permissions, status, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from django.conf import settings
from .models import ChatSession, ChatMessage, ScamCheck
from .serializers import (
    ChatSessionSerializer, 
    ChatMessageSerializer,
    ScamCheckSerializer
)
from .safe_browsing import SafeBrowsingChecker
from .ai_service import AIService

logger = logging.getLogger(__name__)

# Initialize AI service
ai_service = AIService()


class URLSecurityAnalyzer:
    """
    Comprehensive URL security analyzer with multiple detection methods.
    """
    
    # Known brand list for typo detection
    BRAND_LIST = [
        'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix',
        'paypal', 'ebay', 'walmart', 'target', 'bestbuy', 'homedepot',
        'lowes', 'costco', 'kroger', 'walgreens', 'cvs', 'bankofamerica',
        'chase', 'wellsfargo', 'citibank', 'capitalone', 'amex',
        'discover', 'mastercard', 'visa', 'instagram', 'twitter',
        'linkedin', 'youtube', 'spotify', 'slack', 'zoom', 'github',
        'gitlab', 'atlassian', 'salesforce', 'oracle', 'ibm', 'cisco'
    ]
    
    # URL shorteners
    SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'shorturl.at', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'tiny.cc',
        'linktr.ee', 't.co', 'rb.gy', 'short.link', 'v.gd', 'qr.ae',
        'lnkd.in', 'g.co', 'm.me', 'fb.com'
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.online', '.site', '.space']
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = ['.exe', '.js', '.hta', '.scr', '.vbs', '.bat', '.cmd', '.ps1', '.jar']
    
    @classmethod
    def analyze_url(cls, url: str) -> dict:
        """
        Perform comprehensive analysis on a URL.
        Returns dict with findings, severity, and overall verdict.
        """
        findings = []
        severity = 'safe'  # safe, low, medium, medium_high, high, critical
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query
            
            # Remove www. prefix for analysis
            clean_domain = domain.replace('www.', '')
            
            # --- Check 1: Brand name positioning (Critical) ---
            brand_finding = cls._check_brand_position(url, domain, clean_domain)
            if brand_finding:
                findings.append(brand_finding)
                severity = cls._update_severity(severity, 'critical')
            
            # --- Check 2: Typo/character-swap detection (Critical) ---
            typo_finding = cls._check_typo_domain(domain, clean_domain)
            if typo_finding:
                findings.append(typo_finding)
                severity = cls._update_severity(severity, 'critical')
            
            # --- Check 3: Punycode/IDN detection (Critical) ---
            punycode_finding = cls._check_punycode(domain)
            if punycode_finding:
                findings.append(punycode_finding)
                severity = cls._update_severity(severity, 'critical')
            
            # --- Check 4: Display text vs href mismatch (Critical) ---
            # This is handled at the text level separately
            
            # --- Check 5: @ symbol in URL (Critical) ---
            at_symbol_finding = cls._check_at_symbol(url)
            if at_symbol_finding:
                findings.append(at_symbol_finding)
                severity = cls._update_severity(severity, 'critical')
            
            # --- Check 6: IP address instead of domain (High) ---
            ip_finding = cls._check_ip_address(domain)
            if ip_finding:
                findings.append(ip_finding)
                severity = cls._update_severity(severity, 'high')
            
            # --- Check 7: Domain age (High) ---
            whois_finding = cls._check_domain_age(clean_domain)
            if whois_finding:
                findings.append(whois_finding)
                severity = cls._update_severity(severity, 'high')
            
            # --- Check 8: HTTPS/SSL check (Medium-High) ---
            ssl_finding = cls._check_ssl(url, domain)
            if ssl_finding:
                findings.append(ssl_finding)
                severity = cls._update_severity(severity, 'medium_high')
            
            # --- Check 9: Dangerous file extensions (Critical) ---
            extension_finding = cls._check_dangerous_extension(path)
            if extension_finding:
                findings.append(extension_finding)
                severity = cls._update_severity(severity, 'critical')
            
            # --- Check 10: URL shorteners (Low) ---
            shortener_finding = cls._check_shortener(domain)
            if shortener_finding:
                findings.append(shortener_finding)
                # Only escalate if combined with other flags
                if len(findings) > 1:
                    severity = cls._update_severity(severity, 'medium')
            
            # --- Check 11: Excess subdomains/hyphens (Medium) ---
            subdomain_finding = cls._check_subdomains(domain, clean_domain)
            if subdomain_finding:
                findings.append(subdomain_finding)
                severity = cls._update_severity(severity, 'medium')
            
            # --- Check 12: Suspicious TLD (Medium) ---
            tld_finding = cls._check_tld(clean_domain)
            if tld_finding:
                findings.append(tld_finding)
                severity = cls._update_severity(severity, 'medium')
            
        except Exception as e:
            logger.error(f"URL analysis error: {str(e)}")
            findings.append({
                'type': 'analysis_error',
                'severity': 'unknown',
                'message': f'Analysis error: {str(e)}'
            })
        
        return {
            'findings': findings,
            'overall_severity': severity,
            'findings_count': len(findings),
            'url_analyzed': url
        }
    
    @classmethod
    def _update_severity(cls, current: str, new: str) -> str:
        """Update severity to the highest level."""
        levels = ['safe', 'low', 'medium', 'medium_high', 'high', 'critical']
        current_idx = levels.index(current)
        new_idx = levels.index(new)
        return levels[max(current_idx, new_idx)]
    
    @classmethod
    def _check_brand_position(cls, url: str, domain: str, clean_domain: str) -> dict:
        """
        Check if a brand name appears in a suspicious position.
        e.g., paypal in paypal.secure-login.ru (Critical)
        """
        for brand in cls.BRAND_LIST:
            if brand in clean_domain:
                # Check if brand appears before the domain suffix
                parts = clean_domain.split('.')
                if len(parts) > 2:
                    # Check if brand is in subdomain but not in the main domain
                    main_domain = parts[-2] if len(parts) >= 2 else ''
                    if brand != main_domain and brand in url.lower():
                        return {
                            'type': 'brand_misposition',
                            'severity': 'critical',
                            'message': f'Brand "{brand}" appears in suspicious position',
                            'detail': f'URL contains "{brand}" but the main domain is "{main_domain}"'
                        }
        return None
    
    @classmethod
    def _check_typo_domain(cls, domain: str, clean_domain: str) -> dict:
        """
        Check if domain is a character-swap/typo of a known brand.
        Uses string-distance matching (Critical)
        """
        for brand in cls.BRAND_LIST:
            # Skip if it's an exact match (legitimate)
            if brand == clean_domain or brand == domain:
                continue
            
            # Calculate similarity ratio
            ratio = SequenceMatcher(None, brand, clean_domain).ratio()
            
            # Check for common typo patterns
            # 1. Character substitution (paypa1.com vs paypal.com)
            if ratio > 0.85 and ratio < 0.99:
                # Check if it's a known typo pattern
                diff_chars = sum(a != b for a, b in zip(brand, clean_domain))
                if diff_chars <= 2:  # Only 1-2 characters different
                    return {
                        'type': 'typo_domain',
                        'severity': 'critical',
                        'message': f'Domain appears to be a typo of "{brand}"',
                        'detail': f'"{domain}" is suspiciously similar to "{brand}" (similarity: {ratio:.0%})'
                    }
        return None
    
    @classmethod
    def _check_punycode(cls, domain: str) -> dict:
        """
        Check for Punycode/IDN domains with lookalike characters.
        """
        if domain.startswith('xn--'):
            return {
                'type': 'punycode',
                'severity': 'critical',
                'message': 'Punycode/IDN domain detected',
                'detail': 'Domain uses internationalized characters that may disguise a different domain'
            }
        
        # Check for non-Latin characters in domain
        try:
            # Try to decode any punycode
            import idna
            decoded = idna.decode(domain)
            if decoded != domain:
                return {
                    'type': 'punycode',
                    'severity': 'critical',
                    'message': 'Punycode/IDN domain detected',
                    'detail': f'Domain "{domain}" decodes to "{decoded}" which may be misleading'
                }
        except:
            pass
        
        return None
    
    @classmethod
    def _check_at_symbol(cls, url: str) -> dict:
        """
        Check for @ symbol in URL (everything before @ is cosmetic).
        """
        if '@' in url and 'https://' in url:
            return {
                'type': 'at_symbol',
                'severity': 'critical',
                'message': 'URL contains @ symbol',
                'detail': 'The @ symbol can be used to disguise the actual destination'
            }
        return None
    
    @classmethod
    def _check_ip_address(cls, domain: str) -> dict:
        """
        Check if domain is an IP address instead of a domain name.
        """
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(domain.replace('www.', '')):
            return {
                'type': 'ip_address',
                'severity': 'high',
                'message': 'IP address used instead of domain name',
                'detail': f'Using IP address "{domain}" instead of a proper domain name is suspicious'
            }
        return None
    
    @classmethod
    def _check_domain_age(cls, domain: str) -> dict:
        """
        Check domain registration age using WHOIS.
        """
        try:
            # Remove subdomains for WHOIS check
            parts = domain.split('.')
            if len(parts) > 2:
                # Try to get the registered domain
                domain_for_whois = '.'.join(parts[-2:])
            else:
                domain_for_whois = domain
            
            # Query WHOIS with timeout
            w = whois.whois(domain_for_whois)
            if w.creation_date:
                # Handle list of dates
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                # Check if domain is recently registered
                days_old = (datetime.now() - creation_date).days
                if days_old < 90:
                    return {
                        'type': 'domain_age',
                        'severity': 'high',
                        'message': 'Domain registered recently',
                        'detail': f'Domain "{domain_for_whois}" was registered {days_old} days ago (less than 90 days)'
                    }
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {str(e)}")
            # WHOIS lookup failed - could be a sign of suspicious domain
            return {
                'type': 'domain_age_unknown',
                'severity': 'medium',
                'message': 'Could not verify domain age',
                'detail': 'Unable to check domain registration information'
            }
        return None
    
    @classmethod
    def _check_ssl(cls, url: str, domain: str) -> dict:
        """
        Check HTTPS/SSL certificate validity.
        """
        if not url.startswith('https://'):
            return {
                'type': 'no_https',
                'severity': 'medium_high',
                'message': 'No HTTPS encryption',
                'detail': 'URL does not use HTTPS - information sent in plain text'
            }
        
        # Try to check SSL certificate
        try:
            hostname = domain.replace('www.', '')
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                
            # Check if certificate matches domain
            cert_domains = []
            for entry in cert.get('subject', []):
                for item in entry:
                    if item[0] == 'commonName':
                        cert_domains.append(item[1])
            for entry in cert.get('subjectAltName', []):
                if entry[0] == 'DNS':
                    cert_domains.append(entry[1])
            
            if cert_domains and not any(domain in d or d in domain for d in cert_domains):
                return {
                    'type': 'ssl_mismatch',
                    'severity': 'medium_high',
                    'message': 'SSL certificate domain mismatch',
                    'detail': f'Certificate issued for {cert_domains[0]} but URL domain is {domain}'
                }
        except Exception as e:
            logger.debug(f"SSL check failed: {str(e)}")
            # Could not verify SSL - flag as caution
            return {
                'type': 'ssl_verify_failed',
                'severity': 'medium',
                'message': 'Could not verify SSL certificate',
                'detail': 'Unable to validate the security certificate'
            }
        
        return None
    
    @classmethod
    def _check_dangerous_extension(cls, path: str) -> dict:
        """
        Check for dangerous file extensions in URL path.
        """
        for ext in cls.DANGEROUS_EXTENSIONS:
            if path.endswith(ext):
                return {
                    'type': 'dangerous_extension',
                    'severity': 'critical',
                    'message': f'Dangerous file extension "{ext}" detected',
                    'detail': f'URL points to an executable or script file'
                }
        return None
    
    @classmethod
    def _check_shortener(cls, domain: str) -> dict:
        """
        Check if URL uses a shortener service.
        """
        clean_domain = domain.replace('www.', '')
        for shortener in cls.SHORTENERS:
            if shortener in clean_domain:
                return {
                    'type': 'url_shortener',
                    'severity': 'low',
                    'message': f'URL shortener "{shortener}" used',
                    'detail': 'Shortened URLs can hide the final destination'
                }
        return None
    
    @classmethod
    def _check_subdomains(cls, domain: str, clean_domain: str) -> dict:
        """
        Check for excess subdomains or hyphens mimicking a brand.
        """
        parts = clean_domain.split('.')
        subdomain_parts = parts[:-2] if len(parts) > 2 else []
        
        if len(subdomain_parts) > 2:
            return {
                'type': 'excess_subdomains',
                'severity': 'medium',
                'message': 'Multiple subdomains detected',
                'detail': f'URL uses {len(subdomain_parts)} subdomain levels which is unusual'
            }
        
        # Check for hyphens mimicking a brand
        for brand in cls.BRAND_LIST:
            if brand in clean_domain and '-' in clean_domain:
                # Check if it looks like a brand with hyphens (secure-paypal-login.com)
                return {
                    'type': 'hyphenated_brand',
                    'severity': 'medium',
                    'message': f'Hyphenated domain mimicking "{brand}"',
                    'detail': f'Domain "{clean_domain}" contains "{brand}" with hyphens, which is suspicious'
                }
        
        return None
    
    @classmethod
    def _check_tld(cls, domain: str) -> dict:
        """
        Check for suspicious TLDs.
        """
        for tld in cls.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return {
                    'type': 'suspicious_tld',
                    'severity': 'medium',
                    'message': f'Suspicious TLD "{tld}" used',
                    'detail': f'This TLD is commonly associated with scam websites'
                }
        return None


class ChatbotCheckView(generics.GenericAPIView):
    """
    Enhanced URL safety checker with comprehensive analysis.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChatbotCheckSerializer
    
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
        urls = self._extract_urls(text)
        url_checked = urls[0] if urls else None
        
        # Store all findings
        all_findings = []
        overall_verdict = 'safe'
        overall_reason = []
        source = 'combined'
        safe_browsing_data = None
        
        # --- Stage 1: Safe Browsing Check ---
        safe_browsing_flagged = False
        if urls:
            safe_browsing_result = self._check_safe_browsing(urls[0])
            if safe_browsing_result:
                safe_browsing_flagged = True
                all_findings.append(safe_browsing_result)
                overall_verdict = 'risky'
                overall_reason.append(safe_browsing_result.get('reason', 'Flagged by Safe Browsing'))
                source = 'safe_browsing'
        
        # --- Stage 2: Comprehensive URL Analysis ---
        if not safe_browsing_flagged and urls:
            analysis = URLSecurityAnalyzer.analyze_url(urls[0])
            all_findings.extend(analysis.get('findings', []))
            
            # Update verdict based on severity
            severity = analysis.get('overall_severity', 'safe')
            if severity in ['critical', 'high']:
                overall_verdict = 'risky'
            elif severity in ['medium_high', 'medium'] and not overall_verdict == 'risky':
                overall_verdict = 'unknown'
            
            # Build reason from findings
            for finding in analysis.get('findings', []):
                if finding.get('severity') in ['critical', 'high']:
                    overall_reason.append(finding.get('message', ''))
        
        # --- Stage 3: Heuristics on text (if no URLs or no flags) ---
        if not urls or (overall_verdict == 'safe' and not safe_browsing_flagged):
            heuristic_result = self._check_heuristics(text)
            if heuristic_result:
                all_findings.append(heuristic_result)
                if heuristic_result.get('severity') in ['critical', 'high']:
                    overall_verdict = 'risky'
                    overall_reason.append(heuristic_result.get('message', ''))
                elif overall_verdict == 'safe':
                    overall_verdict = 'unknown'
        
        # --- Stage 4: Final verdict ---
        if not all_findings:
            overall_verdict = 'safe'
            overall_reason = ['No suspicious content detected']
        
        # Log the check
        try:
            scam_check = ScamCheck.objects.create(
                user=request.user,
                submitted_text=text,
                verdict=overall_verdict,
                reason=' | '.join(overall_reason) if overall_reason else 'No issues detected',
                source=source,
                url_checked=url_checked,
                safe_browsing_response={'findings': all_findings}
            )
        except Exception as e:
            logger.error(f"Failed to save ScamCheck: {str(e)}")
            class MockScamCheck:
                created_at = timezone.now()
            scam_check = MockScamCheck()
        
        # --- Return response ---
        return Response({
            'verdict': overall_verdict,
            'reason': ' | '.join(overall_reason[:5]),  # Limit to prevent massive responses
            'source': source,
            'checked_at': timezone.now().isoformat(),
            'url_checked': url_checked,
            'submitted_text': text,
            'findings': all_findings[:10],  # Return top 10 findings for debugging
            'findings_count': len(all_findings),
            'message': 'Analysis complete'
        }, status=status.HTTP_200_OK)
    
    def _extract_urls(self, text: str) -> list:
        """Extract URLs from text using regex."""
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+'
        )
        return url_pattern.findall(text)
    
    def _check_safe_browsing(self, url: str) -> dict:
        """Check URL against Google Safe Browsing."""
        try:
            result = SafeBrowsingChecker.check_url(url)
            if result.get('is_flagged'):
                return {
                    'type': 'safe_browsing',
                    'severity': 'critical',
                    'message': result.get('reason', 'Flagged by Google Safe Browsing'),
                    'detail': 'URL is known to be malicious'
                }
        except Exception as e:
            logger.error(f"Safe Browsing check failed: {str(e)}")
        return None
    
    def _check_heuristics(self, text: str) -> dict:
        """Run heuristics on text content."""
        # Check for phishing keywords
        phishing_keywords = [
            'urgent', 'immediately', 'act now', 'limited time',
            'verify your account', 'confirm your account', 'account suspended',
            'you have won', 'claim your prize', 'free gift',
            'send otp', 'one time password', 'bank details', 'credit card',
            'virus detected', 'malware detected', 'security alert'
        ]
        
        text_lower = text.lower()
        for keyword in phishing_keywords:
            if keyword in text_lower:
                return {
                    'type': 'phishing_keyword',
                    'severity': 'high',
                    'message': f'Phishing keyword detected: "{keyword}"',
                    'detail': f'Text contains "{keyword}" which is commonly used in scams'
                }
        return None


class ChatbotHistoryView(generics.ListAPIView):
    """
    Get the user's past scam check history.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ScamCheckSerializer
    
    def get_queryset(self):
        return ScamCheck.objects.filter(user=self.request.user)