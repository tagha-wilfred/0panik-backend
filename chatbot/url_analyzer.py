"""
Enhanced URL Security Analyzer
Adds advanced URL analysis without modifying existing code.
"""

import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse
from difflib import SequenceMatcher
import logging

logger = logging.getLogger(__name__)


class URLSecurityAnalyzer:
    """
    Comprehensive URL security analyzer with multiple detection methods.
    All checks are organized by severity level.
    """
    
    # Known brand list for typo detection
    BRAND_LIST = [
        'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix',
        'paypal', 'ebay', 'walmart', 'target', 'bestbuy', 'homedepot',
        'lowes', 'costco', 'kroger', 'walgreens', 'cvs', 'bankofamerica',
        'chase', 'wellsfargo', 'citibank', 'capitalone', 'amex',
        'discover', 'mastercard', 'visa', 'instagram', 'twitter',
        'linkedin', 'youtube', 'spotify', 'slack', 'zoom', 'github',
        'gitlab', 'atlassian', 'salesforce', 'oracle', 'ibm', 'cisco',
        'whatsapp', 'telegram', 'signal', 'discord', 'reddit', 'tiktok'
    ]
    
    # URL shorteners
    SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'shorturl.at', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'tiny.cc',
        'linktr.ee', 't.co', 'rb.gy', 'short.link', 'v.gd', 'qr.ae',
        'lnkd.in', 'g.co', 'm.me', 'fb.com'
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.online', '.site', '.space', '.click']
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = ['.exe', '.js', '.hta', '.scr', '.vbs', '.bat', '.cmd', '.ps1', '.jar', '.msi', '.apk']
    
    @classmethod
    def analyze_url(cls, url: str) -> dict:
        """
        Perform comprehensive analysis on a URL.
        Returns dict with findings, severity, and overall verdict.
        
        Returns:
        {
            'findings': [...],
            'overall_severity': 'safe' | 'low' | 'medium' | 'medium_high' | 'high' | 'critical',
            'findings_count': int,
            'url_analyzed': str,
            'is_suspicious': bool
        }
        """
        findings = []
        severity = 'safe'
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Remove www. prefix for analysis
            clean_domain = domain.replace('www.', '')
            
            # --- Run all checks ---
            checks = [
                ('brand_misposition', cls._check_brand_position, ['critical']),
                ('typo_domain', cls._check_typo_domain, ['critical']),
                ('punycode', cls._check_punycode, ['critical']),
                ('at_symbol', cls._check_at_symbol, ['critical']),
                ('ip_address', cls._check_ip_address, ['high']),
                ('domain_age', cls._check_domain_age, ['high']),
                ('ssl', cls._check_ssl, ['medium_high']),
                ('dangerous_extension', cls._check_dangerous_extension, ['critical']),
                ('shortener', cls._check_shortener, ['low']),
                ('subdomains', cls._check_subdomains, ['medium']),
                ('suspicious_tld', cls._check_tld, ['medium']),
            ]
            
            for check_name, check_func, severities in checks:
                try:
                    # Call the check function with appropriate arguments
                    if check_name == 'ssl':
                        result = check_func(url, domain)
                    elif check_name == 'domain_age':
                        result = check_func(clean_domain)
                    elif check_name in ['brand_misposition', 'typo_domain', 'subdomains']:
                        result = check_func(domain, clean_domain)
                    else:
                        result = check_func(url if check_name == 'at_symbol' else 
                                          domain if check_name in ['ip_address', 'punycode', 'shortener', 'suspicious_tld'] else
                                          path if check_name == 'dangerous_extension' else
                                          None)
                    
                    if result:
                        findings.append(result)
                        # Update severity
                        severity = cls._update_severity(severity, result.get('severity', 'medium'))
                except Exception as e:
                    logger.debug(f"Check {check_name} failed: {str(e)}")
            
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
            'url_analyzed': url,
            'is_suspicious': severity in ['critical', 'high', 'medium_high']
        }
    
    @classmethod
    def _update_severity(cls, current: str, new: str) -> str:
        """Update severity to the highest level."""
        levels = ['safe', 'low', 'medium', 'medium_high', 'high', 'critical']
        current_idx = levels.index(current) if current in levels else 0
        new_idx = levels.index(new) if new in levels else 0
        return levels[max(current_idx, new_idx)]
    
    @classmethod
    def _check_brand_position(cls, domain: str, clean_domain: str) -> dict:
        """Check if a brand name appears in a suspicious position."""
        for brand in cls.BRAND_LIST:
            if brand in clean_domain:
                parts = clean_domain.split('.')
                if len(parts) > 2:
                    main_domain = parts[-2] if len(parts) >= 2 else ''
                    if brand != main_domain:
                        return {
                            'type': 'brand_misposition',
                            'severity': 'critical',
                            'message': f'Brand "{brand}" appears in suspicious position',
                            'detail': f'URL contains "{brand}" but the main domain is "{main_domain}"'
                        }
        return None
    
    @classmethod
    def _check_typo_domain(cls, domain: str, clean_domain: str) -> dict:
        """Check if domain is a character-swap/typo of a known brand."""
        for brand in cls.BRAND_LIST:
            if brand == clean_domain or brand == domain:
                continue
            
            ratio = SequenceMatcher(None, brand, clean_domain).ratio()
            
            if ratio > 0.85 and ratio < 0.99:
                diff_chars = sum(a != b for a, b in zip(brand, clean_domain))
                if diff_chars <= 2:
                    return {
                        'type': 'typo_domain',
                        'severity': 'critical',
                        'message': f'Domain appears to be a typo of "{brand}"',
                        'detail': f'"{domain}" is suspiciously similar to "{brand}" (similarity: {ratio:.0%})'
                    }
        return None
    
    @classmethod
    def _check_punycode(cls, domain: str) -> dict:
        """Check for Punycode/IDN domains."""
        if domain.startswith('xn--'):
            return {
                'type': 'punycode',
                'severity': 'critical',
                'message': 'Punycode/IDN domain detected',
                'detail': 'Domain uses internationalized characters that may disguise a different domain'
            }
        return None
    
    @classmethod
    def _check_at_symbol(cls, url: str) -> dict:
        """Check for @ symbol in URL."""
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
        """Check if domain is an IP address."""
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
        """Check domain registration age using WHOIS."""
        try:
            import whois
            parts = domain.split('.')
            domain_for_whois = '.'.join(parts[-2:]) if len(parts) > 2 else domain
            
            w = whois.whois(domain_for_whois)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
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
        return None
    
    @classmethod
    def _check_ssl(cls, url: str, domain: str) -> dict:
        """Check HTTPS/SSL certificate validity."""
        if not url.startswith('https://'):
            return {
                'type': 'no_https',
                'severity': 'medium_high',
                'message': 'No HTTPS encryption',
                'detail': 'URL does not use HTTPS - information sent in plain text'
            }
        return None
    
    @classmethod
    def _check_dangerous_extension(cls, path: str) -> dict:
        """Check for dangerous file extensions."""
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
        """Check if URL uses a shortener service."""
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
        """Check for excess subdomains or hyphens mimicking a brand."""
        parts = clean_domain.split('.')
        subdomain_parts = parts[:-2] if len(parts) > 2 else []
        
        if len(subdomain_parts) > 2:
            return {
                'type': 'excess_subdomains',
                'severity': 'medium',
                'message': 'Multiple subdomains detected',
                'detail': f'URL uses {len(subdomain_parts)} subdomain levels which is unusual'
            }
        
        for brand in cls.BRAND_LIST:
            if brand in clean_domain and '-' in clean_domain:
                return {
                    'type': 'hyphenated_brand',
                    'severity': 'medium',
                    'message': f'Hyphenated domain mimicking "{brand}"',
                    'detail': f'Domain "{clean_domain}" contains "{brand}" with hyphens, which is suspicious'
                }
        return None
    
    @classmethod
    def _check_tld(cls, domain: str) -> dict:
        """Check for suspicious TLDs."""
        for tld in cls.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return {
                    'type': 'suspicious_tld',
                    'severity': 'medium',
                    'message': f'Suspicious TLD "{tld}" used',
                    'detail': f'This TLD is commonly associated with scam websites'
                }
        return None