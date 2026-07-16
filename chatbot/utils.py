import re
import urllib.parse
from typing import List, Optional, Tuple

def extract_urls(text: str) -> List[str]:
    """
    Extract all URLs from text using regex.
    Returns list of URLs found.
    """
    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+'
    )
    return url_pattern.findall(text)

def extract_domain(url: str) -> Optional[str]:
    """
    Extract domain from URL for analysis.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain.lower()
    except:
        return None

def check_phishing_keywords(text: str) -> Tuple[bool, str]:
    """
    Check for common phishing keywords.
    Returns (is_flagged, reason)
    """
    # Expanded list of phishing/scam keywords
    phishing_keywords = [
        # Urgency
        ('urgent', 'Contains urgency-related phrasing'),
        ('immediately', 'Contains urgency-related phrasing'),
        ('act now', 'Contains urgency-related phrasing'),
        ('limited time', 'Contains urgency-related phrasing'),
        
        # Account verification
        ('verify your account', 'Account verification scam pattern'),
        ('verify your identity', 'Account verification scam pattern'),
        ('confirm your account', 'Account verification scam pattern'),
        ('account suspended', 'Account suspension scam pattern'),
        ('account deactivated', 'Account suspension scam pattern'),
        
        # Prizes and winnings
        ('you have won', 'Prize/winnings scam pattern'),
        ('congratulations you', 'Prize/winnings scam pattern'),
        ('claim your prize', 'Prize/winnings scam pattern'),
        ('free gift', 'Prize/winnings scam pattern'),
        
        # Personal information
        ('send otp', 'OTP/authentication code scam pattern'),
        ('one time password', 'OTP/authentication code scam pattern'),
        ('enter your password', 'Password harvesting scam pattern'),
        ('provide your password', 'Password harvesting scam pattern'),
        ('bank details', 'Financial information scam pattern'),
        ('credit card', 'Financial information scam pattern'),
        
        # Tech support scams
        ('virus detected', 'Tech support scam pattern'),
        ('malware detected', 'Tech support scam pattern'),
        ('security alert', 'Security alert scam pattern'),
        ('suspicious activity', 'Security alert scam pattern'),
        ('unusual activity', 'Security alert scam pattern'),
    ]
    
    text_lower = text.lower()
    for keyword, reason in phishing_keywords:
        if keyword in text_lower:
            return True, reason
    
    return False, ''

def check_suspicious_patterns(url: str, text: str) -> Tuple[bool, str]:
    """
    Check for suspicious URL patterns.
    Returns (is_flagged, reason)
    """
    # IP-based URLs
    ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    if ip_pattern.search(url):
        return True, 'IP-based URL detected (often used in scams)'
    
    # Lookalike domains (e.g., google.com.xyz.com)
    domain_parts = extract_domain(url)
    if domain_parts:
        parts = domain_parts.split('.')
        if len(parts) > 2 and parts[-2] in ['com', 'org', 'net'] and len(parts[-1]) > 2:
            # This could be a subdomain trick like "google.com.xyz.com"
            for tld in ['com', 'org', 'net', 'info', 'biz']:
                if f'.{tld}.' in domain_parts:
                    return True, f'Potentially misleading domain structure'
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.online']
    for tld in suspicious_tlds:
        if tld in url.lower():
            return True, f'Unusual TLD "{tld}" often used in scams'
    
    # Check for hyphens in domain (typosquatting)
    if domain_parts and '-' in domain_parts:
        return True, 'Domain contains hyphens (potential typosquatting)'
    
    return False, ''

def check_short_urls(url: str) -> Tuple[bool, str]:
    """
    Check if URL is a short URL service.
    """
    short_url_services = [
        'bit.ly', 'tinyurl.com', 'shorturl.at', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'tiny.cc',
        'linktr.ee', 't.co', 'rb.gy'
    ]
    domain = extract_domain(url)
    if domain:
        for service in short_url_services:
            if service in domain:
                return True, f'Short URL service "{service}" (can hide final destination)'
    return False, ''