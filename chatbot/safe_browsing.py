import requests
import logging
from django.conf import settings
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class SafeBrowsingChecker:
    """Google Safe Browsing API integration."""
    
    API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    TIMEOUT = 5  # seconds
    
    @classmethod
    def check_url(cls, url: str) -> Dict[str, Any]:
        """
        Check a single URL against Google Safe Browsing.
        Returns: {
            'is_flagged': bool,
            'reason': str,
            'response': dict,
            'error': str or None
        }
        """
        api_key = getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', '')
        
        # 🔍 Debug logging
        logger.info(f"=== Safe Browsing Check ===")
        logger.info(f"URL: {url}")
        logger.info(f"API Key present: {bool(api_key)}")
        logger.info(f"API Key length: {len(api_key) if api_key else 0}")
        
        if not api_key:
            logger.warning("Google Safe Browsing API key not configured")
            return {
                'is_flagged': False,
                'reason': 'API key not configured',
                'response': None,
                'error': 'API_KEY_MISSING'
            }
        
        payload = {
            "client": {
                "clientId": "0panik-backend",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        logger.info(f"Payload: {payload}")
        
        try:
            response = requests.post(
                f'{cls.API_URL}?key={api_key}',
                json=payload,
                timeout=cls.TIMEOUT
            )
            
            logger.info(f"Response status: {response.status_code}")
            logger.info(f"Response body: {response.text[:500]}")  # First 500 chars
            
            if response.status_code == 200:
                data = response.json()
                is_flagged = bool(data.get('matches'))
                logger.info(f"Is flagged: {is_flagged}")
                logger.info(f"Matches: {data.get('matches')}")
                
                return {
                    'is_flagged': is_flagged,
                    'reason': 'Flagged by Google Safe Browsing' if is_flagged else 'Not flagged by Google Safe Browsing',
                    'response': data,
                    'error': None
                }
            else:
                logger.error(f"Safe Browsing API error: {response.status_code} - {response.text}")
                return {
                    'is_flagged': False,
                    'reason': f'API error: {response.status_code}',
                    'response': None,
                    'error': f'API_ERROR_{response.status_code}'
                }
                
        except requests.Timeout:
            logger.error("Safe Browsing API timeout")
            return {
                'is_flagged': False,
                'reason': 'Request timeout',
                'response': None,
                'error': 'TIMEOUT'
            }
        except Exception as e:
            logger.error(f"Safe Browsing API exception: {str(e)}")
            return {
                'is_flagged': False,
                'reason': f'Error: {str(e)}',
                'response': None,
                'error': 'EXCEPTION'
            }