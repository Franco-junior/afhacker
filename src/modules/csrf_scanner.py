"""
CSRF Scanner Module
Detects CSRF vulnerabilities
"""
import logging
from typing import List, Dict
from bs4 import BeautifulSoup
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.payloads import CSRF_INDICATORS
from utils.http_client import HTTPClient
from utils.scoring import VulnerabilityType, calculate_vulnerability_score

logger = logging.getLogger(__name__)


class CSRFScanner:
    """Scanner for CSRF vulnerabilities"""
    
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.vulnerabilities = []
    
    def scan(self, url: str) -> List[Dict]:
        """Scan for CSRF vulnerabilities"""
        logger.info(f"Starting CSRF scan on {url}")
        self.vulnerabilities = []
        
        try:
            response = self.http_client.get(url)
            if not response:
                return self.vulnerabilities
            
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                method = form.get('method', 'get').upper()
                
                if method == 'POST':
                    has_csrf_token = False
                    
                    # Check for CSRF token in form
                    inputs = form.find_all('input')
                    for inp in inputs:
                        name = inp.get('name', '').lower()
                        for indicator in CSRF_INDICATORS:
                            if indicator.lower() in name:
                                has_csrf_token = True
                                break
                    
                    if not has_csrf_token:
                        vuln_score = calculate_vulnerability_score(
                            VulnerabilityType.CSRF,
                            confirmed=True
                        )
                        
                        form_action = form.get('action', 'current_page')
                        
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Request Forgery (CSRF)',
                            'subtype': 'Missing CSRF Token',
                            'severity': vuln_score.severity.value,
                            'cvss_score': vuln_score.base_score,
                            'cvss_vector': vuln_score.cvss_vector,
                            'location': url,
                            'parameter': f'Form action: {form_action}',
                            'evidence': str(form)[:500],
                            'description': f"POST form without CSRF protection detected at '{form_action}'.",
                            'remediation': 'Implement anti-CSRF tokens and SameSite cookie attributes',
                            'confidence': 'MEDIUM'
                        })
        
        except Exception as e:
            logger.error(f"Error in CSRF scan: {e}")
        
        return self.vulnerabilities
