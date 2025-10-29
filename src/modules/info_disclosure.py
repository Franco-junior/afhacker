"""
Information Disclosure Scanner Module
"""
import re
import logging
from typing import List, Dict
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.payloads import SENSITIVE_INFO_PATTERNS, SECURITY_HEADERS, COMMON_ENDPOINTS
from utils.http_client import HTTPClient, analyze_response
from utils.scoring import VulnerabilityType, calculate_vulnerability_score, Severity

logger = logging.getLogger(__name__)


class InfoDisclosureScanner:
    """Scanner for Information Disclosure vulnerabilities"""
    
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.vulnerabilities = []
    
    def scan(self, url: str) -> List[Dict]:
        """Scan for information disclosure"""
        logger.info(f"Starting Info Disclosure scan on {url}")
        self.vulnerabilities = []
        
        # Check security headers
        self._check_security_headers(url)
        
        # Check for sensitive information in response
        self._check_sensitive_info(url)
        
        # Check common endpoints
        self._check_common_endpoints(url)
        
        return self.vulnerabilities
    
    def _check_security_headers(self, url: str):
        """Check for missing security headers"""
        try:
            response = self.http_client.get(url)
            if not response:
                return
            
            analysis = analyze_response(response)
            missing_headers = []
            
            for header in SECURITY_HEADERS:
                if analysis['security_headers'].get(header) == 'Missing':
                    missing_headers.append(header)
            
            if missing_headers:
                vuln_score = calculate_vulnerability_score(
                    VulnerabilityType.SECURITY_MISCONFIG,
                    confirmed=True
                )
                
                self.vulnerabilities.append({
                    'type': 'Security Misconfiguration',
                    'subtype': 'Missing Security Headers',
                    'severity': Severity.MEDIUM.value,
                    'cvss_score': vuln_score.base_score,
                    'cvss_vector': vuln_score.cvss_vector,
                    'location': url,
                    'evidence': f"Missing headers: {', '.join(missing_headers)}",
                    'description': f"Application is missing important security headers.",
                    'remediation': 'Implement all recommended security headers',
                    'confidence': 'HIGH'
                })
        
        except Exception as e:
            logger.error(f"Error checking headers: {e}")
    
    def _check_sensitive_info(self, url: str):
        """Check for sensitive information in response"""
        try:
            response = self.http_client.get(url)
            if not response or not response.text:
                return
            
            for info_type, pattern in SENSITIVE_INFO_PATTERNS.items():
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                
                if matches:
                    vuln_score = calculate_vulnerability_score(
                        VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                        confirmed=True,
                        response_evidence=True
                    )
                    
                    # Mask sensitive data
                    masked_matches = [m[:5] + '***' if len(str(m)) > 5 else '***' 
                                      for m in matches[:3]]
                    
                    self.vulnerabilities.append({
                        'type': 'Sensitive Data Exposure',
                        'subtype': f'{info_type.replace("_", " ").title()} Exposure',
                        'severity': vuln_score.severity.value,
                        'cvss_score': vuln_score.base_score,
                        'cvss_vector': vuln_score.cvss_vector,
                        'location': url,
                        'evidence': f"Found {len(matches)} instance(s): {', '.join(masked_matches)}",
                        'description': f"Sensitive {info_type} exposed in response.",
                        'remediation': 'Remove sensitive information from public responses',
                        'confidence': 'HIGH'
                    })
        
        except Exception as e:
            logger.error(f"Error checking sensitive info: {e}")
    
    def _check_common_endpoints(self, url: str):
        """Check for exposed common endpoints"""
        from urllib.parse import urlparse, urlunparse
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        exposed_endpoints = []
        
        for endpoint in COMMON_ENDPOINTS[:15]:  # Test first 15
            test_url = base_url + endpoint
            
            try:
                response = self.http_client.get(test_url)
                
                if response and 200 <= response.status_code < 300:
                    exposed_endpoints.append((endpoint, response.status_code))
            
            except:
                continue
        
        if exposed_endpoints:
            vuln_score = calculate_vulnerability_score(
                VulnerabilityType.INFO_DISCLOSURE,
                confirmed=True
            )
            
            endpoints_str = ', '.join([f"{ep} ({code})" for ep, code in exposed_endpoints])
            
            self.vulnerabilities.append({
                'type': 'Information Disclosure',
                'subtype': 'Exposed Sensitive Endpoints',
                'severity': Severity.MEDIUM.value,
                'cvss_score': vuln_score.base_score,
                'cvss_vector': vuln_score.cvss_vector,
                'location': base_url,
                'evidence': f"Exposed endpoints: {endpoints_str}",
                'description': "Sensitive endpoints are publicly accessible.",
                'remediation': 'Restrict access to administrative and sensitive endpoints',
                'confidence': 'HIGH'
            })
