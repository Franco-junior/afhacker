"""
Cross-Site Scripting (XSS) Scanner Module
Detects XSS vulnerabilities
"""
import re
import logging
from typing import List, Dict, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
from bs4 import BeautifulSoup
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.payloads import XSS_PAYLOADS
from utils.http_client import HTTPClient
from utils.scoring import VulnerabilityType, calculate_vulnerability_score

logger = logging.getLogger(__name__)


class XSSScanner:
    """Scanner for Cross-Site Scripting vulnerabilities"""
    
    # XSS detection patterns
    XSS_INDICATORS = [
        r"<script[^>]*>.*?alert\(.*?\).*?</script>",
        r"onerror\s*=\s*['\"]?alert\(",
        r"onload\s*=\s*['\"]?alert\(",
        r"javascript:alert\(",
        r"<svg[^>]*onload\s*=",
        r"<img[^>]*onerror\s*=",
        r"<body[^>]*onload\s*=",
        r"<iframe[^>]*src\s*=\s*['\"]?javascript:",
    ]
    
    def __init__(self, http_client: HTTPClient):
        """
        Initialize XSS Scanner
        
        Args:
            http_client: HTTP client instance
        """
        self.http_client = http_client
        self.vulnerabilities = []
    
    def scan(self, url: str, parameters: Optional[Dict] = None) -> List[Dict]:
        """
        Scan URL for XSS vulnerabilities
        
        Args:
            url: Target URL
            parameters: URL parameters to test
            
        Returns:
            List of found vulnerabilities
        """
        logger.info(f"Starting XSS scan on {url}")
        self.vulnerabilities = []
        
        if not parameters:
            parameters = self._extract_parameters(url)
        
        if not parameters:
            logger.warning(f"No parameters found for {url}")
            # Test URL path for reflected XSS
            self._test_path_xss(url)
            return self.vulnerabilities
        
        # Test each parameter
        for param_name in parameters.keys():
            logger.debug(f"Testing parameter: {param_name}")
            self._test_reflected_xss(url, parameters, param_name)
        
        logger.info(f"XSS scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def _extract_parameters(self, url: str) -> Dict:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        # Convert list values to single values
        return {k: v[0] if isinstance(v, list) and len(v) > 0 else v for k, v in params.items()}
    
    def _test_reflected_xss(self, url: str, parameters: Dict, param_name: str):
        """Test for reflected XSS"""
        original_params = parameters.copy()
        
        for payload in XSS_PAYLOADS[:15]:  # Test first 15 payloads
            test_params = original_params.copy()
            test_params[param_name] = payload
            
            # Build test URL
            parsed = urlparse(url)
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                query,
                parsed.fragment
            ))
            
            try:
                response = self.http_client.get(test_url)
                
                if response and response.text:
                    # Check if payload is reflected in response
                    if payload in response.text:
                        # Check if it's in a dangerous context
                        if self._is_dangerous_context(response.text, payload):
                            logger.warning(f"XSS vulnerability found: {param_name} with payload: {payload}")
                            
                            vuln_score = calculate_vulnerability_score(
                                VulnerabilityType.XSS,
                                confirmed=True,
                                has_payload=True,
                                response_evidence=True
                            )
                            
                            context = self._get_context(response.text, payload)
                            
                            self.vulnerabilities.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'subtype': 'Reflected XSS',
                                'severity': vuln_score.severity.value,
                                'cvss_score': vuln_score.base_score,
                                'cvss_vector': vuln_score.cvss_vector,
                                'location': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': context,
                                'description': f"Reflected XSS vulnerability detected in parameter '{param_name}'. "
                                             f"User input is reflected in the response without proper encoding.",
                                'remediation': 'Implement proper output encoding and Content Security Policy',
                                'confidence': 'HIGH'
                            })
                            return  # Stop testing this parameter
                    
                    # Check for XSS patterns even if exact payload not found
                    for pattern in self.XSS_INDICATORS:
                        if re.search(pattern, response.text, re.IGNORECASE | re.DOTALL):
                            logger.info(f"Potential XSS vulnerability: {param_name}")
                            
                            vuln_score = calculate_vulnerability_score(
                                VulnerabilityType.XSS,
                                confirmed=False,
                                has_payload=True,
                                response_evidence=True
                            )
                            
                            self.vulnerabilities.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'subtype': 'Potential Reflected XSS',
                                'severity': vuln_score.severity.value,
                                'cvss_score': vuln_score.base_score,
                                'cvss_vector': vuln_score.cvss_vector,
                                'location': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': re.search(pattern, response.text, re.IGNORECASE | re.DOTALL).group(0)[:200],
                                'description': f"Potential XSS vulnerability detected in parameter '{param_name}'.",
                                'remediation': 'Implement proper output encoding and Content Security Policy',
                                'confidence': 'MEDIUM'
                            })
                            return
            
            except Exception as e:
                logger.debug(f"Error testing {param_name} with payload {payload}: {e}")
                continue
    
    def _test_path_xss(self, url: str):
        """Test for XSS in URL path"""
        parsed = urlparse(url)
        
        for payload in XSS_PAYLOADS[:5]:
            test_path = parsed.path + payload
            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                test_path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            try:
                response = self.http_client.get(test_url)
                
                if response and payload in response.text:
                    if self._is_dangerous_context(response.text, payload):
                        vuln_score = calculate_vulnerability_score(
                            VulnerabilityType.XSS,
                            confirmed=True,
                            has_payload=True,
                            response_evidence=True
                        )
                        
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'subtype': 'Path-based Reflected XSS',
                            'severity': vuln_score.severity.value,
                            'cvss_score': vuln_score.base_score,
                            'cvss_vector': vuln_score.cvss_vector,
                            'location': url,
                            'parameter': 'URL Path',
                            'payload': payload,
                            'evidence': self._get_context(response.text, payload),
                            'description': "Reflected XSS vulnerability detected in URL path.",
                            'remediation': 'Implement proper output encoding and Content Security Policy',
                            'confidence': 'HIGH'
                        })
                        return
            
            except Exception as e:
                logger.debug(f"Error testing path XSS: {e}")
                continue
    
    def _is_dangerous_context(self, html: str, payload: str) -> bool:
        """
        Check if payload is in a dangerous context (not encoded)
        
        Args:
            html: HTML content
            payload: Injected payload
            
        Returns:
            True if in dangerous context
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Check if payload is in script tags
            scripts = soup.find_all('script')
            for script in scripts:
                if payload in str(script):
                    return True
            
            # Check if payload is in event handlers
            for tag in soup.find_all(True):
                for attr, value in tag.attrs.items():
                    if attr.startswith('on') and payload in str(value):
                        return True
            
            # Check for unencoded special characters
            if '<' in payload or '>' in payload:
                if payload in html:
                    return True
            
            return False
        
        except:
            # If parsing fails, assume it might be dangerous
            return True
    
    def _get_context(self, html: str, payload: str, context_length: int = 100) -> str:
        """
        Get context around payload in HTML
        
        Args:
            html: HTML content
            payload: Injected payload
            context_length: Characters to include before/after
            
        Returns:
            Context string
        """
        try:
            index = html.find(payload)
            if index == -1:
                return "Payload not found in response"
            
            start = max(0, index - context_length)
            end = min(len(html), index + len(payload) + context_length)
            
            context = html[start:end]
            
            # Escape for display
            context = context.replace('<', '&lt;').replace('>', '&gt;')
            
            return f"...{context}..."
        
        except:
            return "Unable to extract context"
