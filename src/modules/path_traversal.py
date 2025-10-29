"""
Path Traversal Scanner Module
"""
import logging
from typing import List, Dict, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.payloads import PATH_TRAVERSAL_PAYLOADS
from utils.http_client import HTTPClient
from utils.scoring import VulnerabilityType, calculate_vulnerability_score

logger = logging.getLogger(__name__)


class PathTraversalScanner:
    """Scanner for Path Traversal vulnerabilities"""
    
    SENSITIVE_FILES_PATTERNS = [
        'root:',  # /etc/passwd
        '[boot loader]',  # boot.ini
        '; for 16-bit app support',  # win.ini
        '[extensions]',  # win.ini
    ]
    
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.vulnerabilities = []
    
    def scan(self, url: str, parameters: Optional[Dict] = None) -> List[Dict]:
        """Scan for Path Traversal vulnerabilities"""
        logger.info(f"Starting Path Traversal scan on {url}")
        self.vulnerabilities = []
        
        if not parameters:
            parameters = self._extract_parameters(url)
        
        if not parameters:
            return self.vulnerabilities
        
        for param_name in parameters.keys():
            self._test_path_traversal(url, parameters, param_name)
        
        return self.vulnerabilities
    
    def _extract_parameters(self, url: str) -> Dict:
        parsed = urlparse(url)
        return {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}
    
    def _test_path_traversal(self, url: str, parameters: Dict, param_name: str):
        """Test parameter for path traversal"""
        original_params = parameters.copy()
        
        for payload in PATH_TRAVERSAL_PAYLOADS[:20]:
            test_params = original_params.copy()
            test_params[param_name] = payload
            
            parsed = urlparse(url)
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, query, parsed.fragment))
            
            try:
                response = self.http_client.get(test_url)
                
                if response and response.text:
                    for pattern in self.SENSITIVE_FILES_PATTERNS:
                        if pattern in response.text:
                            vuln_score = calculate_vulnerability_score(
                                VulnerabilityType.PATH_TRAVERSAL,
                                confirmed=True,
                                has_payload=True,
                                response_evidence=True
                            )
                            
                            self.vulnerabilities.append({
                                'type': 'Path Traversal',
                                'subtype': 'Directory Traversal',
                                'severity': vuln_score.severity.value,
                                'cvss_score': vuln_score.base_score,
                                'cvss_vector': vuln_score.cvss_vector,
                                'location': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': response.text[:500],
                                'description': f"Path Traversal vulnerability in parameter '{param_name}'.",
                                'remediation': 'Validate and sanitize file paths; use whitelist',
                                'confidence': 'HIGH'
                            })
                            return
            
            except Exception as e:
                logger.debug(f"Error testing {param_name}: {e}")
