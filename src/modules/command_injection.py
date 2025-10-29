"""
Command Injection Scanner Module
"""
import logging
import time
from typing import List, Dict, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.payloads import COMMAND_INJECTION_PAYLOADS
from utils.http_client import HTTPClient
from utils.scoring import VulnerabilityType, calculate_vulnerability_score

logger = logging.getLogger(__name__)


class CommandInjectionScanner:
    """Scanner for Command Injection vulnerabilities"""
    
    COMMAND_OUTPUT_PATTERNS = [
        'uid=', 'gid=', 'groups=',  # id/whoami output
        'Linux', 'Darwin', 'Windows',  # uname/ver output
        'root', 'administrator',  # user info
        'C:\\', 'C:/',  # Windows paths
        '/bin/', '/usr/', '/etc/',  # Unix paths
    ]
    
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.vulnerabilities = []
    
    def scan(self, url: str, parameters: Optional[Dict] = None) -> List[Dict]:
        """Scan for Command Injection"""
        logger.info(f"Starting Command Injection scan on {url}")
        self.vulnerabilities = []
        
        if not parameters:
            parameters = self._extract_parameters(url)
        
        if not parameters:
            return self.vulnerabilities
        
        for param_name in parameters.keys():
            self._test_command_injection(url, parameters, param_name)
        
        return self.vulnerabilities
    
    def _extract_parameters(self, url: str) -> Dict:
        parsed = urlparse(url)
        return {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}
    
    def _test_command_injection(self, url: str, parameters: Dict, param_name: str):
        """Test for command injection"""
        original_params = parameters.copy()
        
        # Test time-based detection first
        baseline_start = time.time()
        self.http_client.get(url)
        baseline_time = time.time() - baseline_start
        
        time_payloads = ["; sleep 5", "& timeout 5", "| sleep 5"]
        
        for payload in time_payloads:
            test_params = original_params.copy()
            test_params[param_name] = payload
            
            parsed = urlparse(url)
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, query, parsed.fragment))
            
            try:
                start = time.time()
                response = self.http_client.get(test_url)
                response_time = time.time() - start
                
                if response and response_time > baseline_time + 4:
                    vuln_score = calculate_vulnerability_score(
                        VulnerabilityType.COMMAND_INJECTION,
                        confirmed=True,
                        has_payload=True,
                        response_evidence=True
                    )
                    
                    self.vulnerabilities.append({
                        'type': 'Command Injection',
                        'subtype': 'Time-based',
                        'severity': vuln_score.severity.value,
                        'cvss_score': vuln_score.base_score,
                        'cvss_vector': vuln_score.cvss_vector,
                        'location': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f"Response time: {response_time:.2f}s (baseline: {baseline_time:.2f}s)",
                        'description': f"Command Injection vulnerability in '{param_name}'.",
                        'remediation': 'Never pass user input to system commands',
                        'confidence': 'HIGH'
                    })
                    return
            
            except Exception as e:
                logger.debug(f"Error: {e}")
        
        # Test output-based detection
        for payload in COMMAND_INJECTION_PAYLOADS[:10]:
            test_params = original_params.copy()
            test_params[param_name] = payload
            
            parsed = urlparse(url)
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, query, parsed.fragment))
            
            try:
                response = self.http_client.get(test_url)
                
                if response and response.text:
                    for pattern in self.COMMAND_OUTPUT_PATTERNS:
                        if pattern in response.text:
                            vuln_score = calculate_vulnerability_score(
                                VulnerabilityType.COMMAND_INJECTION,
                                confirmed=True,
                                has_payload=True,
                                response_evidence=True
                            )
                            
                            self.vulnerabilities.append({
                                'type': 'Command Injection',
                                'subtype': 'Output-based',
                                'severity': vuln_score.severity.value,
                                'cvss_score': vuln_score.base_score,
                                'cvss_vector': vuln_score.cvss_vector,
                                'location': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': response.text[:300],
                                'description': f"Command Injection in '{param_name}'.",
                                'remediation': 'Never pass user input to system commands',
                                'confidence': 'HIGH'
                            })
                            return
            
            except Exception as e:
                logger.debug(f"Error: {e}")
