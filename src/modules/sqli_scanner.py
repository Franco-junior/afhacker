"""
SQL Injection Scanner Module
Detects SQL injection vulnerabilities
"""
import re
import logging
from typing import List, Dict, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.payloads import SQL_INJECTION_PAYLOADS
from utils.http_client import HTTPClient
from utils.scoring import VulnerabilityType, calculate_vulnerability_score

logger = logging.getLogger(__name__)


class SQLInjectionScanner:
    """Scanner for SQL Injection vulnerabilities"""
    
    # SQL error patterns from different databases
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*?error",
        r"Warning.*?mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"Unknown column.*?in.*?field list",
        r"You have an error in your SQL syntax",
        r"PostgreSQL.*?ERROR",
        r"Warning.*?pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"Microsoft SQL Server.*?error",
        r"OLE DB.*?SQL Server",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"SqlException",
        r"System\.Data\.SqlClient\.SqlException",
        r"Oracle error",
        r"ORA-[0-9]{5}",
        r"Oracle.*?Driver",
        r"java\.sql\.SQLException",
        r"sqlite3\.OperationalError:",
        r"SQLite\/JDBCDriver",
        r"System\.Data\.SQLite\.SQLiteException",
        r"JET Database Engine",
        r"Access Database Engine",
        r"Microsoft Access Driver",
    ]
    
    # Time-based detection
    TIME_BASED_PAYLOADS = [
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' OR SLEEP(5)--",
        "' WAITFOR DELAY '0:0:5'--",
        "'; WAITFOR DELAY '0:0:5'--",
    ]
    
    # Boolean-based detection
    BOOLEAN_TRUE = ["' OR '1'='1", "' OR 1=1--", "' OR 'a'='a"]
    BOOLEAN_FALSE = ["' AND '1'='2", "' AND 1=0--", "' AND 'a'='b"]
    
    def __init__(self, http_client: HTTPClient):
        """
        Initialize SQL Injection Scanner
        
        Args:
            http_client: HTTP client instance
        """
        self.http_client = http_client
        self.vulnerabilities = []
    
    def scan(self, url: str, parameters: Optional[Dict] = None) -> List[Dict]:
        """
        Scan URL for SQL injection vulnerabilities
        
        Args:
            url: Target URL
            parameters: URL parameters to test
            
        Returns:
            List of found vulnerabilities
        """
        logger.info(f"Starting SQL Injection scan on {url}")
        self.vulnerabilities = []
        
        if not parameters:
            parameters = self._extract_parameters(url)
        
        if not parameters:
            logger.warning(f"No parameters found for {url}")
            return self.vulnerabilities
        
        # Test each parameter
        for param_name in parameters.keys():
            logger.debug(f"Testing parameter: {param_name}")
            
            # Error-based SQL injection
            self._test_error_based(url, parameters, param_name)
            
            # Boolean-based SQL injection
            self._test_boolean_based(url, parameters, param_name)
            
            # Time-based SQL injection
            self._test_time_based(url, parameters, param_name)
        
        logger.info(f"SQL Injection scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def _extract_parameters(self, url: str) -> Dict:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        return parse_qs(parsed.query)
    
    def _test_error_based(self, url: str, parameters: Dict, param_name: str):
        """Test for error-based SQL injection"""
        original_params = parameters.copy()
        
        for payload in SQL_INJECTION_PAYLOADS[:10]:  # Test first 10 payloads
            test_params = original_params.copy()
            
            # Handle list values
            if isinstance(test_params[param_name], list):
                test_params[param_name] = test_params[param_name][0]
            
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
                    # Check for SQL error patterns
                    for pattern in self.SQL_ERROR_PATTERNS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            logger.warning(f"SQL Injection found: {param_name} with payload: {payload}")
                            
                            vuln_score = calculate_vulnerability_score(
                                VulnerabilityType.SQL_INJECTION,
                                confirmed=True,
                                has_payload=True,
                                response_evidence=True
                            )
                            
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'subtype': 'Error-based',
                                'severity': vuln_score.severity.value,
                                'cvss_score': vuln_score.base_score,
                                'cvss_vector': vuln_score.cvss_vector,
                                'location': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': re.search(pattern, response.text, re.IGNORECASE).group(0)[:200],
                                'description': f"SQL Injection vulnerability detected in parameter '{param_name}'. "
                                             f"The application returned a database error message.",
                                'remediation': 'Use prepared statements and parameterized queries',
                                'confidence': 'HIGH'
                            })
                            return  # Stop testing this parameter
            
            except Exception as e:
                logger.debug(f"Error testing {param_name} with payload {payload}: {e}")
                continue
    
    def _test_boolean_based(self, url: str, parameters: Dict, param_name: str):
        """Test for boolean-based SQL injection"""
        original_params = parameters.copy()
        
        # Get baseline response
        if isinstance(original_params[param_name], list):
            original_params[param_name] = original_params[param_name][0]
        
        try:
            baseline_response = self.http_client.get(url)
            if not baseline_response:
                return
            
            baseline_length = len(baseline_response.text)
            
            # Test TRUE payloads
            true_lengths = []
            for payload in self.BOOLEAN_TRUE[:3]:
                test_params = original_params.copy()
                test_params[param_name] = payload
                
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
                
                response = self.http_client.get(test_url)
                if response:
                    true_lengths.append(len(response.text))
            
            # Test FALSE payloads
            false_lengths = []
            for payload in self.BOOLEAN_FALSE[:3]:
                test_params = original_params.copy()
                test_params[param_name] = payload
                
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
                
                response = self.http_client.get(test_url)
                if response:
                    false_lengths.append(len(response.text))
            
            # Check if TRUE and FALSE responses differ significantly
            if true_lengths and false_lengths:
                avg_true = sum(true_lengths) / len(true_lengths)
                avg_false = sum(false_lengths) / len(false_lengths)
                
                # If responses differ by more than 5%, it might be vulnerable
                if abs(avg_true - avg_false) / max(avg_true, avg_false) > 0.05:
                    logger.warning(f"Possible boolean-based SQL Injection: {param_name}")
                    
                    vuln_score = calculate_vulnerability_score(
                        VulnerabilityType.SQL_INJECTION,
                        confirmed=False,
                        has_payload=True,
                        response_evidence=False
                    )
                    
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'subtype': 'Boolean-based (blind)',
                        'severity': vuln_score.severity.value,
                        'cvss_score': vuln_score.base_score,
                        'cvss_vector': vuln_score.cvss_vector,
                        'location': url,
                        'parameter': param_name,
                        'payload': self.BOOLEAN_TRUE[0],
                        'evidence': f"TRUE response length: {int(avg_true)}, FALSE response length: {int(avg_false)}",
                        'description': f"Possible blind SQL Injection detected in parameter '{param_name}'. "
                                     f"Response length varies with boolean conditions.",
                        'remediation': 'Use prepared statements and parameterized queries',
                        'confidence': 'MEDIUM'
                    })
        
        except Exception as e:
            logger.debug(f"Error in boolean-based test for {param_name}: {e}")
    
    def _test_time_based(self, url: str, parameters: Dict, param_name: str):
        """Test for time-based SQL injection"""
        original_params = parameters.copy()
        
        if isinstance(original_params[param_name], list):
            original_params[param_name] = original_params[param_name][0]
        
        # Get baseline response time
        import time
        start = time.time()
        baseline_response = self.http_client.get(url)
        baseline_time = time.time() - start
        
        if not baseline_response:
            return
        
        # Test time-based payloads
        for payload in self.TIME_BASED_PAYLOADS:
            test_params = original_params.copy()
            test_params[param_name] = payload
            
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
                start = time.time()
                response = self.http_client.get(test_url)
                response_time = time.time() - start
                
                # If response takes significantly longer (at least 4 seconds more)
                if response and response_time > baseline_time + 4:
                    logger.warning(f"Time-based SQL Injection found: {param_name}")
                    
                    vuln_score = calculate_vulnerability_score(
                        VulnerabilityType.SQL_INJECTION,
                        confirmed=True,
                        has_payload=True,
                        response_evidence=True
                    )
                    
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'subtype': 'Time-based (blind)',
                        'severity': vuln_score.severity.value,
                        'cvss_score': vuln_score.base_score,
                        'cvss_vector': vuln_score.cvss_vector,
                        'location': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f"Response time increased from {baseline_time:.2f}s to {response_time:.2f}s",
                        'description': f"Time-based blind SQL Injection detected in parameter '{param_name}'. "
                                     f"Database delays were successfully triggered.",
                        'remediation': 'Use prepared statements and parameterized queries',
                        'confidence': 'HIGH'
                    })
                    return
            
            except Exception as e:
                logger.debug(f"Error in time-based test for {param_name}: {e}")
                continue
