"""
HTTP Client with custom features for security scanning
"""
import requests
import urllib3
from typing import Dict, Optional, List
import time
import random
from urllib.parse import urljoin, urlparse
import logging

# Disable SSL warnings (for testing purposes only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class HTTPClient:
    """Custom HTTP client for security scanning"""
    
    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 3,
        user_agent: Optional[str] = None,
        verify_ssl: bool = False,
        follow_redirects: bool = True,
        proxy: Optional[Dict[str, str]] = None
    ):
        """
        Initialize HTTP client
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries
            user_agent: Custom user agent string
            verify_ssl: Whether to verify SSL certificates
            follow_redirects: Whether to follow redirects
            proxy: Proxy configuration
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        # Set user agent
        if user_agent:
            self.session.headers['User-Agent'] = user_agent
        else:
            self.session.headers['User-Agent'] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        
        if proxy:
            self.session.proxies.update(proxy)
    
    def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        Send GET request
        
        Args:
            url: Target URL
            params: Query parameters
            headers: Custom headers
            **kwargs: Additional arguments
            
        Returns:
            Response object
        """
        return self._request('GET', url, params=params, headers=headers, **kwargs)
    
    def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        Send POST request
        
        Args:
            url: Target URL
            data: Form data
            json: JSON data
            headers: Custom headers
            **kwargs: Additional arguments
            
        Returns:
            Response object
        """
        return self._request('POST', url, data=data, json=json, headers=headers, **kwargs)
    
    def _request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Internal method to send HTTP request with retry logic
        
        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Request arguments
            
        Returns:
            Response object or None if failed
        """
        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    **kwargs
                )
                return response
            
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout on attempt {attempt + 1} for {url}")
                if attempt < self.max_retries - 1:
                    time.sleep(random.uniform(1, 3))
                continue
            
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error on attempt {attempt + 1} for {url}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(random.uniform(1, 3))
                continue
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error for {url}: {e}")
                break
        
        return None
    
    def is_accessible(self, url: str) -> bool:
        """
        Check if URL is accessible
        
        Args:
            url: Target URL
            
        Returns:
            True if accessible, False otherwise
        """
        try:
            response = self.get(url)
            return response is not None and response.status_code < 500
        except:
            return False
    
    def get_response_time(self, url: str) -> float:
        """
        Measure response time
        
        Args:
            url: Target URL
            
        Returns:
            Response time in seconds
        """
        start_time = time.time()
        try:
            self.get(url)
            return time.time() - start_time
        except:
            return -1
    
    def close(self):
        """Close the session"""
        self.session.close()


class URLAnalyzer:
    """Analyze and parse URLs"""
    
    @staticmethod
    def parse(url: str) -> Dict:
        """
        Parse URL into components
        
        Args:
            url: URL to parse
            
        Returns:
            Dictionary with URL components
        """
        parsed = urlparse(url)
        return {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'hostname': parsed.hostname,
            'port': parsed.port,
            'path': parsed.path,
            'params': parsed.params,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'base_url': f"{parsed.scheme}://{parsed.netloc}"
        }
    
    @staticmethod
    def join(base_url: str, path: str) -> str:
        """
        Join base URL with path
        
        Args:
            base_url: Base URL
            path: Path to join
            
        Returns:
            Complete URL
        """
        return urljoin(base_url, path)
    
    @staticmethod
    def extract_parameters(url: str) -> Dict:
        """
        Extract query parameters from URL
        
        Args:
            url: URL with parameters
            
        Returns:
            Dictionary of parameters
        """
        from urllib.parse import parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        # Convert lists to single values
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}
    
    @staticmethod
    def build_url(base_url: str, params: Dict) -> str:
        """
        Build URL with parameters
        
        Args:
            base_url: Base URL
            params: Query parameters
            
        Returns:
            URL with parameters
        """
        from urllib.parse import urlencode
        if not params:
            return base_url
        
        query_string = urlencode(params)
        separator = '&' if '?' in base_url else '?'
        return f"{base_url}{separator}{query_string}"
    
    @staticmethod
    def is_same_domain(url1: str, url2: str) -> bool:
        """
        Check if two URLs are from the same domain
        
        Args:
            url1: First URL
            url2: Second URL
            
        Returns:
            True if same domain, False otherwise
        """
        domain1 = urlparse(url1).netloc
        domain2 = urlparse(url2).netloc
        return domain1 == domain2


def detect_waf(response: requests.Response) -> Optional[str]:
    """
    Detect Web Application Firewall
    
    Args:
        response: HTTP response
        
    Returns:
        WAF name if detected, None otherwise
    """
    waf_signatures = {
        'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
        'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
        'Akamai': ['akamai', 'x-akamai'],
        'Imperva': ['visid_incap', 'incap_ses'],
        'ModSecurity': ['mod_security', 'NOYB'],
        'Barracuda': ['barra_counter_session', 'barracuda'],
        'F5 BIG-IP': ['BigIP', 'F5', 'TS'],
        'Sucuri': ['sucuri', 'x-sucuri'],
        'Wordfence': ['wordfence'],
    }
    
    headers_str = str(response.headers).lower()
    content_str = response.text[:1000].lower() if hasattr(response, 'text') else ''
    
    for waf_name, signatures in waf_signatures.items():
        for signature in signatures:
            if signature.lower() in headers_str or signature.lower() in content_str:
                return waf_name
    
    return None


def analyze_response(response: requests.Response) -> Dict:
    """
    Analyze HTTP response
    
    Args:
        response: HTTP response
        
    Returns:
        Analysis results
    """
    analysis = {
        'status_code': response.status_code,
        'content_length': len(response.content),
        'content_type': response.headers.get('Content-Type', ''),
        'server': response.headers.get('Server', ''),
        'response_time': response.elapsed.total_seconds(),
        'waf_detected': detect_waf(response),
        'security_headers': {},
        'cookies': {}
    }
    
    # Check security headers
    security_headers = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'Referrer-Policy',
    ]
    
    for header in security_headers:
        value = response.headers.get(header)
        analysis['security_headers'][header] = value if value else 'Missing'
    
    # Extract cookies
    for cookie in response.cookies:
        analysis['cookies'][cookie.name] = {
            'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
            'secure': cookie.secure,
            'httponly': cookie.has_nonstandard_attr('HttpOnly'),
            'samesite': cookie.get_nonstandard_attr('SameSite', 'None')
        }
    
    return analysis
