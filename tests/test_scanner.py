"""
Unit tests for Scanner module
"""
import pytest
from src.scanner import SecurityScanner
from src.utils.http_client import HTTPClient


class TestSecurityScanner:
    """Test cases for SecurityScanner"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.scanner = SecurityScanner()
    
    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        assert self.scanner is not None
        assert hasattr(self.scanner, 'http_client')
        assert hasattr(self.scanner, 'scanners')
    
    def test_scanner_has_all_modules(self):
        """Test scanner has all required modules"""
        expected_modules = [
            'sqli', 'xss', 'csrf', 'path_traversal',
            'command_injection', 'info_disclosure'
        ]
        
        for module in expected_modules:
            assert module in self.scanner.scanners
    
    def test_url_validation(self):
        """Test URL validation"""
        # Valid URLs
        assert self.scanner._validate_url('https://example.com') == True
        assert self.scanner._validate_url('http://test.com') == True
        
        # Invalid URLs
        assert self.scanner._validate_url('not-a-url') == False
        assert self.scanner._validate_url('') == False
    
    def test_scan_with_invalid_url(self):
        """Test scan with invalid URL"""
        result = self.scanner.scan('invalid-url')
        assert result.get('error') == True
    
    def test_scan_result_structure(self):
        """Test scan result has correct structure"""
        # Mock a simple scan
        result = self.scanner.scan('http://httpbin.org/get')
        
        assert 'scan_id' in result
        assert 'target_url' in result
        assert 'scan_date' in result
        assert 'vulnerabilities' in result
        assert isinstance(result['vulnerabilities'], list)


class TestHTTPClient:
    """Test cases for HTTPClient"""
    
    def test_http_client_initialization(self):
        """Test HTTP client initializes"""
        client = HTTPClient()
        assert client is not None
        assert client.timeout == 10
        assert client.max_retries == 3
    
    def test_http_client_get_request(self):
        """Test GET request"""
        client = HTTPClient()
        response = client.get('https://httpbin.org/get')
        assert response is not None
        assert response.status_code == 200
    
    def test_http_client_is_accessible(self):
        """Test URL accessibility check"""
        client = HTTPClient()
        assert client.is_accessible('https://httpbin.org') == True
        assert client.is_accessible('https://this-should-not-exist-12345.com') == False


@pytest.fixture
def sample_scan_result():
    """Sample scan result fixture"""
    return {
        'scan_id': '20251028_120000',
        'target_url': 'https://example.com',
        'vulnerabilities_found': 3,
        'risk_score': 7.5,
        'risk_level': 'HIGH',
        'vulnerabilities': [
            {
                'type': 'SQL Injection',
                'severity': 'CRITICAL',
                'cvss_score': 9.8,
                'location': 'https://example.com/login'
            }
        ]
    }


def test_sample_scan_result_fixture(sample_scan_result):
    """Test sample scan result fixture"""
    assert sample_scan_result['vulnerabilities_found'] == 3
    assert sample_scan_result['risk_level'] == 'HIGH'
    assert len(sample_scan_result['vulnerabilities']) == 1
