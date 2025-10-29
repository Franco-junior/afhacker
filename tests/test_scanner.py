"""
Unit tests for Scanner module
"""
import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.utils.http_client import HTTPClient


class TestHTTPClient:
    """Test cases for HTTPClient"""
    
    def test_http_client_initialization(self):
        """Test HTTP client initializes"""
        client = HTTPClient()
        assert client is not None
        assert client.timeout == 10
        assert client.max_retries == 3
    
    def test_http_client_has_session(self):
        """Test HTTP client has session"""
        client = HTTPClient()
        assert hasattr(client, 'session')
        assert client.session is not None
    
    def test_http_client_methods_exist(self):
        """Test HTTP client has required methods"""
        client = HTTPClient()
        assert hasattr(client, 'get')
        assert hasattr(client, 'post')
        assert hasattr(client, 'is_accessible')


class TestScannerStructure:
    """Test scanner module structure"""
    
    def test_scanner_module_imports(self):
        """Test that scanner modules can be imported"""
        try:
            from src.modules import sqli_scanner
            from src.modules import xss_scanner
            from src.modules import csrf_scanner
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import scanner modules: {e}")
    
    def test_utils_modules_import(self):
        """Test that utility modules can be imported"""
        try:
            from src.utils import scoring
            from src.utils import payloads
            from src.utils import auth
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import utility modules: {e}")


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
    assert sample_scan_result['risk_score'] == 7.5


def test_scan_result_structure(sample_scan_result):
    """Test scan result has correct structure"""
    required_fields = ['scan_id', 'target_url', 'vulnerabilities_found', 
                      'risk_score', 'risk_level', 'vulnerabilities']
    
    for field in required_fields:
        assert field in sample_scan_result, f"Missing required field: {field}"
    
    assert isinstance(sample_scan_result['vulnerabilities'], list)
    assert len(sample_scan_result['vulnerabilities']) > 0
    
    vuln = sample_scan_result['vulnerabilities'][0]
    assert 'type' in vuln
    assert 'severity' in vuln
    assert 'cvss_score' in vuln
    assert 'location' in vuln
