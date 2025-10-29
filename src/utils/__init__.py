"""Utils package initialization"""

from .http_client import HTTPClient, URLAnalyzer, detect_waf, analyze_response
from .scoring import (
    Severity,
    VulnerabilityType,
    VulnerabilityScore,
    calculate_vulnerability_score,
    calculate_overall_risk_score,
    get_remediation
)
from .payloads import (
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS,
    FILE_INCLUSION_PAYLOADS,
    XXE_PAYLOADS,
    CSRF_INDICATORS,
    SENSITIVE_INFO_PATTERNS,
    SECURITY_HEADERS,
    COMMON_ENDPOINTS,
    USER_AGENTS
)
from .auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    generate_api_key
)

__all__ = [
    'HTTPClient',
    'URLAnalyzer',
    'detect_waf',
    'analyze_response',
    'Severity',
    'VulnerabilityType',
    'VulnerabilityScore',
    'calculate_vulnerability_score',
    'calculate_overall_risk_score',
    'get_remediation',
    'SQL_INJECTION_PAYLOADS',
    'XSS_PAYLOADS',
    'PATH_TRAVERSAL_PAYLOADS',
    'COMMAND_INJECTION_PAYLOADS',
    'FILE_INCLUSION_PAYLOADS',
    'XXE_PAYLOADS',
    'CSRF_INDICATORS',
    'SENSITIVE_INFO_PATTERNS',
    'SECURITY_HEADERS',
    'COMMON_ENDPOINTS',
    'USER_AGENTS',
    'hash_password',
    'verify_password',
    'create_access_token',
    'decode_access_token',
    'generate_api_key'
]
