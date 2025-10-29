"""
CVSS-like scoring system for vulnerability assessment
"""
from enum import Enum
from typing import Dict, List
from dataclasses import dataclass


class Severity(Enum):
    """Vulnerability severity levels"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VulnerabilityType(Enum):
    """OWASP Top 10 vulnerability types"""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    PATH_TRAVERSAL = "Path Traversal"
    COMMAND_INJECTION = "Command Injection"
    FILE_INCLUSION = "File Inclusion (LFI/RFI)"
    XXE = "XML External Entities (XXE)"
    INFO_DISCLOSURE = "Information Disclosure"
    BROKEN_AUTH = "Broken Authentication"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    SENSITIVE_DATA_EXPOSURE = "Sensitive Data Exposure"
    MISSING_ACCESS_CONTROL = "Missing Access Control"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    INSUFFICIENT_LOGGING = "Insufficient Logging"


@dataclass
class VulnerabilityScore:
    """Vulnerability scoring details"""
    base_score: float  # 0-10
    severity: Severity
    exploitability: float  # 0-10
    impact: float  # 0-10
    cvss_vector: str


# Base scores for each vulnerability type (CVSS-like)
VULNERABILITY_BASE_SCORES = {
    VulnerabilityType.SQL_INJECTION: 9.8,
    VulnerabilityType.COMMAND_INJECTION: 9.8,
    VulnerabilityType.XXE: 9.1,
    VulnerabilityType.FILE_INCLUSION: 8.6,
    VulnerabilityType.XSS: 7.2,
    VulnerabilityType.BROKEN_AUTH: 8.1,
    VulnerabilityType.SENSITIVE_DATA_EXPOSURE: 7.5,
    VulnerabilityType.CSRF: 6.5,
    VulnerabilityType.PATH_TRAVERSAL: 7.5,
    VulnerabilityType.SECURITY_MISCONFIG: 6.5,
    VulnerabilityType.MISSING_ACCESS_CONTROL: 8.2,
    VulnerabilityType.INSECURE_DESERIALIZATION: 8.8,
    VulnerabilityType.INFO_DISCLOSURE: 5.3,
    VulnerabilityType.INSUFFICIENT_LOGGING: 3.3,
}


def calculate_severity(score: float) -> Severity:
    """
    Calculate severity level based on CVSS score
    
    Args:
        score: CVSS score (0-10)
        
    Returns:
        Severity level
    """
    if score == 0:
        return Severity.INFO
    elif 0 < score < 4.0:
        return Severity.LOW
    elif 4.0 <= score < 7.0:
        return Severity.MEDIUM
    elif 7.0 <= score < 9.0:
        return Severity.HIGH
    else:  # 9.0-10.0
        return Severity.CRITICAL


def calculate_exploitability(
    attack_vector: str = "NETWORK",
    attack_complexity: str = "LOW",
    privileges_required: str = "NONE",
    user_interaction: str = "NONE"
) -> float:
    """
    Calculate exploitability score based on CVSS metrics
    
    Args:
        attack_vector: NETWORK, ADJACENT, LOCAL, PHYSICAL
        attack_complexity: LOW, HIGH
        privileges_required: NONE, LOW, HIGH
        user_interaction: NONE, REQUIRED
        
    Returns:
        Exploitability score (0-10)
    """
    av_scores = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2}
    ac_scores = {"LOW": 0.77, "HIGH": 0.44}
    pr_scores = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
    ui_scores = {"NONE": 0.85, "REQUIRED": 0.62}
    
    exploitability = (
        8.22 * 
        av_scores.get(attack_vector, 0.85) *
        ac_scores.get(attack_complexity, 0.77) *
        pr_scores.get(privileges_required, 0.85) *
        ui_scores.get(user_interaction, 0.85)
    )
    
    return round(exploitability, 1)


def calculate_impact(
    confidentiality: str = "HIGH",
    integrity: str = "HIGH",
    availability: str = "HIGH"
) -> float:
    """
    Calculate impact score based on CVSS metrics
    
    Args:
        confidentiality: NONE, LOW, HIGH
        integrity: NONE, LOW, HIGH
        availability: NONE, LOW, HIGH
        
    Returns:
        Impact score (0-10)
    """
    cia_scores = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}
    
    impact_base = (
        1 - (
            (1 - cia_scores.get(confidentiality, 0.56)) *
            (1 - cia_scores.get(integrity, 0.56)) *
            (1 - cia_scores.get(availability, 0.56))
        )
    )
    
    impact = 6.42 * impact_base
    
    return round(impact, 1)


def calculate_vulnerability_score(
    vuln_type: VulnerabilityType,
    confirmed: bool = False,
    has_payload: bool = False,
    response_evidence: bool = False,
    **kwargs
) -> VulnerabilityScore:
    """
    Calculate comprehensive vulnerability score
    
    Args:
        vuln_type: Type of vulnerability
        confirmed: Whether vulnerability is confirmed
        has_payload: Whether working payload was found
        response_evidence: Whether response contains evidence
        **kwargs: Additional CVSS metrics
        
    Returns:
        VulnerabilityScore object
    """
    base_score = VULNERABILITY_BASE_SCORES.get(vuln_type, 5.0)
    
    # Adjust score based on confirmation level
    if not confirmed:
        base_score *= 0.6  # Reduce score for unconfirmed
    if has_payload:
        base_score = min(10.0, base_score * 1.1)  # Increase for working payload
    if response_evidence:
        base_score = min(10.0, base_score * 1.05)  # Slight increase for evidence
    
    # Calculate exploitability and impact
    exploitability = calculate_exploitability(
        attack_vector=kwargs.get("attack_vector", "NETWORK"),
        attack_complexity=kwargs.get("attack_complexity", "LOW"),
        privileges_required=kwargs.get("privileges_required", "NONE"),
        user_interaction=kwargs.get("user_interaction", "NONE")
    )
    
    impact = calculate_impact(
        confidentiality=kwargs.get("confidentiality", "HIGH"),
        integrity=kwargs.get("integrity", "HIGH"),
        availability=kwargs.get("availability", "HIGH")
    )
    
    # Calculate final score
    final_score = round(base_score, 1)
    severity = calculate_severity(final_score)
    
    # Generate CVSS vector string
    cvss_vector = (
        f"CVSS:3.1/"
        f"AV:{kwargs.get('attack_vector', 'N')[0]}/"
        f"AC:{kwargs.get('attack_complexity', 'L')[0]}/"
        f"PR:{kwargs.get('privileges_required', 'N')[0]}/"
        f"UI:{kwargs.get('user_interaction', 'N')[0]}/"
        f"S:U/"
        f"C:{kwargs.get('confidentiality', 'H')[0]}/"
        f"I:{kwargs.get('integrity', 'H')[0]}/"
        f"A:{kwargs.get('availability', 'H')[0]}"
    )
    
    return VulnerabilityScore(
        base_score=final_score,
        severity=severity,
        exploitability=exploitability,
        impact=impact,
        cvss_vector=cvss_vector
    )


def calculate_overall_risk_score(vulnerabilities: List[Dict]) -> Dict:
    """
    Calculate overall risk score for a scan
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        Dictionary with risk metrics
    """
    if not vulnerabilities:
        return {
            "overall_score": 0.0,
            "risk_level": "LOW",
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "total_count": 0
        }
    
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }
    
    total_cvss_score = 0
    max_cvss_score = 0
    cvss_scores = []
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "INFO")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        cvss_score = vuln.get("cvss_score", 0)
        if cvss_score:
            cvss_scores.append(cvss_score)
            total_cvss_score += cvss_score
            max_cvss_score = max(max_cvss_score, cvss_score)
    
    # Calculate overall risk score using multiple factors:
    # 1. Maximum CVSS score (40% weight) - represents worst case
    # 2. Average CVSS score (30% weight) - represents overall severity
    # 3. Weighted count (30% weight) - represents volume of issues
    
    avg_cvss = total_cvss_score / len(cvss_scores) if cvss_scores else 0
    
    weighted_count_score = (
        severity_counts["CRITICAL"] * 10.0 +
        severity_counts["HIGH"] * 7.5 +
        severity_counts["MEDIUM"] * 5.0 +
        severity_counts["LOW"] * 2.5 +
        severity_counts["INFO"] * 1.0
    ) / max(len(vulnerabilities), 1)
    
    # Combined risk score (0-10 scale)
    risk_score = (
        max_cvss_score * 0.40 +      # Highest severity drives 40% of score
        avg_cvss * 0.30 +             # Average severity drives 30%
        weighted_count_score * 0.30   # Volume/distribution drives 30%
    )
    
    # Ensure score is between 0-10
    risk_score = min(10.0, max(0.0, risk_score))
    
    # Determine overall risk level based on both score and severity counts
    if risk_score >= 8.0 or severity_counts["CRITICAL"] > 0:
        risk_level = "CRITICAL"
    elif risk_score >= 6.0 or severity_counts["HIGH"] >= 3:
        risk_level = "HIGH"
    elif risk_score >= 4.0 or severity_counts["MEDIUM"] >= 5:
        risk_level = "MEDIUM"
    elif risk_score >= 2.0:
        risk_level = "LOW"
    else:
        risk_level = "INFO"
    
    return {
        "overall_score": round(risk_score, 1),
        "risk_level": risk_level,
        "max_cvss_score": round(max_cvss_score, 1),
        "avg_cvss_score": round(avg_cvss, 1),
        "critical_count": severity_counts["CRITICAL"],
        "high_count": severity_counts["HIGH"],
        "medium_count": severity_counts["MEDIUM"],
        "low_count": severity_counts["LOW"],
        "info_count": severity_counts["INFO"],
        "total_count": len(vulnerabilities)
    }


# Remediation recommendations for each vulnerability type
REMEDIATION_RECOMMENDATIONS = {
    VulnerabilityType.SQL_INJECTION: {
        "summary": "Use prepared statements (parameterized queries) and input validation",
        "details": [
            "Always use parameterized queries or prepared statements",
            "Never concatenate user input directly into SQL queries",
            "Implement proper input validation and sanitization",
            "Use ORM frameworks with built-in SQL injection protection",
            "Apply principle of least privilege for database accounts",
            "Implement Web Application Firewall (WAF) rules"
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
    },
    VulnerabilityType.XSS: {
        "summary": "Sanitize all user input and implement Content Security Policy",
        "details": [
            "Encode all output data before rendering in HTML",
            "Use context-aware output encoding",
            "Implement Content Security Policy (CSP) headers",
            "Validate and sanitize all user inputs",
            "Use frameworks with built-in XSS protection",
            "Avoid using dangerous functions like innerHTML"
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
    },
    VulnerabilityType.CSRF: {
        "summary": "Implement anti-CSRF tokens and SameSite cookies",
        "details": [
            "Use anti-CSRF tokens for all state-changing operations",
            "Implement SameSite cookie attribute",
            "Verify Origin and Referer headers",
            "Use framework-provided CSRF protection",
            "Require re-authentication for sensitive actions",
            "Implement proper session management"
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
        ]
    },
    VulnerabilityType.COMMAND_INJECTION: {
        "summary": "Avoid system calls with user input; use safe APIs instead",
        "details": [
            "Never pass user input directly to system commands",
            "Use language-specific libraries instead of shell commands",
            "Implement strict input validation and whitelist allowed values",
            "Use parameterized commands when available",
            "Apply principle of least privilege",
            "Run applications in sandboxed environments"
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
        ]
    },
    VulnerabilityType.PATH_TRAVERSAL: {
        "summary": "Validate and sanitize file paths; use whitelist approach",
        "details": [
            "Never use user input directly in file paths",
            "Implement strict path validation and canonicalization",
            "Use whitelist of allowed files/directories",
            "Reject paths containing '../' or similar patterns",
            "Run application with minimal file system permissions",
            "Use chroot jails or containerization"
        ],
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal"
        ]
    }
}


def get_remediation(vuln_type: VulnerabilityType) -> Dict:
    """
    Get remediation recommendations for a vulnerability type
    
    Args:
        vuln_type: Type of vulnerability
        
    Returns:
        Dictionary with remediation information
    """
    return REMEDIATION_RECOMMENDATIONS.get(vuln_type, {
        "summary": "Review and fix the identified vulnerability",
        "details": ["Consult security best practices for this vulnerability type"],
        "references": ["https://owasp.org/www-project-top-ten/"]
    })
