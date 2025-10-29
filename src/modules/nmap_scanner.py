"""
Nmap Scanner Module
Performs network reconnaissance using Nmap
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from urllib.parse import urlparse
import subprocess
import json
import re
from typing import Dict, List


class NmapScanner:
    """
    Network scanner using Nmap for reconnaissance
    Detects open ports, services, and potential vulnerabilities
    """
    
    def __init__(self):
        self.vulnerabilities = []
        self.nmap_path = 'nmap'  # Default, will be updated if found elsewhere
        
    def scan(self, target_url: str) -> Dict:
        """
        Perform Nmap scan on target
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            Dictionary with scan results
        """
        print(f"[*] Starting Nmap reconnaissance on {target_url}")
        
        # Extract host from URL
        parsed = urlparse(target_url)
        host = parsed.netloc or parsed.path
        
        # Remove port if present
        if ':' in host:
            host = host.split(':')[0]
            
        results = {
            "vulnerabilities": [],
            "open_ports": [],
            "services": [],
            "summary": ""
        }
        
        # Check if nmap is available
        if not self._check_nmap_available():
            print("[!] Nmap not found. Skipping network scan.")
            results["summary"] = "Nmap not installed - reconnaissance skipped"
            return results
        
        # Run basic port scan
        scan_results = self._run_nmap_scan(host)
        
        if scan_results:
            results = self._parse_results(scan_results, host, target_url)
        
        print(f"[+] Nmap scan completed. Found {len(results['open_ports'])} open ports")
        
        return results
    
    def _check_nmap_available(self) -> bool:
        """Check if nmap is installed and accessible"""
        # Try to find nmap in common Windows locations
        nmap_paths = [
            'nmap',  # In PATH
            r'C:\Program Files (x86)\Nmap\nmap.exe',
            r'C:\Program Files\Nmap\nmap.exe',
            r'C:\Windows\System32\nmap.exe',
        ]
        
        for nmap_path in nmap_paths:
            try:
                result = subprocess.run(
                    [nmap_path, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    # Store the working path for later use
                    self.nmap_path = nmap_path
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
                continue
        
        return False
    
    def _run_nmap_scan(self, host: str) -> str:
        """
        Run nmap scan on host
        
        Args:
            host: Target host to scan
            
        Returns:
            Raw nmap output
        """
        try:
            # Run nmap with service detection on common ports
            # -sV: Version detection
            # -p: Port range (common web ports)
            # -T4: Faster execution
            # --open: Only show open ports
            cmd = [
                self.nmap_path,  # Use the nmap path found earlier
                '-sV',
                '-p', '21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443',
                '-T4',
                '--open',
                host
            ]
            
            print(f"[*] Running: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minutes timeout
            )
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            print("[!] Nmap scan timed out")
            return ""
        except Exception as e:
            print(f"[!] Error running nmap: {e}")
            return ""
    
    def _parse_results(self, scan_output: str, host: str, target_url: str) -> Dict:
        """
        Parse nmap output and generate vulnerability findings
        
        Args:
            scan_output: Raw nmap output
            host: Target host
            target_url: Original target URL
            
        Returns:
            Dictionary with structured results
        """
        results = {
            "vulnerabilities": [],
            "open_ports": [],
            "services": [],
            "summary": ""
        }
        
        lines = scan_output.split('\n')
        open_ports_found = []
        
        # Parse port information
        for line in lines:
            # Match lines like: "80/tcp   open  http    Apache httpd 2.4.41"
            match = re.match(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)', line)
            if match:
                port = match.group(1)
                service = match.group(2)
                version = match.group(3).strip()
                
                open_ports_found.append({
                    "port": port,
                    "service": service,
                    "version": version
                })
                
                results["open_ports"].append(port)
                results["services"].append(f"{service} ({port})")
                
                # Check for potentially vulnerable services
                vuln = self._check_service_vulnerabilities(
                    port, service, version, host, target_url
                )
                if vuln:
                    results["vulnerabilities"].extend(vuln)
        
        # Generate summary
        if open_ports_found:
            results["summary"] = f"Found {len(open_ports_found)} open ports on {host}"
        else:
            results["summary"] = "No open ports detected in scan range"
        
        return results
    
    def _check_service_vulnerabilities(
        self, port: str, service: str, version: str, host: str, target_url: str
    ) -> List[Dict]:
        """
        Check if service/version has known vulnerabilities
        
        Args:
            port: Port number
            service: Service name
            version: Service version
            host: Target host
            target_url: Original URL
            
        Returns:
            List of vulnerability findings
        """
        vulnerabilities = []
        
        # Severity to CVSS score mapping
        severity_scores = {
            'CRITICAL': 9.5,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5,
            'INFO': 0.5
        }
        
        # Check for exposed admin ports
        dangerous_ports = {
            '21': ('FTP', 'FTP service exposed', 'MEDIUM'),
            '22': ('SSH', 'SSH service exposed', 'LOW'),
            '23': ('Telnet', 'Insecure Telnet service', 'HIGH'),
            '3306': ('MySQL', 'MySQL database exposed', 'HIGH'),
            '5432': ('PostgreSQL', 'PostgreSQL database exposed', 'HIGH'),
            '3389': ('RDP', 'Remote Desktop exposed', 'HIGH'),
            '445': ('SMB', 'SMB service exposed', 'MEDIUM'),
        }
        
        if port in dangerous_ports:
            name, desc, severity = dangerous_ports[port]
            vulnerabilities.append({
                "type": "Information Disclosure",
                "subtype": "Exposed Service",
                "severity": severity,
                "cvss_score": severity_scores[severity],
                "location": f"{host}:{port}",
                "parameter": service,
                "description": f"{desc}. Port {port} ({name}) is publicly accessible.",
                "evidence": f"Nmap detected open {service} on port {port}\nVersion: {version or 'Unknown'}",
                "remediation": f"Restrict access to port {port} using firewall rules. Only allow access from trusted IP addresses.",
                "confidence": "High"
            })
        
        # Check for outdated/vulnerable versions
        if version:
            # Check for old Apache versions
            if 'apache' in version.lower() or 'httpd' in version.lower():
                if self._is_outdated_apache(version):
                    vulnerabilities.append({
                        "type": "Information Disclosure",
                        "subtype": "Outdated Software",
                        "severity": "MEDIUM",
                        "cvss_score": severity_scores['MEDIUM'],
                        "location": f"{target_url}",
                        "parameter": "Server",
                        "description": f"Outdated Apache version detected: {version}",
                        "evidence": f"Nmap service detection: {version}",
                        "remediation": "Update Apache to the latest stable version to patch known vulnerabilities.",
                        "confidence": "High"
                    })
            
            # Check for old nginx versions
            if 'nginx' in version.lower():
                if self._is_outdated_nginx(version):
                    vulnerabilities.append({
                        "type": "Information Disclosure",
                        "subtype": "Outdated Software",
                        "severity": "MEDIUM",
                        "cvss_score": severity_scores['MEDIUM'],
                        "location": f"{target_url}",
                        "parameter": "Server",
                        "description": f"Outdated Nginx version detected: {version}",
                        "evidence": f"Nmap service detection: {version}",
                        "remediation": "Update Nginx to the latest stable version.",
                        "confidence": "High"
                    })
        
        # Check for version disclosure
        if version and version.lower() != 'unknown':
            vulnerabilities.append({
                "type": "Information Disclosure",
                "subtype": "Version Disclosure",
                "severity": "LOW",
                "cvss_score": severity_scores['LOW'],
                "location": f"{host}:{port}",
                "parameter": service,
                "description": f"Service version information exposed: {service} {version}",
                "evidence": f"Nmap detected: {version}",
                "remediation": "Configure the service to hide version information in banners and headers.",
                "confidence": "High"
            })
        
        return vulnerabilities
    
    def _is_outdated_apache(self, version: str) -> bool:
        """Check if Apache version is outdated (simple heuristic)"""
        try:
            # Extract version number (e.g., "2.4.41" from "Apache httpd 2.4.41")
            match = re.search(r'(\d+)\.(\d+)\.(\d+)', version)
            if match:
                major, minor, patch = map(int, match.groups())
                # Consider versions older than 2.4.50 as outdated (example)
                if major < 2 or (major == 2 and minor < 4) or (major == 2 and minor == 4 and patch < 50):
                    return True
        except:
            pass
        return False
    
    def _is_outdated_nginx(self, version: str) -> bool:
        """Check if Nginx version is outdated (simple heuristic)"""
        try:
            # Extract version number
            match = re.search(r'(\d+)\.(\d+)\.(\d+)', version)
            if match:
                major, minor, patch = map(int, match.groups())
                # Consider versions older than 1.20.0 as outdated (example)
                if major < 1 or (major == 1 and minor < 20):
                    return True
        except:
            pass
        return False


if __name__ == "__main__":
    # Test the scanner
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python nmap_scanner.py <url>")
        sys.exit(1)
    
    scanner = NmapScanner()
    results = scanner.scan(sys.argv[1])
    
    print("\n" + "="*60)
    print("NMAP SCAN RESULTS")
    print("="*60)
    print(f"\nSummary: {results['summary']}")
    print(f"\nOpen Ports: {', '.join(results['open_ports']) if results['open_ports'] else 'None'}")
    print(f"\nServices: {', '.join(results['services']) if results['services'] else 'None'}")
    print(f"\nVulnerabilities Found: {len(results['vulnerabilities'])}")
    
    for vuln in results['vulnerabilities']:
        print(f"\n[{vuln['severity']}] {vuln['type']} - {vuln['subtype']}")
        print(f"  Location: {vuln['location']}")
        print(f"  Description: {vuln['description']}")
