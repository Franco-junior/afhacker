"""
Main Security Scanner
Coordinates all vulnerability scanning modules
"""
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Optional
import json
import sys
from urllib.parse import urlparse

from utils.http_client import HTTPClient, URLAnalyzer
from utils.scoring import calculate_overall_risk_score
from modules.sqli_scanner import SQLInjectionScanner
from modules.xss_scanner import XSSScanner
from modules.csrf_scanner import CSRFScanner
from modules.path_traversal import PathTraversalScanner
from modules.command_injection import CommandInjectionScanner
from modules.info_disclosure import InfoDisclosureScanner
from modules.nmap_scanner import NmapScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityScanner:
    """Main security scanner coordinating all modules"""
    
    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 3,
        verify_ssl: bool = False
    ):
        """
        Initialize Security Scanner
        
        Args:
            timeout: Request timeout
            max_retries: Maximum retries
            verify_ssl: Verify SSL certificates
        """
        self.http_client = HTTPClient(
            timeout=timeout,
            max_retries=max_retries,
            verify_ssl=verify_ssl
        )
        
        # Initialize all scanners
        self.scanners = {
            'sqli': SQLInjectionScanner(self.http_client),
            'xss': XSSScanner(self.http_client),
            'csrf': CSRFScanner(self.http_client),
            'path_traversal': PathTraversalScanner(self.http_client),
            'command_injection': CommandInjectionScanner(self.http_client),
            'info_disclosure': InfoDisclosureScanner(self.http_client)
        }
        
        self.scan_results = []
    
    def scan(
        self,
        url: str,
        scan_types: Optional[List[str]] = None,
        parameters: Optional[Dict] = None
    ) -> Dict:
        """
        Perform security scan
        
        Args:
            url: Target URL
            scan_types: List of scan types to perform (None = all)
            parameters: URL parameters to test
            
        Returns:
            Scan results dictionary
        """
        logger.info(f"=" * 80)
        logger.info(f"Starting security scan on: {url}")
        logger.info(f"=" * 80)
        
        # Validate URL
        if not self._validate_url(url):
            logger.error(f"Invalid URL: {url}")
            return self._create_error_result("Invalid URL")
        
        # Check if target is accessible
        if not self.http_client.is_accessible(url):
            logger.error(f"Target URL is not accessible: {url}")
            return self._create_error_result("Target not accessible")
        
        # Extract parameters if not provided
        if not parameters:
            parameters = URLAnalyzer.extract_parameters(url)
        
        # Perform scans
        all_vulnerabilities = []
        scan_start_time = datetime.now()
        
        # STEP 1: Network reconnaissance with Nmap (if available)
        logger.info(f"\n[+] Running NMAP reconnaissance...")
        try:
            nmap_scanner = NmapScanner()
            nmap_results = nmap_scanner.scan(url)
            
            if nmap_results['vulnerabilities']:
                all_vulnerabilities.extend(nmap_results['vulnerabilities'])
                logger.info(f"    Found {len(nmap_results['vulnerabilities'])} network issues")
            
            logger.info(f"    {nmap_results['summary']}")
            
            if nmap_results['open_ports']:
                logger.info(f"    Open ports: {', '.join(nmap_results['open_ports'])}")
            if nmap_results['services']:
                logger.info(f"    Services: {', '.join(nmap_results['services'])}")
        
        except Exception as e:
            logger.warning(f"Nmap scan failed (not critical): {e}")
        
        # STEP 2: Web application vulnerability scans
        # Determine which scans to run
        if not scan_types:
            scan_types = list(self.scanners.keys())
        
        for scan_type in scan_types:
            if scan_type not in self.scanners:
                logger.warning(f"Unknown scan type: {scan_type}")
                continue
            
            logger.info(f"\n[+] Running {scan_type.upper()} scan...")
            
            try:
                scanner = self.scanners[scan_type]
                
                # Some scanners don't need parameters
                if scan_type in ['csrf', 'info_disclosure']:
                    vulnerabilities = scanner.scan(url)
                else:
                    vulnerabilities = scanner.scan(url, parameters)
                
                all_vulnerabilities.extend(vulnerabilities)
                logger.info(f"    Found {len(vulnerabilities)} issues")
            
            except Exception as e:
                logger.error(f"Error in {scan_type} scan: {e}")
                continue
        
        scan_end_time = datetime.now()
        scan_duration = (scan_end_time - scan_start_time).total_seconds()
        
        # Calculate overall risk
        risk_metrics = calculate_overall_risk_score(all_vulnerabilities)
        
        # Build result
        result = {
            'scan_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'target_url': url,
            'scan_date': scan_start_time.isoformat(),
            'scan_duration': scan_duration,
            'scan_types': scan_types,
            'parameters_tested': len(parameters) if parameters else 0,
            'vulnerabilities_found': len(all_vulnerabilities),
            'risk_score': risk_metrics['overall_score'],
            'risk_level': risk_metrics['risk_level'],
            'severity_distribution': {
                'critical': risk_metrics['critical_count'],
                'high': risk_metrics['high_count'],
                'medium': risk_metrics['medium_count'],
                'low': risk_metrics['low_count'],
                'info': risk_metrics['info_count']
            },
            'vulnerabilities': all_vulnerabilities,
            'scanner_info': {
                'name': 'WebSecScanner',
                'version': '1.0.0',
                'modules': list(self.scanners.keys())
            }
        }
        
        self.scan_results.append(result)
        
        # Print summary
        self._print_summary(result)
        
        return result
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _create_error_result(self, error_message: str) -> Dict:
        """Create error result"""
        return {
            'error': True,
            'message': error_message,
            'scan_date': datetime.now().isoformat()
        }
    
    def _print_summary(self, result: Dict):
        """Print scan summary"""
        print("\n" + "=" * 80)
        print("SCAN SUMMARY")
        print("=" * 80)
        print(f"Target URL:         {result['target_url']}")
        print(f"Scan Duration:      {result['scan_duration']:.2f} seconds")
        print(f"Risk Score:         {result['risk_score']}/10.0 (Overall)")
        print(f"Risk Level:         {result['risk_level']}")
        print(f"\nVulnerabilities Found: {result['vulnerabilities_found']}")
        print(f"  - Critical:       {result['severity_distribution']['critical']}")
        print(f"  - High:           {result['severity_distribution']['high']}")
        print(f"  - Medium:         {result['severity_distribution']['medium']}")
        print(f"  - Low:            {result['severity_distribution']['low']}")
        print(f"  - Info:           {result['severity_distribution']['info']}")
        print("=" * 80)
        
        # Print details of critical and high severity vulnerabilities
        critical_high = [v for v in result['vulnerabilities'] 
                         if v['severity'] in ['CRITICAL', 'HIGH']]
        
        if critical_high:
            print(f"\nCRITICAL & HIGH SEVERITY VULNERABILITIES:")
            print("-" * 80)
            for vuln in critical_high:
                print(f"\n[{vuln['severity']}] {vuln['type']}")
                print(f"  Location: {vuln['location']}")
                if 'parameter' in vuln:
                    print(f"  Parameter: {vuln['parameter']}")
                if 'payload' in vuln:
                    print(f"  Payload: {vuln['payload'][:50]}...")
                print(f"  CVSS Score: {vuln['cvss_score']}")
        
        print("\n" + "=" * 80)
    
    def save_results(self, output_file: str, format: str = 'json'):
        """
        Save scan results to file
        
        Args:
            output_file: Output file path
            format: Output format (json, csv, txt)
        """
        if not self.scan_results:
            logger.warning("No scan results to save")
            return
        
        if format == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results[-1], f, indent=2, ensure_ascii=False)
            logger.info(f"Results saved to {output_file}")
        
        elif format == 'txt':
            with open(output_file, 'w', encoding='utf-8') as f:
                result = self.scan_results[-1]
                f.write("WEBSECSCANNER SECURITY SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Target URL:      {result['target_url']}\n")
                f.write(f"Scan Date:       {result['scan_date']}\n")
                f.write(f"Risk Score:      {result['risk_score']}/10.0\n")
                f.write(f"Risk Level:      {result['risk_level']}\n")
                f.write(f"Vulnerabilities: {result['vulnerabilities_found']}\n\n")
                
                for vuln in result['vulnerabilities']:
                    f.write("-" * 80 + "\n")
                    f.write(f"[{vuln['severity']}] {vuln['type']}\n")
                    f.write(f"Location: {vuln['location']}\n")
                    if 'parameter' in vuln:
                        f.write(f"Parameter: {vuln['parameter']}\n")
                    f.write(f"Description: {vuln['description']}\n")
                    f.write(f"Remediation: {vuln['remediation']}\n\n")
            
            logger.info(f"Results saved to {output_file}")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='WebSecScanner - Web Application Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py --url https://example.com
  python scanner.py --url https://example.com --full
  python scanner.py --url https://example.com --tests xss,sqli
  python scanner.py --url https://example.com --output report.json
        """
    )
    
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--tests', help='Comma-separated list of tests (sqli,xss,csrf,path_traversal,command_injection,info_disclosure)')
    parser.add_argument('--full', action='store_true', help='Run all tests')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--format', choices=['json', 'txt'], default='json', help='Output format')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Determine scan types
    scan_types = None
    if args.tests:
        scan_types = [t.strip() for t in args.tests.split(',')]
    elif args.full:
        scan_types = None  # Run all tests
    
    # Create scanner
    scanner = SecurityScanner(timeout=args.timeout)
    
    # Perform scan
    result = scanner.scan(args.url, scan_types=scan_types)
    
    # Save results if requested
    if args.output:
        scanner.save_results(args.output, format=args.format)
    
    # Exit with appropriate code
    if result.get('error'):
        sys.exit(1)
    elif result.get('risk_level') in ['CRITICAL', 'HIGH']:
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
