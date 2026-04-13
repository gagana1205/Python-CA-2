"""Main vulnerability scanner orchestrator.

Coordinates all scanning modules (headers, ports, SSL, crawler)
and aggregates results into a unified vulnerability report.
"""
import json
import logging
from datetime import datetime, timezone

from app import db
from app.models import ScanResult, Vulnerability
from app.services.header_scanner import HeaderScanner
from app.services.port_scanner import PortScanner
from app.services.ssl_scanner import SSLScanner
from app.services.crawler import WebCrawler

logger = logging.getLogger(__name__)


class VulnScanner:
    """Orchestrates vulnerability scans across multiple modules."""

    def __init__(self):
        self.header_scanner = HeaderScanner()
        self.port_scanner = PortScanner()
        self.ssl_scanner = SSLScanner()
        self.web_crawler = WebCrawler()

    def run_full_scan(self, url, user_id, timeout=10, max_pages=50):
        """Execute a comprehensive vulnerability scan.

        Args:
            url: Target URL to scan.
            user_id: ID of the user initiating the scan.
            timeout: Request timeout in seconds.
            max_pages: Max pages for crawler.

        Returns:
            ScanResult model instance with all findings.
        """
        scan = ScanResult(
            target_url=url,
            scan_type='full',
            status='running',
            user_id=user_id
        )
        db.session.add(scan)
        db.session.commit()

        all_vulns = []
        full_results = {}

        # 1. Header scan
        try:
            header_results = self.header_scanner.scan(url, timeout)
            full_results['headers'] = header_results
            all_vulns.extend(header_results.get('vulnerabilities', []))
        except Exception as e:
            full_results['headers'] = {'error': str(e)}

        # 2. Port scan
        try:
            port_results = self.port_scanner.scan(url, timeout=2)
            full_results['ports'] = port_results
            all_vulns.extend(port_results.get('vulnerabilities', []))
        except Exception as e:
            full_results['ports'] = {'error': str(e)}

        # 3. SSL scan
        try:
            ssl_results = self.ssl_scanner.scan(url, timeout)
            full_results['ssl'] = ssl_results
            all_vulns.extend(ssl_results.get('vulnerabilities', []))
        except Exception as e:
            full_results['ssl'] = {'error': str(e)}

        # 4. Web crawler
        try:
            crawl_results = self.web_crawler.crawl(url, max_pages=max_pages, timeout=timeout)
            full_results['crawler'] = crawl_results
            all_vulns.extend(crawl_results.get('vulnerabilities', []))

            # Add sensitive file findings as vulnerabilities
            for sf in crawl_results.get('sensitive_files', []):
                all_vulns.append({
                    'category': 'info',
                    'name': f'Sensitive File Exposed: {sf["path"]}',
                    'severity': 'high' if sf['path'] in ('/.env', '/.git/config', '/wp-config.php') else 'medium',
                    'description': f'Sensitive file {sf["path"]} is publicly accessible.',
                    'recommendation': f'Restrict access to {sf["path"]} via server configuration.',
                    'evidence': f'HTTP 200 - {sf["size"]} bytes'
                })
        except Exception as e:
            full_results['crawler'] = {'error': str(e)}

        # Store results
        scan.set_results(full_results)
        scan.total_vulnerabilities = len(all_vulns)
        scan.risk_level = self._calculate_risk(all_vulns)
        scan.status = 'completed'
        scan.completed_at = datetime.now(timezone.utc)

        # Save individual vulnerabilities
        for v in all_vulns:
            vuln = Vulnerability(
                scan_id=scan.id,
                category=v.get('category', 'info'),
                name=v.get('name', 'Unknown'),
                severity=v.get('severity', 'info'),
                description=v.get('description', ''),
                recommendation=v.get('recommendation', ''),
                evidence=v.get('evidence', '')
            )
            db.session.add(vuln)

        db.session.commit()
        return scan

    def run_single_scan(self, url, scan_type, user_id, timeout=10):
        """Run a single scan module.

        Args:
            url: Target URL.
            scan_type: One of 'headers', 'ports', 'ssl', 'crawl'.
            user_id: User ID.
            timeout: Request timeout.

        Returns:
            ScanResult model instance.
        """
        scan = ScanResult(
            target_url=url,
            scan_type=scan_type,
            status='running',
            user_id=user_id
        )
        db.session.add(scan)
        db.session.commit()

        vulns = []
        results = {}

        scanners = {
            'headers': lambda: self.header_scanner.scan(url, timeout),
            'ports': lambda: self.port_scanner.scan(url, timeout=2),
            'ssl': lambda: self.ssl_scanner.scan(url, timeout),
            'crawl': lambda: self.web_crawler.crawl(url, max_pages=20, timeout=timeout),
        }

        try:
            scanner_fn = scanners.get(scan_type)
            if scanner_fn:
                results = scanner_fn()
                vulns = results.get('vulnerabilities', [])
        except Exception as e:
            results = {'error': str(e)}

        scan.set_results(results)
        scan.total_vulnerabilities = len(vulns)
        scan.risk_level = self._calculate_risk(vulns)
        scan.status = 'completed'
        scan.completed_at = datetime.now(timezone.utc)

        for v in vulns:
            vuln = Vulnerability(
                scan_id=scan.id,
                category=v.get('category', 'info'),
                name=v.get('name', 'Unknown'),
                severity=v.get('severity', 'info'),
                description=v.get('description', ''),
                recommendation=v.get('recommendation', ''),
                evidence=v.get('evidence', '')
            )
            db.session.add(vuln)

        db.session.commit()
        return scan

    def _calculate_risk(self, vulnerabilities):
        """Calculate overall risk level from vulnerability list.

        Uses severity-weighted scoring algorithm.

        Args:
            vulnerabilities: List of vulnerability dicts.

        Returns:
            Risk level string: low, medium, high, or critical.
        """
        if not vulnerabilities:
            return 'low'

        severity_weights = {
            'critical': 10,
            'high': 5,
            'medium': 2,
            'low': 1,
            'info': 0
        }

        total_score = sum(
            severity_weights.get(v.get('severity', 'info'), 0)
            for v in vulnerabilities
        )

        if total_score >= 30:
            return 'critical'
        elif total_score >= 15:
            return 'high'
        elif total_score >= 5:
            return 'medium'
        return 'low'

    def export_scan_json(self, scan):
        """Export scan results as JSON."""
        return json.dumps(scan.to_dict(), indent=2)

    def export_scan_xml(self, scan):
        """Export scan results as XML."""
        vulns_xml = ''
        for v in scan.vulnerabilities.all():
            vulns_xml += (
                f'  <vulnerability>'
                f'<name>{v.name}</name>'
                f'<severity>{v.severity}</severity>'
                f'<category>{v.category}</category>'
                f'<description>{v.description}</description>'
                f'</vulnerability>\n'
            )
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<scan_report>\n'
            f'{scan.to_xml()}\n'
            f'<vulnerabilities>\n{vulns_xml}</vulnerabilities>\n'
            f'</scan_report>'
        )

    def export_scan_csv(self, scan):
        """Export scan vulnerabilities as CSV."""
        lines = ['name,category,severity,description,recommendation']
        for v in scan.vulnerabilities.all():
            desc = v.description.replace(',', ';') if v.description else ''
            rec = v.recommendation.replace(',', ';') if v.recommendation else ''
            lines.append(f'{v.name},{v.category},{v.severity},{desc},{rec}')
        return '\n'.join(lines)
