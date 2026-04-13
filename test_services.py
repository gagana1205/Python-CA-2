"""Unit tests for service layer components."""
import pytest
from app import db
from app.models import User, ScanResult
from app.services.header_scanner import HeaderScanner, SECURITY_HEADERS
from app.services.port_scanner import PortScanner, COMMON_PORTS
from app.services.ssl_scanner import SSLScanner
from app.services.crawler import WebCrawler, SENSITIVE_PATHS, VULN_PATTERNS
from app.services.vuln_scanner import VulnScanner
from app.utils.security import sanitize_input, validate_url, validate_password_strength


class TestInputValidation:
    def test_sanitize_xss(self):
        malicious = '<script>alert("XSS")</script>'
        clean = sanitize_input(malicious)
        assert '<script>' not in clean
        assert '&lt;script&gt;' in clean

    def test_sanitize_none(self):
        assert sanitize_input(None) is None

    def test_sanitize_strips_whitespace(self):
        assert sanitize_input('  hello  ') == 'hello'

    def test_valid_url(self):
        valid, url, err = validate_url('https://example.com')
        assert valid is True
        assert url == 'https://example.com'

    def test_url_auto_https(self):
        valid, url, err = validate_url('example.com')
        assert valid is True
        assert url == 'https://example.com'

    def test_invalid_url(self):
        valid, url, err = validate_url('')
        assert valid is False

    def test_block_localhost(self):
        valid, url, err = validate_url('http://localhost')
        assert valid is False
        assert 'internal' in err.lower() or 'private' in err.lower()

    def test_block_private_ip(self):
        valid, url, err = validate_url('http://127.0.0.1')
        assert valid is False

    def test_strong_password(self):
        valid, msg = validate_password_strength('Strong@Pass1')
        assert valid is True

    def test_weak_password_short(self):
        valid, msg = validate_password_strength('Ab@1')
        assert valid is False
        assert 'at least 8' in msg

    def test_weak_password_no_uppercase(self):
        valid, msg = validate_password_strength('alllower@1')
        assert valid is False

    def test_weak_password_no_special(self):
        valid, msg = validate_password_strength('NoSpecial1')
        assert valid is False


class TestHeaderScanner:
    def test_security_headers_defined(self):
        assert len(SECURITY_HEADERS) >= 7
        assert 'Strict-Transport-Security' in SECURITY_HEADERS
        assert 'Content-Security-Policy' in SECURITY_HEADERS
        assert 'X-Frame-Options' in SECURITY_HEADERS

    def test_header_severity_levels(self):
        for header, info in SECURITY_HEADERS.items():
            assert info['severity'] in ('info', 'low', 'medium', 'high', 'critical')
            assert 'description' in info
            assert 'recommendation' in info


class TestPortScanner:
    def test_common_ports_defined(self):
        assert len(COMMON_PORTS) >= 20
        assert 80 in COMMON_PORTS
        assert 443 in COMMON_PORTS
        assert 22 in COMMON_PORTS

    def test_port_info_structure(self):
        for port, (service, severity, desc) in COMMON_PORTS.items():
            assert isinstance(port, int)
            assert isinstance(service, str)
            assert severity in ('info', 'low', 'medium', 'high', 'critical')

    def test_check_port_closed(self):
        scanner = PortScanner()
        result = scanner._check_port('127.0.0.1', 59999, timeout=1)
        assert result is False


class TestSSLScanner:
    def test_parse_empty_cert(self):
        scanner = SSLScanner()
        result = scanner._parse_cert(None, 'example.com')
        assert result == {}

    def test_parse_cert_with_data(self):
        scanner = SSLScanner()
        mock_cert = {
            'subject': ((('commonName', 'example.com'),),),
            'issuer': ((('organizationName', 'Test CA'),),),
            'notBefore': 'Jan  1 00:00:00 2025 GMT',
            'notAfter': 'Dec 31 23:59:59 2026 GMT',
            'serialNumber': 'ABC123',
            'subjectAltName': (('DNS', 'example.com'), ('DNS', '*.example.com'))
        }
        result = scanner._parse_cert(mock_cert, 'example.com')
        assert result['common_name'] == 'example.com'
        assert result['issuer'] == 'Test CA'
        assert 'example.com' in result['san']
        assert result['days_until_expiry'] is not None


class TestWebCrawler:
    def test_sensitive_paths_defined(self):
        assert len(SENSITIVE_PATHS) >= 10
        assert '/.env' in SENSITIVE_PATHS
        assert '/robots.txt' in SENSITIVE_PATHS
        assert '/.git/config' in SENSITIVE_PATHS

    def test_vuln_patterns_defined(self):
        assert len(VULN_PATTERNS) >= 3
        assert 'inline_script' in VULN_PATTERNS
        assert 'form_action_http' in VULN_PATTERNS

    def test_vuln_pattern_matching(self):
        html_with_script = '<script>alert("test")</script>'
        matches = VULN_PATTERNS['inline_script']['pattern'].findall(html_with_script)
        assert len(matches) > 0

    def test_form_http_pattern(self):
        html = '<form action="http://insecure.com/login" method="POST">'
        matches = VULN_PATTERNS['form_action_http']['pattern'].findall(html)
        assert len(matches) > 0

    def test_email_pattern(self):
        html = 'Contact us at admin@example.com for help'
        matches = VULN_PATTERNS['email_exposure']['pattern'].findall(html)
        assert 'admin@example.com' in matches


class TestVulnScanner:
    def test_risk_calculation_no_vulns(self):
        scanner = VulnScanner()
        assert scanner._calculate_risk([]) == 'low'

    def test_risk_calculation_low(self):
        scanner = VulnScanner()
        vulns = [{'severity': 'info'}, {'severity': 'low'}]
        assert scanner._calculate_risk(vulns) == 'low'

    def test_risk_calculation_medium(self):
        scanner = VulnScanner()
        vulns = [{'severity': 'medium'}, {'severity': 'medium'}, {'severity': 'medium'}]
        assert scanner._calculate_risk(vulns) == 'medium'

    def test_risk_calculation_high(self):
        scanner = VulnScanner()
        vulns = [{'severity': 'high'}, {'severity': 'high'}, {'severity': 'high'}, {'severity': 'medium'}]
        assert scanner._calculate_risk(vulns) == 'high'

    def test_risk_calculation_critical(self):
        scanner = VulnScanner()
        vulns = [{'severity': 'critical'}, {'severity': 'critical'}, {'severity': 'critical'}, {'severity': 'high'}]
        assert scanner._calculate_risk(vulns) == 'critical'

    def test_export_json(self, app):
        with app.app_context():
            user = User(username='exp1', email='exp1@test.com')
            user.set_password('Pass@1234')
            db.session.add(user)
            db.session.commit()
            scan = ScanResult(target_url='https://export.com', scan_type='full', user_id=user.id)
            db.session.add(scan)
            db.session.commit()

            scanner = VulnScanner()
            json_str = scanner.export_scan_json(scan)
            assert 'export.com' in json_str

    def test_export_xml(self, app):
        with app.app_context():
            user = User(username='exp2', email='exp2@test.com')
            user.set_password('Pass@1234')
            db.session.add(user)
            db.session.commit()
            scan = ScanResult(target_url='https://xml.com', scan_type='full', user_id=user.id)
            db.session.add(scan)
            db.session.commit()

            scanner = VulnScanner()
            xml_str = scanner.export_scan_xml(scan)
            assert '<?xml version' in xml_str
            assert 'xml.com' in xml_str

    def test_export_csv(self, app):
        with app.app_context():
            user = User(username='exp3', email='exp3@test.com')
            user.set_password('Pass@1234')
            db.session.add(user)
            db.session.commit()
            scan = ScanResult(target_url='https://csv.com', scan_type='full', user_id=user.id)
            db.session.add(scan)
            db.session.commit()

            scanner = VulnScanner()
            csv_str = scanner.export_scan_csv(scan)
            assert 'name,category,severity' in csv_str
