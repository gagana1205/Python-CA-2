"""Unit tests for database models."""
import pytest
import json
from app import db
from app.models import User, ScanResult, Vulnerability, AuditLog


class TestUserModel:
    def test_create_user(self, app):
        with app.app_context():
            user = User(username='john', email='john@test.com')
            user.set_password('MyPass@123')
            db.session.add(user)
            db.session.commit()
            assert user.id is not None
            assert user.username == 'john'
            assert user.role == 'analyst'

    def test_password_hashing(self, app):
        with app.app_context():
            user = User(username='alice', email='alice@test.com')
            user.set_password('Secret@99')
            assert user.password_hash != 'Secret@99'
            assert user.check_password('Secret@99') is True
            assert user.check_password('WrongPass') is False

    def test_password_salt_uniqueness(self, app):
        with app.app_context():
            u1 = User(username='u1', email='u1@test.com')
            u2 = User(username='u2', email='u2@test.com')
            u1.set_password('Same@Pass1')
            u2.set_password('Same@Pass1')
            assert u1.password_hash != u2.password_hash

    def test_user_repr(self, app):
        with app.app_context():
            user = User(username='bob', email='bob@test.com')
            assert repr(user) == '<User bob>'

    def test_unique_username(self, app):
        with app.app_context():
            u1 = User(username='unique', email='u1@test.com')
            u1.set_password('Pass@1234')
            db.session.add(u1)
            db.session.commit()
            u2 = User(username='unique', email='u2@test.com')
            u2.set_password('Pass@1234')
            db.session.add(u2)
            with pytest.raises(Exception):
                db.session.commit()


class TestScanResultModel:
    def test_create_scan(self, app):
        with app.app_context():
            user = User(username='scanner', email='scan@test.com')
            user.set_password('Pass@1234')
            db.session.add(user)
            db.session.commit()

            scan = ScanResult(
                target_url='https://example.com',
                scan_type='full',
                user_id=user.id
            )
            db.session.add(scan)
            db.session.commit()
            assert scan.id is not None
            assert scan.status == 'running'
            assert scan.risk_level == 'unknown'

    def test_scan_results_json(self, app):
        with app.app_context():
            user = User(username='s2', email='s2@test.com')
            user.set_password('Pass@1234')
            db.session.add(user)
            db.session.commit()

            scan = ScanResult(target_url='https://test.com', scan_type='headers', user_id=user.id)
            test_data = {'headers': {'score': 75}, 'vulns': 3}
            scan.set_results(test_data)
            db.session.add(scan)
            db.session.commit()

            retrieved = scan.get_results()
            assert retrieved['headers']['score'] == 75
            assert retrieved['vulns'] == 3

    def test_scan_to_dict(self, app):
        with app.app_context():
            user = User(username='s3', email='s3@test.com')
            user.set_password('Pass@1234')
            db.session.add(user)
            db.session.commit()

            scan = ScanResult(target_url='https://dict.com', scan_type='full', user_id=user.id)
            db.session.add(scan)
            db.session.commit()

            data = scan.to_dict()
            assert data['target_url'] == 'https://dict.com'
            assert data['scan_type'] == 'full'
            assert data['user'] == 's3'

    def test_scan_to_xml(self, app):
        with app.app_context():
            user = User(username='s4', email='s4@test.com')
            user.set_password('Pass@1234')
            db.session.add(user)
            db.session.commit()

            scan = ScanResult(target_url='https://xml.com', scan_type='ssl', user_id=user.id, risk_level='high')
            db.session.add(scan)
            db.session.commit()

            xml = scan.to_xml()
            assert '<target_url>https://xml.com</target_url>' in xml
            assert '<risk_level>high</risk_level>' in xml


class TestVulnerabilityModel:
    def test_create_vulnerability(self, app):
        with app.app_context():
            user = User(username='v1', email='v1@test.com')
            user.set_password('Pass@1234')
            db.session.add(user)
            db.session.commit()

            scan = ScanResult(target_url='https://vuln.com', scan_type='full', user_id=user.id)
            db.session.add(scan)
            db.session.commit()

            vuln = Vulnerability(
                scan_id=scan.id,
                category='headers',
                name='Missing CSP',
                severity='high',
                description='Content-Security-Policy header not found.',
                recommendation='Add CSP header.'
            )
            db.session.add(vuln)
            db.session.commit()
            assert vuln.id is not None
            assert vuln.severity == 'high'

    def test_vulnerability_to_dict(self, app):
        with app.app_context():
            user = User(username='v2', email='v2@test.com')
            user.set_password('Pass@1234')
            db.session.add(user)
            db.session.commit()

            scan = ScanResult(target_url='https://v2.com', scan_type='full', user_id=user.id)
            db.session.add(scan)
            db.session.commit()

            vuln = Vulnerability(
                scan_id=scan.id, category='ssl', name='Expired Cert',
                severity='critical', description='SSL cert expired.'
            )
            db.session.add(vuln)
            db.session.commit()

            data = vuln.to_dict()
            assert data['name'] == 'Expired Cert'
            assert data['severity'] == 'critical'


class TestAuditLogModel:
    def test_create_audit_log(self, app):
        with app.app_context():
            log = AuditLog(action='login_success', ip_address='127.0.0.1')
            db.session.add(log)
            db.session.commit()
            assert log.id is not None
            assert log.timestamp is not None
