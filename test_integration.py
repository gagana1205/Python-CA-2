"""Integration tests - testing full workflows across components."""
import pytest
from app import db
from app.models import User, ScanResult, Vulnerability


class TestUserWorkflow:
    def test_register_login_flow(self, app, client):
        response = client.post('/register', data={
            'username': 'integ', 'email': 'integ@test.com',
            'password': 'Integ@Pass1', 'confirm_password': 'Integ@Pass1'
        }, follow_redirects=True)
        assert b'Registration successful' in response.data

        response = client.post('/login', data={
            'username': 'integ', 'password': 'Integ@Pass1'
        }, follow_redirects=True)
        assert b'Welcome back' in response.data

        response = client.get('/')
        assert response.status_code == 200
        assert b'Vulnerability Scanner Dashboard' in response.data

    def test_scan_and_view_flow(self, app, auth_client):
        # Create a scan directly in DB (to avoid network calls in tests)
        with app.app_context():
            user = User.query.filter_by(username='testuser').first()
            scan = ScanResult(
                target_url='https://testsite.com',
                scan_type='headers',
                status='completed',
                risk_level='high',
                total_vulnerabilities=3,
                user_id=user.id
            )
            scan.set_results({'headers': {'score': 40}})
            db.session.add(scan)
            db.session.commit()

            vuln = Vulnerability(
                scan_id=scan.id, category='headers',
                name='Missing CSP', severity='high',
                description='No Content-Security-Policy header.',
                recommendation='Add CSP header.'
            )
            db.session.add(vuln)
            db.session.commit()
            scan_id = scan.id

        # View scan detail
        response = auth_client.get(f'/scans/{scan_id}')
        assert response.status_code == 200
        assert b'testsite.com' in response.data
        assert b'Missing CSP' in response.data

        # View scan list
        response = auth_client.get('/scans')
        assert response.status_code == 200
        assert b'testsite.com' in response.data

    def test_export_flow(self, app, auth_client):
        with app.app_context():
            user = User.query.filter_by(username='testuser').first()
            scan = ScanResult(
                target_url='https://export-test.com', scan_type='full',
                status='completed', risk_level='medium',
                total_vulnerabilities=2, user_id=user.id
            )
            db.session.add(scan)
            db.session.commit()

            for name, sev in [('Missing HSTS', 'high'), ('Server header exposed', 'info')]:
                v = Vulnerability(scan_id=scan.id, category='headers', name=name,
                                   severity=sev, description=f'{name} found.')
                db.session.add(v)
            db.session.commit()
            scan_id = scan.id

        # Export JSON
        response = auth_client.get(f'/scans/{scan_id}/export/json')
        assert response.status_code == 200
        assert 'application/json' in response.content_type

        # Export XML
        response = auth_client.get(f'/scans/{scan_id}/export/xml')
        assert response.status_code == 200
        assert 'application/xml' in response.content_type

        # Export CSV
        response = auth_client.get(f'/scans/{scan_id}/export/csv')
        assert response.status_code == 200
        assert 'text/csv' in response.content_type
        assert b'Missing HSTS' in response.data

    def test_delete_scan_flow(self, app, auth_client):
        with app.app_context():
            user = User.query.filter_by(username='testuser').first()
            scan = ScanResult(
                target_url='https://delete-me.com', scan_type='headers',
                status='completed', user_id=user.id
            )
            db.session.add(scan)
            db.session.commit()
            scan_id = scan.id

        response = auth_client.post(f'/scans/{scan_id}/delete', follow_redirects=True)
        assert b'deleted' in response.data.lower()

        with app.app_context():
            assert db.session.get(ScanResult, scan_id) is None

    def test_api_integration(self, app, auth_client):
        with app.app_context():
            user = User.query.filter_by(username='testuser').first()
            scan = ScanResult(
                target_url='https://api-test.com', scan_type='full',
                status='completed', risk_level='high',
                total_vulnerabilities=5, user_id=user.id
            )
            db.session.add(scan)
            db.session.commit()

        response = auth_client.get('/api/scans')
        data = response.get_json()
        assert data['total'] >= 1

        response = auth_client.get('/api/stats')
        data = response.get_json()
        assert data['total_scans'] >= 1
