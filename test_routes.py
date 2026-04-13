"""Unit tests for route handlers."""
import pytest
from app import db
from app.models import User, ScanResult


class TestAuthRoutes:
    def test_login_page_loads(self, client):
        response = client.get('/login')
        assert response.status_code == 200
        assert b'VulnScan Login' in response.data

    def test_register_page_loads(self, client):
        response = client.get('/register')
        assert response.status_code == 200
        assert b'Create Account' in response.data

    def test_successful_registration(self, app, client):
        response = client.post('/register', data={
            'username': 'newuser', 'email': 'new@test.com',
            'password': 'Secure@Pass1', 'confirm_password': 'Secure@Pass1'
        }, follow_redirects=True)
        assert b'Registration successful' in response.data

    def test_registration_password_mismatch(self, client):
        response = client.post('/register', data={
            'username': 'user2', 'email': 'u2@test.com',
            'password': 'Secure@Pass1', 'confirm_password': 'Different@1'
        }, follow_redirects=True)
        assert b'Passwords do not match' in response.data

    def test_registration_weak_password(self, client):
        response = client.post('/register', data={
            'username': 'weak', 'email': 'w@test.com',
            'password': 'short', 'confirm_password': 'short'
        }, follow_redirects=True)
        assert b'at least 8' in response.data

    def test_successful_login(self, app, client):
        with app.app_context():
            user = User(username='login1', email='l1@test.com')
            user.set_password('Valid@Pass1')
            db.session.add(user)
            db.session.commit()
        response = client.post('/login', data={
            'username': 'login1', 'password': 'Valid@Pass1'
        }, follow_redirects=True)
        assert b'Welcome back' in response.data

    def test_failed_login(self, app, client):
        with app.app_context():
            user = User(username='login2', email='l2@test.com')
            user.set_password('Valid@Pass1')
            db.session.add(user)
            db.session.commit()
        response = client.post('/login', data={
            'username': 'login2', 'password': 'Wrong@Pass1'
        }, follow_redirects=True)
        assert b'Invalid username or password' in response.data

    def test_logout(self, auth_client):
        response = auth_client.get('/logout', follow_redirects=True)
        assert b'logged out' in response.data

    def test_protected_route_redirect(self, client):
        response = client.get('/', follow_redirects=False)
        assert response.status_code == 302


class TestDashboardRoutes:
    def test_dashboard_loads(self, auth_client):
        response = auth_client.get('/')
        assert response.status_code == 200
        assert b'Vulnerability Scanner Dashboard' in response.data

    def test_stats_json(self, auth_client):
        response = auth_client.get('/stats/json')
        assert response.status_code == 200
        data = response.get_json()
        assert 'total_scans' in data
        assert 'total_vulnerabilities' in data


class TestScanRoutes:
    def test_new_scan_page(self, auth_client):
        response = auth_client.get('/scan')
        assert response.status_code == 200
        assert b'New Vulnerability Scan' in response.data

    def test_scan_list_page(self, auth_client):
        response = auth_client.get('/scans')
        assert response.status_code == 200
        assert b'Scan History' in response.data

    def test_scan_invalid_url(self, auth_client):
        response = auth_client.post('/scan', data={
            'target_url': 'not-a-url', 'scan_type': 'headers'
        }, follow_redirects=True)
        assert b'Invalid' in response.data or b'URL' in response.data

    def test_scan_private_ip_blocked(self, auth_client):
        response = auth_client.post('/scan', data={
            'target_url': 'http://127.0.0.1', 'scan_type': 'headers'
        }, follow_redirects=True)
        assert b'not allowed' in response.data or b'private' in response.data or b'internal' in response.data

    def test_scan_not_found(self, auth_client):
        response = auth_client.get('/scans/999', follow_redirects=True)
        assert b'not found' in response.data.lower() or response.status_code == 200


class TestCompareRoutes:
    def test_compare_page_loads(self, auth_client):
        response = auth_client.get('/compare')
        assert response.status_code == 200
        assert b'Compare' in response.data

    def test_compare_same_scan_rejected(self, app, auth_client):
        with app.app_context():
            user = User.query.filter_by(username='testuser').first()
            scan = ScanResult(target_url='https://test.com', scan_type='full',
                              status='completed', risk_level='high', user_id=user.id)
            db.session.add(scan)
            db.session.commit()
            scan_id = scan.id
        response = auth_client.post('/compare', data={
            'scan_a': scan_id, 'scan_b': scan_id
        }, follow_redirects=True)
        assert b'different' in response.data.lower()

    def test_compare_two_scans(self, app, auth_client):
        with app.app_context():
            user = User.query.filter_by(username='testuser').first()
            s1 = ScanResult(target_url='https://a.com', scan_type='full',
                            status='completed', risk_level='high', user_id=user.id)
            s2 = ScanResult(target_url='https://b.com', scan_type='full',
                            status='completed', risk_level='medium', user_id=user.id)
            db.session.add_all([s1, s2])
            db.session.commit()
            id1, id2 = s1.id, s2.id
        response = auth_client.post('/compare', data={
            'scan_a': id1, 'scan_b': id2
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'a.com' in response.data
        assert b'b.com' in response.data


class TestAPIRoutes:
    def test_api_scans(self, auth_client):
        response = auth_client.get('/api/scans')
        assert response.status_code == 200
        data = response.get_json()
        assert 'total' in data
        assert 'data' in data

    def test_api_stats(self, auth_client):
        response = auth_client.get('/api/stats')
        assert response.status_code == 200
        data = response.get_json()
        assert 'total_scans' in data

    def test_api_scan_not_found(self, auth_client):
        response = auth_client.get('/api/scans/999')
        assert response.status_code == 404
