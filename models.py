"""Database models for the Vulnerability Scanner."""
import json
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, login_manager


class User(UserMixin, db.Model):
    """User model with secure password hashing."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='analyst')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)

    scans = db.relationship('ScanResult', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class ScanResult(db.Model):
    """Stores complete scan results for a target URL."""
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False, index=True)
    scan_type = db.Column(db.String(50), nullable=False)  # full, headers, ports, ssl, crawl
    status = db.Column(db.String(20), default='running')  # running, completed, failed
    risk_level = db.Column(db.String(20), default='unknown')  # low, medium, high, critical
    total_vulnerabilities = db.Column(db.Integer, default=0)
    results_json = db.Column(db.Text, nullable=True)  # JSON string of full results
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)

    def get_results(self):
        if self.results_json:
            return json.loads(self.results_json)
        return {}

    def set_results(self, data):
        self.results_json = json.dumps(data, indent=2)

    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'scan_type': self.scan_type,
            'status': self.status,
            'risk_level': self.risk_level,
            'total_vulnerabilities': self.total_vulnerabilities,
            'results': self.get_results(),
            'user': self.user.username if self.user else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }

    def to_xml(self):
        return (
            f'<scan>'
            f'<id>{self.id}</id>'
            f'<target_url>{self.target_url}</target_url>'
            f'<scan_type>{self.scan_type}</scan_type>'
            f'<status>{self.status}</status>'
            f'<risk_level>{self.risk_level}</risk_level>'
            f'<vulnerabilities>{self.total_vulnerabilities}</vulnerabilities>'
            f'<created_at>{self.created_at.isoformat() if self.created_at else ""}</created_at>'
            f'</scan>'
        )

    def __repr__(self):
        return f'<ScanResult {self.target_url}>'


class Vulnerability(db.Model):
    """Individual vulnerability found during a scan."""
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)  # headers, ssl, ports, xss, sqli, info
    name = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # info, low, medium, high, critical
    description = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)

    scan = db.relationship('ScanResult', backref=db.backref('vulnerabilities', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'category': self.category,
            'name': self.name,
            'severity': self.severity,
            'description': self.description,
            'recommendation': self.recommendation,
            'evidence': self.evidence
        }

    def __repr__(self):
        return f'<Vulnerability {self.name}>'


class AuditLog(db.Model):
    """Audit trail for security-sensitive actions."""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=True)
    resource_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='audit_logs')

    def __repr__(self):
        return f'<AuditLog {self.action} at {self.timestamp}>'
