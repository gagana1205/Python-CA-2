"""Dashboard routes - main overview with scan statistics."""
from flask import Blueprint, render_template, jsonify
from flask_login import login_required

from app import db
from app.models import ScanResult, Vulnerability

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@login_required
def index():
    """Render the main dashboard with scan statistics."""
    stats = _get_dashboard_stats()
    recent_scans = ScanResult.query.order_by(
        ScanResult.created_at.desc()
    ).limit(10).all()

    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)


@dashboard_bp.route('/stats/json')
@login_required
def stats_json():
    """Return dashboard statistics as JSON."""
    return jsonify(_get_dashboard_stats())


def _get_dashboard_stats():
    """Calculate dashboard statistics."""
    total_scans = ScanResult.query.count()
    completed_scans = ScanResult.query.filter_by(status='completed').count()
    total_vulns = Vulnerability.query.count()

    # Severity distribution
    severity_counts = {}
    for sev in ['info', 'low', 'medium', 'high', 'critical']:
        severity_counts[sev] = Vulnerability.query.filter_by(severity=sev).count()

    # Category distribution
    categories = db.session.query(
        Vulnerability.category, db.func.count(Vulnerability.id)
    ).group_by(Vulnerability.category).all()
    category_counts = {c[0]: c[1] for c in categories}

    # Risk distribution of scans
    risk_counts = {}
    for risk in ['low', 'medium', 'high', 'critical']:
        risk_counts[risk] = ScanResult.query.filter_by(
            risk_level=risk, status='completed'
        ).count()

    # Critical findings
    critical_vulns = Vulnerability.query.filter_by(severity='critical').count()
    high_vulns = Vulnerability.query.filter_by(severity='high').count()

    return {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'total_vulnerabilities': total_vulns,
        'critical_vulns': critical_vulns,
        'high_vulns': high_vulns,
        'severity_distribution': severity_counts,
        'category_distribution': category_counts,
        'risk_distribution': risk_counts
    }
