"""REST API routes for programmatic access to scan data."""
from flask import Blueprint, jsonify, request
from flask_login import login_required

from app import db
from app.models import ScanResult, Vulnerability

api_bp = Blueprint('api', __name__)


@api_bp.route('/scans', methods=['GET'])
@login_required
def get_scans():
    """Get scan results with optional filters."""
    risk = request.args.get('risk', '')
    scan_type = request.args.get('type', '')
    limit = min(request.args.get('limit', 50, type=int), 100)
    offset = request.args.get('offset', 0, type=int)

    query = ScanResult.query.filter_by(status='completed')
    if risk:
        query = query.filter_by(risk_level=risk)
    if scan_type:
        query = query.filter_by(scan_type=scan_type)

    total = query.count()
    scans = query.order_by(ScanResult.created_at.desc()).offset(offset).limit(limit).all()

    return jsonify({
        'total': total,
        'limit': limit,
        'offset': offset,
        'data': [s.to_dict() for s in scans]
    })


@api_bp.route('/scans/<int:scan_id>', methods=['GET'])
@login_required
def get_scan(scan_id):
    """Get a single scan result by ID."""
    scan = db.session.get(ScanResult, scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(scan.to_dict())


@api_bp.route('/scans/<int:scan_id>/vulnerabilities', methods=['GET'])
@login_required
def get_vulnerabilities(scan_id):
    """Get vulnerabilities for a specific scan."""
    scan = db.session.get(ScanResult, scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    vulns = scan.vulnerabilities.all()
    return jsonify({
        'scan_id': scan_id,
        'total': len(vulns),
        'data': [v.to_dict() for v in vulns]
    })


@api_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    """Get summary statistics."""
    return jsonify({
        'total_scans': ScanResult.query.count(),
        'completed_scans': ScanResult.query.filter_by(status='completed').count(),
        'total_vulnerabilities': Vulnerability.query.count(),
        'critical_vulns': Vulnerability.query.filter_by(severity='critical').count(),
        'high_vulns': Vulnerability.query.filter_by(severity='high').count()
    })
