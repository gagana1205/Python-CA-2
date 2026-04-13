"""Report routes - export scan results in multiple formats."""
from flask import Blueprint, Response, redirect, url_for, flash
from flask_login import login_required

from app import db
from app.models import ScanResult
from app.services.vuln_scanner import VulnScanner

reports_bp = Blueprint('reports', __name__)
scanner = VulnScanner()


@reports_bp.route('/scans/<int:scan_id>/export/<format_type>')
@login_required
def export_scan(scan_id, format_type):
    """Export scan results in JSON, XML, or CSV format."""
    scan = db.session.get(ScanResult, scan_id)
    if not scan:
        flash('Scan not found.', 'danger')
        return redirect(url_for('scans.list_scans'))

    if format_type == 'json':
        data = scanner.export_scan_json(scan)
        return Response(data, mimetype='application/json',
                        headers={'Content-Disposition': f'attachment;filename=scan_{scan_id}.json'})
    elif format_type == 'xml':
        data = scanner.export_scan_xml(scan)
        return Response(data, mimetype='application/xml',
                        headers={'Content-Disposition': f'attachment;filename=scan_{scan_id}.xml'})
    elif format_type == 'csv':
        data = scanner.export_scan_csv(scan)
        return Response(data, mimetype='text/csv',
                        headers={'Content-Disposition': f'attachment;filename=scan_{scan_id}.csv'})
    else:
        flash('Unsupported export format.', 'danger')
        return redirect(url_for('scans.view_scan', scan_id=scan_id))
