"""Scan management routes - initiate scans, view results."""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user

from app import db
from app.models import ScanResult
from app.services.vuln_scanner import VulnScanner
from app.utils.security import validate_url, sanitize_input, log_audit

scans_bp = Blueprint('scans', __name__)
scanner = VulnScanner()


@scans_bp.route('/scan', methods=['GET', 'POST'])
@login_required
def new_scan():
    """Initiate a new vulnerability scan."""
    if request.method == 'POST':
        target_url = request.form.get('target_url', '').strip()
        scan_type = sanitize_input(request.form.get('scan_type', 'full'))

        is_valid, cleaned_url, error = validate_url(target_url)
        if not is_valid:
            flash(error, 'danger')
            return render_template('new_scan.html')

        try:
            if scan_type == 'full':
                scan = scanner.run_full_scan(cleaned_url, current_user.id)
            else:
                scan = scanner.run_single_scan(cleaned_url, scan_type, current_user.id)

            log_audit('scan_initiated', 'scan', scan.id, f'{scan_type}: {cleaned_url}')
            flash(f'Scan completed! Found {scan.total_vulnerabilities} vulnerabilities.', 'success')
            return redirect(url_for('scans.view_scan', scan_id=scan.id))

        except Exception as e:
            flash(f'Scan error: {str(e)[:200]}', 'danger')
            return render_template('new_scan.html')

    return render_template('new_scan.html')


@scans_bp.route('/scans')
@login_required
def list_scans():
    """List all scan results with filtering."""
    page = request.args.get('page', 1, type=int)
    risk = request.args.get('risk', '')
    scan_type = request.args.get('type', '')

    query = ScanResult.query
    if risk:
        query = query.filter_by(risk_level=risk)
    if scan_type:
        query = query.filter_by(scan_type=scan_type)

    scans = query.order_by(
        ScanResult.created_at.desc()
    ).paginate(page=page, per_page=15, error_out=False)

    return render_template('scan_list.html', scans=scans, risk=risk, scan_type=scan_type)


@scans_bp.route('/scans/<int:scan_id>')
@login_required
def view_scan(scan_id):
    """View detailed scan results."""
    scan = db.session.get(ScanResult, scan_id)
    if not scan:
        flash('Scan not found.', 'danger')
        return redirect(url_for('scans.list_scans'))

    vulnerabilities = scan.vulnerabilities.order_by(
        db.case(
            (db.literal_column("severity") == 'critical', 1),
            (db.literal_column("severity") == 'high', 2),
            (db.literal_column("severity") == 'medium', 3),
            (db.literal_column("severity") == 'low', 4),
            else_=5
        )
    ).all()

    results = scan.get_results()

    return render_template('scan_detail.html', scan=scan,
                           vulnerabilities=vulnerabilities, results=results)


@scans_bp.route('/scans/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    """Delete a scan and its vulnerabilities."""
    scan = db.session.get(ScanResult, scan_id)
    if not scan:
        flash('Scan not found.', 'danger')
        return redirect(url_for('scans.list_scans'))

    log_audit('delete_scan', 'scan', scan.id, scan.target_url)
    for v in scan.vulnerabilities.all():
        db.session.delete(v)
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted.', 'info')
    return redirect(url_for('scans.list_scans'))
