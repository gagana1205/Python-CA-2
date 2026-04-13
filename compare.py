"""Scan comparison routes - compare two scan results side by side."""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required

from app import db
from app.models import ScanResult, Vulnerability

compare_bp = Blueprint('compare', __name__)


@compare_bp.route('/compare', methods=['GET', 'POST'])
@login_required
def compare_scans():
    """Show scan comparison form or comparison results."""
    completed_scans = ScanResult.query.filter_by(status='completed').order_by(
        ScanResult.created_at.desc()
    ).all()

    if request.method == 'POST':
        scan_id_a = request.form.get('scan_a', type=int)
        scan_id_b = request.form.get('scan_b', type=int)

        if not scan_id_a or not scan_id_b:
            flash('Please select two scans to compare.', 'warning')
            return render_template('compare.html', scans=completed_scans)

        if scan_id_a == scan_id_b:
            flash('Please select two different scans to compare.', 'warning')
            return render_template('compare.html', scans=completed_scans)

        scan_a = db.session.get(ScanResult, scan_id_a)
        scan_b = db.session.get(ScanResult, scan_id_b)

        if not scan_a or not scan_b:
            flash('One or both scans not found.', 'danger')
            return render_template('compare.html', scans=completed_scans)

        comparison = _build_comparison(scan_a, scan_b)
        return render_template('compare.html', scans=completed_scans,
                               scan_a=scan_a, scan_b=scan_b,
                               comparison=comparison,
                               selected_a=scan_id_a, selected_b=scan_id_b)

    return render_template('compare.html', scans=completed_scans)


def _build_comparison(scan_a, scan_b):
    """Build a detailed comparison between two scans."""
    vulns_a = Vulnerability.query.filter_by(scan_id=scan_a.id).all()
    vulns_b = Vulnerability.query.filter_by(scan_id=scan_b.id).all()

    severity_order = ['critical', 'high', 'medium', 'low', 'info']

    # Count vulnerabilities by severity for each scan
    counts_a = {}
    counts_b = {}
    for sev in severity_order:
        counts_a[sev] = sum(1 for v in vulns_a if v.severity == sev)
        counts_b[sev] = sum(1 for v in vulns_b if v.severity == sev)

    # Identify unique and common vulnerabilities by (category, name) pair
    vuln_keys_a = {(v.category, v.name) for v in vulns_a}
    vuln_keys_b = {(v.category, v.name) for v in vulns_b}

    common_keys = vuln_keys_a & vuln_keys_b
    only_a_keys = vuln_keys_a - vuln_keys_b
    only_b_keys = vuln_keys_b - vuln_keys_a

    # Build lists with full vulnerability info
    def find_vuln(vulns, category, name):
        for v in vulns:
            if v.category == category and v.name == name:
                return v
        return None

    common_vulns = []
    for cat, name in sorted(common_keys):
        va = find_vuln(vulns_a, cat, name)
        vb = find_vuln(vulns_b, cat, name)
        common_vulns.append({'name': name, 'category': cat,
                             'severity_a': va.severity if va else '',
                             'severity_b': vb.severity if vb else ''})

    only_a = []
    for cat, name in sorted(only_a_keys):
        v = find_vuln(vulns_a, cat, name)
        if v:
            only_a.append(v)

    only_b = []
    for cat, name in sorted(only_b_keys):
        v = find_vuln(vulns_b, cat, name)
        if v:
            only_b.append(v)

    # Sort unique lists by severity
    def sev_sort_key(v):
        try:
            return severity_order.index(v.severity)
        except ValueError:
            return 99

    only_a.sort(key=sev_sort_key)
    only_b.sort(key=sev_sort_key)
    common_vulns.sort(key=lambda v: severity_order.index(v['severity_a'])
                      if v['severity_a'] in severity_order else 99)

    return {
        'counts_a': counts_a,
        'counts_b': counts_b,
        'common': common_vulns,
        'only_a': only_a,
        'only_b': only_b,
        'severity_order': severity_order,
    }
