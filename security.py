"""Security utilities for input validation, sanitisation, and audit logging."""
import re
from urllib.parse import urlparse
from functools import wraps

from flask import request, abort, redirect, url_for
from flask_login import current_user

from app import db


def sanitize_input(text):
    """Remove potentially dangerous characters from user input."""
    if text is None:
        return None
    text = str(text).strip()
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&#x27;')
    return text


def validate_url(url):
    """Validate a URL format.

    Args:
        url: URL string to validate.

    Returns:
        Tuple of (is_valid, cleaned_url, error_message).
    """
    if not url:
        return False, None, "URL is required."

    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False, None, "Invalid URL format."
        # Block private/internal IPs first
        blocked = ['127.0.0.1', 'localhost', '0.0.0.0', '10.', '192.168.', '172.16.']
        for b in blocked:
            if parsed.netloc.startswith(b) or parsed.netloc == b:
                return False, None, "Scanning internal/private addresses is not allowed."
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', parsed.netloc):
            return False, None, "Invalid domain in URL."
        return True, url, None
    except Exception:
        return False, None, "Could not parse URL."


def validate_password_strength(password):
    """Check password meets security requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, ""


def log_audit(action, resource_type=None, resource_id=None, details=None):
    """Create an audit log entry."""
    from app.models import AuditLog

    entry = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(entry)
    db.session.commit()


def role_required(role):
    """Decorator to restrict access based on user role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            if current_user.role != role and current_user.role != 'admin':
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
