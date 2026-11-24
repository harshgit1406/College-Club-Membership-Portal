"""
Security middleware for the College Club Membership Portal.
Provides security headers, request logging, and rate limiting helpers.
"""

import logging
import time
from functools import wraps
from flask import request, g, current_app, abort
from flask_login import current_user

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Security Headers
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    # Prevent embedding in iframes (clickjacking)
    "X-Frame-Options": "DENY",
    # Prevent MIME-type sniffing
    "X-Content-Type-Options": "nosniff",
    # Enable XSS filter in older browsers
    "X-XSS-Protection": "1; mode=block",
    # Control referrer information
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # Disable FLoC / interest-cohort tracking
    "Permissions-Policy": (
        "geolocation=(), microphone=(), camera=(), interest-cohort=()"
    ),
    # Content Security Policy
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' "
        "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' "
        "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
    ),
}

# HSTS is only applied over HTTPS
HSTS_HEADER = "max-age=31536000; includeSubDomains; preload"


def apply_security_headers(response):
    """
    After-request hook: attach all security headers to every response.
    HSTS is added only when the request arrived via HTTPS.
    """
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value

    if request.is_secure:
        response.headers["Strict-Transport-Security"] = HSTS_HEADER

    # Remove server identification header
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)

    return response


# ---------------------------------------------------------------------------
# Request Logging
# ---------------------------------------------------------------------------

def log_request_start():
    """Before-request hook: record request start time and basic info."""
    g.request_start_time = time.time()
    g.request_id = id(request)  # rough unique id for correlation

    # Only log at DEBUG to avoid flooding logs in production
    logger.debug(
        "REQUEST  id=%s  method=%s  path=%s  ip=%s  ua=%s",
        g.request_id,
        request.method,
        request.path,
        get_client_ip(),
        request.user_agent.string[:120] if request.user_agent.string else "-",
    )


def log_request_end(response):
    """After-request hook: log completed request with duration and status."""
    duration_ms = 0.0
    if hasattr(g, "request_start_time"):
        duration_ms = (time.time() - g.request_start_time) * 1000

    # Log suspicious status codes at a higher level
    if response.status_code >= 400:
        log_fn = logger.warning
    else:
        log_fn = logger.debug

    user_id = None
    if current_user and current_user.is_authenticated:
        user_id = current_user.id

    log_fn(
        "RESPONSE id=%s  status=%s  duration=%.1fms  user_id=%s  path=%s",
        getattr(g, "request_id", "-"),
        response.status_code,
        duration_ms,
        user_id,
        request.path,
    )
    return response


# ---------------------------------------------------------------------------
# Suspicious Request Detection
# ---------------------------------------------------------------------------

# Simple patterns that might indicate probing / injection attempts.
# These are logged as warnings; the ORM / template engine already block them.
SUSPICIOUS_PATTERNS = [
    # SQL injection probes
    "' OR '1'='1",
    "' OR 1=1",
    "UNION SELECT",
    "DROP TABLE",
    "INSERT INTO",
    "' --",
    "\" --",
    "xp_cmdshell",
    # XSS probes
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "alert(",
    # Path traversal
    "../",
    "..\\",
    "/etc/passwd",
    # Command injection
    "; ls",
    "| cat",
    "`whoami`",
]


def check_suspicious_input():
    """
    Before-request hook: scan query params and form data for suspicious
    patterns and log a warning (but do NOT block – the framework already
    prevents the actual attacks).
    """
    client_ip = get_client_ip()

    def _scan(value: str, source: str):
        upper_val = value.upper()
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.upper() in upper_val:
                logger.warning(
                    "SUSPICIOUS INPUT detected  ip=%s  source=%s  pattern=%r  path=%s",
                    client_ip,
                    source,
                    pattern,
                    request.path,
                )
                break  # one warning per field is enough

    # Scan query string values
    for key, val in request.args.items():
        _scan(val, f"query[{key}]")

    # Scan form values (only when content type is form-encoded / multipart)
    if request.content_type and (
        "application/x-www-form-urlencoded" in request.content_type
        or "multipart/form-data" in request.content_type
    ):
        for key, val in request.form.items():
            if key != "csrf_token":  # skip the CSRF token itself
                _scan(val, f"form[{key}]")


# ---------------------------------------------------------------------------
# IP Helper
# ---------------------------------------------------------------------------

def get_client_ip() -> str:
    """
    Return the real client IP, respecting common reverse-proxy headers.
    Returns the first trusted forwarded address or REMOTE_ADDR.
    """
    # X-Forwarded-For may contain a comma-separated list; take the first
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ---------------------------------------------------------------------------
# Rate Limiting Helpers
# ---------------------------------------------------------------------------

def rate_limit_exceeded_handler(e):
    """
    Custom handler for Flask-Limiter's RateLimitExceeded exception.
    Returns JSON when the client accepts it, otherwise plain text.
    """
    from flask import jsonify, make_response

    retry_after = getattr(e, "retry_after", None)

    logger.warning(
        "RATE LIMIT exceeded  ip=%s  path=%s  limit=%s",
        get_client_ip(),
        request.path,
        getattr(e, "description", "unknown"),
    )

    if _client_wants_json():
        resp = jsonify(
            {
                "error": "Too many requests",
                "message": "Rate limit exceeded. Please slow down.",
                "retry_after": retry_after,
            }
        )
        resp.status_code = 429
        if retry_after:
            resp.headers["Retry-After"] = str(retry_after)
        return resp

    from flask import make_response
    resp = make_response(
        "429 Too Many Requests – Rate limit exceeded. Please slow down.",
        429,
    )
    if retry_after:
        resp.headers["Retry-After"] = str(retry_after)
    return resp


def _client_wants_json() -> bool:
    """Check whether the client prefers a JSON response."""
    best = request.accept_mimetypes.best_match(
        ["application/json", "text/html"]
    )
    return best == "application/json"


# ---------------------------------------------------------------------------
# Role-Based Access Decorators (convenience wrappers used across blueprints)
# ---------------------------------------------------------------------------

def roles_required(*roles):
    """
    Decorator factory – restricts a view to users whose role is in *roles*.
    Must be placed AFTER @login_required.

    Usage::

        @bp.route("/admin/only")
        @login_required
        @roles_required("admin")
        def admin_only_view():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                logger.warning(
                    "PRIVILEGE ESCALATION attempt  user_id=%s  role=%s  "
                    "required=%s  path=%s  ip=%s",
                    current_user.id,
                    current_user.role,
                    roles,
                    request.path,
                    get_client_ip(),
                )
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def student_required(f):
    """Shorthand: restrict to students."""
    return roles_required("student")(f)


def coordinator_required(f):
    """Shorthand: restrict to coordinators."""
    return roles_required("coordinator")(f)


def admin_required(f):
    """Shorthand: restrict to admins."""
    return roles_required("admin")(f)


# ---------------------------------------------------------------------------
# IDOR Protection Helper
# ---------------------------------------------------------------------------

def owns_resource(resource_user_id: int) -> bool:
    """
    Return True if the currently logged-in user is the owner of a resource
    OR is an admin (admins can always access everything).
    """
    if not current_user.is_authenticated:
        return False
    if current_user.role == "admin":
        return True
    return current_user.id == resource_user_id


def abort_if_not_owner(resource_user_id: int):
    """
    Abort with 403 Forbidden if the current user does not own the resource
    and is not an admin.
    """
    if not owns_resource(resource_user_id):
        logger.warning(
            "IDOR attempt  requester_id=%s  owner_id=%s  path=%s  ip=%s",
            current_user.id if current_user.is_authenticated else "anon",
            resource_user_id,
            request.path,
            get_client_ip(),
        )
        abort(403)


# ---------------------------------------------------------------------------
# Session Security Checker (called on app start for diagnostics)
# ---------------------------------------------------------------------------

def check_session_config(app):
    """
    Log warnings if the Flask session is not configured securely.
    Called once during app initialisation.
    """
    warnings = []

    if not app.config.get("SESSION_COOKIE_HTTPONLY", True):
        warnings.append("SESSION_COOKIE_HTTPONLY is False – XSS can steal sessions!")

    if not app.config.get("SESSION_COOKIE_SAMESITE"):
        warnings.append("SESSION_COOKIE_SAMESITE not set – CSRF risk.")

    secret = app.config.get("SECRET_KEY", "")
    if secret in ("", "dev", "secret", "changeme", "your-secret-key"):
        warnings.append(
            "SECRET_KEY appears to be a weak / default value – "
            "change it in production!"
        )

    if app.config.get("DEBUG") and app.config.get("ENV") == "production":
        warnings.append("DEBUG=True in production environment – disable it!")

    for w in warnings:
        logger.warning("SESSION CONFIG WARNING: %s", w)

    return warnings
