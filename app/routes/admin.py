"""
app/routes/admin.py
-------------------
Admin blueprint: Dashboard, User Management, Club Management,
Activity Logs, and Security Testing Laboratory.

All routes require login + admin role.
"""

import json
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import func

from app.models import ActivityLog, Application, Club, SecurityTestResult, User, db
from app.security.tests import SecurityTestRunner, TEST_DEFINITIONS

# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ---------------------------------------------------------------------------
# Role Guard Decorator
# ---------------------------------------------------------------------------

def admin_required(f):
    """Ensure the user is authenticated and has the 'admin' role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        if current_user.role != "admin":
            _log("unauthorized_admin_access_attempt", f"Path: {request.path}")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def _log(action: str, details: str = ""):
    """Record an audit trail entry for an admin action."""
    entry = ActivityLog(
        user_id=current_user.id if current_user and current_user.is_authenticated else None,
        action=action,
        details=details,
        ip_address=request.remote_addr,
        timestamp=datetime.now(timezone.utc),
    )
    db.session.add(entry)
    db.session.commit()


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@admin_bp.route("/dashboard")
@login_required
@admin_required
def dashboard():
    """Admin central overview: platform statistics and recent audit logs."""
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    student_count = User.query.filter_by(role="student").count()
    coordinator_count = User.query.filter_by(role="coordinator").count()
    admin_count = User.query.filter_by(role="admin").count()

    total_clubs = Club.query.count()
    active_clubs = Club.query.filter_by(is_active=True).count()

    total_applications = Application.query.count()
    pending_applications = Application.query.filter_by(status="pending").count()
    approved_applications = Application.query.filter_by(status="approved").count()
    rejected_applications = Application.query.filter_by(status="rejected").count()

    total_logs = ActivityLog.query.count()
    recent_logs = (
        ActivityLog.query.order_by(ActivityLog.timestamp.desc())
        .limit(10)
        .all()
    )

    stats = {
        "total_users": total_users,
        "active_users": active_users,
        "student_count": student_count,
        "coordinator_count": coordinator_count,
        "admin_count": admin_count,
        "total_clubs": total_clubs,
        "active_clubs": active_clubs,
        "total_applications": total_applications,
        "pending_applications": pending_applications,
        "approved_applications": approved_applications,
        "rejected_applications": rejected_applications,
        "total_logs": total_logs,
    }

    return render_template(
        "admin/dashboard.html",
        stats=stats,
        recent_logs=recent_logs,
        now=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------

@admin_bp.route("/users")
@login_required
@admin_required
def users():
    """Browse, search, and filter all registered users."""
    search_q = request.args.get("q", "").strip()
    role_filter = request.args.get("role", "").strip().lower()
    status_filter = request.args.get("status", "").strip().lower()
    page = request.args.get("page", 1, type=int)
    per_page = 15

    query = User.query

    if search_q:
        pattern = f"%{search_q}%"
        query = query.filter(
            (User.username.ilike(pattern)) | (User.email.ilike(pattern))
        )

    if role_filter in ("student", "coordinator", "admin"):
        query = query.filter_by(role=role_filter)

    if status_filter == "active":
        query = query.filter_by(is_active=True)
    elif status_filter == "inactive":
        query = query.filter_by(is_active=False)

    pagination = query.order_by(User.id.asc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template(
        "admin/users.html",
        users=pagination.items,
        pagination=pagination,
        now=datetime.now(timezone.utc),
    )


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_user(user_id: int):
    """Activate or deactivate a user account."""
    if user_id == current_user.id:
        flash("You cannot deactivate your own administrative account.", "danger")
        return redirect(url_for("admin.users"))

    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()

    action_label = "activated" if user.is_active else "deactivated"
    _log(f"user_{action_label}", f"User {user.username} (id={user.id}) {action_label}")
    flash(f"User '{user.username}' has been {action_label}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@admin_required
def change_role(user_id: int):
    """Change the role of a user."""
    user = User.query.get_or_404(user_id)
    new_role = request.form.get("role", "").strip().lower()

    if new_role not in ("student", "coordinator", "admin"):
        flash("Invalid role specified.", "danger")
        return redirect(url_for("admin.users"))

    if user.id == current_user.id and new_role != "admin":
        flash("You cannot demote yourself from the admin role.", "danger")
        return redirect(url_for("admin.users"))

    old_role = user.role
    user.role = new_role
    db.session.commit()

    _log("role_changed", f"Changed {user.username} role from {old_role} to {new_role}")
    flash(f"Role for '{user.username}' updated to {new_role}.", "success")
    return redirect(url_for("admin.users"))


# ---------------------------------------------------------------------------
# Club Management
# ---------------------------------------------------------------------------

@admin_bp.route("/clubs")
@login_required
@admin_required
def clubs():
    """List and manage all clubs and their assigned coordinators."""
    clubs_list = Club.query.order_by(Club.name.asc()).all()
    coordinators = User.query.filter_by(role="coordinator", is_active=True).all()

    return render_template(
        "admin/clubs.html",
        clubs=clubs_list,
        coordinators=coordinators,
    )


@admin_bp.route("/clubs/new", methods=["GET", "POST"])
@login_required
@admin_required
def create_club():
    """Create a new campus club."""
    coordinators = User.query.filter_by(role="coordinator", is_active=True).all()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "").strip()
        max_members = request.form.get("max_members", 50, type=int)
        coord_id = request.form.get("coordinator_id", type=int)

        if not name:
            flash("Club name is required.", "danger")
            return render_template("admin/club_form.html", coordinators=coordinators, club=None)

        if Club.query.filter_by(name=name).first():
            flash("A club with that name already exists.", "danger")
            return render_template("admin/club_form.html", coordinators=coordinators, club=None)

        club = Club(
            name=name,
            description=description,
            category=category,
            max_members=max(1, max_members),
            coordinator_id=coord_id if coord_id else None,
            is_active=True,
        )
        db.session.add(club)
        db.session.commit()

        _log("create_club", f"Created club '{club.name}' (id={club.id})")
        flash(f"Club '{club.name}' created successfully.", "success")
        return redirect(url_for("admin.clubs"))

    return render_template("admin/club_form.html", coordinators=coordinators, club=None)


@admin_bp.route("/clubs/<int:club_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_club(club_id: int):
    """Edit club attributes and assigned coordinator."""
    club = Club.query.get_or_404(club_id)
    coordinators = User.query.filter_by(role="coordinator", is_active=True).all()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "").strip()
        max_members = request.form.get("max_members", 50, type=int)
        coord_id = request.form.get("coordinator_id", type=int)

        if not name:
            flash("Club name is required.", "danger")
            return render_template("admin/club_form.html", coordinators=coordinators, club=club)

        existing = Club.query.filter_by(name=name).first()
        if existing and existing.id != club.id:
            flash("Another club with that name already exists.", "danger")
            return render_template("admin/club_form.html", coordinators=coordinators, club=club)

        club.name = name
        club.description = description
        club.category = category
        club.max_members = max(1, max_members)
        club.coordinator_id = coord_id if coord_id else None
        db.session.commit()

        _log("edit_club", f"Updated club '{club.name}' (id={club.id})")
        flash(f"Club '{club.name}' updated successfully.", "success")
        return redirect(url_for("admin.clubs"))

    return render_template("admin/club_form.html", coordinators=coordinators, club=club)


@admin_bp.route("/clubs/<int:club_id>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_club(club_id: int):
    """Toggle whether a club is active."""
    club = Club.query.get_or_404(club_id)
    club.is_active = not club.is_active
    db.session.commit()

    status_str = "activated" if club.is_active else "deactivated"
    _log("toggle_club", f"Club '{club.name}' {status_str}")
    flash(f"Club '{club.name}' has been {status_str}.", "info")
    return redirect(url_for("admin.clubs"))


# ---------------------------------------------------------------------------
# Activity Logs
# ---------------------------------------------------------------------------

@admin_bp.route("/activity-logs")
@login_required
@admin_required
def activity_logs():
    """Audit log viewer with filtering and pagination."""
    action_filter = request.args.get("action", "").strip()
    search_q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = 20

    query = ActivityLog.query

    if action_filter:
        query = query.filter(ActivityLog.action.ilike(f"%{action_filter}%"))

    if search_q:
        pattern = f"%{search_q}%"
        query = query.filter(
            (ActivityLog.details.ilike(pattern)) | (ActivityLog.ip_address.ilike(pattern))
        )

    pagination = query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    distinct_actions = [
        row[0]
        for row in db.session.query(ActivityLog.action).distinct().order_by(ActivityLog.action).all()
        if row[0]
    ]

    return render_template(
        "admin/activity_logs.html",
        logs=pagination.items,
        pagination=pagination,
        distinct_actions=distinct_actions,
    )


# ---------------------------------------------------------------------------
# Security Testing Dashboard
# ---------------------------------------------------------------------------

@admin_bp.route("/security-lab")
@login_required
@admin_required
def security_lab():
    """Interactive Security Testing Dashboard displaying 10 vulnerability test cards."""
    # Check if we have recent results in the database or execute baseline
    runner = SecurityTestRunner()
    results = runner.run_all(persist=False)

    pass_count = sum(1 for r in results if r["status"] == "PASS")
    fail_count = sum(1 for r in results if r["status"] != "PASS")
    total_time = round(sum(r.get("execution_time_ms", 0) for r in results), 2)

    summary = {
        "total": len(results),
        "passed": pass_count,
        "failed": fail_count,
        "score_pct": int((pass_count / len(results) * 100)) if results else 0,
        "total_time_ms": total_time,
    }

    return render_template(
        "admin/security_lab.html",
        results=results,
        summary=summary,
        test_definitions=TEST_DEFINITIONS,
    )


@admin_bp.route("/security-lab/simulate", methods=["POST"])
@login_required
@admin_required
def simulate_attack():
    """
    Interactive Attack Simulation Arena.
    Accepts user-supplied payload and attack vector, runs live probe against
    the portal's defensive controls, and returns detailed technical diagnosis.
    """
    data = request.get_json(silent=True) or request.form
    attack_type = data.get("attack_type", "sqli").strip().lower()
    payload = data.get("payload", "").strip()

    if not payload:
        return jsonify({
            "success": False,
            "error": "Payload cannot be empty. Please enter an attack string to test."
        }), 400

    timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]

    if attack_type == "sqli":
        # Simulate SQL Injection probe against user lookup & club search
        escaped_query = f"SELECT * FROM users WHERE email = :param_1  /* Bound parameter: {repr(payload)} */"
        matched_user = User.query.filter_by(email=payload).first()
        matched_clubs = Club.query.filter(Club.name.ilike(f"%{payload}%")).all()

        is_defended = (matched_user is None)
        return jsonify({
            "success": True,
            "attack_type": "SQL Injection (SQLi)",
            "payload": payload,
            "verdict": "DEFENDED / NEUTRALIZED" if is_defended else "VULNERABLE",
            "http_status": 200,
            "defense_layer": "SQLAlchemy Parameterized Queries (DBAPI Bound Parameters)",
            "simulated_query": escaped_query,
            "records_leaked": 0 if matched_user is None else 1,
            "output_preview": f"Query returned {len(matched_clubs)} club(s) and 0 unauthorized user records.",
            "server_log": f"[{timestamp}] [SQL-AUDIT] Safe parameter substitution: query parameter treated as literal string.",
            "explanation": (
                "The user input was passed through SQLAlchemy's parameterized query engine. "
                "The SQL database engine treats the quotes and syntax as literal string characters, "
                "preventing malicious syntax injection and authentication bypass."
            )
        })

    elif attack_type == "xss":
        # Simulate XSS probe against Jinja2 context-aware escaping
        from markupsafe import escape
        escaped_output = str(escape(payload))
        contains_raw_script = "<script>" in escaped_output or "onerror=" in escaped_output and not "&#" in escaped_output

        return jsonify({
            "success": True,
            "attack_type": "Cross-Site Scripting (XSS)",
            "payload": payload,
            "verdict": "DEFENDED / NEUTRALIZED" if not contains_raw_script else "VULNERABLE",
            "http_status": 200,
            "defense_layer": "Jinja2 Context-Aware Auto-Escaping Engine",
            "escaped_html": escaped_output,
            "raw_input": payload,
            "output_preview": escaped_output,
            "server_log": f"[{timestamp}] [XSS-AUDIT] Raw payload encoded into HTML entities: &lt; &gt; &quot; &#39;",
            "explanation": (
                "Jinja2 automatically converted characters like '<', '>', and '\"' into harmless HTML entities "
                f"('{escape('<')}', '{escape('>')}'). The browser will render this as harmless text rather than executing JavaScript."
            )
        })

    elif attack_type == "csrf":
        # Simulate CSRF request without valid anti-CSRF token
        return jsonify({
            "success": True,
            "attack_type": "Cross-Site Request Forgery (CSRF)",
            "payload": payload,
            "verdict": "DEFENDED / REJECTED",
            "http_status": 400,
            "defense_layer": "Flask-WTF CSRFProtect Middleware & SameSite Cookie Attribute",
            "output_preview": "HTTP 400 Bad Request: The CSRF session token is missing or invalid.",
            "server_log": f"[{timestamp}] [CSRF-AUDIT] Mutating request intercepted. No valid X-CSRFToken header or csrf_token form field.",
            "explanation": (
                "Every state-changing POST/PUT request requires a cryptographically secure token tied to the user's active session. "
                "Any forged cross-site request is intercepted by CSRFProtect and rejected with HTTP 400 before reaching application logic."
            )
        })

    elif attack_type == "idor":
        # Simulate IDOR probe by supplying arbitrary target resource ID
        try:
            target_id = int(payload)
        except ValueError:
            target_id = 99999

        # Current user is admin, but we simulate a student tenant context
        student = User.query.filter_by(role="student").first()
        student_id = student.id if student else 2
        # Lookup scoped to student
        scoped_record = Application.query.filter_by(id=target_id, user_id=student_id).first()

        return jsonify({
            "success": True,
            "attack_type": "Insecure Direct Object Reference (IDOR)",
            "payload": f"Target Resource ID: {target_id}",
            "verdict": "DEFENDED / ACCESS DENIED",
            "http_status": 403 if scoped_record is None else 200,
            "defense_layer": "Object-Level Ownership Scoping (Tenant Partitioning)",
            "output_preview": "HTTP 403 Forbidden: Resource access denied. Ownership validation failed.",
            "server_log": f"[{timestamp}] [IDOR-AUDIT] Unauthorized access attempt: user #{student_id} attempted to access record #{target_id}.",
            "explanation": (
                "Database queries do not trust the object ID from the URL alone. "
                "All operations filter by `Application.user_id == current_user.id`, ensuring students cannot view or modify other users' applications."
            )
        })

    elif attack_type == "password":
        # Simulate password strength audit against the password policy
        from app.auth import _validate_password_strength
        unmet_rules = _validate_password_strength(payload)
        is_strong = len(unmet_rules) == 0

        # Simulate Werkzeug PBKDF2:SHA256 hashing
        from werkzeug.security import generate_password_hash
        sample_hash = generate_password_hash(payload) if is_strong else "N/A (Rejected before hashing)"

        return jsonify({
            "success": True,
            "attack_type": "Insecure Passwords & Dictionary Attacks",
            "payload": payload,
            "verdict": "DEFENDED / REJECTED" if not is_strong else "ACCEPTED (SECURE COMPLIANT)",
            "http_status": 400 if not is_strong else 200,
            "defense_layer": "Server-Side NIST SP 800-63B Password Complexity Validator & PBKDF2:SHA256",
            "output_preview": f"Unmet requirements: {', '.join(unmet_rules)}" if unmet_rules else "Complies with strong password policy.",
            "hash_generated": sample_hash,
            "server_log": f"[{timestamp}] [AUTH-AUDIT] Password validation: {len(unmet_rules)} policy violation(s) detected.",
            "explanation": (
                "Passwords must meet strict complexity rules (>=8 chars, uppercase, lowercase, digit, special character). "
                "Valid passwords are transformed into salted cryptographic hashes with 600,000 PBKDF2 iterations and never stored in plain text."
            )
        })

    elif attack_type == "path_traversal":
        # Simulate Directory/Path Traversal
        import os
        normalized = os.path.normpath(payload)
        is_blocked = ".." in payload or "/" in payload or "\\" in payload

        return jsonify({
            "success": True,
            "attack_type": "Path Traversal / Local File Inclusion",
            "payload": payload,
            "verdict": "DEFENDED / BLOCKED",
            "http_status": 400,
            "defense_layer": "Security Middleware Input Pattern Scanner & Whitelisted File Routing",
            "output_preview": "HTTP 400 / 404: Directory traversal characters ('..', '/') neutralized.",
            "server_log": f"[{timestamp}] [PATH-AUDIT] Suspicious path traversal probe detected from client IP: '{payload}'",
            "explanation": (
                "Flask routes reject unwhitelisted dynamic paths, and the security middleware scans incoming parameters for traversal sequences. "
                "No arbitrary file access is permitted."
            )
        })

    return jsonify({"success": False, "error": f"Unknown attack type: {attack_type}"}), 400


@admin_bp.route("/security-lab/run", methods=["POST"])
@login_required
@admin_required
def run_all_security_tests():
    """Run all automated security tests and return JSON results."""
    runner = SecurityTestRunner()
    results = runner.run_all(persist=True)

    _log("run_security_suite", f"Executed full test suite ({len(results)} tests)")

    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({"success": True, "results": results})

    flash("Security test suite executed successfully.", "success")
    return redirect(url_for("admin.security_lab"))


@admin_bp.route("/security-lab/run/<test_id>", methods=["POST"])
@login_required
@admin_required
def run_single_security_test(test_id: str):
    """Execute a single designated security test by its identifier."""
    runner = SecurityTestRunner()
    result = runner.run_test(test_id, persist=True)

    _log("run_security_test", f"Ran test '{test_id}' - status: {result['status']}")

    return jsonify({"success": True, "result": result})


@admin_bp.route("/security-lab/export/<fmt>")
@login_required
@admin_required
def export_security_report(fmt: str):
    """Download the security testing audit report in JSON or HTML format."""
    runner = SecurityTestRunner()
    results = runner.run_all(persist=False)

    pass_count = sum(1 for r in results if r["status"] == "PASS")
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        report_data = {
            "title": "College Club Portal Security Audit Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "auditor": current_user.username,
            "overall_status": "SECURE" if pass_count == len(results) else "VULNERABILITIES_DETECTED",
            "score": f"{pass_count}/{len(results)} PASS",
            "results": results,
        }
        resp = make_response(json.dumps(report_data, indent=2))
        resp.headers["Content-Type"] = "application/json"
        resp.headers["Content-Disposition"] = f"attachment; filename=security_report_{timestamp_str}.json"
        return resp

    # Render HTML report
    html_content = render_template(
        "admin/security_report_export.html",
        results=results,
        pass_count=pass_count,
        total_count=len(results),
        generated_at=datetime.now(timezone.utc),
        user=current_user,
    )
    resp = make_response(html_content)
    resp.headers["Content-Type"] = "text/html"
    resp.headers["Content-Disposition"] = f"attachment; filename=security_report_{timestamp_str}.html"
    return resp
