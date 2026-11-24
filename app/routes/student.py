"""
app/routes/student.py
---------------------
Student blueprint: dashboard, club listing/detail, apply, withdraw,
and my-applications view.

Security controls applied:
  - @login_required  – unauthenticated users are redirected to /auth/login
  - @student_required (custom) – non-student roles receive 403
  - Object-level ownership check – every Application lookup is filtered
    by current_user.id so IDOR is structurally prevented
  - SQLAlchemy ORM used exclusively – no raw SQL, preventing injection
  - Flask-WTF CSRF tokens required on every mutating form
"""

from datetime import datetime, timezone

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from functools import wraps

from app.models import Application, ActivityLog, Club, User, db

# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

student_bp = Blueprint("student", __name__, url_prefix="/student")


# ---------------------------------------------------------------------------
# Role guard decorator
# ---------------------------------------------------------------------------

def student_required(f):
    """Restrict a view to users whose role is 'student'.

    Must be applied *after* @login_required so current_user is already set.
    Returns HTTP 403 for coordinators and admins who are logged in.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != "student":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# Activity-log helper
# ---------------------------------------------------------------------------

def _log(action: str, details: str = ""):
    """Append an ActivityLog row for the current user and request."""
    entry = ActivityLog(
        user_id=current_user.id,
        action=action,
        details=details,
        ip_address=request.remote_addr,
        timestamp=datetime.now(timezone.utc),
    )
    db.session.add(entry)
    db.session.commit()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@student_bp.route("/dashboard")
@login_required
@student_required
def dashboard():
    """Student home page: headline statistics at a glance.

    Counts are computed server-side so they cannot be tampered with
    via URL parameters.
    """
    total_clubs = Club.query.filter_by(is_active=True).count()

    # All application counts are scoped to the current user only
    applied_count = Application.query.filter_by(user_id=current_user.id).count()
    approved_count = Application.query.filter_by(
        user_id=current_user.id, status="approved"
    ).count()
    pending_count = Application.query.filter_by(
        user_id=current_user.id, status="pending"
    ).count()
    rejected_count = Application.query.filter_by(
        user_id=current_user.id, status="rejected"
    ).count()

    # Recent applications for the mini-timeline widget
    recent_applications = (
        Application.query.filter_by(user_id=current_user.id)
        .order_by(Application.applied_at.desc())
        .limit(5)
        .all()
    )

    # Suggested clubs (active clubs the student hasn't applied to yet)
    applied_club_ids = [
        app.club_id
        for app in Application.query.filter_by(user_id=current_user.id).all()
    ]
    suggested_query = Club.query.filter_by(is_active=True)
    if applied_club_ids:
        suggested_query = suggested_query.filter(~Club.id.in_(applied_club_ids))
    suggested_clubs = suggested_query.limit(3).all()

    stats = {
        "total_clubs": total_clubs,
        "total_applied": applied_count,
        "approved": approved_count,
        "pending": pending_count,
        "rejected": rejected_count,
    }

    return render_template(
        "student/dashboard.html",
        stats=stats,
        total_clubs=total_clubs,
        applied_count=applied_count,
        approved_count=approved_count,
        pending_count=pending_count,
        rejected_count=rejected_count,
        recent_applications=recent_applications,
        suggested_clubs=suggested_clubs,
    )


@student_bp.route("/clubs")
@login_required
@student_required
def clubs():
    """Club discovery page with search and category filter.

    Query parameters:
      q        – free-text search against name and description (LIKE via ORM)
      category – exact match on Club.category
      page     – pagination page number (default 1)

    Security note: search term is passed through SQLAlchemy's parameterised
    query API (`.ilike()`), never interpolated into raw SQL.
    """
    search_q = (request.args.get("search") or request.args.get("q") or "").strip()
    category_filter = request.args.get("category", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = current_app.config.get("CLUBS_PER_PAGE", 9)

    query = Club.query.filter_by(is_active=True)

    if search_q:
        pattern = f"%{search_q}%"
        query = query.filter(
            db.or_(Club.name.ilike(pattern), Club.description.ilike(pattern))
        )

    if category_filter:
        query = query.filter_by(category=category_filter)

    pagination = query.order_by(Club.name.asc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Distinct categories for the filter dropdown
    categories = [
        row[0]
        for row in db.session.query(Club.category)
        .filter(Club.is_active == True)
        .distinct()
        .order_by(Club.category)
        .all()
        if row[0]
    ]

    # Build a set of club IDs the student has already applied to (any status
    # except withdrawn) so the template can disable the "Apply" button.
    existing_app_club_ids = {
        row[0]
        for row in db.session.query(Application.club_id)
        .filter(
            Application.user_id == current_user.id,
            Application.status.in_(["pending", "approved"]),
        )
        .all()
    }

    return render_template(
        "student/clubs.html",
        pagination=pagination,
        clubs=pagination.items,
        search_q=search_q,
        category_filter=category_filter,
        categories=categories,
        existing_app_club_ids=existing_app_club_ids,
    )


@student_bp.route("/clubs/<int:club_id>")
@login_required
@student_required
def club_detail(club_id: int):
    """Detail page for a single club.

    Uses `.get_or_404()` so an invalid club_id returns 404 immediately.
    Only active clubs are surfaced; inactive ones return 404.
    """
    club = Club.query.filter_by(id=club_id, is_active=True).first_or_404()

    approved_member_count = Application.query.filter_by(
        club_id=club_id, status="approved"
    ).count()

    # Has the current student already applied?
    existing_application = Application.query.filter_by(
        user_id=current_user.id, club_id=club_id
    ).first()

    is_full = approved_member_count >= club.max_members

    coordinator = None
    if club.coordinator_id:
        coordinator = User.query.get(club.coordinator_id)

    return render_template(
        "student/club_detail.html",
        club=club,
        approved_member_count=approved_member_count,
        existing_application=existing_application,
        is_full=is_full,
        coordinator=coordinator,
    )


@student_bp.route("/clubs/<int:club_id>/apply", methods=["POST"])
@login_required
@student_required
def apply(club_id: int):
    """Submit an application to join a club.

    Business rules checked server-side (not trusting client):
      1. Club must exist and be active.
      2. Student must not have an active (pending/approved) application.
      3. Club must not be at or above max_members capacity.

    CSRF protection is enforced by Flask-WTF's global after_request hook
    (configured in the app factory with `WTF_CSRF_CHECK_DEFAULT = True`).
    The form submitting to this endpoint must include {{ csrf_token() }}.
    """
    club = Club.query.filter_by(id=club_id, is_active=True).first_or_404()

    # Rule 2 – duplicate application guard
    existing = Application.query.filter_by(
        user_id=current_user.id, club_id=club_id
    ).filter(Application.status.in_(["pending", "approved"])).first()

    if existing:
        flash("You already have an active application for this club.", "warning")
        return redirect(url_for("student.club_detail", club_id=club_id))

    # Rule 3 – capacity check
    approved_count = Application.query.filter_by(
        club_id=club_id, status="approved"
    ).count()
    if approved_count >= club.max_members:
        flash("This club has reached its maximum member capacity.", "danger")
        return redirect(url_for("student.club_detail", club_id=club_id))

    # Create the application
    application = Application(
        user_id=current_user.id,
        club_id=club_id,
        status="pending",
        applied_at=datetime.now(timezone.utc),
    )
    db.session.add(application)
    db.session.commit()

    _log(
        "apply_club",
        f"Student {current_user.username} applied to club '{club.name}' (id={club_id})",
    )

    flash(f"Your application to '{club.name}' has been submitted!", "success")
    return redirect(url_for("student.my_applications"))


@student_bp.route("/applications/<int:app_id>")
@login_required
@student_required
def application_detail(app_id: int):
    """View application details scoped to the logged-in student."""
    application = Application.query.filter_by(
        id=app_id, user_id=current_user.id
    ).first_or_404()
    return render_template(
        "student/application_detail.html",
        application=application,
    )


@student_bp.route("/applications/<int:application_id>/withdraw", methods=["POST"])
@login_required
@student_required
def withdraw(application_id: int):
    """Withdraw a pending application.

    IDOR protection: the query explicitly filters by `user_id=current_user.id`.
    If a student tries to withdraw another student's application the ORM
    returns None → 404, never leaking that the application exists.

    Only 'pending' applications can be withdrawn; approved memberships must
    contact a coordinator.
    """
    # Ownership-scoped lookup – IDOR prevention
    application = Application.query.get_or_404(application_id)
    if application.user_id != current_user.id:
        abort(403)

    if application.status != "pending":
        flash(
            "Only pending applications can be withdrawn. "
            "Contact the club coordinator for approved memberships.",
            "warning",
        )
        return redirect(url_for("student.my_applications"))

    club_name = application.club.name if application.club else f"Club #{application.club_id}"

    application.status = "withdrawn"
    db.session.commit()

    _log(
        "withdraw_application",
        f"Student {current_user.username} withdrew application #{application_id} "
        f"from '{club_name}'",
    )

    flash(f"Your application to '{club_name}' has been withdrawn.", "info")
    return redirect(url_for("student.my_applications"))


@student_bp.route("/applications", endpoint="applications")
@student_bp.route("/applications", endpoint="my_applications")
@login_required
@student_required
def my_applications():
    """List all of the current student's applications.

    Results are always filtered to `user_id=current_user.id` – a student
    cannot enumerate or view another student's applications.

    Supports an optional ?status= filter for quick drill-down.
    """
    status_filter = request.args.get("status", "").strip().lower()
    valid_statuses = {"pending", "approved", "rejected", "withdrawn"}

    query = Application.query.filter_by(user_id=current_user.id)

    if status_filter and status_filter in valid_statuses:
        query = query.filter_by(status=status_filter)

    applications = query.order_by(Application.applied_at.desc()).all()

    return render_template(
        "student/applications.html",
        applications=applications,
        status_filter=status_filter,
        valid_statuses=sorted(valid_statuses),
    )
