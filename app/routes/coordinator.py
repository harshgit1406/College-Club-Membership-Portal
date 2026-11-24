"""
Coordinator routes - scoped to assigned clubs only.
All routes require login + coordinator role.
"""

from functools import wraps
from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    abort,
    current_app,
)
from flask_login import login_required, current_user
from sqlalchemy import func

from app.models import db, User, Club, Application, ActivityLog

coordinator_bp = Blueprint("coordinator", __name__, url_prefix="/coordinator")


# ---------------------------------------------------------------------------
# Role guard decorator
# ---------------------------------------------------------------------------

def coordinator_required(f):
    """Ensure the current user is a coordinator (or admin)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        if current_user.role not in ("coordinator", "admin"):
            abort(403)
        return f(*args, **kwargs)
    return decorated


def _log_action(action: str, details: str = ""):
    """Append an ActivityLog entry for the current request."""
    entry = ActivityLog(
        user_id=current_user.id,
        action=action,
        details=details,
        ip_address=request.remote_addr,
    )
    db.session.add(entry)
    db.session.commit()


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@coordinator_bp.route("/dashboard")
@login_required
@coordinator_required
def dashboard():
    """
    Overview of all clubs assigned to this coordinator.
    Shows pending application count per club and overall stats.
    """
    # Admins see all clubs; coordinators only see theirs
    if current_user.role == "admin":
        clubs = Club.query.filter_by(is_active=True).all()
    else:
        clubs = Club.query.filter_by(
            coordinator_id=current_user.id, is_active=True
        ).all()

    club_ids = [c.id for c in clubs]

    # Aggregate stats
    total_pending = (
        Application.query.filter(
            Application.club_id.in_(club_ids),
            Application.status == "pending",
        ).count()
        if club_ids else 0
    )
    total_approved = (
        Application.query.filter(
            Application.club_id.in_(club_ids),
            Application.status == "approved",
        ).count()
        if club_ids else 0
    )
    total_rejected = (
        Application.query.filter(
            Application.club_id.in_(club_ids),
            Application.status == "rejected",
        ).count()
        if club_ids else 0
    )

    # Per-club stats
    club_stats = []
    for club in clubs:
        pending = Application.query.filter_by(
            club_id=club.id, status="pending"
        ).count()
        approved = Application.query.filter_by(
            club_id=club.id, status="approved"
        ).count()
        club_stats.append(
            {
                "club": club,
                "pending": pending,
                "approved": approved,
                "total": pending + approved,
            }
        )

    return render_template(
        "coordinator/dashboard.html",
        clubs=clubs,
        club_stats=club_stats,
        total_pending=total_pending,
        total_approved=total_approved,
        total_rejected=total_rejected,
    )


# ---------------------------------------------------------------------------
# Club management
# ---------------------------------------------------------------------------

@coordinator_bp.route("/club/<int:club_id>")
@login_required
@coordinator_required
def manage_club(club_id):
    """
    View and manage a single club: list applications and members.
    Coordinators can only access their own clubs.
    """
    club = _get_owned_club(club_id)

    pending_applications = (
        Application.query.filter_by(club_id=club.id, status="pending")
        .join(User, Application.user_id == User.id)
        .order_by(Application.applied_at.asc())
        .all()
    )
    approved_members = (
        Application.query.filter_by(club_id=club.id, status="approved")
        .join(User, Application.user_id == User.id)
        .order_by(Application.reviewed_at.desc())
        .all()
    )
    rejected_applications = (
        Application.query.filter_by(club_id=club.id, status="rejected")
        .join(User, Application.user_id == User.id)
        .order_by(Application.reviewed_at.desc())
        .all()
    )

    return render_template(
        "coordinator/manage_club.html",
        club=club,
        pending_applications=pending_applications,
        approved_members=approved_members,
        rejected_applications=rejected_applications,
        member_count=len(approved_members),
    )


# ---------------------------------------------------------------------------
# Application actions
# ---------------------------------------------------------------------------

@coordinator_bp.route(
    "/club/<int:club_id>/application/<int:app_id>/approve",
    methods=["POST"],
)
@login_required
@coordinator_required
def approve_application(club_id, app_id):
    """
    Approve a pending application.
    Checks max_members limit before approving.
    """
    club = _get_owned_club(club_id)
    application = _get_club_application(app_id, club.id)

    if application.status != "pending":
        flash("Only pending applications can be approved.", "warning")
        return redirect(url_for("coordinator.manage_club", club_id=club.id))

    # Enforce max_members cap
    current_members = Application.query.filter_by(
        club_id=club.id, status="approved"
    ).count()
    if club.max_members and current_members >= club.max_members:
        flash(
            f"Cannot approve: {club.name} has reached its maximum member limit "
            f"({club.max_members}).",
            "danger",
        )
        return redirect(url_for("coordinator.manage_club", club_id=club.id))

    notes = request.form.get("notes", "").strip()
    application.status = "approved"
    application.reviewed_by = current_user.id
    application.notes = notes
    from datetime import datetime
    application.reviewed_at = datetime.utcnow()
    db.session.commit()

    applicant = User.query.get(application.user_id)
    _log_action(
        "approve_application",
        f"Approved application #{app_id} for user {applicant.username} "
        f"in club '{club.name}'",
    )
    flash(
        f"Application from {applicant.username} approved successfully.", "success"
    )
    return redirect(url_for("coordinator.manage_club", club_id=club.id))


@coordinator_bp.route(
    "/club/<int:club_id>/application/<int:app_id>/reject",
    methods=["POST"],
)
@login_required
@coordinator_required
def reject_application(club_id, app_id):
    """Reject a pending application."""
    club = _get_owned_club(club_id)
    application = _get_club_application(app_id, club.id)

    if application.status != "pending":
        flash("Only pending applications can be rejected.", "warning")
        return redirect(url_for("coordinator.manage_club", club_id=club.id))

    notes = request.form.get("notes", "").strip()
    application.status = "rejected"
    application.reviewed_by = current_user.id
    application.notes = notes
    from datetime import datetime
    application.reviewed_at = datetime.utcnow()
    db.session.commit()

    applicant = User.query.get(application.user_id)
    _log_action(
        "reject_application",
        f"Rejected application #{app_id} for user {applicant.username} "
        f"in club '{club.name}'",
    )
    flash(
        f"Application from {applicant.username} rejected.", "info"
    )
    return redirect(url_for("coordinator.manage_club", club_id=club.id))


# ---------------------------------------------------------------------------
# Member list
# ---------------------------------------------------------------------------

@coordinator_bp.route("/club/<int:club_id>/members")
@login_required
@coordinator_required
def member_list(club_id):
    """
    Dedicated member list page for a club.
    """
    club = _get_owned_club(club_id)
    members = (
        Application.query.filter_by(club_id=club.id, status="approved")
        .join(User, Application.user_id == User.id)
        .order_by(Application.reviewed_at.desc())
        .all()
    )
    return render_template(
        "coordinator/member_list.html",
        club=club,
        members=members,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _get_owned_club(club_id: int) -> Club:
    """
    Return the Club if it exists and belongs to the current coordinator.
    Admins bypass the ownership check.
    Raises 404 if not found, 403 if not owned.
    """
    club = Club.query.get_or_404(club_id)
    if current_user.role != "admin" and club.coordinator_id != current_user.id:
        abort(403)
    return club


def _get_club_application(app_id: int, club_id: int) -> Application:
    """
    Return the Application if it belongs to the specified club.
    Raises 404 if not found, 403 if not in this club.
    """
    application = Application.query.get_or_404(app_id)
    if application.club_id != club_id:
        abort(403)
    return application
