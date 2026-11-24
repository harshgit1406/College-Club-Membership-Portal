"""
Database models for the College Club Membership Portal.

Models:
  - User           : portal user (student / coordinator / admin)
  - Club           : campus club entity
  - Application    : student ↔ club membership application
  - ActivityLog    : audit trail of every significant action
  - SecurityTestResult : persisted result of a security-lab test run
"""

from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db  # imported from the app package's extensions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now():
    """UTC-aware current datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    """
    Portal user.

    Roles:
      student     – can browse clubs and apply for membership
      coordinator – manages one or more clubs
      admin       – full access, including security lab
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)

    # Role: 'student' | 'coordinator' | 'admin'
    role = db.Column(db.String(20), nullable=False, default="student")

    # Account state
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Brute-force / lockout tracking
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True), default=_now, nullable=False
    )

    # --- relationships ---
    # Clubs this user coordinates (only relevant when role == 'coordinator')
    coordinated_clubs = db.relationship(
        "Club",
        back_populates="coordinator",
        lazy="dynamic",
        foreign_keys="Club.coordinator_id",
    )

    # Membership applications submitted by this user (role == 'student')
    applications = db.relationship(
        "Application",
        back_populates="applicant",
        lazy="dynamic",
        foreign_keys="Application.user_id",
        cascade="all, delete-orphan",
    )

    # Activity records belonging to this user
    activity_logs = db.relationship(
        "ActivityLog",
        back_populates="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    # -----------------------------------------------------------------
    # Password helpers  – passwords are NEVER stored in plain-text
    # -----------------------------------------------------------------

    def set_password(self, password: str) -> None:
        """Hash *password* with pbkdf2:sha256 and store the digest."""
        self.password_hash = generate_password_hash(
            password, method="pbkdf2:sha256", salt_length=16
        )

    def check_password(self, password: str) -> bool:
        """Return True if *password* matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    # -----------------------------------------------------------------
    # Lockout helpers
    # -----------------------------------------------------------------

    def is_locked(self) -> bool:
        """Return True when the account is currently locked out."""
        if self.locked_until is None:
            return False
        now = _now()
        # locked_until may be naive (SQLite stores without tz); normalise.
        lu = self.locked_until
        if lu.tzinfo is None:
            lu = lu.replace(tzinfo=timezone.utc)
        return now < lu

    def increment_failed_attempts(self) -> None:
        """
        Increment the failed-login counter and lock the account for
        15 minutes after the 5th consecutive failure.
        """
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            from datetime import timedelta
            self.locked_until = _now() + timedelta(minutes=15)

    def reset_failed_attempts(self) -> None:
        """Clear the lockout state after a successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None

    # -----------------------------------------------------------------
    # Convenience
    # -----------------------------------------------------------------

    @property
    def is_student(self) -> bool:
        return self.role == "student"

    @property
    def is_coordinator(self) -> bool:
        return self.role == "coordinator"

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def __repr__(self) -> str:
        return f"<User {self.username!r} role={self.role!r}>"


# ---------------------------------------------------------------------------
# Club
# ---------------------------------------------------------------------------

class Club(db.Model):
    """Campus club entity."""

    __tablename__ = "clubs"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=True)
    max_members = db.Column(db.Integer, default=50, nullable=False)

    # FK → coordinator (a User with role == 'coordinator')
    coordinator_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True
    )

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), default=_now, nullable=False
    )

    # --- relationships ---
    coordinator = db.relationship(
        "User",
        back_populates="coordinated_clubs",
        foreign_keys=[coordinator_id],
    )

    applications = db.relationship(
        "Application",
        back_populates="club",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    # -----------------------------------------------------------------
    # Computed helpers
    # -----------------------------------------------------------------

    @property
    def approved_member_count(self) -> int:
        """Number of approved (active) members."""
        return self.applications.filter_by(status="approved").count()

    @property
    def is_full(self) -> bool:
        """True when the club has reached its member cap."""
        return self.approved_member_count >= self.max_members

    def __repr__(self) -> str:
        return f"<Club {self.name!r}>"


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class Application(db.Model):
    """
    Membership application linking a student (User) to a Club.

    Status lifecycle: pending → approved | rejected
                      pending → withdrawn  (by the student)
    """

    __tablename__ = "applications"

    id = db.Column(db.Integer, primary_key=True)

    # FK → applicant
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )

    # FK → target club
    club_id = db.Column(
        db.Integer, db.ForeignKey("clubs.id"), nullable=False, index=True
    )

    # 'pending' | 'approved' | 'rejected' | 'withdrawn'
    status = db.Column(db.String(20), default="pending", nullable=False)

    applied_at = db.Column(
        db.DateTime(timezone=True), default=_now, nullable=False
    )
    reviewed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # FK → coordinator/admin who reviewed
    reviewed_by = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True
    )

    notes = db.Column(db.Text, nullable=True)

    # --- relationships ---
    applicant = db.relationship(
        "User",
        back_populates="applications",
        foreign_keys=[user_id],
    )

    club = db.relationship(
        "Club",
        back_populates="applications",
        foreign_keys=[club_id],
    )

    reviewer = db.relationship(
        "User",
        foreign_keys=[reviewed_by],
    )

    # Unique constraint: one active application per student per club
    __table_args__ = (
        db.UniqueConstraint(
            "user_id",
            "club_id",
            name="uq_application_user_club",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Application user_id={self.user_id} "
            f"club_id={self.club_id} status={self.status!r}>"
        )


# ---------------------------------------------------------------------------
# ActivityLog
# ---------------------------------------------------------------------------

class ActivityLog(db.Model):
    """
    Audit trail.  Every significant action (login, apply, approve …)
    is recorded here for the admin activity log viewer.
    """

    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)

    # Nullable: some events (failed login by unknown user) have no user
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True, index=True
    )

    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6-safe length

    timestamp = db.Column(
        db.DateTime(timezone=True), default=_now, nullable=False, index=True
    )

    # --- relationship ---
    user = db.relationship("User", back_populates="activity_logs")

    def __repr__(self) -> str:
        return (
            f"<ActivityLog action={self.action!r} user_id={self.user_id}>"
        )


# ---------------------------------------------------------------------------
# SecurityTestResult
# ---------------------------------------------------------------------------

class SecurityTestResult(db.Model):
    """
    Persisted result of a single security-lab test run.

    The full result payload (severity, code snippets, request/response
    details …) is serialised as JSON in the *details* column so that the
    model stays simple while the SecurityTestRunner can store arbitrary
    metadata.
    """

    __tablename__ = "security_test_results"

    id = db.Column(db.Integer, primary_key=True)
    test_name = db.Column(db.String(100), nullable=False, index=True)

    # 'passed' | 'failed' | 'error'
    status = db.Column(db.String(20), nullable=False)

    # JSON blob – see SecurityTestRunner for schema
    details = db.Column(db.Text, nullable=True)

    run_at = db.Column(
        db.DateTime(timezone=True), default=_now, nullable=False, index=True
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityTestResult test={self.test_name!r} "
            f"status={self.status!r}>"
        )
