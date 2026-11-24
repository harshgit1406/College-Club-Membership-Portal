"""
Authentication blueprint for the College Club Membership Portal.

Provides:
  GET/POST  /auth/login     – login form (rate-limited: 5 req/min per IP)
  GET/POST  /auth/register  – registration form
  GET       /auth/logout    – logout and session teardown

Security controls implemented here:
  • CSRF protection on every POST (Flask-WTF)
  • Werkzeug pbkdf2:sha256 password hashing
  • Rate limiting on /login  (5 attempts / minute / IP via Flask-Limiter)
  • Account lockout after 5 consecutive failures (15-minute lockout)
  • Strong password policy enforced server-side
  • Activity logging for every significant auth event
  • Secure session flags set at app level (HttpOnly, SameSite, Secure)
  • Sensitive data (passwords) never logged or returned in responses
"""

import re
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    session,
    current_app,
)
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    EqualTo,
    ValidationError,
)

from app import db, limiter
from app.models import User, ActivityLog


# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client_ip() -> str:
    """Return the best-guess client IP, honoring X-Forwarded-For if present."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _log_activity(user_id, action: str, details: str = "") -> None:
    """Persist an ActivityLog record (fire-and-forget within the same tx)."""
    try:
        entry = ActivityLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=_client_ip(),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as exc:  # pragma: no cover
        current_app.logger.error("Activity log write failed: %s", exc)
        db.session.rollback()


# ---------------------------------------------------------------------------
# Password policy
# ---------------------------------------------------------------------------

_PASSWORD_POLICY = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]).{8,}$"
)


def _validate_password_strength(password: str) -> list[str]:
    """
    Return a list of unmet policy requirements, empty list = OK.

    Policy:
      - At least 8 characters
      - At least one uppercase letter
      - At least one lowercase letter
      - At least one digit
      - At least one special character
    """
    errors: list[str] = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("at least one lowercase letter")
    if not re.search(r"\d", password):
        errors.append("at least one digit")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};':\"\\|,.<>/?]", password):
        errors.append("at least one special character (!@#$%^&* …)")
    return errors


# ---------------------------------------------------------------------------
# WTForms
# ---------------------------------------------------------------------------

class LoginForm(FlaskForm):
    """Login form – email or username + password + optional remember-me."""

    email = StringField(
        "Email or Username",
        validators=[Length(max=120)],
    )
    username = StringField(
        "Username or Email",
        validators=[Length(max=120)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required.")],
    )
    remember = BooleanField("Remember me")
    submit = SubmitField("Sign In")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.email.data and not self.username.data:
            self.username.data = self.email.data
        elif self.username.data and not self.email.data:
            self.email.data = self.username.data

    def validate(self, extra_validators=None):
        initial = super().validate(extra_validators=extra_validators)
        if not initial:
            return False
        if not (self.email.data or self.username.data):
            self.email.errors.append("Email or username is required.")
            self.username.errors.append("Email or username is required.")
            return False
        return True


class RegisterForm(FlaskForm):
    """Registration form – username, email, password (+ confirmation)."""

    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=64, message="Username must be 3–64 characters."),
        ],
    )
    email = StringField(
        "Email",
        validators=[
            DataRequired(message="Email is required."),
            Email(message="Enter a valid email address."),
            Length(max=120),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required.")],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(message="Please confirm your password."),
            EqualTo("password", message="Passwords must match."),
        ],
    )
    submit = SubmitField("Create Account")

    # --- custom cross-field validators ---

    def validate_username(self, field):  # noqa: D401
        """Reject usernames already taken."""
        if User.query.filter_by(username=field.data).first():
            raise ValidationError(
                "That username is already taken. Please choose another."
            )

    def validate_email(self, field):  # noqa: D401
        """Reject emails already registered."""
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError(
                "An account with that email already exists."
            )

    def validate_password(self, field):  # noqa: D401
        """Enforce the password strength policy."""
        issues = _validate_password_strength(field.data)
        if issues:
            raise ValidationError(
                "Password must contain: " + ", ".join(issues) + "."
            )


# ---------------------------------------------------------------------------
# Role-based access-control decorators (re-used by other blueprints)
# ---------------------------------------------------------------------------

def roles_required(*roles):
    """
    Decorator factory that restricts a route to logged-in users whose
    *role* is in *roles*.  Returns 403 for authenticated users with an
    insufficient role.

    Usage::

        @bp.route("/admin-only")
        @login_required
        @roles_required("admin")
        def admin_view():
            ...
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                # flask-login handles the redirect to login
                from flask_login import current_app as _ca  # noqa: F401
                return redirect(url_for("auth.login"))
            if current_user.role not in roles:
                _log_activity(
                    current_user.id,
                    "privilege_escalation_attempt",
                    f"Tried to access {request.path} (role={current_user.role!r})",
                )
                from flask import abort
                abort(403)
            return f(*args, **kwargs)

        return decorated

    return decorator


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", error_message="Too many login attempts. Please wait a minute and try again.")
def login():
    """
    Login route.

    Security controls:
      - Rate limited to 5 POST requests per minute per IP
      - Account lockout after 5 consecutive failed attempts
      - Password never compared in raw form in logs/responses
      - Activity logged on success and failure
    """
    if current_user.is_authenticated:
        return _redirect_by_role(current_user)

    form = LoginForm()

    if form.validate_on_submit():
        login_val = (form.email.data or form.username.data or "").strip().lower()
        password = form.password.data  # never log this

        # Lookup user by email or username (ORM – parameterised query, no raw SQL)
        from sqlalchemy import func
        user = User.query.filter(
            (func.lower(User.email) == login_val) | (func.lower(User.username) == login_val)
        ).first()

        # --- Account-not-found ---
        if user is None:
            _log_activity(
                None,
                "login_failed",
                f"No account found for identifier={login_val!r}",
            )
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", form=form)

        # --- Account inactive (disabled by admin) ---
        if not user.is_active:
            _log_activity(
                user.id,
                "login_blocked_inactive",
                "Attempted login on deactivated account",
            )
            flash(
                "Your account has been deactivated. "
                "Please contact an administrator.",
                "warning",
            )
            return render_template("auth/login.html", form=form)

        # --- Account locked out ---
        if user.is_locked():
            lu = user.locked_until
            if lu and lu.tzinfo is None:
                lu = lu.replace(tzinfo=timezone.utc)
            remaining = int((lu - datetime.now(timezone.utc)).total_seconds() // 60) + 1
            _log_activity(
                user.id,
                "login_blocked_locked",
                f"Account locked, {remaining} minute(s) remaining",
            )
            flash(
                f"Account locked. Too many failed attempts. "
                f"Try again in {remaining} minute(s).",
                "danger",
            )
            return render_template("auth/login.html", form=form, locked=True)

        # --- Wrong password ---
        if not user.check_password(password):
            user.increment_failed_attempts()
            db.session.commit()

            remaining_attempts = max(0, 5 - user.failed_login_attempts)
            _log_activity(
                user.id,
                "login_failed",
                f"Wrong password, {user.failed_login_attempts} consecutive failures",
            )

            if user.is_locked():
                flash(
                    "Too many failed attempts. Account locked for 15 minutes.",
                    "danger",
                )
            else:
                flash(
                    f"Invalid email or password. "
                    f"{remaining_attempts} attempt(s) remaining before lockout.",
                    "danger",
                )
            return render_template("auth/login.html", form=form)

        # --- Successful login ---
        user.reset_failed_attempts()
        db.session.commit()

        login_user(user, remember=form.remember.data)
        _log_activity(user.id, "login_success", f"Logged in from {_client_ip()}")

        # Honour next= param (safe redirect only)
        next_page = request.args.get("next")
        if next_page and next_page.startswith("/"):
            return redirect(next_page)
        return _redirect_by_role(user)

    return render_template("auth/login.html", form=form)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Registration route.

    New accounts are always created with role='student'.
    Coordinators and admins are assigned by an existing admin.

    Security controls:
      - CSRF via Flask-WTF
      - Server-side password strength validation
      - Duplicate username/email checked via ORM
      - Password stored hashed, never in plain text
    """
    if current_user.is_authenticated:
        return _redirect_by_role(current_user)

    form = RegisterForm()

    if form.validate_on_submit():
        user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            role="student",
            is_active=True,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        _log_activity(
            user.id,
            "register",
            f"New student account created: {user.username!r}",
        )

        flash(
            "Account created successfully! You can now sign in.",
            "success",
        )
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    """
    Logout route.

    Clears the server-side session and redirects to the login page.
    """
    user_id = current_user.id
    username = current_user.username
    _log_activity(user_id, "logout", f"{username!r} signed out")

    logout_user()
    session.clear()

    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _redirect_by_role(user: User):
    """Send the authenticated user to the correct dashboard for their role."""
    if user.is_admin:
        return redirect(url_for("admin.dashboard"))
    if user.is_coordinator:
        return redirect(url_for("coordinator.dashboard"))
    return redirect(url_for("student.dashboard"))
