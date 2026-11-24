"""
Flask application factory for the College Club Membership Portal.
Initialises extensions, registers blueprints, and attaches security
headers middleware.
"""

import os
from datetime import timedelta

from flask import Flask, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ---------------------------------------------------------------------------
# Extension instances (created here, bound to app in create_app)
# ---------------------------------------------------------------------------
db: SQLAlchemy = SQLAlchemy()
login_manager: LoginManager = LoginManager()
csrf: CSRFProtect = CSRFProtect()
limiter: Limiter = Limiter(key_func=get_remote_address)


def create_app(config_name: str | None = None) -> Flask:
    """
    Application factory.

    Parameters
    ----------
    config_name : str, optional
        One of 'development', 'testing', 'production'.
        Falls back to the ``FLASK_ENV`` environment variable, then
        'development'.
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    _load_config(app, config_name)

    # Ensure instance directory exists for SQLite database files
    os.makedirs(app.instance_path, exist_ok=True)
    instance_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "instance")
    os.makedirs(instance_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Initialise extensions
    # ------------------------------------------------------------------
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Login-manager settings
    login_manager.login_view = "auth.login"          # type: ignore[assignment]
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    # ------------------------------------------------------------------
    # User loader callback
    # ------------------------------------------------------------------
    from app.models import User  # noqa: PLC0415

    @login_manager.user_loader
    def load_user(user_id: str):
        return db.session.get(User, int(user_id))

    # ------------------------------------------------------------------
    # Register blueprints
    # ------------------------------------------------------------------
    _register_blueprints(app)

    # ------------------------------------------------------------------
    # Root route and error handlers
    # ------------------------------------------------------------------
    from flask import redirect, url_for, render_template
    from flask_login import current_user

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            if current_user.role == "admin":
                return redirect(url_for("admin.dashboard"))
            elif current_user.role == "coordinator":
                return redirect(url_for("coordinator.dashboard"))
            return redirect(url_for("student.dashboard"))
        return redirect(url_for("auth.login"))

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("errors/500.html"), 500

    # ------------------------------------------------------------------
    # Security headers middleware
    # ------------------------------------------------------------------
    _attach_security_headers(app)

    # ------------------------------------------------------------------
    # Create tables & initialise app context utilities
    # ------------------------------------------------------------------
    with app.app_context():
        db.create_all()

    return app


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _load_config(app: Flask, config_name: str | dict | None) -> None:
    """Select and apply the right Config object or dictionary."""
    from config import config_map, TestingConfig  # noqa: PLC0415

    if isinstance(config_name, dict):
        app.config.from_object(TestingConfig)
        app.config.update(config_name)
        return

    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    cfg = config_map.get(config_name)
    if cfg is None:
        raise ValueError(
            f"Unknown config name '{config_name}'. "
            f"Choose from: {list(config_map.keys())}"
        )

    app.config.from_object(cfg)

    # Allow .env overrides for secret values
    _override_from_env(app)


def _override_from_env(app: Flask) -> None:
    """
    Pull sensitive values from environment variables so they are never
    hard-coded in source.
    """
    env_keys = {
        "SECRET_KEY": "SECRET_KEY",
        "DATABASE_URL": "SQLALCHEMY_DATABASE_URI",
    }
    for env_var, cfg_key in env_keys.items():
        value = os.environ.get(env_var)
        if value:
            app.config[cfg_key] = value


def _register_blueprints(app: Flask) -> None:
    """Import and register every blueprint."""
    from app.auth import auth_bp  # noqa: PLC0415
    from app.routes.student import student_bp  # noqa: PLC0415
    from app.routes.coordinator import coordinator_bp  # noqa: PLC0415
    from app.routes.admin import admin_bp  # noqa: PLC0415

    app.register_blueprint(auth_bp)
    app.register_blueprint(student_bp, url_prefix="/student")
    app.register_blueprint(coordinator_bp, url_prefix="/coordinator")
    app.register_blueprint(admin_bp, url_prefix="/admin")


def _attach_security_headers(app: Flask) -> None:
    """
    Register an ``after_request`` hook that injects security-related
    HTTP response headers on every response.

    Headers applied
    ---------------
    * Content-Security-Policy
    * Strict-Transport-Security
    * X-Frame-Options
    * X-Content-Type-Options
    * X-XSS-Protection
    * Referrer-Policy
    * Permissions-Policy
    * Cache-Control  (for authenticated pages)
    """

    @app.after_request
    def set_security_headers(response):
        # Content-Security-Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' "
            "  https://cdn.jsdelivr.net "
            "  https://cdnjs.cloudflare.com "
            "  'unsafe-inline'; "
            "style-src 'self' "
            "  https://cdn.jsdelivr.net "
            "  https://cdnjs.cloudflare.com "
            "  'unsafe-inline'; "
            "font-src 'self' "
            "  https://cdn.jsdelivr.net "
            "  https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp

        # HSTS – tell browsers to use HTTPS for 1 year (incl. subdomains)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Legacy XSS filter (belt-and-suspenders for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer information leakage
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Disable powerful browser features that the app does not need
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), payment=()"
        )

        # Prevent caching of authenticated / sensitive responses
        if request.endpoint and request.endpoint not in ("static",):
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate, private"
            )
            response.headers["Pragma"] = "no-cache"

        return response
