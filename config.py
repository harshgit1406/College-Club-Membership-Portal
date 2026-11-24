"""
Flask Application Configuration
=================================
Defines DevelopmentConfig, TestingConfig, and ProductionConfig.
All sensitive values are read from environment variables.
"""

import os
from datetime import timedelta


class BaseConfig:
    """Base configuration shared across all environments."""

    # ------------------------------------------------------------------ #
    #  Core Flask settings
    # ------------------------------------------------------------------ #
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "change-me-in-production-use-strong-random-key")
    DEBUG: bool = False
    TESTING: bool = False

    # ------------------------------------------------------------------ #
    #  Database
    # ------------------------------------------------------------------ #
    # Absolute path so SQLite files land predictably regardless of CWD
    _BASE_DIR: str = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(_BASE_DIR, 'instance', 'app.db')}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ECHO: bool = False  # Set True in dev to log SQL queries

    # ------------------------------------------------------------------ #
    #  Flask-WTF / CSRF
    # ------------------------------------------------------------------ #
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600  # 1 hour in seconds

    # ------------------------------------------------------------------ #
    #  Session security
    # ------------------------------------------------------------------ #
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = False      # Overridden to True in Production
    SESSION_COOKIE_SAMESITE: str = "Lax"
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(hours=2)
    SESSION_COOKIE_NAME: str = "ccp_session"  # College Club Portal session

    # ------------------------------------------------------------------ #
    #  Flask-Limiter
    # ------------------------------------------------------------------ #
    # Uses in-memory storage by default; override with Redis URL in prod
    RATELIMIT_STORAGE_URI: str = os.environ.get("REDIS_URL", "memory://")
    RATELIMIT_DEFAULT: str = "200 per day;50 per hour"
    RATELIMIT_HEADERS_ENABLED: bool = True          # Expose X-RateLimit-* headers

    # ------------------------------------------------------------------ #
    #  Login / account lockout
    # ------------------------------------------------------------------ #
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15

    # ------------------------------------------------------------------ #
    #  Upload / static
    # ------------------------------------------------------------------ #
    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024  # 16 MB upload limit

    # ------------------------------------------------------------------ #
    #  Application-level metadata
    # ------------------------------------------------------------------ #
    APP_NAME: str = "College Club Membership Portal"
    APP_VERSION: str = "1.0.0"


class DevelopmentConfig(BaseConfig):
    """
    Development configuration.
    Debug mode on, verbose SQL, relaxed session cookie security.
    """

    DEBUG: bool = True
    SQLALCHEMY_ECHO: bool = False  # Flip to True to debug queries

    # Friendlier for local HTTP dev
    SESSION_COOKIE_SECURE: bool = False

    # Shorter rate-limit window so manual testing isn't blocked
    RATELIMIT_DEFAULT: str = "500 per day;200 per hour"

    # SQLite in a local instance folder
    _BASE_DIR: str = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(_BASE_DIR, 'instance', 'dev.db')}",
    )


class TestingConfig(BaseConfig):
    """
    Testing configuration.
    Uses an in-memory SQLite DB, CSRF disabled for easier test client usage.
    """

    TESTING: bool = True
    DEBUG: bool = True

    # In-memory SQLite — isolated, fast, torn down after each test session
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    from sqlalchemy.pool import StaticPool
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "poolclass": StaticPool,
        "connect_args": {"check_same_thread": False},
    }

    # Disable CSRF so test client can POST without generating tokens
    WTF_CSRF_ENABLED: bool = False

    # Disable rate limiting so unit tests don't trigger 429 responses
    RATELIMIT_ENABLED: bool = False

    # Suppress login-manager redirects during testing (set per-test as needed)
    LOGIN_DISABLED: bool = False

    # Short lockout for faster test execution
    ACCOUNT_LOCKOUT_MINUTES: int = 1

    SECRET_KEY: str = "test-secret-key-not-for-production"

    # Deterministic session cookie name for test assertions
    SESSION_COOKIE_NAME: str = "ccp_test_session"


class ProductionConfig(BaseConfig):
    """
    Production configuration.
    Enforces HTTPS cookies, requires real SECRET_KEY and DATABASE_URL env vars.
    """

    DEBUG: bool = False
    TESTING: bool = False

    # Must be set via environment — falls back to placeholder if unset
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "change-me-in-production-use-strong-random-key")
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BaseConfig._BASE_DIR, 'instance', 'prod.db')}",
    )

    # Enforce secure cookies over HTTPS
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_SAMESITE: str = "Strict"

    # Tighter session lifetime in production
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(hours=1)

    # Stricter rate limiting
    RATELIMIT_DEFAULT: str = "100 per day;20 per hour"


# ---------------------------------------------------------------------- #
#  Configuration registry
# ---------------------------------------------------------------------- #
config_map: dict[str, type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(env: str | None = None) -> type[BaseConfig]:
    """
    Return the appropriate config class for *env*.

    Falls back to the FLASK_ENV environment variable, then 'default'.

    Usage::

        from config import get_config
        app.config.from_object(get_config())
    """
    if env is None:
        env = os.environ.get("FLASK_ENV", "default")
    return config_map.get(env, DevelopmentConfig)
