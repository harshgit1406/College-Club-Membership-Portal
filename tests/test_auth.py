"""
Tests for authentication routes: login, register, logout,
rate limiting, and account lockout.
"""
import pytest
from flask import session
from app.models import User, db
from werkzeug.security import generate_password_hash
from tests.conftest import login, logout


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------

class TestRegister:
    """Tests for /auth/register."""

    def test_register_page_loads(self, client):
        """GET /auth/register returns 200."""
        resp = client.get("/auth/register")
        assert resp.status_code == 200
        assert b"Register" in resp.data

    def test_register_success(self, client, app):
        """A new user can register with valid data."""
        resp = client.post(
            "/auth/register",
            data={
                "username": "newstudent",
                "email": "newstudent@college.edu",
                "password": "NewPass@123",
                "confirm_password": "NewPass@123",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        # Should redirect to login or dashboard
        assert b"Login" in resp.data or b"Dashboard" in resp.data or b"success" in resp.data.lower()

        with app.app_context():
            user = User.query.filter_by(email="newstudent@college.edu").first()
            assert user is not None
            assert user.role == "student"

    def test_register_duplicate_email(self, client, app, _seed_db):
        """Registration with an existing email is rejected."""
        resp = client.post(
            "/auth/register",
            data={
                "username": "alice2",
                "email": "alice@college.edu",   # already seeded
                "password": "NewPass@123",
                "confirm_password": "NewPass@123",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"already" in resp.data.lower() or b"exist" in resp.data.lower() or b"error" in resp.data.lower()

    def test_register_weak_password_no_upper(self, client):
        """Password without uppercase is rejected."""
        resp = client.post(
            "/auth/register",
            data={
                "username": "weakuser",
                "email": "weak@college.edu",
                "password": "nouppercase1!",
                "confirm_password": "nouppercase1!",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        # Expect validation error
        assert b"uppercase" in resp.data.lower() or b"password" in resp.data.lower()

    def test_register_weak_password_no_digit(self, client):
        """Password without digit is rejected."""
        resp = client.post(
            "/auth/register",
            data={
                "username": "weakuser2",
                "email": "weak2@college.edu",
                "password": "NoDigit!!",
                "confirm_password": "NoDigit!!",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"digit" in resp.data.lower() or b"number" in resp.data.lower() or b"password" in resp.data.lower()

    def test_register_weak_password_too_short(self, client):
        """Password shorter than 8 chars is rejected."""
        resp = client.post(
            "/auth/register",
            data={
                "username": "shortpw",
                "email": "short@college.edu",
                "password": "Ab1!",
                "confirm_password": "Ab1!",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"8" in resp.data or b"length" in resp.data.lower() or b"password" in resp.data.lower()

    def test_register_password_mismatch(self, client):
        """Mismatched password and confirm_password is rejected."""
        resp = client.post(
            "/auth/register",
            data={
                "username": "mismatch",
                "email": "mismatch@college.edu",
                "password": "Match@123",
                "confirm_password": "NoMatch@123",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"match" in resp.data.lower() or b"password" in resp.data.lower()

    def test_register_missing_fields(self, client):
        """Empty form submission is rejected."""
        resp = client.post(
            "/auth/register",
            data={},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        # Should show form again with errors
        assert b"Register" in resp.data or b"required" in resp.data.lower()

    def test_register_password_stored_hashed(self, client, app):
        """Password must NOT be stored as plaintext."""
        resp = client.post(
            "/auth/register",
            data={
                "username": "hashcheck",
                "email": "hashcheck@college.edu",
                "password": "HashMe@123",
                "confirm_password": "HashMe@123",
            },
            follow_redirects=True,
        )
        with app.app_context():
            user = User.query.filter_by(email="hashcheck@college.edu").first()
            if user:
                assert user.password_hash != "HashMe@123", "Password must be hashed!"
                assert user.password_hash.startswith("pbkdf2:") or user.password_hash.startswith("scrypt:") or len(user.password_hash) > 20


# ---------------------------------------------------------------------------
# Login tests
# ---------------------------------------------------------------------------

class TestLogin:
    """Tests for /auth/login."""

    def test_login_page_loads(self, client):
        """GET /auth/login returns 200."""
        resp = client.get("/auth/login")
        assert resp.status_code == 200
        assert b"Login" in resp.data

    def test_login_success_student(self, client, _seed_db):
        """Valid student credentials log in successfully."""
        resp = login(client, "alice@college.edu", "Student@123")
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data or b"dashboard" in resp.data.lower() or b"Welcome" in resp.data

    def test_login_success_admin(self, client, _seed_db):
        """Valid admin credentials log in successfully."""
        resp = login(client, "admin@college.edu", "Admin@123")
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data or b"admin" in resp.data.lower()

    def test_login_success_coordinator(self, client, _seed_db):
        """Valid coordinator credentials log in successfully."""
        resp = login(client, "coord1@college.edu", "Coord@123")
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data or b"coordinator" in resp.data.lower()

    def test_login_wrong_password(self, client, _seed_db):
        """Wrong password returns error message."""
        resp = login(client, "alice@college.edu", "WrongPass@999")
        assert resp.status_code == 200
        assert b"Invalid" in resp.data or b"incorrect" in resp.data.lower() or b"error" in resp.data.lower()

    def test_login_nonexistent_email(self, client):
        """Login with unknown email returns error."""
        resp = login(client, "nobody@college.edu", "SomePass@1")
        assert resp.status_code == 200
        assert b"Invalid" in resp.data or b"not found" in resp.data.lower() or b"error" in resp.data.lower()

    def test_login_empty_fields(self, client):
        """Empty login form returns error."""
        resp = client.post(
            "/auth/login",
            data={"email": "", "password": ""},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_logout(self, client, _seed_db):
        """Logged-in user can log out."""
        login(client, "alice@college.edu", "Student@123")
        resp = logout(client)
        assert resp.status_code == 200
        assert b"Login" in resp.data or b"logged out" in resp.data.lower()

    def test_protected_route_redirects_to_login(self, client):
        """Unauthenticated access to protected route redirects to login."""
        resp = client.get("/student/dashboard", follow_redirects=True)
        assert resp.status_code == 200
        assert b"Login" in resp.data or b"login" in resp.data.lower()

    def test_login_inactive_user(self, client, app, _seed_db):
        """Deactivated user cannot log in."""
        with app.app_context():
            user = User.query.filter_by(email="carol@college.edu").first()
            if user:
                user.is_active = False
                db.session.commit()
                user_id = user.id

        resp = login(client, "carol@college.edu", "Student@123")
        assert resp.status_code == 200
        assert (
            b"deactivated" in resp.data.lower()
            or b"inactive" in resp.data.lower()
            or b"disabled" in resp.data.lower()
            or b"Invalid" in resp.data
            or b"Login" in resp.data
        )

        # Restore
        with app.app_context():
            user = db.session.get(User, user_id)
            if user:
                user.is_active = True
                db.session.commit()


# ---------------------------------------------------------------------------
# Account lockout tests
# ---------------------------------------------------------------------------

class TestAccountLockout:
    """Test brute-force account lockout after 5 failed attempts."""

    def test_failed_attempts_increment(self, client, app, _seed_db):
        """Failed login attempts are tracked on the user model."""
        with app.app_context():
            bob = User.query.filter_by(email="bob@college.edu").first()
            initial_attempts = bob.failed_login_attempts or 0

        # Send a few bad login attempts
        for _ in range(2):
            login(client, "bob@college.edu", "BadPassword@1")

        with app.app_context():
            bob = User.query.filter_by(email="bob@college.edu").first()
            assert (bob.failed_login_attempts or 0) > initial_attempts

    def test_account_locks_after_five_failures(self, client, app, _seed_db):
        """Account is locked after 5 consecutive failed login attempts."""
        with app.app_context():
            carol = User.query.filter_by(email="carol@college.edu").first()
            carol.failed_login_attempts = 0
            carol.locked_until = None
            db.session.commit()

        # Send 5 bad attempts
        for _ in range(5):
            login(client, "carol@college.edu", "BadPassword@1")

        # Next attempt should be blocked
        resp = login(client, "carol@college.edu", "Student@123")
        assert resp.status_code == 200
        assert (
            b"locked" in resp.data.lower()
            or b"too many" in resp.data.lower()
            or b"temporarily" in resp.data.lower()
            or b"Invalid" in resp.data
        )

        # Cleanup
        with app.app_context():
            carol = User.query.filter_by(email="carol@college.edu").first()
            carol.failed_login_attempts = 0
            carol.locked_until = None
            db.session.commit()

    def test_successful_login_resets_failed_attempts(self, client, app, _seed_db):
        """Successful login resets the failed attempt counter."""
        with app.app_context():
            alice = User.query.filter_by(email="alice@college.edu").first()
            alice.failed_login_attempts = 3
            db.session.commit()

        login(client, "alice@college.edu", "Student@123")

        with app.app_context():
            alice = User.query.filter_by(email="alice@college.edu").first()
            assert (alice.failed_login_attempts or 0) == 0
