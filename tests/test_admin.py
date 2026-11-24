"""
tests/test_admin.py
-------------------
Tests for admin routes: dashboard, user management,
club management, activity logs, and role enforcement.
"""

import pytest
from app.models import ActivityLog, Club, User, db
from tests.conftest import login, logout


def login_admin(client, email="admin@college.edu", password="Admin@123"):
    return login(client, email, password)


class TestAdminDashboard:
    """Tests for GET /admin/dashboard."""

    def test_dashboard_requires_admin(self, client, _seed_db):
        # Student gets 403
        login(client, "alice@college.edu", "Student@123")
        resp = client.get("/admin/dashboard")
        assert resp.status_code == 403

    def test_dashboard_accessible_to_admin(self, client, _seed_db):
        login_admin(client)
        resp = client.get("/admin/dashboard")
        assert resp.status_code == 200
        assert b"Admin Dashboard" in resp.data
        assert b"Security Lab" in resp.data


class TestAdminUserManagement:
    """Tests for user administration."""

    def test_users_list_loads(self, client, _seed_db):
        login_admin(client)
        resp = client.get("/admin/users")
        assert resp.status_code == 200
        assert b"alice" in resp.data
        assert b"coord1" in resp.data

    def test_toggle_user_active_status(self, client, app, _seed_db):
        login_admin(client)
        with app.app_context():
            user = User.query.filter_by(email="bob@college.edu").first()
            user_id = user.id
            initially_active = user.is_active

        resp = client.post(f"/admin/users/{user_id}/toggle", follow_redirects=True)
        assert resp.status_code == 200

        with app.app_context():
            updated = db.session.get(User, user_id)
            assert updated.is_active != initially_active

    def test_admin_cannot_deactivate_self(self, client, app, _seed_db):
        login_admin(client)
        with app.app_context():
            admin = User.query.filter_by(role="admin").first()
            admin_id = admin.id

        resp = client.post(f"/admin/users/{admin_id}/toggle", follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            admin = db.session.get(User, admin_id)
            assert admin.is_active is True

    def test_change_user_role(self, client, app, _seed_db):
        login_admin(client)
        with app.app_context():
            bob = User.query.filter_by(email="bob@college.edu").first()
            bob_id = bob.id

        resp = client.post(
            f"/admin/users/{bob_id}/role",
            data={"role": "coordinator"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        with app.app_context():
            updated = db.session.get(User, bob_id)
            assert updated.role == "coordinator"


class TestAdminClubManagement:
    """Tests for creating and editing clubs."""

    def test_admin_clubs_list(self, client, _seed_db):
        login_admin(client)
        resp = client.get("/admin/clubs")
        assert resp.status_code == 200
        assert b"Tech Club" in resp.data

    def test_admin_create_club(self, client, app, _seed_db):
        login_admin(client)
        with app.app_context():
            coord = User.query.filter_by(role="coordinator").first()
            coord_id = coord.id

        resp = client.post(
            "/admin/clubs/new",
            data={
                "name": "Astronomy Club",
                "category": "Science",
                "max_members": 30,
                "coordinator_id": coord_id,
                "description": "Stargazing and space exploration.",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        with app.app_context():
            club = Club.query.filter_by(name="Astronomy Club").first()
            assert club is not None
            assert club.max_members == 30

    def test_admin_toggle_club(self, client, app, _seed_db):
        login_admin(client)
        with app.app_context():
            club = Club.query.filter_by(name="Sports Club").first()
            club_id = club.id

        resp = client.post(f"/admin/clubs/{club_id}/toggle", follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            updated = db.session.get(Club, club_id)
            assert updated.is_active is False


class TestAdminActivityLogs:
    """Tests for audit trail viewer."""

    def test_activity_logs_accessible_to_admin(self, client, app, _seed_db):
        login_admin(client)
        resp = client.get("/admin/activity-logs")
        assert resp.status_code == 200
        assert b"Audit Activity Logs" in resp.data
