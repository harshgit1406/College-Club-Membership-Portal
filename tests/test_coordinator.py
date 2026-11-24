"""
tests/test_coordinator.py
--------------------------
Tests for coordinator routes: dashboard, club management,
application approvals/rejections, and role boundary protection.
"""

import pytest
from app.models import Application, Club, User, db
from tests.conftest import login, logout


def login_coordinator(client, email="coord1@college.edu", password="Coord@123"):
    return login(client, email, password)


class TestCoordinatorDashboard:
    """Tests for coordinator dashboard."""

    def test_dashboard_requires_login(self, client):
        resp = client.get("/coordinator/dashboard", follow_redirects=True)
        assert resp.status_code == 200
        assert b"Sign In" in resp.data or b"login" in resp.data.lower()

    def test_dashboard_accessible_to_coordinator(self, client, _seed_db):
        login_coordinator(client)
        resp = client.get("/coordinator/dashboard", follow_redirects=True)
        assert resp.status_code == 200
        assert b"Coordinator Dashboard" in resp.data or b"Tech Club" in resp.data

    def test_dashboard_forbidden_for_student(self, client, _seed_db):
        login(client, "alice@college.edu", "Student@123")
        resp = client.get("/coordinator/dashboard", follow_redirects=True)
        assert resp.status_code in (403, 302, 200)
        if resp.status_code == 200:
            assert b"Forbidden" in resp.data or b"403" in resp.data

    def test_dashboard_accessible_to_admin(self, client, _seed_db):
        login(client, "admin@college.edu", "Admin@123")
        resp = client.get("/coordinator/dashboard", follow_redirects=True)
        assert resp.status_code == 200


class TestCoordinatorClubActions:
    """Tests for managing assigned clubs, approving/rejecting applications."""

    def test_manage_owned_club(self, client, app, _seed_db):
        login_coordinator(client, "coord1@college.edu")
        with app.app_context():
            club = Club.query.filter_by(name="Tech Club").first()
            club_id = club.id
        resp = client.get(f"/coordinator/club/{club_id}")
        assert resp.status_code == 200
        assert b"Tech Club" in resp.data

    def test_cannot_manage_unowned_club(self, client, app, _seed_db):
        """Coord1 cannot manage Art Club which is assigned to Coord2."""
        login_coordinator(client, "coord1@college.edu")
        with app.app_context():
            art_club = Club.query.filter_by(name="Art Club").first()
            art_id = art_club.id
        resp = client.get(f"/coordinator/club/{art_id}")
        assert resp.status_code == 403

    def test_approve_application_success(self, client, app, _seed_db):
        login_coordinator(client, "coord1@college.edu")
        with app.app_context():
            tech_club = Club.query.filter_by(name="Tech Club").first()
            pending_app = Application.query.filter_by(club_id=tech_club.id, status="pending").first()
            app_id = pending_app.id
            club_id = tech_club.id

        resp = client.post(
            f"/coordinator/club/{club_id}/application/{app_id}/approve",
            data={"notes": "Welcome to Tech Club!"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        with app.app_context():
            updated = db.session.get(Application, app_id)
            assert updated.status == "approved"

    def test_reject_application_success(self, client, app, _seed_db):
        login_coordinator(client, "coord2@college.edu")
        with app.app_context():
            art_club = Club.query.filter_by(name="Art Club").first()
            pending_app = Application.query.filter_by(club_id=art_club.id, status="pending").first()
            app_id = pending_app.id
            club_id = art_club.id

        resp = client.post(
            f"/coordinator/club/{club_id}/application/{app_id}/reject",
            data={"notes": "Not enough portfolio materials."},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        with app.app_context():
            updated = db.session.get(Application, app_id)
            assert updated.status == "rejected"

    def test_member_list_view(self, client, app, _seed_db):
        login_coordinator(client, "coord1@college.edu")
        with app.app_context():
            tech_club = Club.query.filter_by(name="Tech Club").first()
            club_id = tech_club.id
        resp = client.get(f"/coordinator/club/{club_id}/members")
        assert resp.status_code == 200
        assert b"Tech Club" in resp.data
