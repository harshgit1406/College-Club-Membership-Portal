"""
Pytest configuration and shared fixtures for the College Club Membership Portal.
"""
import pytest
from app import create_app
from app.models import db as _db, User, Club, Application, ActivityLog
from werkzeug.security import generate_password_hash
from datetime import datetime


@pytest.fixture(scope="session")
def app():
    """Create application configured for testing."""
    from sqlalchemy.pool import StaticPool
    test_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_ENGINE_OPTIONS": {
            "poolclass": StaticPool,
            "connect_args": {"check_same_thread": False},
        },
        "WTF_CSRF_ENABLED": False,          # disable CSRF for most tests
        "SECRET_KEY": "test-secret-key-not-for-production",
        "SERVER_NAME": None,
        "RATELIMIT_ENABLED": False,          # disable rate limits by default
        "LOGIN_DISABLED": False,
        "BCRYPT_LOG_ROUNDS": 4,             # faster hashing in tests
    }
    app = create_app(test_config)

    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture(scope="session")
def db(app):
    """Session-wide test database."""
    return _db


@pytest.fixture(scope="function")
def session(db, app):
    """Function-scoped database session that rolls back after each test."""
    with app.app_context():
        connection = db.engine.connect()
        transaction = connection.begin()
        # Bind a session to this connection
        db.session.remove()
        yield db.session
        db.session.remove()
        transaction.rollback()
        connection.close()


@pytest.fixture(scope="function")
def _seed_db(app, db):
    """Seed the in-memory database cleanly for each test."""
    with app.app_context():
        _db.session.rollback()
        Application.query.delete()
        Club.query.delete()
        ActivityLog.query.delete()
        User.query.delete()
        _db.session.commit()
        # --- Users ---
        admin = User(
            username="admin",
            email="admin@college.edu",
            password_hash=generate_password_hash("Admin@123"),
            role="admin",
            is_active=True,
        )
        coord1 = User(
            username="coordinator1",
            email="coord1@college.edu",
            password_hash=generate_password_hash("Coord@123"),
            role="coordinator",
            is_active=True,
        )
        coord2 = User(
            username="coordinator2",
            email="coord2@college.edu",
            password_hash=generate_password_hash("Coord@123"),
            role="coordinator",
            is_active=True,
        )
        alice = User(
            username="alice",
            email="alice@college.edu",
            password_hash=generate_password_hash("Student@123"),
            role="student",
            is_active=True,
        )
        bob = User(
            username="bob",
            email="bob@college.edu",
            password_hash=generate_password_hash("Student@123"),
            role="student",
            is_active=True,
        )
        carol = User(
            username="carol",
            email="carol@college.edu",
            password_hash=generate_password_hash("Student@123"),
            role="student",
            is_active=True,
        )

        db.session.add_all([admin, coord1, coord2, alice, bob, carol])
        db.session.flush()

        # --- Clubs ---
        tech_club = Club(
            name="Tech Club",
            description="Explore technology and programming.",
            category="Technology",
            max_members=20,
            coordinator_id=coord1.id,
            is_active=True,
        )
        robotics_club = Club(
            name="Robotics Club",
            description="Build and program robots.",
            category="Engineering",
            max_members=15,
            coordinator_id=coord1.id,
            is_active=True,
        )
        art_club = Club(
            name="Art Club",
            description="Creative arts and design.",
            category="Arts",
            max_members=25,
            coordinator_id=coord2.id,
            is_active=True,
        )
        music_club = Club(
            name="Music Club",
            description="Music performance and theory.",
            category="Arts",
            max_members=20,
            coordinator_id=None,
            is_active=True,
        )
        sports_club = Club(
            name="Sports Club",
            description="Various sports activities.",
            category="Sports",
            max_members=50,
            coordinator_id=None,
            is_active=True,
        )

        db.session.add_all(
            [tech_club, robotics_club, art_club, music_club, sports_club]
        )
        db.session.flush()

        # --- Applications ---
        app1 = Application(
            user_id=alice.id,
            club_id=tech_club.id,
            status="approved",
            applied_at=datetime.utcnow(),
            reviewed_by=coord1.id,
        )
        app2 = Application(
            user_id=alice.id,
            club_id=art_club.id,
            status="pending",
            applied_at=datetime.utcnow(),
        )
        app3 = Application(
            user_id=bob.id,
            club_id=tech_club.id,
            status="pending",
            applied_at=datetime.utcnow(),
        )

        db.session.add_all([app1, app2, app3])
        db.session.commit()

        yield {
            "admin": admin,
            "coord1": coord1,
            "coord2": coord2,
            "alice": alice,
            "bob": bob,
            "carol": carol,
            "tech_club": tech_club,
            "robotics_club": robotics_club,
            "art_club": art_club,
            "music_club": music_club,
            "sports_club": sports_club,
            "app1": app1,
            "app2": app2,
            "app3": app3,
        }


@pytest.fixture(scope="function")
def seeded(app, _seed_db):
    """Provide seed data dictionary within app context for each test."""
    with app.app_context():
        # Refresh objects from db to avoid DetachedInstanceError
        data = {}
        for key, obj in _seed_db.items():
            if hasattr(obj, "__class__") and hasattr(obj, "id"):
                data[key] = db_get(app, obj.__class__, obj.id)
            else:
                data[key] = obj
        yield data


def db_get(app, model, obj_id):
    """Helper to re-fetch a model instance."""
    return _db.session.get(model, obj_id)


@pytest.fixture(scope="function")
def client(app):
    """Test client (session-scoped app, function-scoped client)."""
    return app.test_client()


# ---------------------------------------------------------------------------
# Login helpers
# ---------------------------------------------------------------------------

def login(client, email, password):
    """Helper to log in via the test client."""
    return client.post(
        "/auth/login",
        data={"email": email, "password": password},
        follow_redirects=True,
    )


def logout(client):
    """Helper to log out via the test client."""
    return client.get("/auth/logout", follow_redirects=True)


# Expose helpers on the module so tests can import them
__all__ = ["login", "logout", "db_get"]
