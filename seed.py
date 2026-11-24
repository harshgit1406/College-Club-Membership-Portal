"""
seed.py
=======
Seeds the database with sample demonstration data:
  - Users across all 3 roles: Admin, Coordinators, Students
  - Campus clubs with categories and capacities
  - Sample membership applications with pending/approved status
  - Baseline activity log entries
"""

import os
from datetime import datetime, timezone
from app import create_app, db
from app.models import User, Club, Application, ActivityLog


def seed_database():
    env = os.environ.get("FLASK_ENV", "development")
    app = create_app(env)

    with app.app_context():
        print(f"[*] Seeding database ({app.config.get('SQLALCHEMY_DATABASE_URI')})...")

        # Create all tables if not exist
        db.create_all()

        # Check if already seeded
        if User.query.filter_by(email="admin@college.edu").first():
            print("[!] Database is already seeded. Skipping.")
            return

        print("[*] Creating demo users...")
        # 1. Admin
        admin = User(
            username="admin",
            email="admin@college.edu",
            role="admin",
            is_active=True,
        )
        admin.set_password("Admin@123")

        # 2. Coordinators
        coord1 = User(
            username="coord1",
            email="coord1@college.edu",
            role="coordinator",
            is_active=True,
        )
        coord1.set_password("Coord@123")

        coord2 = User(
            username="coord2",
            email="coord2@college.edu",
            role="coordinator",
            is_active=True,
        )
        coord2.set_password("Coord@123")

        # 3. Students
        alice = User(
            username="alice",
            email="alice@college.edu",
            role="student",
            is_active=True,
        )
        alice.set_password("Student@123")

        bob = User(
            username="bob",
            email="bob@college.edu",
            role="student",
            is_active=True,
        )
        bob.set_password("Student@123")

        carol = User(
            username="carol",
            email="carol@college.edu",
            role="student",
            is_active=True,
        )
        carol.set_password("Student@123")

        db.session.add_all([admin, coord1, coord2, alice, bob, carol])
        db.session.commit()

        print("[*] Creating sample campus clubs...")
        tech_club = Club(
            name="Tech Club",
            description="Explore software engineering, open source, and cybersecurity.",
            category="Technology",
            max_members=20,
            coordinator_id=coord1.id,
            is_active=True,
        )
        robotics_club = Club(
            name="Robotics Club",
            description="Hands-on robotics hardware, autonomous drones, and embedded systems.",
            category="Engineering",
            max_members=15,
            coordinator_id=coord1.id,
            is_active=True,
        )
        art_club = Club(
            name="Art Club",
            description="Visual design, digital illustration, and traditional studio arts.",
            category="Arts",
            max_members=25,
            coordinator_id=coord2.id,
            is_active=True,
        )
        music_club = Club(
            name="Music Club",
            description="Jam sessions, music theory workshops, and campus concerts.",
            category="Arts",
            max_members=20,
            coordinator_id=None,
            is_active=True,
        )
        sports_club = Club(
            name="Sports Club",
            description="Inter-college athletics, football, basketball, and recreational fitness.",
            category="Sports",
            max_members=50,
            coordinator_id=None,
            is_active=True,
        )

        db.session.add_all([tech_club, robotics_club, art_club, music_club, sports_club])
        db.session.commit()

        print("[*] Creating sample membership applications...")
        app1 = Application(
            user_id=alice.id,
            club_id=tech_club.id,
            status="approved",
            applied_at=datetime.now(timezone.utc),
            reviewed_at=datetime.now(timezone.utc),
            reviewed_by=coord1.id,
            notes="Strong coding background. Welcome!",
        )
        app2 = Application(
            user_id=alice.id,
            club_id=art_club.id,
            status="pending",
            applied_at=datetime.now(timezone.utc),
        )
        app3 = Application(
            user_id=bob.id,
            club_id=tech_club.id,
            status="pending",
            applied_at=datetime.now(timezone.utc),
        )

        db.session.add_all([app1, app2, app3])

        print("[*] Creating initial audit log records...")
        log1 = ActivityLog(
            user_id=admin.id,
            action="system_seed",
            details="Initial database seed executed with demo fixtures",
            ip_address="127.0.0.1",
        )
        log2 = ActivityLog(
            user_id=alice.id,
            action="apply_club",
            details="Applied to Tech Club",
            ip_address="127.0.0.1",
        )
        log3 = ActivityLog(
            user_id=coord1.id,
            action="approve_application",
            details="Approved Alice for Tech Club",
            ip_address="127.0.0.1",
        )

        db.session.add_all([log1, log2, log3])
        db.session.commit()

        print("[+] Database seeding completed successfully!")
        print("    Demo accounts:")
        print("    - Admin:       admin@college.edu   / Admin@123")
        print("    - Coordinator: coord1@college.edu  / Coord@123")
        print("    - Student:     alice@college.edu   / Student@123")


if __name__ == "__main__":
    seed_database()
