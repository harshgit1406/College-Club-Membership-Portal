"""
tests/test_security.py
----------------------
Automated vulnerability verification tests for the Security Testing Lab.
Validates defenses against:
  1. SQL injection
  2. Cross-Site Scripting (XSS)
  3. CSRF protection
  4. Brute-force / Rate limiting
  5. Insecure Direct Object Reference (IDOR)
  6. Privilege escalation (RBAC)
  7. Insecure passwords & storage
  8. Session cookie flags
  9. Security response headers
 10. Account lockout
"""

import json
import pytest
from app.models import User, db
from app.security.tests import SecurityTestRunner, TEST_DEFINITIONS
from tests.conftest import login


class TestSecurityRunner:
    """Tests for the SecurityTestRunner test engine."""

    def test_all_ten_tests_defined(self):
        assert len(TEST_DEFINITIONS) == 10

    def test_run_all_security_tests_pass(self, app, _seed_db):
        """Verify that all 10 security tests achieve PASS status."""
        with app.app_context():
            runner = SecurityTestRunner(app)
            results = runner.run_all(persist=False)

            assert len(results) == 10
            for r in results:
                assert r["status"] == "PASS", f"Test {r['name']} failed: {r.get('explanation')}"

    def test_individual_test_sql_injection(self, app, _seed_db):
        with app.app_context():
            runner = SecurityTestRunner(app)
            res = runner.run_test("sql_injection", persist=False)
            assert res["status"] == "PASS"

    def test_individual_test_xss(self, app):
        with app.app_context():
            runner = SecurityTestRunner(app)
            res = runner.run_test("xss", persist=False)
            assert res["status"] == "PASS"

    def test_individual_test_csrf(self, app):
        with app.app_context():
            runner = SecurityTestRunner(app)
            res = runner.run_test("csrf", persist=False)
            assert res["status"] == "PASS"

    def test_individual_test_privilege_escalation(self, app, _seed_db):
        with app.app_context():
            runner = SecurityTestRunner(app)
            res = runner.run_test("privilege_escalation", persist=False)
            assert res["status"] == "PASS"

    def test_individual_test_password_storage(self, app, _seed_db):
        with app.app_context():
            runner = SecurityTestRunner(app)
            res = runner.run_test("password_storage", persist=False)
            assert res["status"] == "PASS"

    def test_individual_test_session_security(self, app):
        with app.app_context():
            runner = SecurityTestRunner(app)
            res = runner.run_test("session_security", persist=False)
            assert res["status"] == "PASS"

    def test_individual_test_security_headers(self, app):
        with app.app_context():
            runner = SecurityTestRunner(app)
            res = runner.run_test("security_headers", persist=False)
            assert res["status"] == "PASS"

    def test_individual_test_account_lockout(self, app, _seed_db):
        with app.app_context():
            runner = SecurityTestRunner(app)
            res = runner.run_test("account_lockout", persist=False)
            assert res["status"] == "PASS"


class TestSecurityLabRoutes:
    """Tests for Security Testing Dashboard endpoints."""

    def test_security_lab_forbidden_for_student(self, client, _seed_db):
        login(client, "alice@college.edu", "Student@123")
        resp = client.get("/admin/security-lab")
        assert resp.status_code == 403

    def test_security_lab_loads_for_admin(self, client, _seed_db):
        login(client, "admin@college.edu", "Admin@123")
        resp = client.get("/admin/security-lab")
        assert resp.status_code == 200
        assert b"Security Testing Laboratory" in resp.data
        assert b"SQL Injection" in resp.data

    def test_run_single_test_api(self, client, _seed_db):
        login(client, "admin@college.edu", "Admin@123")
        resp = client.post("/admin/security-lab/run/sql_injection")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["result"]["status"] == "PASS"

    def test_export_security_report_json(self, client, _seed_db):
        login(client, "admin@college.edu", "Admin@123")
        resp = client.get("/admin/security-lab/export/json")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "application/json"
        data = json.loads(resp.data)
        failed = [(r['id'], r['status'], r.get('actual_result')) for r in data['results'] if r['status'] != 'PASS']
        assert not failed, f"Failed tests: {failed}"
        assert data["overall_status"] == "SECURE"
        assert len(data["results"]) == 10

    def test_export_security_report_html(self, client, _seed_db):
        login(client, "admin@college.edu", "Admin@123")
        resp = client.get("/admin/security-lab/export/html")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["Content-Type"]
        assert b"Security Audit Report" in resp.data

    def test_simulate_sqli_attack(self, client, _seed_db):
        login(client, "admin@college.edu", "Admin@123")
        resp = client.post(
            "/admin/security-lab/simulate",
            json={"attack_type": "sqli", "payload": "' OR '1'='1"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["verdict"] == "DEFENDED / NEUTRALIZED"
        assert "SQLAlchemy" in data["defense_layer"]

    def test_simulate_xss_attack(self, client, _seed_db):
        login(client, "admin@college.edu", "Admin@123")
        resp = client.post(
            "/admin/security-lab/simulate",
            json={"attack_type": "xss", "payload": "<script>alert('pwn')</script>"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["verdict"] == "DEFENDED / NEUTRALIZED"
        assert "&lt;script&gt;" in data["escaped_html"]

    def test_simulate_idor_attack(self, client, _seed_db):
        login(client, "admin@college.edu", "Admin@123")
        resp = client.post(
            "/admin/security-lab/simulate",
            json={"attack_type": "idor", "payload": "99999"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "DEFENDED" in data["verdict"]

    def test_simulate_weak_password_attack(self, client, _seed_db):
        login(client, "admin@college.edu", "Admin@123")
        resp = client.post(
            "/admin/security-lab/simulate",
            json={"attack_type": "password", "payload": "12345"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "DEFENDED" in data["verdict"] or "REJECTED" in data["verdict"]
