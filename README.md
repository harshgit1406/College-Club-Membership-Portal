# College Club Membership Portal
### with Security Testing Dashboard

A full-stack Flask web application demonstrating **secure coding practices** for a college club membership system, complete with an admin-only security testing lab that runs real penetration tests against an isolated database.

---

## Table of Contents

1. [Features](#features)
2. [Tech Stack](#tech-stack)
3. [Project Structure](#project-structure)
4. [Quick Start (Local)](#quick-start-local)
5. [Quick Start (Docker)](#quick-start-docker)
6. [Demo Credentials](#demo-credentials)
7. [User Roles](#user-roles)
8. [Security Features](#security-features)
9. [Security Testing Dashboard](#security-testing-dashboard)
10. [Running Tests](#running-tests)
11. [Security Scanning](#security-scanning)
12. [Environment Variables](#environment-variables)
13. [Configuration Classes](#configuration-classes)

---

## Features

| Area | Highlights |
|------|-----------|
| **Authentication** | Register / login / logout with Werkzeug password hashing |
| **Role-Based Access** | Student · Coordinator · Admin with decorator-enforced RBAC |
| **Club Management** | Browse clubs, apply, withdraw; coordinator approve/reject |
| **Admin Dashboard** | User & club management, activity logs, coordinator assignment |
| **Security Lab** | 10 real automated security tests with side-by-side code comparison |
| **Report Export** | Download test results as HTML or JSON |
| **Rate Limiting** | Per-route limits via Flask-Limiter; account lockout after 5 failures |
| **CSRF Protection** | Flask-WTF tokens on every form; header-based CSRF for AJAX |
| **Activity Logging** | Every sensitive action logged with IP and timestamp |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, Flask 3.1 |
| ORM | SQLAlchemy 2.0 / Flask-SQLAlchemy 3.1 |
| Auth | Flask-Login 0.6, Werkzeug 3.1 |
| Forms | Flask-WTF 1.2, WTForms 3.2 |
| Rate Limiting | Flask-Limiter 3.9 |
| Database | SQLite (dev/test), swappable to PostgreSQL |
| Frontend | Bootstrap 5, Jinja2, Vanilla JS |
| Testing | Pytest 8.3, pytest-flask 1.3 |
| Security Scanning | Bandit 1.8, pip-audit 2.9 |

---

## Project Structure

```
capstone secure-coding/
├── app/
│   ├── __init__.py          # App factory, extensions, blueprints
│   ├── models.py            # SQLAlchemy models
│   ├── auth.py              # Login / register / logout routes
│   ├── routes/
│   │   ├── student.py       # Student-facing routes
│   │   ├── coordinator.py   # Coordinator routes
│   │   └── admin.py         # Admin + security lab routes
│   ├── security/
│   │   ├── middleware.py    # Security headers, request logging
│   │   └── tests.py         # SecurityTestRunner (10 tests)
│   ├── templates/           # Jinja2 HTML templates
│   └── static/              # CSS & JS assets
├── tests/
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_student.py
│   ├── test_coordinator.py
│   ├── test_admin.py
│   └── test_security.py
├── config.py                # Dev / Test / Prod config classes
├── run.py                   # Entry point
├── seed.py                  # DB seed script
├── requirements.txt
├── .env.example
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Quick Start (Local)

### Prerequisites

- Python 3.11+
- pip

### Steps

```bash
# 1. Clone / navigate to the project
cd "capstone secure-coding"

# 2. Create and activate a virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables
copy .env.example .env
# Edit .env — set SECRET_KEY to a long random string

# 5. Seed the database with demo data
python seed.py

# 6. Start the development server
python run.py
```

Open **http://localhost:5000** in your browser.

---

## Quick Start (Docker)

```bash
# 1. Copy and configure environment
copy .env.example .env
# Edit .env — set SECRET_KEY

# 2. Build and start
docker compose up --build

# 3. Open the app
# http://localhost:5000
```

> **Tip:** The Docker entrypoint automatically runs `seed.py` before starting the server, so demo data is always available.

To stop:

```bash
docker compose down
```

To stop and wipe the SQLite volume:

```bash
docker compose down -v
```

---

## Demo Credentials

| Role | Email | Password | Notes |
|------|-------|----------|-------|
| **Admin** | admin@college.edu | `Admin@123` | Full access + Security Lab |
| **Coordinator 1** | coord1@college.edu | `Coord@123` | Manages Tech Club, Robotics Club |
| **Coordinator 2** | coord2@college.edu | `Coord@123` | Manages Art Club |
| **Student 1** | alice@college.edu | `Student@123` | Has existing applications |
| **Student 2** | bob@college.edu | `Student@123` | No applications yet |
| **Student 3** | carol@college.edu | `Student@123` | No applications yet |

> **Password policy:** Minimum 8 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character.

---

## User Roles

### Student
- Register and log in
- Browse clubs (search by name / filter by category)
- Apply to clubs (subject to `max_members` capacity)
- View and withdraw pending applications
- Personal dashboard with application stats

### Coordinator
- View dashboard scoped to assigned clubs
- Approve or reject pending applications
- View current club members
- Cannot access or modify clubs not assigned to them

### Admin
- Full user management (activate / deactivate accounts)
- Full club management (create, edit, assign coordinators)
- View complete activity logs
- Access the **Security Testing Lab**
- Download security test reports (HTML / JSON)

---

## Security Features

| Feature | Implementation |
|---------|---------------|
| Password hashing | `werkzeug.security.generate_password_hash` (pbkdf2:sha256) |
| RBAC | `@login_required` + custom `@role_required` decorators |
| SQL injection prevention | SQLAlchemy ORM — parameterized queries only |
| XSS prevention | Jinja2 autoescaping on all templates |
| CSRF protection | Flask-WTF tokens on every form; `X-CSRFToken` header for AJAX |
| IDOR prevention | Object-level ownership checks before every read/write |
| Rate limiting | Flask-Limiter — 5 login attempts / minute; custom per-route limits |
| Account lockout | 5 failed attempts → 15-minute lockout (configurable) |
| Secure session cookies | `HttpOnly=True`, `SameSite=Lax` (Strict in production), `Secure=True` in production |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Activity logging | Every auth event and sensitive mutation logged to `ActivityLog` |
| Sensitive data protection | Passwords never logged or included in API responses |

---

## Security Testing Dashboard

Navigate to **Admin → Security Lab** (requires admin login).

### Available Tests

| # | Test | Severity |
|---|------|----------|
| 1 | SQL Injection | 🔴 Critical |
| 2 | Cross-Site Scripting (XSS) | 🔴 Critical |
| 3 | CSRF Protection | 🟠 High |
| 4 | Brute-Force / Rate Limiting | 🟠 High |
| 5 | IDOR (Insecure Direct Object Reference) | 🟠 High |
| 6 | Privilege Escalation | 🟠 High |
| 7 | Password Storage (Hash Check) | 🔴 Critical |
| 8 | Session Cookie Security | 🟡 Medium |
| 9 | Security Headers | 🟡 Medium |
| 10 | Account Lockout | 🟠 High |

Each test card shows:
- **Description** and **Prevention** advice
- **Expected vs Actual** result
- **Execution time**
- **Vulnerable code snippet** vs **Secure code snippet** (side by side)
- **Request / Response details** (collapsible)
- **Before / After remediation** comparison

### Running Tests

- Click **Run All Tests** to execute all 10 tests sequentially.
- Click individual **Run** buttons to execute a single test.
- Tests run against an **isolated in-memory SQLite database** — the production data is never touched.
- Use the **Download Report** button to export results as HTML or JSON.

---

## Running Tests

```bash
# Activate virtual environment first
pip install -r requirements.txt

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_security.py -v

# Run with coverage (if coverage installed)
pytest --cov=app tests/
```

Expected output: all tests pass in roughly 10–30 seconds.

---

## Security Scanning

### Static Analysis (Bandit)

```bash
bandit -r app/ -ll
```

Bandit scans the application source for common security anti-patterns (hardcoded secrets, `eval`, `subprocess` with shell=True, etc.).

### Dependency Vulnerability Audit (pip-audit)

```bash
pip-audit
```

pip-audit checks all installed packages against the PyPI Advisory Database and reports known CVEs.

> **Goal:** both commands should produce zero findings on a clean install.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | *(must set)* | Flask session signing key — use `secrets.token_hex(32)` |
| `FLASK_ENV` | `development` | `development` / `testing` / `production` |
| `FLASK_HOST` | `0.0.0.0` | Bind address for `run.py` |
| `FLASK_PORT` | `5000` | Port for `run.py` |
| `DATABASE_URL` | SQLite in `instance/` | Full SQLAlchemy DB URI |
| `REDIS_URL` | `memory://` | Redis URI for Flask-Limiter (optional) |

Copy `.env.example` to `.env` and fill in values before running.

---

## Configuration Classes

| Class | File | Purpose |
|-------|------|---------|
| `BaseConfig` | `config.py` | Shared defaults |
| `DevelopmentConfig` | `config.py` | Local dev (debug on, relaxed limits) |
| `TestingConfig` | `config.py` | Pytest (in-memory DB, CSRF off, rate limit off) |
| `ProductionConfig` | `config.py` | Production (secure cookies, strict limits) |

Select config via `FLASK_ENV` environment variable or pass explicitly to `create_app(env)`.

---

## License

This project is created for educational purposes as a secure-coding capstone. All demo credentials are intentionally public — **do not use in a real production environment without changing all secrets and credentials.**
