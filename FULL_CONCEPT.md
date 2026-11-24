# College Club Membership Portal &mdash; Complete Concept & Architecture Guide

> **Project Type:** Secure Coding & Vulnerability Assessment Capstone Project  
> **Tech Stack:** Python 3.11+, Flask 3.1, SQLite, SQLAlchemy 2.0, Jinja2, Bootstrap 5  
> **Target Audience:** Development team members, project evaluators, and security auditors  

---

## Table of Contents

1. [Executive Summary & Purpose](#1-executive-summary--purpose)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Project Directory Structure](#3-project-directory-structure)
4. [Database Models & Entity Relationships](#4-database-models--entity-relationships)
5. [Role-Based Access Control (RBAC) & User Workflows](#5-role-based-access-control-rbac--user-workflows)
   - [5.1 Student Workflow](#51-student-workflow)
   - [5.2 Coordinator Workflow](#52-coordinator-workflow)
   - [5.3 Admin Workflow](#53-admin-workflow)
6. [Defense-in-Depth: The 10 Walls of Security](#6-defense-in-depth-the-10-walls-of-security)
   - [Wall 1: SQL Injection (SQLi) Defense](#wall-1-sql-injection-sqli-defense)
   - [Wall 2: Cross-Site Scripting (XSS) Defense](#wall-2-cross-site-scripting-xss-defense)
   - [Wall 3: Cross-Site Request Forgery (CSRF) Defense](#wall-3-cross-site-request-forgery-csrf-defense)
   - [Wall 4: Broken Object Level Authorization (IDOR) Defense](#wall-4-broken-object-level-authorization-idor-defense)
   - [Wall 5: Privilege Escalation & Role Boundaries](#wall-5-privilege-escalation--role-boundaries)
   - [Wall 6: Password Hashing & NIST Policy Enforcement](#wall-6-password-hashing--nist-policy-enforcement)
   - [Wall 7: Brute-Force Rate Limiting](#wall-7-brute-force-rate-limiting)
   - [Wall 8: Account Lockout Mechanism](#wall-8-account-lockout-mechanism)
   - [Wall 9: Secure Session Cookie Architecture](#wall-9-secure-session-cookie-architecture)
   - [Wall 10: Defensive HTTP Security Headers](#wall-10-defensive-http-security-headers)
7. [Security Testing Dashboard & Live Attack Arena](#7-security-testing-dashboard--live-attack-arena)
   - [7.1 Automated 10-Test Suite](#71-automated-10-test-suite)
   - [7.2 Live Attack Simulation Arena](#72-live-attack-simulation-arena)
   - [7.3 Exportable Audit Reports](#73-exportable-audit-reports)
8. [Automated Test Suite (Pytest)](#8-automated-test-suite-pytest)
9. [How to Run, Seed, and Demo](#9-how-to-run-seed-and-demo)

---

## 1. Executive Summary & Purpose

The **College Club Membership Portal** is a secure web application designed to demonstrate the practical application of **Secure Software Development Life Cycle (SSDLC)** and **OWASP Top 10** defensive controls.

While conventional web applications often treat security as an afterthought or patch vulnerabilities after deployment, this project embeds security directly into each architectural layer:
- **Presentation Layer (Jinja2 / Bootstrap):** Context-aware escaping, anti-CSRF token embedding, safe DOM manipulation.
- **Application Layer (Flask Blueprints & Decorators):** Strict RBAC guards, input sanitization, object-level ownership scoping, rate limiting.
- **Persistence Layer (SQLAlchemy ORM):** Parameterized queries with strongly typed models, avoiding raw SQL concatenation.
- **Audit Layer (ActivityLog):** Comprehensive logging of authentication events, authorization attempts, and administrative mutations.
- **Verification Layer (Security Lab):** An integrated testing engine demonstrating that all 10 vulnerability domains are defended with live proof.

---

## 2. High-Level Architecture

The portal follows the **Application Factory Pattern** (`create_app`) with modular Blueprints:

```
                      +-----------------------------+
                      |   Client (Browser / Curl)   |
                      +--------------+--------------+
                                     |
                                     v [HTTP / HTTPS]
             +-----------------------------------------------+
             |      Security Middleware (Headers & Logs)     |
             |  - Injects CSP, HSTS, X-Frame-Options: DENY   |
             |  - Scans for Suspicious Input Patterns        |
             |  - Flask-Limiter (Rate Limiting)              |
             |  - Flask-WTF (CSRF Token Verification)        |
             +-----------------------+-----------------------+
                                     |
                                     v
             +-----------------------------------------------+
             |               Routing & Blueprints            |
             |  /auth        -> auth_bp        (Login/Reg)   |
             |  /student     -> student_bp     (Browse/Apply)|
             |  /coordinator -> coordinator_bp (Review/Apps) |
             |  /admin       -> admin_bp       (Manage/Lab)  |
             +-----------------------+-----------------------+
                                     |
                                     v
             +-----------------------------------------------+
             |         RBAC & Ownership Guard Layer          |
             |  @login_required                              |
             |  @student_required / @coordinator_required    |
             |  @admin_required / Ownership Scoping Checks   |
             +-----------------------+-----------------------+
                                     |
                                     v
             +-----------------------------------------------+
             |         SQLAlchemy ORM (Data Layer)           |
             |  - Parameterized Queries (No Raw Concatenation)|
             |  - User, Club, Application, ActivityLog       |
             +-----------------------+-----------------------+
                                     |
                                     v
             +-----------------------------------------------+
             |               SQLite Database                 |
             |           (instance/dev.db or in-memory)      |
             +-----------------------------------------------+
```

---

## 3. Project Directory Structure

```
capstone secure-coding/
├── app/
│   ├── __init__.py          # App factory, extensions (db, login_manager, csrf, limiter), blueprints
│   ├── auth.py              # Authentication routes (login, register, logout, lockout logic)
│   ├── models.py            # Database schema models and helper methods
│   ├── routes/
│   │   ├── student.py       # Student dashboard, club browsing, application submission & withdrawal
│   │   ├── coordinator.py   # Coordinator dashboard, club management, approve/reject workflow
│   │   └── admin.py         # Admin dashboard, user management, club management, Security Lab API
│   ├── security/
│   │   ├── middleware.py    # Request logging, suspicious input detector, security response headers
│   │   └── tests.py         # SecurityTestRunner: 10 automated vulnerability assessment tests
│   ├── static/
│   │   ├── css/main.css     # Responsive UI styling, badge colors, stat cards
│   │   └── js/main.js       # Client-side validation, sidebar toggle, confirmation prompts
│   └── templates/           # Jinja2 HTML templates
│       ├── base.html        # Master layout (sidebar, topbar, CSRF meta tag, alerts)
│       ├── auth/            # login.html, register.html
│       ├── student/         # dashboard.html, clubs.html, club_detail.html, applications.html
│       ├── coordinator/     # dashboard.html, manage_club.html, member_list.html
│       ├── admin/           # dashboard.html, users.html, clubs.html, club_form.html,
│       │                    # activity_logs.html, security_lab.html, security_report_export.html
│       └── errors/          # 403.html, 404.html, 500.html
├── tests/
│   ├── conftest.py          # Pytest fixtures (in-memory SQLite, StaticPool, client, seed data)
│   ├── test_auth.py         # 22 tests: registration, password strength, login, lockout
│   ├── test_student.py      # 23 tests: dashboard, browsing, apply, withdraw, IDOR prevention
│   ├── test_coordinator.py  # 9 tests: assigned clubs, approve/reject, capacity enforcement
│   ├── test_admin.py        # 10 tests: user management, role toggle, club creation, audit logs
│   └── test_security.py     # 15 tests: all 10 security tests, simulation API, report exports
├── config.py                # Environment configs (DevelopmentConfig, TestingConfig, ProductionConfig)
├── run.py                   # Development entrypoint
├── seed.py                  # Database seeder with demo accounts across all 3 roles
├── requirements.txt         # Pinned production dependencies
├── .env.example             # Template for environment secrets
├── .gitignore               # Ignores .env, SQLite databases, caches, virtual environments
├── Dockerfile               # Multi-stage production Docker container
├── docker-compose.yml       # Container orchestration with volume persistence
└── README.md                # Quickstart documentation
```

---

## 4. Database Models & Entity Relationships

The data model is implemented in [app/models.py](file:///c:/Users/Harsh/Desktop/capstone%20secure-coding/app/models.py) using SQLAlchemy 2.0:

### 1. `User` Model
- `id` (Integer, Primary Key)
- `username` (String(64), Unique, Indexed)
- `email` (String(120), Unique, Indexed)
- `password_hash` (String(256), Salted PBKDF2:SHA256 digest)
- `role` (String(20): `'student'`, `'coordinator'`, or `'admin'`)
- `is_active` (Boolean: Deactivated accounts are blocked at login)
- `failed_login_attempts` (Integer: Tracks consecutive authentication failures)
- `locked_until` (DateTime: Lockout timestamp set after 5 failures)
- `created_at` (DateTime with UTC timezone)

### 2. `Club` Model
- `id` (Integer, Primary Key)
- `name` (String(100), Unique)
- `description` (Text)
- `category` (String(50))
- `max_members` (Integer: Maximum approved capacity)
- `coordinator_id` (ForeignKey &rarr; `users.id`)
- `is_active` (Boolean: Soft deletion/deactivation)

### 3. `Application` Model
- `id` (Integer, Primary Key)
- `user_id` (ForeignKey &rarr; `users.id`)
- `club_id` (ForeignKey &rarr; `clubs.id`)
- `status` (String(20): `'pending'`, `'approved'`, `'rejected'`, or `'withdrawn'`)
- `applied_at` (DateTime UTC)
- `reviewed_at` (DateTime UTC)
- `reviewed_by` (ForeignKey &rarr; `users.id`)
- `notes` (Text: Feedback from coordinator/admin)
- **Constraint:** Unique constraint on `(user_id, club_id)` &mdash; prevents duplicate applications.

### 4. `ActivityLog` Model (Audit Trail)
- `id` (Integer, Primary Key)
- `user_id` (ForeignKey &rarr; `users.id`, Nullable for unauthenticated events)
- `action` (String(100): e.g., `'login_failed'`, `'apply_club'`, `'privilege_escalation_attempt'`)
- `details` (Text: Event context)
- `ip_address` (String(45): IPv4 or IPv6 client address)
- `timestamp` (DateTime UTC, Indexed)

### 5. `SecurityTestResult` Model
- `id` (Integer, Primary Key)
- `test_name` (String(100))
- `status` (String(20): `'passed'`, `'failed'`, or `'error'`)
- `details` (JSON Text: Full diagnostic payload)
- `run_at` (DateTime UTC)

---

## 5. Role-Based Access Control (RBAC) & User Workflows

```
       [Unauthenticated User]
                 |
      +----------+----------+
      |                     |
      v                     v
   Register               Login
 (Role: student)            |
                            v
                 Role Inspection at Login
                            |
         +------------------+------------------+
         |                  |                  |
         v                  v                  v
     [Student]        [Coordinator]         [Admin]
   /student/*         /coordinator/*        /admin/*
```

### 5.1 Student Workflow
- **Registration:** Automatically assigned `role = 'student'`. Cannot register as coordinator or admin.
- **Explore Clubs:** Search clubs by name or filter by category (`Technology`, `Arts`, `Engineering`, etc.).
- **Apply to Club:**
  - Server verifies club exists and is active.
  - Server verifies student does not already have an active application.
  - Server checks `approved_member_count < club.max_members` before accepting.
- **Manage Applications:** View application statuses (`pending`, `approved`, `rejected`).
- **Withdraw Application:** Cancel a pending application.

### 5.2 Coordinator Workflow
- **Assigned Clubs Only:** Coordinators only see and manage clubs where `club.coordinator_id == current_user.id`.
- **Review Queue:** Review pending student applications with student profile and submission timestamp.
- **Approve / Reject:**
  - Approving validates that the club has not reached capacity limit.
  - Updates application status, sets `reviewed_by = current_user.id`, and records timestamp.
  - Logs action to `ActivityLog`.
- **Member Roster:** View all approved active members in assigned clubs.

### 5.3 Admin Workflow
- **User Management:**
  - View all registered users with search, role filters, and status filters.
  - Activate or deactivate accounts (cannot deactivate self).
  - Promote or change user roles (`student` &harr; `coordinator` &harr; `admin`).
- **Club Management:**
  - Create new clubs, set descriptions, categories, and member caps.
  - Assign or reassign faculty/student coordinators.
  - Toggle club active status.
- **Audit Logs:** Filterable, paginated viewer for all system actions with IP tracking.
- **Security Laboratory:** Run automated vulnerability scans, test live payloads, and export audit reports.

---

## 6. Defense-in-Depth: The 10 Walls of Security

```
                                  INCOMING REQUEST
                                         |
     [Wall 10] Security Headers Middleware (CSP, X-Frame-Options, HSTS)
                                         |
     [Wall 7]  Rate Limiter (5 requests / min on auth endpoints)
                                         |
     [Wall 8]  Account Lockout (Locks user after 5 consecutive failures)
                                         |
     [Wall 3]  CSRF Token Verification (Flask-WTF on all POST requests)
                                         |
     [Wall 5]  RBAC Decorator Layer (@roles_required, @admin_required)
                                         |
     [Wall 4]  Object-Level Ownership Check (Tenant Partitioning / IDOR)
                                         |
     [Wall 1]  Parameterized Query Engine (SQLAlchemy ORM - Anti-SQLi)
                                         |
     [Wall 6]  Salted Password Hashing (PBKDF2:SHA256 - 600,000 rounds)
                                         |
     [Wall 9]  Secure Session Flags (HttpOnly=True, SameSite=Lax)
                                         |
     [Wall 2]  Context-Aware Template Auto-Escaping (Jinja2 - Anti-XSS)
                                         |
                                 SECURE RESPONSE
```

---

### Wall 1: SQL Injection (SQLi) Defense
- **The Threat:** Attackers input SQL control characters (`'`, `--`, `OR 1=1`) to manipulate queries, bypass logins, or dump databases.
- **Vulnerable Code (Anti-Pattern):**
  ```python
  query = f"SELECT * FROM users WHERE email = '{email}'"
  cursor.execute(query)
  ```
- **Portal Implementation (Secure):**
  All database access is handled strictly through SQLAlchemy ORM parameter binding:
  ```python
  user = User.query.filter_by(email=email).first()
  ```
  The database engine treats the input strictly as a literal data parameter, never as executable SQL syntax.

---

### Wall 2: Cross-Site Scripting (XSS) Defense
- **The Threat:** Attackers inject `<script>` tags or malicious event handlers (`<img onerror=...>`) into inputs, executing arbitrary JavaScript in victim browsers to steal tokens or deface sites.
- **Vulnerable Code (Anti-Pattern):**
  ```html
  <div>{{ user_input | safe }}</div>
  ```
- **Portal Implementation (Secure):**
  Jinja2 context-aware auto-escaping is active globally. Untrusted inputs are automatically converted into HTML entities:
  - `<` becomes `&lt;`
  - `>` becomes `&gt;`
  - `"` becomes `&quot;`
  - `'` becomes `&#39;`

---

### Wall 3: Cross-Site Request Forgery (CSRF) Defense
- **The Threat:** A malicious third-party site tricks an authenticated user's browser into submitting unauthorized POST requests (e.g., transferring funds or deleting accounts).
- **Vulnerable Code (Anti-Pattern):**
  ```python
  @app.route("/withdraw", methods=["POST"])
  def withdraw():
      # Accepts POST request without verifying caller origin
  ```
- **Portal Implementation (Secure):**
  - Flask-WTF `CSRFProtect` is initialized globally.
  - Every form includes a hidden `{{ csrf_token() }}` input.
  - AJAX endpoints validate the `X-CSRFToken` request header.
  - Any mutating request lacking a valid cryptographic token is rejected immediately with **HTTP 400 Bad Request**.

---

### Wall 4: Broken Object Level Authorization (IDOR) Defense
- **The Threat:** A user changes an ID parameter in the URL (e.g., `POST /student/applications/5/withdraw`) to view, modify, or delete another student's application.
- **Vulnerable Code (Anti-Pattern):**
  ```python
  app_record = Application.query.get(application_id)
  app_record.status = "withdrawn"  # No ownership verification!
  ```
- **Portal Implementation (Secure):**
  Every single student resource mutation explicitly verifies ownership against `current_user.id`:
  ```python
  application = Application.query.get_or_404(application_id)
  if application.user_id != current_user.id:
      _log("idor_attempt", f"User {current_user.id} tried to touch app #{application_id}")
      abort(403)
  ```

---

### Wall 5: Privilege Escalation & Role Boundaries
- **The Threat:** A standard student attempts to directly browse administrative or coordinator endpoints (e.g., `/admin/users` or `/coordinator/dashboard`).
- **Vulnerable Code (Anti-Pattern):**
  ```python
  @app.route("/admin/dashboard")
  @login_required
  def admin_dashboard():
      # Only checks if logged in, doesn't verify role!
  ```
- **Portal Implementation (Secure):**
  Custom decorators enforce role verification at the view entry:
  ```python
  def admin_required(f):
      @wraps(f)
      def decorated_function(*args, **kwargs):
          if not current_user.is_authenticated:
              return redirect(url_for("auth.login"))
          if current_user.role != "admin":
              _log("privilege_escalation_attempt", f"Path: {request.path}")
              abort(403)
          return f(*args, **kwargs)
      return decorated_function
  ```

---

### Wall 6: Password Hashing & NIST Policy Enforcement
- **The Threat:** Weak passwords susceptible to dictionary attacks; database breaches exposing plaintext or weakly hashed passwords (MD5/SHA1).
- **Vulnerable Code (Anti-Pattern):**
  ```python
  user.password = raw_password  # Plaintext!
  ```
- **Portal Implementation (Secure):**
  - **Server-Side NIST SP 800-63B Policy:** Minimum 8 characters, with required uppercase letter, lowercase letter, digit, and special character.
  - **Cryptographic Hashing:** Salted `pbkdf2:sha256` with 16-byte random salt and 600,000 iterations via `werkzeug.security`.
  - Passwords are never logged, echoed in templates, or returned via APIs.

---

### Wall 7: Brute-Force Rate Limiting
- **The Threat:** Automated credential stuffing tools attempting thousands of password guesses per second against `/auth/login`.
- **Portal Implementation (Secure):**
  Flask-Limiter is attached to the authentication route:
  ```python
  @auth_bp.route("/login", methods=["GET", "POST"])
  @limiter.limit("5 per minute", error_message="Too many login attempts. Please wait a minute and try again.")
  def login():
  ```
  Exceeding the limit results in **HTTP 429 Too Many Requests**.

---

### Wall 8: Account Lockout Mechanism
- **The Threat:** Distributed brute-force attacks rotating IP addresses to evade IP-based rate limiting.
- **Portal Implementation (Secure):**
  - The `User` database model maintains `failed_login_attempts` and `locked_until`.
  - Every failed login increments the counter.
  - Upon the **5th consecutive failed attempt**, the account is locked for **15 minutes**:
    ```python
    def increment_failed_attempts(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
    ```
  - A successful login resets the counter to 0.

---

### Wall 9: Secure Session Cookie Architecture
- **The Threat:** Session hijacking via XSS (stealing cookies via `document.cookie`) or session fixation attacks.
- **Portal Implementation (Secure):**
  Configured in [config.py](file:///c:/Users/Harsh/Desktop/capstone%20secure-coding/config.py):
  - `SESSION_COOKIE_HTTPONLY = True`: Disallows JavaScript access to the session cookie.
  - `SESSION_COOKIE_SAMESITE = 'Lax'`: Prevents cross-site cookie transmission.
  - `SESSION_COOKIE_SECURE = True` in Production: Restricts transmission to HTTPS only.
  - `session.clear()` and `logout_user()` on logout: Destroys server-side and client-side session state.

---

### Wall 10: Defensive HTTP Security Headers
- **The Threat:** Clickjacking (embedding site in an `<iframe>`), MIME-type sniffing, unauthorized cross-origin requests.
- **Portal Implementation (Secure):**
  Injected on every HTTP response via `_attach_security_headers` in [app/\_\_init\_\_.py](file:///c:/Users/Harsh/Desktop/capstone%20secure-coding/app/__init__.py):
  - `Content-Security-Policy`: Restricts scripts, styles, and iframe framing (`frame-ancestors 'none'`).
  - `X-Frame-Options: DENY`: Blocks framing across all browsers to prevent clickjacking.
  - `X-Content-Type-Options: nosniff`: Prevents browsers from MIME-sniffing away from declared content-type.
  - `Strict-Transport-Security (HSTS)`: Enforces HTTPS communication for 1 year.
  - `Referrer-Policy: strict-origin-when-cross-origin`: Prevents sensitive URL path leakage.
  - `Cache-Control: no-store, no-cache`: Prevents sensitive authenticated page caching.

---

## 7. Security Testing Dashboard & Live Attack Arena

Located at **Admin &rarr; Security Lab** (`http://localhost:5000/admin/security-lab`).

### 7.1 Automated 10-Test Suite
Executes real automated penetration tests against the portal and displays structured test cards:
1. **SQL Injection Protection** (Critical)
2. **Cross-Site Scripting (XSS) Prevention** (Critical)
3. **Cross-Site Request Forgery (CSRF) Protection** (High)
4. **Brute-Force Protection & Rate Limiting** (High)
5. **IDOR (Object-Level Access Control)** (High)
6. **Privilege Escalation & RBAC Enforcement** (High)
7. **Password Storage & Cryptographic Hashing** (Critical)
8. **Session Cookie Security Flags** (Medium)
9. **HTTP Security Headers** (Medium)
10. **Account Lockout on Consecutive Failures** (High)

Each card features:
- Live **PASS / FAIL** badge and execution time in milliseconds.
- Side-by-side **Vulnerable Anti-Pattern vs. Secure Remediation** code comparison.
- Collapsible **Request Payload & Server Response Details**.
- Defense mechanism explanation and remediation advice.

### 7.2 Live Attack Simulation Arena
Allows team members and evaluators to test custom attack payloads interactively:
- **Input Field:** Type any attack string.
- **Preset Buttons:** Quick-fill common attack vectors:
  - `' OR '1'='1` (SQLi login bypass)
  - `admin' --` (SQLi comment truncation)
  - `' UNION SELECT ...` (SQLi data leakage)
  - `<script>alert('XSS_POC')</script>` (XSS script injection)
  - `<img src=x onerror=alert(document.cookie)>` (XSS cookie theft attempt)
  - `1` (IDOR unauthorized object access)
  - `password123` (Weak password dictionary probe)
  - `../../instance/dev.db` (Path traversal probe)
- **Live Response Console:** Real-time feedback displaying:
  - Verdict (`DEFENDED / NEUTRALIZED` or `BLOCKED`)
  - Engaged defense layer
  - HTTP status code returned
  - Sanitized output preview
  - Audit log entry generated

### 7.3 Exportable Audit Reports
- **Download HTML Report:** Standalone audit report for submissions.
- **Download JSON Data:** Structured JSON test output for automated CI/CD integration.

---

## 8. Automated Test Suite (Pytest)

The project includes **79 automated tests** covering 100% of the core features and security controls:

| Test File | Test Count | Scope |
|---|---|---|
| `tests/test_auth.py` | 22 | Registration, password policy, login, logout, account lockout |
| `tests/test_student.py` | 23 | Dashboard, club discovery, application submit/withdraw, IDOR protection |
| `tests/test_coordinator.py` | 9 | Coordinator dashboard, club ownership boundaries, approve/reject, capacity |
| `tests/test_admin.py` | 10 | User management, role toggles, club creation, audit logs |
| `tests/test_security.py` | 15 | All 10 security tests, simulation API, report exports |
| **Total** | **79** | **All tests passing** |

To execute the entire test suite:
```powershell
python -m pytest
```

---

## 9. How to Run, Seed, and Demo

### 1. Initial Setup
```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy and set environment secrets
copy .env.example .env
# Optional: generate a 64-character secret key
python -c "import secrets; print(secrets.token_hex(32))"

# 3. Seed database with sample data
python seed.py
```

### 2. Start the Development Server
```powershell
python run.py
```
Open **http://localhost:5000** in your browser.

### 3. Demo Credentials
| Role | Email | Password | Access Highlights |
|---|---|---|---|
| **Admin** | `admin@college.edu` | `Admin@123` | Full control, User/Club management, Security Lab |
| **Coordinator 1** | `coord1@college.edu` | `Coord@123` | Coordinates *Tech Club* and *Robotics Club* |
| **Coordinator 2** | `coord2@college.edu` | `Coord@123` | Coordinates *Art Club* |
| **Student 1** | `alice@college.edu` | `Student@123` | Active member in *Tech Club*, pending in *Art Club* |
| **Student 2** | `bob@college.edu` | `Student@123` | Pending in *Tech Club* |
| **Student 3** | `carol@college.edu` | `Student@123` | Fresh student account |

### 4. Running with Docker
```powershell
docker compose up --build
```
The Docker container automatically runs `seed.py` and starts the application at **http://localhost:5000**.
