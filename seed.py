"""Create the demo accounts and example casework in the configured database.

    python seed.py

The script reads the same configuration as the application (``config.py`` plus
``.env``), so it targets MySQL by default and SQLite when ``DATABASE_URL``
starts with ``sqlite``. It is safe to run more than once: rows are matched by a
natural key and updated instead of duplicated, which also refreshes the
password hashes before a demo.

Besides the accounts it seeds one example application (the platform testing its
own running build, in line with the coursework's ethical-use scope) with the
real findings that were found and fixed while hardening this app. Set
``SEED_DEMO_DATA=0`` to create only the accounts.

Credentials can be overridden with ``SEED_ADMIN_*`` / ``SEED_USER_*`` /
``SEED_CLIENT_*`` environment variables. The defaults are for local
demonstration only.
"""

import os

from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from extensions import db
from models import Application, TestCase, User, Vulnerability

DEFAULT_PASSWORD = "password123"

# One example engagement: the platform testing itself (only 127.0.0.1). The
# findings below are the issues that were actually found and fixed while
# building this project, so the demo report is honest rather than invented.
DEMO_APPLICATION = {
    "name": "WASTP self-test (127.0.0.1)",
    "target_url": "http://127.0.0.1:5000",
    "description": (
        "The platform testing its own running build, per the coursework's "
        "ethical-use scope (only 127.0.0.1 / this deployment)."
    ),
    "tests": [
        {
            "test_name": "Check security response headers on every route",
            "category": "Security Misconfiguration",
            "status": "Passed",
        },
        {
            "test_name": "Attempt repeated wrong logins to test throttling",
            "category": "Broken Authentication",
            "status": "Passed",
        },
        {
            "test_name": "Submit quotes and SQL keywords to the search fields",
            "category": "Injection",
            "status": "Passed",
        },
        {
            "test_name": "Submit script tags to title and description fields",
            "category": "Cross-Site Scripting (XSS)",
            "status": "Passed",
        },
        {
            "test_name": "Inspect the session cookie flags over plain HTTP",
            "category": "Security Misconfiguration",
            "status": "Failed",
        },
    ],
    "vulnerabilities": [
        {
            "title": "No brute-force protection on the login endpoints",
            "severity": "High",
            "cvss_score": 8.1,
            "status": "Fixed",
            "owasp_category": "A07:2021 Identification and Authentication Failures",
            "cwe_id": "CWE-307",
            "description": (
                "The session login and the JWT login accepted an unlimited "
                "number of wrong passwords, so credentials could be guessed at "
                "machine speed."
            ),
            "evidence": (
                "Repeated POST /auth/login (and POST /api/auth/login) with a "
                "wrong password returned 401 every time and was never throttled."
            ),
            "remediation": (
                "Added a shared in-memory sliding-window limiter (rate_limit.py) "
                "used by both login paths. After 5 failures within 5 minutes the "
                "key is locked for 5 minutes and the response is HTTP 429."
            ),
        },
        {
            "title": "Missing Content-Security-Policy and other security headers",
            "severity": "Medium",
            "cvss_score": 5.3,
            "status": "Fixed",
            "owasp_category": "A05:2021 Security Misconfiguration",
            "cwe_id": "CWE-693",
            "description": (
                "Responses carried no CSP, X-Frame-Options, Referrer-Policy or "
                "nosniff header, leaving room for clickjacking and injected scripts."
            ),
            "evidence": "GET / returned no Content-Security-Policy or X-Frame-Options header.",
            "remediation": (
                "Added an after_request hook that sets CSP (script-src 'self'), "
                "X-Frame-Options: DENY, X-Content-Type-Options: nosniff, "
                "Referrer-Policy and Permissions-Policy on every response."
            ),
        },
        {
            "title": "Application accepted the default SECRET_KEY at runtime",
            "severity": "High",
            "cvss_score": 7.5,
            "status": "Fixed",
            "owasp_category": "A05:2021 Security Misconfiguration",
            "cwe_id": "CWE-1188",
            "description": (
                "With the shipped default key, session cookies could be forged "
                "because anyone could read the signing key from the source."
            ),
            "evidence": (
                "config.py shipped SECRET_KEY = 'change-this-in-production' and "
                "the app started with it."
            ),
            "remediation": (
                "Startup now runs configuration_problems(); production refuses to "
                "boot (RuntimeError) when the key is the default or shorter than "
                "32 characters, and development logs a warning."
            ),
        },
        {
            "title": "Rate-limiter counter map could grow without bound",
            "severity": "Medium",
            "cvss_score": 5.3,
            "status": "Fixed",
            "owasp_category": "A04:2021 Insecure Design",
            "cwe_id": "CWE-770",
            "description": (
                "A username/IP spray would add a new key for every attempt, so "
                "the in-memory counter dict could exhaust memory (a denial of "
                "service)."
            ),
            "evidence": (
                "Every distinct identifier created a permanent entry in "
                "rate_limit._attempts with no eviction."
            ),
            "remediation": (
                "The limiter now prunes stale keys once it reaches "
                "MAX_TRACKED_KEYS (10,000), so memory stays bounded under a spray."
            ),
        },
        {
            "title": "State-changing HTML forms had no CSRF protection",
            "severity": "High",
            "cvss_score": 8.8,
            "status": "Fixed",
            "owasp_category": "A01:2021 Broken Access Control",
            "cwe_id": "CWE-352",
            "description": (
                "Without a CSRF token, a third-party page could make a "
                "logged-in user create or delete records."
            ),
            "evidence": "POST forms only required the session cookie; no csrf_token was checked.",
            "remediation": (
                "Enabled Flask-WTF CSRFProtect globally and included csrf_token() "
                "in every POST form; the JSON API is protected by bearer tokens "
                "instead of cookies."
            ),
        },
        {
            "title": "Session cookie Secure flag defaults to off outside production",
            "severity": "Medium",
            "cvss_score": 4.3,
            "status": "Open",
            "owasp_category": "A05:2021 Security Misconfiguration",
            "cwe_id": "CWE-614",
            "description": (
                "In development and testing the session cookie can be sent over "
                "plain HTTP, so it can be captured on a shared network."
            ),
            "evidence": (
                "Config sets SESSION_COOKIE_SECURE = False by default; only "
                "ProductionConfig overrides it to True."
            ),
            "remediation": (
                "Serve over HTTPS and set SESSION_COOKIE_SECURE=true in every "
                "environment that has real users."
            ),
        },
        {
            "title": "HSTS is only sent when the cookie is marked secure",
            "severity": "Low",
            "cvss_score": 3.1,
            "status": "Open",
            "owasp_category": "A05:2021 Security Misconfiguration",
            "cwe_id": "CWE-319",
            "description": (
                "Without Strict-Transport-Security a first request can be "
                "downgraded to HTTP, allowing a man-in-the-middle to hijack the "
                "session."
            ),
            "evidence": (
                "apply_security_headers() adds HSTS only if SESSION_COOKIE_SECURE "
                "is set, so plain-HTTP deployments never learn to upgrade."
            ),
            "remediation": (
                "Deploy behind TLS and enable SESSION_COOKIE_SECURE so HSTS is "
                "emitted on every response."
            ),
        },
    ],
}


def _upsert(username, email, password, role):
    user = User.query.filter_by(username=username).first()
    created = user is None
    if created:
        user = User(username=username, email=email, role=role)
        db.session.add(user)
    user.email = email
    user.role = role
    user.set_password(password)
    return user, created


def _upsert_application(owner, data):
    application = Application.query.filter_by(
        owner_id=owner.id, name=data["name"]
    ).first()
    created = application is None
    if created:
        application = Application(name=data["name"], owner_id=owner.id)
        db.session.add(application)
    application.target_url = data["target_url"]
    application.description = data["description"]
    db.session.flush()
    return application, created


def _upsert_test_case(application, data, assignee):
    test_case = TestCase.query.filter_by(
        app_id=application.id, test_name=data["test_name"]
    ).first()
    if test_case is None:
        test_case = TestCase(app_id=application.id, test_name=data["test_name"])
        db.session.add(test_case)
    test_case.category = data["category"]
    test_case.status = data["status"]
    test_case.assigned_to = assignee.id if assignee else None


def _upsert_vulnerability(application, data):
    vulnerability = Vulnerability.query.filter_by(
        app_id=application.id, title=data["title"]
    ).first()
    if vulnerability is None:
        vulnerability = Vulnerability(app_id=application.id, title=data["title"])
        db.session.add(vulnerability)
    for key in (
        "severity",
        "cvss_score",
        "status",
        "owasp_category",
        "cwe_id",
        "description",
        "evidence",
        "remediation",
    ):
        setattr(vulnerability, key, data.get(key))


def main():
    app = create_app()

    admin_username = os.environ.get("SEED_ADMIN_USERNAME", "admin1")
    admin_email = os.environ.get("SEED_ADMIN_EMAIL", "admin1@example.com")
    admin_password = os.environ.get("SEED_ADMIN_PASSWORD", DEFAULT_PASSWORD)

    user_username = os.environ.get("SEED_USER_USERNAME", "owner1")
    user_email = os.environ.get("SEED_USER_EMAIL", "owner1@example.com")
    user_password = os.environ.get("SEED_USER_PASSWORD", DEFAULT_PASSWORD)

    client_username = os.environ.get("SEED_CLIENT_USERNAME", "client1")
    client_email = os.environ.get("SEED_CLIENT_EMAIL", "client1@example.com")
    client_password = os.environ.get("SEED_CLIENT_PASSWORD", DEFAULT_PASSWORD)

    demo_enabled = os.environ.get("SEED_DEMO_DATA", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }

    with app.app_context():
        try:
            db.create_all()
            admin, admin_created = _upsert(
                admin_username, admin_email, admin_password, "admin"
            )
            user, user_created = _upsert(
                user_username, user_email, user_password, "user"
            )
            client, client_created = _upsert(
                client_username, client_email, client_password, "client"
            )
            # Assign ids before wiring the demo casework to the accounts.
            db.session.flush()

            demo_summary = None
            if demo_enabled:
                application, app_created = _upsert_application(user, DEMO_APPLICATION)
                for test in DEMO_APPLICATION["tests"]:
                    _upsert_test_case(application, test, user)
                for vulnerability in DEMO_APPLICATION["vulnerabilities"]:
                    _upsert_vulnerability(application, vulnerability)
                db.session.flush()
                demo_summary = (
                    application.name,
                    app_created,
                    len(DEMO_APPLICATION["tests"]),
                    len(DEMO_APPLICATION["vulnerabilities"]),
                )

            db.session.commit()
            # Read the values while the session is still open.
            rows = [
                (admin_created, admin.role, admin.username, admin_password),
                (user_created, user.role, user.username, user_password),
                (client_created, client.role, client.username, client_password),
            ]
        except SQLAlchemyError as exc:
            db.session.rollback()
            print(f"Could not seed the database: {exc}")
            print(
                "Check that MySQL is running and that MYSQL_* / DATABASE_URL in "
                ".env are correct, then create the schema with:  mysql -u root -p < schema.sql"
            )
            return 1

    print(f"Database : {app.config['SQLALCHEMY_DATABASE_URI']}")
    for created, role, username, password in rows:
        state = "created" if created else "reset  "
        print(f"  {state}  role={role:<5}  {username:<20}  {password}")
    if demo_summary:
        name, app_created, test_count, vuln_count = demo_summary
        state = "created" if app_created else "updated"
        print(f"\nDemo casework ({state}): {name}")
        print(f"  {test_count} test cases, {vuln_count} findings")
    print("\nThese are demo credentials. Change them before any shared deployment.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
