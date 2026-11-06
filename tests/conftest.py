"""Shared pytest fixtures.

Every test runs against a throwaway in-memory SQLite database (``TestingConfig``
sets ``TEST_DATABASE_URI``), so the suite never touches the MySQL data or the
demo database.
"""

import pytest

import rate_limit
from app import create_app
from extensions import db as _db
from models import Application, TestCase, User, Vulnerability

PASSWORD = "password123"


@pytest.fixture(autouse=True)
def clear_rate_limit():
    """Login counters live in memory, so reset them around every test."""
    rate_limit._attempts.clear()
    yield
    rate_limit._attempts.clear()


@pytest.fixture()
def app():
    application = create_app("testing")
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def db(app):
    return _db


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def make_user(db):
    def _make(username, password=PASSWORD, role="user", email=None):
        user = User(
            username=username,
            email=email or f"{username}@example.com",
            role=role,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    return _make


@pytest.fixture()
def make_application(db):
    def _make(owner, name="Demo app", target_url="http://127.0.0.1:5000"):
        application = Application(
            name=name,
            target_url=target_url,
            owner_id=owner.id,
        )
        db.session.add(application)
        db.session.commit()
        return application

    return _make


@pytest.fixture()
def make_test_case(db):
    def _make(application, assigned_to=None, status="Pending"):
        test_case = TestCase(
            app_id=application.id,
            test_name="Reflected XSS on the search field",
            category="Cross-Site Scripting (XSS)",
            status=status,
            assigned_to=assigned_to.id if assigned_to else None,
        )
        db.session.add(test_case)
        db.session.commit()
        return test_case

    return _make


@pytest.fixture()
def make_vulnerability(db):
    def _make(application, severity="High", cvss_score=7.5, status="Open"):
        vulnerability = Vulnerability(
            app_id=application.id,
            title="Missing security headers",
            severity=severity,
            cvss_score=cvss_score,
            status=status,
        )
        db.session.add(vulnerability)
        db.session.commit()
        return vulnerability

    return _make


@pytest.fixture()
def login(client):
    """Sign in through the HTML form (CSRF is disabled in the testing config)."""

    def _login(identifier, password=PASSWORD):
        return client.post(
            "/auth/login",
            data={"identifier": identifier, "password": password},
            follow_redirects=True,
        )

    return _login


@pytest.fixture()
def api_token(client):
    """Return a JWT access token for the named account."""

    def _token(identifier, password=PASSWORD):
        response = client.post(
            "/api/auth/login",
            json={"username": identifier, "password": password},
        )
        assert response.status_code == 200, response.get_json()
        return response.get_json()["access_token"]

    return _token


@pytest.fixture()
def api_headers(api_token):
    def _headers(identifier, password=PASSWORD):
        return {"Authorization": f"Bearer {api_token(identifier, password)}"}

    return _headers
