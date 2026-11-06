"""Security hardening: response headers, secret validation and cookie flags."""

import pytest
from flask import Flask

from app import create_app
from config import (
    DEFAULT_SECRET_KEY,
    MIN_SECRET_KEY_LENGTH,
    ProductionConfig,
    configuration_problems,
)


def test_html_responses_carry_defense_in_depth_headers(client):
    response = client.get("/auth/login")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_content_security_policy_blocks_inline_scripts(client):
    policy = client.get("/auth/login").headers["Content-Security-Policy"]

    assert "default-src 'self'" in policy
    assert "script-src 'self' https://cdn.jsdelivr.net" in policy
    assert "object-src 'none'" in policy


def test_hsts_is_only_sent_when_cookies_are_secure(client, app):
    # The testing config does not mark cookies as secure, so no HSTS header.
    assert "Strict-Transport-Security" not in client.get("/auth/login").headers

    app.config["SESSION_COOKIE_SECURE"] = True

    assert "Strict-Transport-Security" in client.get("/auth/login").headers


def test_session_cookies_have_browser_protection_flags(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_configuration_problems_flags_the_default_secret():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = DEFAULT_SECRET_KEY
    app.config["JWT_SECRET_KEY"] = "a" * MIN_SECRET_KEY_LENGTH

    problems = configuration_problems(app)

    assert any("SECRET_KEY" in problem for problem in problems)


def test_configuration_problems_flags_a_short_secret():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "too-short"
    app.config["JWT_SECRET_KEY"] = "a" * MIN_SECRET_KEY_LENGTH

    assert configuration_problems(app)


def test_configuration_problems_accepts_strong_secrets():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "a" * MIN_SECRET_KEY_LENGTH
    app.config["JWT_SECRET_KEY"] = "b" * MIN_SECRET_KEY_LENGTH

    assert configuration_problems(app) == []


def test_production_refuses_to_start_with_default_secrets(monkeypatch):
    monkeypatch.setattr(ProductionConfig, "SECRET_KEY", DEFAULT_SECRET_KEY, raising=False)
    monkeypatch.setattr(
        ProductionConfig, "JWT_SECRET_KEY", DEFAULT_SECRET_KEY, raising=False
    )

    with pytest.raises(RuntimeError):
        create_app("production")
