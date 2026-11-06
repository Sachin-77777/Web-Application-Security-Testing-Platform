"""Registration, session login, logout and the login brute-force guard."""

import rate_limit
from models import User

REGISTER = "/auth/register"
LOGIN = "/auth/login"

# Meets the signup policy: 8+ chars, an uppercase letter, a number, a symbol.
STRONG_PASSWORD = "Str0ng-Pass!"


def _register(client, **overrides):
    data = {
        "username": "newuser",
        "email": "newuser@example.com",
        "password": STRONG_PASSWORD,
        "confirm_password": STRONG_PASSWORD,
    }
    data.update(overrides)
    return client.post(REGISTER, data=data, follow_redirects=True)


def test_registration_creates_an_account_with_the_client_role(client, db):
    response = _register(client)

    assert response.status_code == 200
    user = User.query.filter_by(username="newuser").first()
    assert user is not None
    assert user.role == "client"


def test_registration_ignores_a_role_forced_through_the_form(client, db):
    """A visitor must never be able to promote themselves at signup."""
    _register(client, role="admin")

    user = User.query.filter_by(username="newuser").first()
    assert user is not None
    assert user.role == "client"


def test_an_account_created_without_a_role_defaults_to_client(db):
    """The model default is the safest role, so no code path hands out more."""
    user = User(username="norole", email="norole@example.com")
    user.set_password("password123")
    db.session.add(user)
    db.session.commit()

    assert db.session.get(User, user.id).role == "client"


def test_registration_stores_a_hash_not_the_password(client, db):
    _register(client)

    user = User.query.filter_by(username="newuser").first()
    assert user.password_hash != STRONG_PASSWORD
    assert user.check_password(STRONG_PASSWORD)
    assert STRONG_PASSWORD not in user.password_hash


def test_registration_rejects_a_short_password(client, db):
    response = _register(client, password="short", confirm_password="short")

    assert b"at least 8 characters" in response.data
    assert User.query.filter_by(username="newuser").first() is None


def test_registration_requires_an_uppercase_letter(client, db):
    weak = "lowercase1!"

    response = _register(client, password=weak, confirm_password=weak)

    assert b"at least one uppercase letter" in response.data
    assert User.query.filter_by(username="newuser").first() is None


def test_registration_requires_a_number(client, db):
    weak = "NoDigits-Here!"

    response = _register(client, password=weak, confirm_password=weak)

    assert b"at least one number" in response.data
    assert User.query.filter_by(username="newuser").first() is None


def test_registration_requires_a_special_character(client, db):
    weak = "NoSpecial1Char"

    response = _register(client, password=weak, confirm_password=weak)

    assert b"at least one special character" in response.data
    assert User.query.filter_by(username="newuser").first() is None


def test_registration_rejects_a_mismatched_confirmation(client, db):
    response = _register(client, confirm_password="different1")

    assert b"does not match" in response.data
    assert User.query.filter_by(username="newuser").first() is None


def test_registration_rejects_a_duplicate_username(client, make_user):
    make_user("newuser")

    response = _register(client)

    assert b"already taken" in response.data
    assert User.query.filter_by(username="newuser").count() == 1


def test_registration_rejects_an_invalid_email(client, db):
    response = _register(client, email="not-an-email")

    assert b"valid email" in response.data
    assert User.query.filter_by(username="newuser").first() is None


def test_login_with_the_correct_password_redirects_to_the_dashboard(
    client, make_user
):
    make_user("owner1")

    response = client.post(
        LOGIN, data={"identifier": "owner1", "password": "password123"}
    )

    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]


def test_login_accepts_the_email_address(client, make_user):
    make_user("owner1", email="owner@example.com")

    response = client.post(
        LOGIN, data={"identifier": "owner@example.com", "password": "password123"}
    )

    assert response.status_code == 302


def test_login_with_a_wrong_password_is_rejected(client, make_user):
    make_user("owner1")

    response = client.post(
        LOGIN, data={"identifier": "owner1", "password": "wrong-password"}
    )

    assert response.status_code == 401
    assert b"Invalid username/email or password" in response.data


def test_login_with_an_unknown_account_is_rejected(client):
    response = client.post(
        LOGIN, data={"identifier": "ghost", "password": "password123"}
    )

    assert response.status_code == 401


def test_repeated_failures_lock_the_account(client, make_user):
    make_user("owner1")
    bad = {"identifier": "owner1", "password": "wrong-password"}

    for _ in range(4):
        assert client.post(LOGIN, data=bad).status_code == 401
    # Fifth failure trips the lockout.
    assert client.post(LOGIN, data=bad).status_code == 429
    # The correct password is refused while the key is locked.
    response = client.post(
        LOGIN, data={"identifier": "owner1", "password": "password123"}
    )
    assert response.status_code == 429


def test_logout_ends_the_session(client, make_user):
    make_user("owner1")
    client.post(LOGIN, data={"identifier": "owner1", "password": "password123"})
    assert client.get("/dashboard").status_code == 200

    client.post("/auth/logout")
    response = client.get("/dashboard")

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_login_cannot_be_redirected_to_another_host(client, make_user):
    make_user("owner1")

    response = client.post(
        LOGIN + "?next=//evil.example.com",
        data={"identifier": "owner1", "password": "password123"},
    )

    assert response.status_code == 302
    assert "evil.example.com" not in response.headers["Location"]


def test_the_rate_limiter_drops_stale_counters(app, monkeypatch):
    """A username spray must not grow the in-memory counter without bound."""
    monkeypatch.setattr(rate_limit, "MAX_TRACKED_KEYS", 2)
    clock = {"now": 1_000.0}
    monkeypatch.setattr(rate_limit.time, "time", lambda: clock["now"])

    rate_limit.register_failure("key-a")
    # Move past the window so "key-a" no longer counts as an active offender.
    clock["now"] += 10_000
    rate_limit.register_failure("key-b")
    rate_limit.register_failure("key-c")

    assert "key-a" not in rate_limit._attempts
    assert {"key-b", "key-c"} <= set(rate_limit._attempts)
