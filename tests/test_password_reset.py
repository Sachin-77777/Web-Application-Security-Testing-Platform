"""Password reset by emailed one-time code.

The mailer is monkeypatched so the tests capture the code instead of sending
it, which lets the whole flow be exercised without an SMTP server.
"""

from datetime import timedelta

import auth
from models import PasswordResetOTP, utcnow_naive

FORGOT = "/auth/forgot-password"
RESET = "/auth/reset-password"
NEW_PASSWORD = "N3w-Password!"
OLD_PASSWORD = "password123"  # the conftest ``make_user`` default


def _capture_code(monkeypatch):
    """Replace the mailer with a recorder and return the box it writes into."""
    sent = {}

    def fake_send(to_email, code):
        sent["to"] = to_email
        sent["code"] = code
        return "test"

    monkeypatch.setattr(auth, "send_password_reset_code", fake_send)
    return sent


def _request_code(client, email):
    return client.post(FORGOT, data={"email": email})


def _submit(client, email, code, password=NEW_PASSWORD, confirm=NEW_PASSWORD):
    return client.post(
        RESET,
        data={
            "email": email,
            "code": code,
            "password": password,
            "confirm_password": confirm,
        },
    )


def test_requesting_a_reset_sends_a_six_digit_code(client, make_user, db, monkeypatch):
    user = make_user("owner1")
    sent = _capture_code(monkeypatch)

    response = _request_code(client, user.email)

    assert response.status_code == 302
    assert sent["to"] == user.email
    assert len(sent["code"]) == 6 and sent["code"].isdigit()


def test_only_the_hash_of_the_code_is_stored(client, make_user, db, monkeypatch):
    user = make_user("owner1")
    sent = _capture_code(monkeypatch)

    _request_code(client, user.email)

    record = PasswordResetOTP.query.one()
    assert record.user_id == user.id
    assert record.code_hash != sent["code"]
    assert sent["code"] not in record.code_hash
    assert record.check_code(sent["code"])
    assert record.consumed_at is None
    assert record.expires_at > utcnow_naive()


def test_an_unknown_email_is_indistinguishable_from_a_known_one(
    client, make_user, db, monkeypatch
):
    """No user enumeration: the page cannot be used to probe for accounts."""
    _capture_code(monkeypatch)
    user = make_user("owner1")

    known = _request_code(client, user.email)
    unknown = _request_code(client, "nobody@example.com")

    assert known.status_code == unknown.status_code == 302
    assert known.headers["Location"].split("?")[0] == unknown.headers["Location"].split("?")[0]
    assert PasswordResetOTP.query.count() == 1  # only the real account got a code


def test_a_valid_code_sets_the_new_password(client, make_user, db, monkeypatch):
    user = make_user("owner1")
    sent = _capture_code(monkeypatch)
    _request_code(client, user.email)

    response = _submit(client, user.email, sent["code"])

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/login")
    db.session.refresh(user)
    assert user.check_password(NEW_PASSWORD)
    assert not user.check_password(OLD_PASSWORD)
    assert PasswordResetOTP.query.one().consumed_at is not None


def test_the_new_password_works_on_the_login_form(client, make_user, db, monkeypatch):
    user = make_user("owner1")
    sent = _capture_code(monkeypatch)
    _request_code(client, user.email)
    _submit(client, user.email, sent["code"])

    response = client.post(
        "/auth/login", data={"identifier": "owner1", "password": NEW_PASSWORD}
    )

    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]


def test_a_code_cannot_be_used_twice(client, make_user, db, monkeypatch):
    user = make_user("owner1")
    sent = _capture_code(monkeypatch)
    _request_code(client, user.email)
    _submit(client, user.email, sent["code"])

    response = _submit(
        client,
        user.email,
        sent["code"],
        password="0ther-Password!",
        confirm="0ther-Password!",
    )

    assert response.status_code == 400
    db.session.refresh(user)
    assert user.check_password(NEW_PASSWORD)


def test_a_wrong_code_does_not_change_the_password(client, make_user, db, monkeypatch):
    user = make_user("owner1")
    _capture_code(monkeypatch)
    _request_code(client, user.email)
    record = PasswordResetOTP.query.one()

    response = _submit(client, user.email, "000000")

    assert response.status_code == 400
    db.session.refresh(user)
    assert user.check_password(OLD_PASSWORD)
    assert db.session.get(PasswordResetOTP, record.id).attempts == 1


def test_an_expired_code_is_rejected(client, make_user, db, monkeypatch):
    user = make_user("owner1")
    sent = _capture_code(monkeypatch)
    _request_code(client, user.email)

    record = PasswordResetOTP.query.one()
    record.expires_at = utcnow_naive() - timedelta(minutes=1)
    db.session.commit()

    response = _submit(client, user.email, sent["code"])

    assert response.status_code == 400
    db.session.refresh(user)
    assert user.check_password(OLD_PASSWORD)


def test_guessing_is_capped_so_the_code_cannot_be_brute_forced(
    client, make_user, db, monkeypatch
):
    user = make_user("owner1")
    sent = _capture_code(monkeypatch)
    _request_code(client, user.email)

    for _ in range(5):
        assert _submit(client, user.email, "000000").status_code == 400

    # The real code is refused once the attempt budget is spent.
    response = _submit(client, user.email, sent["code"])

    assert response.status_code == 400
    db.session.refresh(user)
    assert user.check_password(OLD_PASSWORD)


def test_the_reset_also_enforces_the_password_policy(client, make_user, db, monkeypatch):
    user = make_user("owner1")
    sent = _capture_code(monkeypatch)
    _request_code(client, user.email)

    response = _submit(client, user.email, sent["code"], password="weak", confirm="weak")

    assert b"at least 8 characters" in response.data
    db.session.refresh(user)
    assert user.check_password(OLD_PASSWORD)
    assert PasswordResetOTP.query.one().consumed_at is None


def test_reset_requests_are_throttled(client, make_user, db, monkeypatch):
    _capture_code(monkeypatch)

    for _ in range(4):
        assert _request_code(client, "spam@example.com").status_code == 302

    assert _request_code(client, "spam@example.com").status_code == 429
