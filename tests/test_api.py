"""JSON REST API: JWT login, protected reads, CRUD, revocation and error shape."""

from models import Application


def test_login_returns_tokens_and_the_user(client, make_user):
    make_user("owner1")

    response = client.post(
        "/api/auth/login", json={"username": "owner1", "password": "password123"}
    )

    body = response.get_json()
    assert response.status_code == 200
    assert {"access_token", "refresh_token", "token_type", "expires_in"} <= set(body)
    assert body["token_type"] == "Bearer"
    assert body["user"]["username"] == "owner1"


def test_login_never_exposes_the_password_hash(client, make_user):
    make_user("owner1")

    response = client.post(
        "/api/auth/login", json={"username": "owner1", "password": "password123"}
    )

    assert "password_hash" not in response.get_json()["user"]


def test_login_rejects_bad_credentials(client, make_user):
    make_user("owner1")

    response = client.post(
        "/api/auth/login", json={"username": "owner1", "password": "wrong"}
    )

    assert response.status_code == 401
    assert response.get_json()["error"] == "Invalid credentials."


def test_login_requires_a_username_and_password(client):
    response = client.post("/api/auth/login", json={"username": "owner1"})

    assert response.status_code == 400


def test_login_is_rate_limited(client, make_user):
    make_user("owner1")
    bad = {"username": "owner1", "password": "wrong"}

    for _ in range(4):
        assert client.post("/api/auth/login", json=bad).status_code == 401
    locked = client.post("/api/auth/login", json=bad)

    assert locked.status_code == 429
    assert "retry_after" in locked.get_json()["details"]


def test_protected_endpoints_require_a_token(client):
    response = client.get("/api/applications")

    assert response.status_code == 401
    assert response.is_json


def test_me_returns_the_authenticated_user(client, make_user, api_headers):
    make_user("owner1")

    response = client.get("/api/auth/me", headers=api_headers("owner1"))

    assert response.status_code == 200
    assert response.get_json()["user"]["username"] == "owner1"


def test_application_crud_round_trip(client, db, make_user, api_headers):
    make_user("owner1")
    headers = api_headers("owner1")

    created = client.post(
        "/api/applications",
        json={"name": "Demo app", "target_url": "http://127.0.0.1:5000"},
        headers=headers,
    )
    assert created.status_code == 201
    app_id = created.get_json()["application"]["id"]

    listed = client.get("/api/applications", headers=headers)
    assert listed.status_code == 200
    assert listed.get_json()["count"] == 1

    fetched = client.get(f"/api/applications/{app_id}", headers=headers)
    assert fetched.status_code == 200

    patched = client.patch(
        f"/api/applications/{app_id}", json={"name": "Renamed"}, headers=headers
    )
    assert patched.status_code == 200
    assert patched.get_json()["application"]["name"] == "Renamed"
    # PATCH keeps the values that were not sent.
    assert patched.get_json()["application"]["target_url"] == "http://127.0.0.1:5000"

    deleted = client.delete(f"/api/applications/{app_id}", headers=headers)
    assert deleted.status_code == 200
    assert db.session.get(Application, app_id) is None


def test_create_application_validates_the_payload(client, make_user, api_headers):
    make_user("owner1")

    response = client.post(
        "/api/applications",
        json={"name": "", "target_url": "javascript:alert(1)"},
        headers=api_headers("owner1"),
    )

    assert response.status_code == 422
    assert len(response.get_json()["details"]) == 2


def test_search_is_driven_by_a_query_parameter(client, db, make_user, api_headers):
    owner = make_user("owner1")
    for name in ("Alpha", "Beta"):
        db.session.add(
            Application(name=name, target_url="http://127.0.0.1:5000", owner_id=owner.id)
        )
    db.session.commit()

    response = client.get("/api/applications?q=alph", headers=api_headers("owner1"))

    assert response.status_code == 200
    assert response.get_json()["count"] == 1
    assert response.get_json()["applications"][0]["name"] == "Alpha"


def test_a_user_only_sees_their_own_applications(client, db, make_user, api_headers):
    owner = make_user("owner1")
    make_user("other1")
    db.session.add(
        Application(
            name="Private app", target_url="http://127.0.0.1:5000", owner_id=owner.id
        )
    )
    db.session.commit()

    response = client.get("/api/applications", headers=api_headers("other1"))

    assert response.get_json()["count"] == 0


def test_logout_revokes_the_token(client, make_user, api_token):
    make_user("owner1")
    token = api_token("owner1")
    headers = {"Authorization": f"Bearer {token}"}

    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    reused = client.get("/api/auth/me", headers=headers)

    assert reused.status_code == 401


def test_unknown_api_paths_return_json_not_html(client):
    response = client.get("/api/does-not-exist")

    assert response.status_code == 404
    assert response.is_json
