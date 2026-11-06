"""Authorisation rules: admin vs user, owner vs assigned tester.

The HTML pages answer a denied request with a 302 redirect plus a flash message
(see the 403 handler in ``app.py``), so the tests assert on the redirect and on
the fact that the protected data is not rendered.
"""

from extensions import db
from models import TestCase, User, Vulnerability


def test_a_user_cannot_open_another_users_application(
    client, login, make_user, make_application
):
    owner = make_user("owner1")
    make_user("other1")
    application = make_application(owner)
    login("other1")

    response = client.get(f"/applications/{application.id}")

    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]


def test_an_admin_can_open_any_application(
    client, login, make_user, make_application
):
    owner = make_user("owner1")
    make_user("admin1", role="admin")
    application = make_application(owner)
    login("admin1")

    response = client.get(f"/applications/{application.id}")

    assert response.status_code == 200
    assert application.name.encode() in response.data


def test_an_assigned_tester_can_view_the_application(
    client, login, make_user, make_application, make_test_case
):
    owner = make_user("owner1")
    tester = make_user("tester1")
    application = make_application(owner)
    make_test_case(application, assigned_to=tester)
    login("tester1")

    response = client.get(f"/applications/{application.id}")

    assert response.status_code == 200


def test_an_assigned_tester_can_only_change_the_status(
    client, login, make_user, make_application, make_test_case
):
    owner = make_user("owner1")
    tester = make_user("tester1")
    application = make_application(owner)
    test_case = make_test_case(application, assigned_to=tester)
    login("tester1")

    client.post(
        f"/test-cases/{test_case.id}/edit",
        data={
            "test_name": "Hijacked name",
            "category": "Other",
            "status": "Passed",
        },
        follow_redirects=True,
    )

    updated = db.session.get(TestCase, test_case.id)
    assert updated.status == "Passed"
    assert updated.test_name == test_case.test_name
    assert updated.category == test_case.category


def test_an_unrelated_user_cannot_open_a_test_case(
    client, login, make_user, make_application, make_test_case
):
    owner = make_user("owner1")
    make_user("other1")
    application = make_application(owner)
    test_case = make_test_case(application)
    login("other1")

    response = client.get(f"/test-cases/{test_case.id}")

    assert response.status_code == 302


def test_a_non_owner_cannot_open_the_edit_form(
    client, login, make_user, make_application
):
    owner = make_user("owner1")
    make_user("other1")
    application = make_application(owner)
    login("other1")

    response = client.get(f"/applications/{application.id}/edit")

    assert response.status_code == 302


def test_a_standard_user_cannot_open_the_admin_user_list(client, login, make_user):
    make_user("owner1")
    login("owner1")

    response = client.get("/auth/users")

    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]


def test_an_admin_can_open_the_user_list(client, login, make_user):
    make_user("admin1", role="admin")
    make_user("owner1")
    login("admin1")

    response = client.get("/auth/users")

    assert response.status_code == 200
    assert b"owner1" in response.data


def test_the_list_views_only_show_visible_records(
    client, login, make_user, make_application
):
    owner = make_user("owner1")
    make_user("other1")
    make_application(owner, name="Owner only app")
    login("other1")

    response = client.get("/applications/")

    assert response.status_code == 200
    assert b"Owner only app" not in response.data


# --- client role -----------------------------------------------------------
# A client submits an application and reads the report, but never records
# tests or findings of its own.


def test_a_client_can_open_their_own_application(
    client, login, make_user, make_application
):
    client_user = make_user("client1", role="client")
    application = make_application(client_user)
    login("client1")

    response = client.get(f"/applications/{application.id}")

    assert response.status_code == 200
    assert application.name.encode() in response.data


def test_a_client_only_sees_their_own_applications(
    client, login, make_user, make_application
):
    owner = make_user("owner1")
    make_user("client1", role="client")
    make_application(owner, name="Internal app")
    login("client1")

    response = client.get("/applications/")

    assert response.status_code == 200
    assert b"Internal app" not in response.data


def test_a_client_cannot_open_the_new_test_case_form(
    client, login, make_user, make_application
):
    client_user = make_user("client1", role="client")
    make_application(client_user)
    login("client1")

    response = client.get("/test-cases/new")

    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]


def test_a_client_cannot_create_a_test_case(
    client, login, make_user, make_application
):
    client_user = make_user("client1", role="client")
    application = make_application(client_user)
    login("client1")

    client.post(
        "/test-cases/new",
        data={"app_id": application.id, "test_name": "Sneaky test", "category": "Other"},
        follow_redirects=True,
    )

    assert TestCase.query.filter_by(app_id=application.id).count() == 0


def test_a_client_cannot_delete_an_existing_test_case(
    client, login, make_user, make_application, make_test_case
):
    client_user = make_user("client1", role="client")
    application = make_application(client_user)
    test_case = make_test_case(application)
    login("client1")

    client.post(f"/test-cases/{test_case.id}/delete", follow_redirects=True)

    assert db.session.get(TestCase, test_case.id) is not None


def test_a_client_cannot_log_a_vulnerability(
    client, login, make_user, make_application
):
    client_user = make_user("client1", role="client")
    application = make_application(client_user)
    login("client1")

    client.post(
        "/vulnerabilities/new",
        data={"app_id": application.id, "title": "Sneaky finding", "severity": "High",
              "status": "Open"},
        follow_redirects=True,
    )

    assert Vulnerability.query.filter_by(app_id=application.id).count() == 0


def test_a_client_cannot_delete_an_existing_vulnerability(
    client, login, make_user, make_application, make_vulnerability
):
    client_user = make_user("client1", role="client")
    application = make_application(client_user)
    vulnerability = make_vulnerability(application)
    login("client1")

    client.post(f"/vulnerabilities/{vulnerability.id}/delete", follow_redirects=True)

    assert db.session.get(Vulnerability, vulnerability.id) is not None


def test_the_api_denies_a_client_creating_a_test_case(
    client, make_user, make_application, api_headers
):
    client_user = make_user("client1", role="client")
    application = make_application(client_user)

    response = client.post(
        "/api/test-cases",
        json={"app_id": application.id, "test_name": "Sneaky test", "category": "Other"},
        headers=api_headers("client1"),
    )

    assert response.status_code == 422
    assert TestCase.query.filter_by(app_id=application.id).count() == 0


def test_the_api_denies_a_client_creating_a_vulnerability(
    client, make_user, make_application, api_headers
):
    client_user = make_user("client1", role="client")
    application = make_application(client_user)

    response = client.post(
        "/api/vulnerabilities",
        json={"app_id": application.id, "title": "Sneaky finding", "severity": "High"},
        headers=api_headers("client1"),
    )

    assert response.status_code == 422
    assert Vulnerability.query.filter_by(app_id=application.id).count() == 0


# --- role management -------------------------------------------------------


def test_an_admin_can_change_another_accounts_role(client, login, make_user):
    make_user("admin1", role="admin")
    account = make_user("owner1")
    login("admin1")

    client.post(f"/auth/users/{account.id}/role", data={"role": "client"},
                follow_redirects=True)

    assert db.session.get(User, account.id).role == "client"


def test_a_standard_user_cannot_change_roles(client, login, make_user):
    make_user("owner1")
    account = make_user("other1")
    login("owner1")

    response = client.post(f"/auth/users/{account.id}/role", data={"role": "admin"})

    assert response.status_code == 302
    assert db.session.get(User, account.id).role == "user"


def test_an_admin_cannot_demote_themselves(client, login, make_user):
    admin = make_user("admin1", role="admin")
    make_user("owner1")
    login("admin1")

    client.post(f"/auth/users/{admin.id}/role", data={"role": "user"},
                follow_redirects=True)

    assert db.session.get(User, admin.id).role == "admin"


def test_a_role_change_rejects_an_unknown_role(client, login, make_user):
    make_user("admin1", role="admin")
    account = make_user("owner1")
    login("admin1")

    client.post(f"/auth/users/{account.id}/role", data={"role": "superuser"},
                follow_redirects=True)

    assert db.session.get(User, account.id).role == "user"
