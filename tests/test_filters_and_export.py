"""Vulnerability list filters, the CSV export, and the score shown in the UI.

The filters and the export share one query builder, so these tests also guard
that a download returns exactly the rows the caller can see on screen.
"""

from models import Vulnerability


def make_finding(db, application, title, severity="High", status="Open", owasp=None):
    vulnerability = Vulnerability(
        app_id=application.id,
        title=title,
        severity=severity,
        status=status,
        owasp_category=owasp,
    )
    db.session.add(vulnerability)
    db.session.commit()
    return vulnerability


def test_the_list_filters_by_severity(client, login, make_user, make_application, db):
    owner = make_user("owner1")
    application = make_application(owner)
    make_finding(db, application, "Critical finding", severity="Critical")
    make_finding(db, application, "Low finding", severity="Low")
    login("owner1")

    body = client.get("/vulnerabilities/?severity=Critical").get_data(as_text=True)
    assert "Critical finding" in body
    assert "Low finding" not in body


def test_the_list_filters_by_status_and_owasp(
    client, login, make_user, make_application, db
):
    owner = make_user("owner1")
    application = make_application(owner)
    make_finding(
        db,
        application,
        "Resolved injection",
        status="Fixed",
        owasp="A03:2021 Injection",
    )
    make_finding(
        db,
        application,
        "Open misconfiguration",
        status="Open",
        owasp="A05:2021 Security Misconfiguration",
    )
    login("owner1")

    body = client.get("/vulnerabilities/?status=Open").get_data(as_text=True)
    assert "Open misconfiguration" in body
    assert "Resolved injection" not in body

    body = client.get(
        "/vulnerabilities/?owasp=A03%3A2021%20Injection"
    ).get_data(as_text=True)
    assert "Resolved injection" in body
    assert "Open misconfiguration" not in body


def test_the_list_ignores_an_unknown_filter(
    client, login, make_user, make_application, db
):
    owner = make_user("owner1")
    application = make_application(owner)
    make_finding(db, application, "Critical finding", severity="Critical")
    login("owner1")

    body = client.get("/vulnerabilities/?severity=NotARealLevel").get_data(as_text=True)
    assert body.count("Critical finding") == 1


def test_the_csv_export_downloads_the_findings(
    client, login, make_user, make_application, db
):
    owner = make_user("owner1")
    application = make_application(owner)
    make_finding(
        db,
        application,
        "Missing security headers",
        severity="High",
        owasp="A05:2021 Security Misconfiguration",
    )
    login("owner1")

    response = client.get("/vulnerabilities/export.csv")

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "attachment" in response.headers["Content-Disposition"]
    text = response.get_data(as_text=True)
    assert "OWASP Category" in text
    assert "Missing security headers" in text
    assert "A05:2021 Security Misconfiguration" in text


def test_the_csv_export_honours_the_active_filters(
    client, login, make_user, make_application, db
):
    owner = make_user("owner1")
    application = make_application(owner)
    make_finding(db, application, "Critical finding", severity="Critical")
    make_finding(db, application, "Low finding", severity="Low")
    login("owner1")

    text = client.get("/vulnerabilities/export.csv?severity=Low").get_data(as_text=True)

    assert "Low finding" in text
    assert "Critical finding" not in text


def test_the_csv_export_neutralises_formula_cells(
    client, login, make_user, make_application, db
):
    owner = make_user("owner1")
    application = make_application(owner)
    make_finding(db, application, "=cmd|' /C calc'!A0", severity="High")
    login("owner1")

    text = client.get("/vulnerabilities/export.csv").get_data(as_text=True)

    # The leading apostrophe stops Excel and Sheets treating the cell as a formula.
    assert "'=cmd|' /C calc'!A0" in text


def test_the_applications_list_shows_the_security_score(
    client, login, make_user, make_application, db
):
    owner = make_user("owner1")
    application = make_application(owner)
    make_finding(db, application, "Unresolved high finding", severity="High")
    login("owner1")

    body = client.get("/applications/").get_data(as_text=True)

    # One unresolved High finding subtracts 10 points from 100.
    assert "90 \u00b7 A" in body


def test_the_dashboard_shows_the_security_score(
    client, login, make_user, make_application, db
):
    owner = make_user("owner1")
    application = make_application(owner)
    make_finding(db, application, "Unresolved high finding", severity="High")
    login("owner1")

    body = client.get("/dashboard").get_data(as_text=True)

    assert "90 \u00b7 A" in body
