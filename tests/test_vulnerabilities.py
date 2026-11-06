"""Vulnerability evidence fields: OWASP category, CWE id, evidence, remediation.

These fields are optional extras on top of the original finding fields, so the
tests also guard that the original create/edit flow still works.
"""

from flask import render_template

from models import Vulnerability
from report_service import report_summary


def test_the_form_saves_the_evidence_fields(
    client, login, make_user, make_application
):
    owner = make_user("owner1")
    application = make_application(owner)
    login("owner1")

    client.post(
        "/vulnerabilities/new",
        data={
            "app_id": application.id,
            "title": "Reflected XSS in the search box",
            "severity": "High",
            "status": "Open",
            "owasp_category": "A03:2021 Injection",
            "cwe_id": "cwe-79",
            "evidence": "The payload appears verbatim in the response.",
            "remediation": "Escape all output with Jinja autoescaping.",
        },
        follow_redirects=True,
    )

    vulnerability = Vulnerability.query.filter_by(app_id=application.id).one()
    assert vulnerability.owasp_category == "A03:2021 Injection"
    assert vulnerability.cwe_id == "CWE-79"  # normalised to upper case
    assert vulnerability.evidence.startswith("The payload")
    assert vulnerability.remediation.startswith("Escape")


def test_the_form_rejects_an_unknown_owasp_category(
    client, login, make_user, make_application
):
    owner = make_user("owner1")
    application = make_application(owner)
    login("owner1")

    client.post(
        "/vulnerabilities/new",
        data={
            "app_id": application.id,
            "title": "Made up category",
            "severity": "High",
            "status": "Open",
            "owasp_category": "A99:2021 Not real",
        },
        follow_redirects=True,
    )

    assert Vulnerability.query.filter_by(app_id=application.id).count() == 0


def test_the_form_rejects_a_malformed_cwe_id(
    client, login, make_user, make_application
):
    owner = make_user("owner1")
    application = make_application(owner)
    login("owner1")

    client.post(
        "/vulnerabilities/new",
        data={
            "app_id": application.id,
            "title": "Bad CWE",
            "severity": "High",
            "status": "Open",
            "cwe_id": "79",
        },
        follow_redirects=True,
    )

    assert Vulnerability.query.filter_by(app_id=application.id).count() == 0


def test_the_edit_form_updates_the_evidence_fields(
    client, login, make_user, make_application, make_vulnerability, db
):
    owner = make_user("owner1")
    application = make_application(owner)
    vulnerability = make_vulnerability(application)
    login("owner1")

    client.post(
        f"/vulnerabilities/{vulnerability.id}/edit",
        data={
            "app_id": application.id,
            "title": "Renamed finding",
            "severity": "Critical",
            "status": "Open",
            "owasp_category": "A03:2021 Injection",
            "cwe_id": "CWE-89",
            "evidence": "id=1' returns every row.",
            "remediation": "Use SQLAlchemy bound parameters.",
        },
        follow_redirects=True,
    )

    db.session.expire_all()
    stored = db.session.get(Vulnerability, vulnerability.id)
    assert stored.title == "Renamed finding"
    assert stored.cwe_id == "CWE-89"
    assert stored.remediation.startswith("Use SQLAlchemy")


def test_the_api_saves_and_returns_the_evidence_fields(
    client, make_user, make_application, api_headers
):
    owner = make_user("owner1")
    application = make_application(owner)

    created = client.post(
        "/api/vulnerabilities",
        json={
            "app_id": application.id,
            "title": "SQL injection in the filter",
            "severity": "Critical",
            "owasp_category": "A03:2021 Injection",
            "cwe_id": "CWE-89",
            "evidence": "id=1'",
            "remediation": "Use SQLAlchemy bound parameters.",
        },
        headers=api_headers("owner1"),
    )

    assert created.status_code == 201
    body = created.get_json()["vulnerability"]
    assert body["owasp_category"] == "A03:2021 Injection"
    assert body["cwe_id"] == "CWE-89"
    assert body["evidence"] == "id=1'"
    assert body["remediation"].startswith("Use SQLAlchemy")


def test_the_api_rejects_an_unknown_owasp_category(
    client, make_user, make_application, api_headers
):
    owner = make_user("owner1")
    application = make_application(owner)

    response = client.post(
        "/api/vulnerabilities",
        json={
            "app_id": application.id,
            "title": "Made up category",
            "severity": "High",
            "owasp_category": "A99:2021 Not real",
        },
        headers=api_headers("owner1"),
    )

    assert response.status_code == 422


def test_the_report_document_shows_the_score_and_evidence_fields(
    app, make_user, make_application, make_vulnerability
):
    owner = make_user("owner1")
    application = make_application(owner)
    make_vulnerability(application, severity="High")
    application.vulnerabilities[0].evidence = "Missing on every response."
    application.vulnerabilities[0].remediation = "Send the headers in after_request."

    summary = report_summary(application)
    html = render_template(
        "dashboard/report_document.html",
        application=application,
        summary=summary,
        generated_at="now",
        generated_by=owner,
    )

    # One unresolved High finding subtracts 10 points from 100.
    assert summary["score"] == 90
    assert summary["grade"] == "A"
    assert "Security score" in html
    assert "Missing on every response." in html
    assert "Send the headers in after_request." in html
