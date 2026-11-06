"""Convert database models into JSON-safe dictionaries.

Every field is listed explicitly. Nothing is dumped straight from the model, so
something like ``User.password_hash`` can never leak into an API response.
"""

import os


def _iso(value):
    return value.isoformat() if value is not None else None


def _decimal(value):
    return float(value) if value is not None else None


def user_dict(user):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "created_at": _iso(user.created_at),
    }


def application_dict(application):
    return {
        "id": application.id,
        "name": application.name,
        "target_url": application.target_url,
        "description": application.description,
        "owner_id": application.owner_id,
        "owner": application.owner.username if application.owner else None,
        "created_at": _iso(application.created_at),
    }


def test_case_dict(test_case):
    return {
        "id": test_case.id,
        "app_id": test_case.app_id,
        "test_name": test_case.test_name,
        "category": test_case.category,
        "status": test_case.status,
        "assigned_to": test_case.assigned_to,
        "assignee": test_case.assignee.username if test_case.assignee else None,
    }


def vulnerability_dict(vulnerability):
    return {
        "id": vulnerability.id,
        "app_id": vulnerability.app_id,
        "title": vulnerability.title,
        "severity": vulnerability.severity,
        "cvss_score": _decimal(vulnerability.cvss_score),
        "status": vulnerability.status,
        "owasp_category": vulnerability.owasp_category,
        "cwe_id": vulnerability.cwe_id,
        "evidence": vulnerability.evidence,
        "remediation": vulnerability.remediation,
        "description": vulnerability.description,
    }


def report_dict(report):
    # Only the file name is exposed; the absolute server path stays private.
    return {
        "id": report.id,
        "app_id": report.app_id,
        "generated_by": report.generated_by,
        "generated_by_username": report.author.username if report.author else None,
        "report_file": os.path.basename(report.report_path) if report.report_path else None,
        "created_at": _iso(report.created_at),
    }
