"""Report storage, visibility rules and generation.

Both the HTML blueprint (``reports.py``) and the JSON API
(``api/reports.py``) use these functions so a report is produced and access
checked in exactly one place.
"""

import os
from datetime import datetime, timezone

from flask import current_app, render_template

from access import application_choices, can_manage_application
from constants import grade_from_score, security_score
from extensions import db
from models import Report


def reports_dir():
    """Folder that holds generated report documents."""
    configured = current_app.config.get("REPORTS_FOLDER")
    folder = configured or os.path.join(current_app.instance_path, "reports")
    os.makedirs(folder, exist_ok=True)
    return folder


def report_file_path(report):
    """Absolute path of a saved report document on this machine.

    Only the file name is stored in the database, so a report keeps resolving
    after the project (and its ``instance/`` folder) is moved to another
    machine or user. Reducing the stored value to its base name also keeps
    older rows that hold a full path working, and makes it impossible for a
    row to point a download outside the reports folder.
    """
    name = os.path.basename(report.report_path or "")
    if not name:
        return ""
    return os.path.join(reports_dir(), name)


def visible_reports(user):
    query = Report.query.order_by(Report.created_at.desc())
    if user.is_admin:
        return query
    allowed = [application.id for application in application_choices(user)]
    if not allowed:
        return query.filter(Report.id == -1)
    return query.filter(Report.app_id.in_(allowed))


def can_view_report(user, report):
    return user.is_admin or can_manage_application(user, report.application)


def application_score(application):
    """Return ``(score, grade, verdict)`` for one application.

    Shared by the report, the dashboard and the applications list so the number
    is always calculated the same way. Returns (None, "N/A", "Pending") if
    no tests have been recorded yet.
    """
    if not application.test_cases:
        return None, "N/A", "Pending"
    score = security_score(application.vulnerabilities)
    grade, verdict = grade_from_score(score)
    return score, grade, verdict


def report_summary(application):
    tests = application.test_cases
    vulns = application.vulnerabilities
    score, grade, verdict = application_score(application)
    return {
        "tests_total": len(tests),
        "tests_passed": sum(1 for item in tests if item.status == "Passed"),
        "tests_failed": sum(1 for item in tests if item.status == "Failed"),
        "tests_pending": sum(1 for item in tests if item.status == "Pending"),
        "vulns_total": len(vulns),
        "vulns_open": sum(1 for item in vulns if item.status == "Open"),
        "vulns_fixed": sum(1 for item in vulns if item.status == "Fixed"),
        "by_severity": {
            level: sum(1 for item in vulns if item.severity == level)
            for level in ("Critical", "High", "Medium", "Low")
        },
        "score": score,
        "grade": grade,
        "verdict": verdict,
    }


def generate_report(application, user):
    """Render the summary document, save it to disk and record it in the DB."""
    summary = report_summary(application)
    generated_at = datetime.now(timezone.utc)
    html = render_template(
        "dashboard/report_document.html",
        application=application,
        summary=summary,
        generated_at=generated_at,
        generated_by=user,
    )
    filename = "report-app-{0}-{1}.html".format(
        application.id,
        generated_at.strftime("%Y%m%d-%H%M%S"),
    )
    path = os.path.join(reports_dir(), filename)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(html)

    # Only the file name goes in the database: the reports folder is resolved
    # again at read time, so the record survives a move to another machine.
    record = Report(
        app_id=application.id,
        generated_by=user.id,
        report_path=filename,
    )
    db.session.add(record)
    db.session.commit()
    return record
