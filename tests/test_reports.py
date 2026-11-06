"""Report storage, portability across machines and download scoping.

A report document is written next to the database, so the path recorded for it
must not be tied to one machine or user folder. These tests pin down that the
database only ever holds a file name and that a download can only ever reach
inside the reports folder.
"""

import os

import pytest

from models import Report
from report_service import generate_report, report_file_path, reports_dir


@pytest.fixture()
def reports_folder(app, tmp_path, monkeypatch):
    """Redirect generated documents into a throwaway folder."""
    monkeypatch.setitem(app.config, "REPORTS_FOLDER", str(tmp_path))
    return tmp_path


def _save_document(file_name, contents="<html>report</html>"):
    """Write a report document to the reports folder, without the database row."""
    with open(os.path.join(reports_dir(), file_name), "w", encoding="utf-8") as handle:
        handle.write(contents)
    return file_name


def _add_report_row(db, application, owner, report_path):
    report = Report(
        app_id=application.id,
        generated_by=owner.id,
        report_path=report_path,
    )
    db.session.add(report)
    db.session.commit()
    return report


def test_a_generated_report_stores_only_the_file_name(
    app, db, make_user, make_application, reports_folder
):
    owner = make_user("owner1")
    application = make_application(owner)

    report = generate_report(application, owner)

    assert report.report_path == os.path.basename(report.report_path)
    assert os.path.dirname(report.report_path) == ""
    assert os.path.isfile(report_file_path(report))


def test_a_report_saved_under_an_old_absolute_path_still_downloads(
    client, login, db, make_user, make_application, reports_folder
):
    """A row written on another machine keeps working after the project moved."""
    owner = make_user("owner1")
    application = make_application(owner)
    file_name = _save_document("report-app-1.html", "<html>portable</html>")
    # What the old machine stored: a full path under a different user folder.
    foreign_path = os.path.join(
        "C:" + os.sep, "Users", "somebody", "webapp-security-platform",
        "instance", "reports", file_name,
    )
    report = _add_report_row(db, application, owner, foreign_path)

    login("owner1")
    response = client.get(f"/reports/{report.id}/download")

    assert response.status_code == 200
    assert b"portable" in response.data


def test_a_report_path_cannot_escape_the_reports_folder(
    client, login, db, make_user, make_application, reports_folder
):
    owner = make_user("owner1")
    application = make_application(owner)
    report = _add_report_row(db, application, owner, os.path.join("..", "..", "app.py"))

    login("owner1")
    response = client.get(f"/reports/{report.id}/download", follow_redirects=True)

    assert response.status_code == 200
    assert b"report file is missing" in response.data


def test_the_api_downloads_a_moved_report(
    client, db, make_user, make_application, api_headers, reports_folder
):
    owner = make_user("owner1")
    application = make_application(owner)
    file_name = _save_document("report-app-2.html", "<html>api</html>")
    report = _add_report_row(db, application, owner, os.path.join("D:" + os.sep, "old", file_name))

    response = client.get(
        f"/api/reports/{report.id}/download",
        headers=api_headers("owner1"),
    )

    assert response.status_code == 200
    assert b"api" in response.data
