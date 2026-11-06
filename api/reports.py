"""JSON endpoints for the reports resource.

Generation is not a plain database insert: it renders the summary document to
disk and records the path, so it stays a POST that performs an action.
"""

import os

from flask import Blueprint, jsonify, send_file
from flask_jwt_extended import current_user as api_user
from flask_jwt_extended import jwt_required

from access import can_manage_application
from api.helpers import error, field_int, json_body
from api.serializers import report_dict
from extensions import db
from models import Application, Report
from report_service import (
    can_view_report,
    generate_report,
    report_file_path,
    report_summary,
    visible_reports,
)

reports_api_bp = Blueprint("api_reports", __name__, url_prefix="/reports")


def _get_visible_report(report_id):
    report = db.session.get(Report, report_id)
    if report is None:
        return None, error("Report not found.", 404)
    if not can_view_report(api_user, report):
        return None, error("You cannot view this report.", 403)
    return report, None


@reports_api_bp.get("", strict_slashes=False)
@jwt_required()
def index():
    reports = visible_reports(api_user).all()
    return jsonify(
        {
            "count": len(reports),
            "reports": [report_dict(item) for item in reports],
        }
    )


@reports_api_bp.post("", strict_slashes=False)
@jwt_required()
def create():
    app_id = field_int(json_body(), "app_id")
    application = db.session.get(Application, app_id) if app_id else None
    if application is None:
        return error("Validation failed.", 422, ["app_id must reference an existing application."])
    if not can_manage_application(api_user, application):
        return error("You cannot generate reports for this application.", 403)

    record = generate_report(application, api_user)
    return jsonify({"report": report_dict(record)}), 201


@reports_api_bp.get("/<int:report_id>")
@jwt_required()
def detail(report_id):
    report, problem = _get_visible_report(report_id)
    if problem:
        return problem
    return jsonify(
        {
            "report": report_dict(report),
            "application": report.application.name,
            "summary": report_summary(report.application),
        }
    )


@reports_api_bp.get("/<int:report_id>/download")
@jwt_required()
def download(report_id):
    report, problem = _get_visible_report(report_id)
    if problem:
        return problem
    path = report_file_path(report)
    if not path or not os.path.isfile(path):
        return error("The saved report file is missing. Generate a new report.", 404)

    return send_file(
        path,
        mimetype="text/html",
        as_attachment=True,
        download_name=os.path.basename(path),
    )


@reports_api_bp.delete("/<int:report_id>")
@jwt_required()
def delete(report_id):
    report = db.session.get(Report, report_id)
    if report is None:
        return error("Report not found.", 404)
    if not (api_user.is_admin or report.generated_by == api_user.id):
        return error("You cannot delete this report.", 403)

    path = report_file_path(report)
    db.session.delete(report)
    db.session.commit()
    if path and os.path.isfile(path):
        os.remove(path)
    return jsonify({"message": "Report deleted.", "id": report_id})
