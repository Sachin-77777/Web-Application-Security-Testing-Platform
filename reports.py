import os

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    send_file,
    url_for,
)
from flask_login import current_user

from access import application_choices, can_manage_application, get_application_or_403
from auth import login_required
from extensions import db
from models import Report
from report_service import (
    can_view_report,
    generate_report,
    report_file_path,
    report_summary,
    visible_reports,
)
from util import form_int, paginate

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def index():
    report_page = paginate(visible_reports(current_user))
    return render_template(
        "dashboard/reports.html",
        reports=report_page.items,
        pagination=report_page,
        applications=application_choices(),
    )


@reports_bp.route("/generate", methods=["POST"])
@login_required
def generate():
    app_id = form_int("app_id")
    if not app_id:
        flash("Select an application to report on.", "error")
        return redirect(url_for("reports.index"))

    application = get_application_or_403(app_id)
    if not can_manage_application(current_user, application):
        abort(403)

    record = generate_report(application, current_user)
    flash("Summary report generated.", "success")
    return redirect(url_for("reports.detail", report_id=record.id))


@reports_bp.route("/<int:report_id>")
@login_required
def detail(report_id):
    report = db.session.get(Report, report_id)
    if report is None:
        abort(404)
    if not can_view_report(current_user, report):
        abort(403)
    return render_template(
        "dashboard/report_detail.html",
        report=report,
        application=report.application,
        summary=report_summary(report.application),
    )


@reports_bp.route("/<int:report_id>/download")
@login_required
def download(report_id):
    report = db.session.get(Report, report_id)
    if report is None:
        abort(404)
    if not can_view_report(current_user, report):
        abort(403)
    path = report_file_path(report)
    if not path or not os.path.isfile(path):
        flash("The saved report file is missing. Generate a new report.", "error")
        return redirect(url_for("reports.detail", report_id=report.id))
    return send_file(
        path,
        mimetype="text/html",
        as_attachment=True,
        download_name=os.path.basename(path),
    )


@reports_bp.route("/<int:report_id>/delete", methods=["POST"])
@login_required
def delete(report_id):
    report = db.session.get(Report, report_id)
    if report is None:
        abort(404)
    if not (current_user.is_admin or report.generated_by == current_user.id):
        abort(403)
    path = report_file_path(report)
    db.session.delete(report)
    db.session.commit()
    if path and os.path.isfile(path):
        os.remove(path)
    flash("Report deleted.", "success")
    return redirect(url_for("reports.index"))
