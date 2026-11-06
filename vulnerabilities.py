import csv
import io
import re

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user
from sqlalchemy import or_

from access import (
    application_choices,
    can_conduct_testing,
    can_view_application,
    get_application_or_403,
    visible_vulnerabilities,
)
from auth import login_required
from constants import (
    OWASP_TOP10,
    VULN_SEVERITIES,
    VULN_STATUSES,
    severity_from_cvss,
)
from extensions import db
from models import Application, Vulnerability
from util import contains_filter, form_float, form_int, form_str, paginate, search_query

vulnerabilities_bp = Blueprint("vulnerabilities", __name__, url_prefix="/vulnerabilities")

CWE_PATTERN = re.compile(r"^CWE-\d+$")


def _fields():
    """Read the vulnerability form and normalise the optional evidence fields."""
    cwe_id = form_str("cwe_id").upper() or None
    return {
        "app_id": form_int("app_id"),
        "title": form_str("title"),
        "severity": form_str("severity"),
        "status": form_str("status") or "Open",
        "cvss_score": form_float("cvss_score"),
        "description": form_str("description") or None,
        "owasp_category": form_str("owasp_category") or None,
        "cwe_id": cwe_id,
        "evidence": form_str("evidence") or None,
        "remediation": form_str("remediation") or None,
    }


def _validate(values):
    errors = []
    application = None
    app_id = values["app_id"]
    if app_id:
        application = get_application_or_403(app_id)
    else:
        errors.append("Select a target application.")

    title = values["title"]
    if not title or len(title) > 255:
        errors.append("Title is required and must be 255 characters or fewer.")
    if values["severity"] not in VULN_SEVERITIES:
        errors.append("Select a CVSS qualitative severity (Low, Medium, High, or Critical).")
    if values["status"] not in VULN_STATUSES:
        errors.append("Status must be Open or Fixed.")
    cvss_score = values["cvss_score"]
    if cvss_score is not None and not 0.0 <= cvss_score <= 10.0:
        errors.append("CVSS score must be between 0.0 and 10.0.")
    if values["owasp_category"] and values["owasp_category"] not in OWASP_TOP10:
        errors.append("Select a valid OWASP Top 10 category.")
    if values["cwe_id"] and not CWE_PATTERN.match(values["cwe_id"]):
        errors.append("CWE ID must look like CWE-79.")
    return errors, application


def _form_context(applications, **overrides):
    context = {
        "applications": applications,
        "severities": VULN_SEVERITIES,
        "statuses": VULN_STATUSES,
        "owasp_options": OWASP_TOP10,
    }
    context.update(overrides)
    return context


def _filters():
    """Read the list filters, ignoring any value that is not a known option."""
    severity = search_query("severity", max_length=20)
    status = search_query("status", max_length=20)
    owasp = search_query("owasp", max_length=100)
    if severity not in VULN_SEVERITIES:
        severity = ""
    if status not in VULN_STATUSES:
        status = ""
    if owasp not in OWASP_TOP10:
        owasp = ""
    return severity, status, owasp


def _filtered_query(query_text, severity, status, owasp):
    """Build the visible-findings query with the search and filter values applied.

    Shared by the list page and the CSV export so a download always matches
    exactly what the caller is looking at.
    """
    query = visible_vulnerabilities().join(Application)
    if query_text:
        query = query.filter(
            or_(
                contains_filter(Vulnerability.title, query_text),
                contains_filter(Vulnerability.description, query_text),
                contains_filter(Application.name, query_text),
            )
        )
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if status:
        query = query.filter(Vulnerability.status == status)
    if owasp:
        query = query.filter(Vulnerability.owasp_category == owasp)
    return query


def _csv_cell(value):
    """Return a spreadsheet-safe cell.

    A leading ``=``, ``+``, ``-`` or ``@`` makes Excel and Sheets treat the text
    as a formula, so exported findings are prefixed with an apostrophe to keep
    them inert (CSV / formula injection).
    """
    if value is None:
        return ""
    text = str(value)
    if text[:1] in ("=", "+", "-", "@"):
        return "'" + text
    return text


@vulnerabilities_bp.route("/")
@login_required
def index():
    query_text = search_query()
    severity, status, owasp = _filters()
    query = _filtered_query(query_text, severity, status, owasp)
    vulns = paginate(query)
    return render_template(
        "dashboard/vulnerabilities.html",
        vulnerabilities=vulns.items,
        pagination=vulns,
        can_create=bool(application_choices()) and not current_user.is_client,
        q=query_text,
        selected_severity=severity,
        selected_status=status,
        selected_owasp=owasp,
        severities=VULN_SEVERITIES,
        statuses=VULN_STATUSES,
        owasp_options=OWASP_TOP10,
    )


@vulnerabilities_bp.route("/export.csv")
@login_required
def export_csv():
    """Download the findings the caller can see, honouring the active filters."""
    query_text = search_query()
    severity, status, owasp = _filters()
    # ``visible_vulnerabilities`` already returns newest first.
    findings = _filtered_query(query_text, severity, status, owasp).all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "ID",
            "Application",
            "Target URL",
            "Title",
            "Severity",
            "CVSS",
            "OWASP Category",
            "CWE",
            "Status",
            "Description",
            "Evidence",
            "Remediation",
        ]
    )
    for vuln in findings:
        writer.writerow(
            [
                vuln.id,
                _csv_cell(vuln.application.name),
                _csv_cell(vuln.application.target_url),
                _csv_cell(vuln.title),
                _csv_cell(vuln.severity),
                "" if vuln.cvss_score is None else vuln.cvss_score,
                _csv_cell(vuln.owasp_category),
                _csv_cell(vuln.cwe_id),
                _csv_cell(vuln.status),
                _csv_cell(vuln.description),
                _csv_cell(vuln.evidence),
                _csv_cell(vuln.remediation),
            ]
        )

    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"},
    )


@vulnerabilities_bp.route("/new", methods=["GET", "POST"])
@login_required
def create():
    if current_user.is_client:
        abort(403)
    apps = application_choices()
    if not apps:
        flash("Add an application before logging vulnerabilities.", "info")
        return redirect(url_for("applications.create"))

    preset_app_id = request.args.get("app_id", type=int)
    if request.method == "POST":
        values = _fields()
        if values["cvss_score"] is not None:
            derived = severity_from_cvss(values["cvss_score"])
            if derived:
                values["severity"] = derived
        errors, application = _validate(values)
        if application and not can_conduct_testing(current_user, application):
            errors.append("You cannot log vulnerabilities for this application.")
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template(
                "dashboard/vulnerability_form.html",
                **_form_context(apps, vulnerability=None, **values),
            )
        vuln = Vulnerability(**values)
        db.session.add(vuln)
        db.session.commit()
        flash("Vulnerability logged.", "success")
        return redirect(url_for("vulnerabilities.index"))

    return render_template(
        "dashboard/vulnerability_form.html",
        **_form_context(apps, vulnerability=None, app_id=preset_app_id),
    )


@vulnerabilities_bp.route("/<int:vuln_id>")
@login_required
def detail(vuln_id):
    vuln = db.session.get(Vulnerability, vuln_id)
    if vuln is None:
        abort(404)
    if not can_view_application(current_user, vuln.application):
        abort(403)
    return render_template(
        "dashboard/vulnerability_detail.html",
        vulnerability=vuln,
        can_manage=can_conduct_testing(current_user, vuln.application),
    )


@vulnerabilities_bp.route("/<int:vuln_id>/edit", methods=["GET", "POST"])
@login_required
def edit(vuln_id):
    vuln = db.session.get(Vulnerability, vuln_id)
    if vuln is None:
        abort(404)
    if not can_conduct_testing(current_user, vuln.application):
        abort(403)

    apps = application_choices()
    if request.method == "POST":
        values = _fields()
        values["app_id"] = values["app_id"] or vuln.app_id
        if values["cvss_score"] is not None:
            derived = severity_from_cvss(values["cvss_score"])
            if derived:
                values["severity"] = derived
        errors, _application = _validate(values)
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template(
                "dashboard/vulnerability_form.html",
                **_form_context(apps, vulnerability=vuln, **values),
            )
        for key, value in values.items():
            setattr(vuln, key, value)
        db.session.commit()
        flash("Vulnerability updated.", "success")
        return redirect(url_for("vulnerabilities.index"))

    return render_template(
        "dashboard/vulnerability_form.html",
        **_form_context(apps, vulnerability=vuln),
    )


@vulnerabilities_bp.route("/<int:vuln_id>/delete", methods=["POST"])
@login_required
def delete(vuln_id):
    vuln = db.session.get(Vulnerability, vuln_id)
    if vuln is None:
        abort(404)
    if not can_conduct_testing(current_user, vuln.application):
        abort(403)
    db.session.delete(vuln)
    db.session.commit()
    flash("Vulnerability deleted.", "success")
    return redirect(url_for("vulnerabilities.index"))
