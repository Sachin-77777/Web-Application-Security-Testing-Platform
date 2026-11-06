"""JSON endpoints for the vulnerabilities resource.

Severity is kept consistent with the HTML form: when a CVSS score is supplied,
the qualitative severity is derived from it (CVSS v3.1 bands in ``constants.py``).
"""

import re

from flask import Blueprint, jsonify, request
from flask_jwt_extended import current_user as api_user
from flask_jwt_extended import jwt_required
from sqlalchemy import or_

from access import (
    can_conduct_testing,
    can_view_application,
    visible_vulnerabilities,
)
from api.helpers import error, field_float, field_int, field_str, json_body
from api.serializers import vulnerability_dict
from constants import (
    OWASP_TOP10,
    VULN_SEVERITIES,
    VULN_STATUSES,
    severity_from_cvss,
)
from extensions import db
from models import Application, Vulnerability
from util import contains_filter, search_query

vulnerabilities_api_bp = Blueprint("api_vulnerabilities", __name__, url_prefix="/vulnerabilities")

CWE_PATTERN = re.compile(r"^CWE-\d+$")


def _validate(data, vulnerability=None):
    """Validate a vulnerability payload (PATCH semantics when editing)."""
    values, errors = {}, []
    full = vulnerability is None

    if full or "app_id" in data:
        app_id = field_int(data, "app_id")
        application = db.session.get(Application, app_id) if app_id else None
        if application is None:
            errors.append("app_id must reference an existing application.")
        elif not can_conduct_testing(api_user, application):
            errors.append("You cannot log vulnerabilities for this application.")
        else:
            values["app_id"] = application.id

    if full or "title" in data:
        title = field_str(data, "title")
        if not title or len(title) > 255:
            errors.append("title is required and must be 255 characters or fewer.")
        else:
            values["title"] = title

    cvss_score = field_float(data, "cvss_score")
    if cvss_score is not None and not 0.0 <= cvss_score <= 10.0:
        errors.append("cvss_score must be between 0.0 and 10.0.")
        cvss_score = None
    if full or "cvss_score" in data:
        values["cvss_score"] = cvss_score

    derived = severity_from_cvss(cvss_score)
    if derived:
        values["severity"] = derived
    elif full or "severity" in data:
        severity = field_str(data, "severity")
        if severity not in VULN_SEVERITIES:
            errors.append("severity must be one of: " + ", ".join(VULN_SEVERITIES) + ".")
        else:
            values["severity"] = severity

    if full or "status" in data:
        status = field_str(data, "status") or "Open"
        if status not in VULN_STATUSES:
            errors.append("status must be one of: " + ", ".join(VULN_STATUSES) + ".")
        else:
            values["status"] = status

    if full or "description" in data:
        values["description"] = field_str(data, "description") or None

    if full or "owasp_category" in data:
        owasp_category = field_str(data, "owasp_category") or None
        if owasp_category and owasp_category not in OWASP_TOP10:
            errors.append("owasp_category must be a known OWASP Top 10 value.")
        else:
            values["owasp_category"] = owasp_category

    if full or "cwe_id" in data:
        cwe_id = (field_str(data, "cwe_id") or "").upper() or None
        if cwe_id and not CWE_PATTERN.match(cwe_id):
            errors.append("cwe_id must look like CWE-79.")
        else:
            values["cwe_id"] = cwe_id

    if full or "evidence" in data:
        values["evidence"] = field_str(data, "evidence") or None

    if full or "remediation" in data:
        values["remediation"] = field_str(data, "remediation") or None

    return values, errors


@vulnerabilities_api_bp.get("", strict_slashes=False)
@jwt_required()
def index():
    term = search_query()
    query = visible_vulnerabilities(api_user)
    if term:
        query = query.filter(
            or_(
                contains_filter(Vulnerability.title, term),
                contains_filter(Vulnerability.description, term),
            )
        )
    vulnerabilities = query.all()
    return jsonify(
        {
            "count": len(vulnerabilities),
            "vulnerabilities": [vulnerability_dict(item) for item in vulnerabilities],
        }
    )


@vulnerabilities_api_bp.get("/<int:vuln_id>")
@jwt_required()
def detail(vuln_id):
    vulnerability = db.session.get(Vulnerability, vuln_id)
    if vulnerability is None:
        return error("Vulnerability not found.", 404)
    if not can_view_application(api_user, vulnerability.application):
        return error("You cannot view this vulnerability.", 403)
    return jsonify({"vulnerability": vulnerability_dict(vulnerability)})


@vulnerabilities_api_bp.post("", strict_slashes=False)
@jwt_required()
def create():
    values, errors = _validate(json_body())
    if errors:
        return error("Validation failed.", 422, errors)

    vulnerability = Vulnerability(**values)
    db.session.add(vulnerability)
    db.session.commit()
    return jsonify({"vulnerability": vulnerability_dict(vulnerability)}), 201


@vulnerabilities_api_bp.route("/<int:vuln_id>", methods=["PUT", "PATCH"])
@jwt_required()
def update(vuln_id):
    vulnerability = db.session.get(Vulnerability, vuln_id)
    if vulnerability is None:
        return error("Vulnerability not found.", 404)
    if not can_conduct_testing(api_user, vulnerability.application):
        return error("You cannot edit this vulnerability.", 403)

    data = json_body()
    if not data:
        return error("A JSON object body is required.")

    values, errors = _validate(data, vulnerability if request.method == "PATCH" else None)
    if errors:
        return error("Validation failed.", 422, errors)

    for key, value in values.items():
        setattr(vulnerability, key, value)
    db.session.commit()
    return jsonify({"vulnerability": vulnerability_dict(vulnerability)})


@vulnerabilities_api_bp.delete("/<int:vuln_id>")
@jwt_required()
def delete(vuln_id):
    vulnerability = db.session.get(Vulnerability, vuln_id)
    if vulnerability is None:
        return error("Vulnerability not found.", 404)
    if not can_conduct_testing(api_user, vulnerability.application):
        return error("You cannot delete this vulnerability.", 403)

    db.session.delete(vulnerability)
    db.session.commit()
    return jsonify({"message": "Vulnerability deleted.", "id": vuln_id})
