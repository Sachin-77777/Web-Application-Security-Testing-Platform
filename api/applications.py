"""JSON endpoints for the applications resource.

Visibility and write permissions come from ``access.py``, so the API and the
HTML pages can never drift apart on who is allowed to do what.
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import current_user as api_user
from flask_jwt_extended import jwt_required
from sqlalchemy import or_

from access import can_manage_application, get_application_or_403, visible_applications
from api.helpers import error, field_str, json_body
from api.serializers import application_dict
from extensions import db
from models import Application
from util import contains_filter, is_http_url, search_query

applications_api_bp = Blueprint("api_applications", __name__, url_prefix="/applications")


def _validate(data, application=None):
    """Validate an application payload.

    When ``application`` is given, keys that were not sent keep their stored
    value (PATCH semantics). Otherwise name and target_url are required.
    """
    values, errors = {}, []
    full = application is None

    if full or "name" in data:
        name = field_str(data, "name")
        if not name or len(name) > 150:
            errors.append("name is required and must be 150 characters or fewer.")
        else:
            values["name"] = name

    if full or "target_url" in data:
        target_url = field_str(data, "target_url")
        if not is_http_url(target_url) or len(target_url) > 2048:
            errors.append("target_url must be a valid http or https address.")
        else:
            values["target_url"] = target_url

    if full or "description" in data:
        values["description"] = field_str(data, "description") or None

    return values, errors


@applications_api_bp.get("", strict_slashes=False)
@jwt_required()
def index():
    term = search_query()
    query = visible_applications(api_user)
    if term:
        query = query.filter(
            or_(
                contains_filter(Application.name, term),
                contains_filter(Application.target_url, term),
                contains_filter(Application.description, term),
            )
        )
    applications = query.all()
    return jsonify(
        {
            "count": len(applications),
            "applications": [application_dict(item) for item in applications],
        }
    )


@applications_api_bp.get("/<int:app_id>")
@jwt_required()
def detail(app_id):
    application = get_application_or_403(app_id, api_user)
    return jsonify({"application": application_dict(application)})


@applications_api_bp.post("", strict_slashes=False)
@jwt_required()
def create():
    data = json_body()
    values, errors = _validate(data)
    if errors:
        return error("Validation failed.", 422, errors)

    application = Application(owner_id=api_user.id, **values)
    db.session.add(application)
    db.session.commit()
    return jsonify({"application": application_dict(application)}), 201


@applications_api_bp.route("/<int:app_id>", methods=["PUT", "PATCH"])
@jwt_required()
def update(app_id):
    application = get_application_or_403(app_id, api_user)
    if not can_manage_application(api_user, application):
        return error("You can view this application but cannot edit it.", 403)

    data = json_body()
    if not data:
        return error("A JSON object body is required.")

    # PUT replaces the record; PATCH edits only the keys that were sent.
    values, errors = _validate(data, application if request.method == "PATCH" else None)
    if errors:
        return error("Validation failed.", 422, errors)

    for key, value in values.items():
        setattr(application, key, value)
    db.session.commit()
    return jsonify({"application": application_dict(application)})


@applications_api_bp.delete("/<int:app_id>")
@jwt_required()
def delete(app_id):
    application = get_application_or_403(app_id, api_user)
    if not can_manage_application(api_user, application):
        return error("You cannot delete this application.", 403)

    db.session.delete(application)
    db.session.commit()
    return jsonify({"message": "Application deleted.", "id": app_id})
