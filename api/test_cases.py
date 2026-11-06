"""JSON endpoints for the test cases resource.

Rules mirror the HTML blueprint: an owner (or admin) manages a test case
completely, while an assigned tester may only change its ``status``.
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import current_user as api_user
from flask_jwt_extended import jwt_required

from access import (
    can_conduct_testing,
    can_view_application,
    visible_test_cases,
)
from api.helpers import error, field_int, field_str, json_body
from api.serializers import test_case_dict
from constants import TEST_CATEGORIES, TEST_STATUSES
from extensions import db
from models import Application, TestCase, User

test_cases_api_bp = Blueprint("api_test_cases", __name__, url_prefix="/test-cases")


def _assignee_error(assigned_to):
    if assigned_to is None:
        return None
    if db.session.get(User, assigned_to) is None:
        return "assigned_to must reference an existing user."
    return None


def _validate_create(data):
    values, errors = {}, []

    app_id = field_int(data, "app_id")
    application = db.session.get(Application, app_id) if app_id else None
    if application is None:
        errors.append("app_id must reference an existing application.")
    elif not can_conduct_testing(api_user, application):
        errors.append("You cannot add test cases to this application.")
    else:
        values["app_id"] = application.id

    test_name = field_str(data, "test_name")
    if not test_name or len(test_name) > 200:
        errors.append("test_name is required and must be 200 characters or fewer.")
    else:
        values["test_name"] = test_name

    category = field_str(data, "category")
    if category not in TEST_CATEGORIES:
        errors.append("category must be one of: " + ", ".join(TEST_CATEGORIES) + ".")
    else:
        values["category"] = category

    status = field_str(data, "status") or "Pending"
    if status not in TEST_STATUSES:
        errors.append("status must be one of: " + ", ".join(TEST_STATUSES) + ".")
    else:
        values["status"] = status

    assigned_to = field_int(data, "assigned_to")
    assignee_problem = _assignee_error(assigned_to)
    if assignee_problem:
        errors.append(assignee_problem)
    else:
        values["assigned_to"] = assigned_to

    return values, errors


def _validate_update(data, test_case):
    values, errors = {}, []

    if not can_conduct_testing(api_user, test_case.application):
        # An assigned tester owns the result of the test, nothing else.
        extra = set(data) - {"status"}
        if extra:
            return {}, ["As an assigned tester you may only update status."]

    if "app_id" in data:
        app_id = field_int(data, "app_id")
        application = db.session.get(Application, app_id) if app_id else None
        if application is None:
            errors.append("app_id must reference an existing application.")
        elif not can_conduct_testing(api_user, application):
            errors.append("You cannot move a test case to that application.")
        else:
            values["app_id"] = application.id

    if "test_name" in data:
        test_name = field_str(data, "test_name")
        if not test_name or len(test_name) > 200:
            errors.append("test_name is required and must be 200 characters or fewer.")
        else:
            values["test_name"] = test_name

    if "category" in data:
        category = field_str(data, "category")
        if category not in TEST_CATEGORIES:
            errors.append("category must be one of: " + ", ".join(TEST_CATEGORIES) + ".")
        else:
            values["category"] = category

    if "status" in data:
        status = field_str(data, "status")
        if status not in TEST_STATUSES:
            errors.append("status must be one of: " + ", ".join(TEST_STATUSES) + ".")
        else:
            values["status"] = status

    if "assigned_to" in data:
        assigned_to = field_int(data, "assigned_to")
        assignee_problem = _assignee_error(assigned_to)
        if assignee_problem:
            errors.append(assignee_problem)
        else:
            values["assigned_to"] = assigned_to

    return values, errors


@test_cases_api_bp.get("", strict_slashes=False)
@jwt_required()
def index():
    test_cases = visible_test_cases(api_user).all()
    return jsonify(
        {
            "count": len(test_cases),
            "test_cases": [test_case_dict(item) for item in test_cases],
        }
    )


@test_cases_api_bp.get("/<int:test_id>")
@jwt_required()
def detail(test_id):
    test_case = db.session.get(TestCase, test_id)
    if test_case is None:
        return error("Test case not found.", 404)
    if not can_view_application(api_user, test_case.application):
        return error("You cannot view this test case.", 403)
    return jsonify({"test_case": test_case_dict(test_case)})


@test_cases_api_bp.post("", strict_slashes=False)
@jwt_required()
def create():
    values, errors = _validate_create(json_body())
    if errors:
        return error("Validation failed.", 422, errors)

    test_case = TestCase(**values)
    db.session.add(test_case)
    db.session.commit()
    return jsonify({"test_case": test_case_dict(test_case)}), 201


@test_cases_api_bp.route("/<int:test_id>", methods=["PUT", "PATCH"])
@jwt_required()
def update(test_id):
    test_case = db.session.get(TestCase, test_id)
    if test_case is None:
        return error("Test case not found.", 404)
    if not can_view_application(api_user, test_case.application):
        return error("You cannot view this test case.", 403)

    data = json_body()
    if not data:
        return error("A JSON object body is required.")

    if request.method == "PUT" and can_conduct_testing(api_user, test_case.application):
        # A full replace still has to send the identifying fields.
        data = {"app_id": test_case.app_id, "test_name": test_case.test_name,
                "category": test_case.category, "assigned_to": test_case.assigned_to, **data}

    values, errors = _validate_update(data, test_case)
    if errors:
        return error("Validation failed.", 422, errors)

    for key, value in values.items():
        setattr(test_case, key, value)
    db.session.commit()
    return jsonify({"test_case": test_case_dict(test_case)})


@test_cases_api_bp.delete("/<int:test_id>")
@jwt_required()
def delete(test_id):
    test_case = db.session.get(TestCase, test_id)
    if test_case is None:
        return error("Test case not found.", 404)
    if not can_conduct_testing(api_user, test_case.application):
        return error("You cannot delete this test case.", 403)

    db.session.delete(test_case)
    db.session.commit()
    return jsonify({"message": "Test case deleted.", "id": test_id})
