from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import or_

from access import (
    application_choices,
    can_conduct_testing,
    can_edit_test_case,
    can_view_application,
    get_application_or_403,
    visible_test_cases,
)
from auth import login_required
from constants import TEST_CATEGORIES, TEST_STATUSES
from extensions import db
from models import Application, TestCase, User
from util import contains_filter, form_int, form_str, paginate, search_query

test_cases_bp = Blueprint("test_cases", __name__, url_prefix="/test-cases")


def _assignee_choices():
    return User.query.order_by(User.username).all()


def _validate(app_id, test_name, category, status, assigned_to):
    errors = []
    application = None
    if app_id:
        application = get_application_or_403(app_id)
        if not can_conduct_testing(current_user, application):
            if assigned_to not in (None, current_user.id):
                errors.append("You can only assign tests to yourself.")
    else:
        errors.append("Select a target application.")

    if not test_name or len(test_name) > 200:
        errors.append("Test name is required and must be 200 characters or fewer.")
    if category not in TEST_CATEGORIES:
        errors.append("Select a valid test category.")
    if status not in TEST_STATUSES:
        errors.append("Select a valid test status.")
    if assigned_to is not None:
        allowed_ids = {user.id for user in _assignee_choices()}
        if assigned_to not in allowed_ids:
            errors.append("Invalid assignee.")
    return errors, application


@test_cases_bp.route("/")
@login_required
def index():
    query_text = search_query()
    query = visible_test_cases().join(Application)
    if query_text:
        query = query.filter(
            or_(
                contains_filter(TestCase.test_name, query_text),
                contains_filter(TestCase.category, query_text),
                contains_filter(Application.name, query_text),
            )
        )
    tests = paginate(query)
    assignees = _assignee_choices() if current_user.is_admin else []
    return render_template(
        "dashboard/test_cases.html",
        test_cases=tests.items,
        pagination=tests,
        can_create=bool(application_choices()) and not current_user.is_client,
        q=query_text,
        assignees=assignees,
    )


@test_cases_bp.route("/new", methods=["GET", "POST"])
@login_required
def create():
    if current_user.is_client:
        abort(403)
    apps = application_choices()
    if not apps:
        flash("Add an application before creating test cases.", "info")
        return redirect(url_for("applications.create"))

    preset_app_id = request.args.get("app_id", type=int)
    if request.method == "POST":
        app_id = form_int("app_id")
        test_name = form_str("test_name")
        category = form_str("category")
        status = form_str("status") or "Pending"
        assigned_to = form_int("assigned_to")
        errors, application = _validate(app_id, test_name, category, status, assigned_to)
        if application and not can_conduct_testing(current_user, application):
            errors.append("You cannot add tests to this application.")
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template(
                "dashboard/test_case_form.html",
                test_case=None,
                applications=apps,
                assignees=_assignee_choices(),
                categories=TEST_CATEGORIES,
                statuses=TEST_STATUSES,
                app_id=app_id,
                test_name=test_name,
                category=category,
                status=status,
                assigned_to=assigned_to,
            )
        test_case = TestCase(
            app_id=app_id,
            test_name=test_name,
            category=category,
            status=status,
            assigned_to=assigned_to,
        )
        db.session.add(test_case)
        db.session.commit()
        flash("Test case created.", "success")
        return redirect(url_for("test_cases.index"))

    return render_template(
        "dashboard/test_case_form.html",
        test_case=None,
        applications=apps,
        assignees=_assignee_choices(),
        categories=TEST_CATEGORIES,
        statuses=TEST_STATUSES,
        app_id=preset_app_id,
    )


@test_cases_bp.route("/<int:test_id>")
@login_required
def detail(test_id):
    test_case = db.session.get(TestCase, test_id)
    if test_case is None:
        abort(404)
    if not can_view_application(current_user, test_case.application):
        abort(403)
    return render_template(
        "dashboard/test_case_detail.html",
        test_case=test_case,
        can_edit=can_edit_test_case(current_user, test_case),
        can_manage=can_conduct_testing(current_user, test_case.application),
    )


@test_cases_bp.route("/<int:test_id>/edit", methods=["GET", "POST"])
@login_required
def edit(test_id):
    test_case = db.session.get(TestCase, test_id)
    if test_case is None:
        abort(404)
    if not can_edit_test_case(current_user, test_case):
        abort(403)

    apps = application_choices()
    if request.method == "POST":
        app_id = form_int("app_id") or test_case.app_id
        test_name = form_str("test_name")
        category = form_str("category")
        status = form_str("status") or "Pending"
        assigned_to = form_int("assigned_to")
        manage = can_conduct_testing(current_user, test_case.application)
        if not manage:
            app_id = test_case.app_id
            test_name = test_case.test_name
            category = test_case.category
            assigned_to = test_case.assigned_to
        errors, _application = _validate(app_id, test_name, category, status, assigned_to)
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template(
                "dashboard/test_case_form.html",
                test_case=test_case,
                applications=apps,
                assignees=_assignee_choices(),
                categories=TEST_CATEGORIES,
                statuses=TEST_STATUSES,
                app_id=app_id,
                test_name=test_name,
                category=category,
                status=status,
                assigned_to=assigned_to,
                status_only=not manage,
            )
        test_case.app_id = app_id
        test_case.test_name = test_name
        test_case.category = category
        test_case.status = status
        test_case.assigned_to = assigned_to
        db.session.commit()
        flash("Test case updated.", "success")
        return redirect(url_for("test_cases.index"))

    return render_template(
        "dashboard/test_case_form.html",
        test_case=test_case,
        applications=apps,
        assignees=_assignee_choices(),
        categories=TEST_CATEGORIES,
        statuses=TEST_STATUSES,
        status_only=not can_conduct_testing(current_user, test_case.application),
    )


@test_cases_bp.route("/<int:test_id>/assign-to-me", methods=["POST"])
@login_required
def assign_to_me(test_id):
    """Let a tester claim a test case with a single click."""
    test_case = db.session.get(TestCase, test_id)
    if test_case is None:
        abort(404)
    if not can_edit_test_case(current_user, test_case):
        abort(403)
    test_case.assigned_to = current_user.id
    db.session.commit()
    flash("Test case assigned to you.", "success")
    return redirect(url_for("test_cases.index"))


@test_cases_bp.route("/<int:test_id>/delete", methods=["POST"])
@login_required
def delete(test_id):
    test_case = db.session.get(TestCase, test_id)
    if test_case is None:
        abort(404)
    if not can_conduct_testing(current_user, test_case.application):
        abort(403)
    db.session.delete(test_case)
    db.session.commit()
    flash("Test case deleted.", "success")
    return redirect(url_for("test_cases.index"))


@test_cases_bp.route("/bulk-assign", methods=["POST"])
@login_required
def bulk_assign():
    """Allow admins to assign multiple test cases to a user at once."""
    if not current_user.is_admin:
        abort(403)
    
    test_ids = request.form.getlist("test_ids")
    assign_to_id = form_int("assign_to")
    
    if not test_ids:
        flash("No test cases selected.", "error")
        return redirect(url_for("test_cases.index"))
    
    if assign_to_id is None:
        flash("Please select an assignee.", "error")
        return redirect(url_for("test_cases.index"))
    
    allowed_ids = {user.id for user in _assignee_choices()}
    if assign_to_id not in allowed_ids:
        flash("Invalid assignee.", "error")
        return redirect(url_for("test_cases.index"))
    
    count = 0
    for test_id in test_ids:
        test_case = db.session.get(TestCase, int(test_id))
        if test_case:
            test_case.assigned_to = assign_to_id
            count += 1
    
    db.session.commit()
    flash(f"{count} test case(s) assigned.", "success")
    return redirect(url_for("test_cases.index"))
