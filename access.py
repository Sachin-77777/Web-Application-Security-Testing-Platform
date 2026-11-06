from flask import abort
from flask_login import current_user
from sqlalchemy import or_

from extensions import db
from models import Application, TestCase, Vulnerability


def visible_applications(user=None):
    user = user or current_user
    query = Application.query.order_by(Application.created_at.desc())
    if user.is_admin:
        return query
    assigned_ids = db.session.query(TestCase.app_id).filter_by(assigned_to=user.id)
    return query.filter(
        or_(Application.owner_id == user.id, Application.id.in_(assigned_ids))
    )


def get_application_or_403(app_id, user=None):
    user = user or current_user
    application = db.session.get(Application, app_id)
    if application is None:
        abort(404)
    if not can_view_application(user, application):
        abort(403)
    return application


def can_view_application(user, application):
    if user.is_admin:
        return True
    if application.owner_id == user.id:
        return True
    assigned = TestCase.query.filter_by(
        app_id=application.id,
        assigned_to=user.id,
    ).first()
    return assigned is not None


def can_manage_application(user, application):
    return user.is_admin or application.owner_id == user.id


def can_conduct_testing(user, application):
    """Who may author test cases and findings for an application.

    The security team (admin, or a "user" who owns the application) records
    tests and vulnerabilities. A "client" may submit an application and read
    the resulting report, but never write findings of its own.
    """
    if user.is_client:
        return False
    return can_manage_application(user, application)


def visible_test_cases(user=None):
    user = user or current_user
    query = TestCase.query.order_by(TestCase.id.desc())
    if user.is_admin:
        return query
    owned_ids = db.session.query(Application.id).filter_by(owner_id=user.id)
    return query.filter(
        or_(TestCase.app_id.in_(owned_ids), TestCase.assigned_to == user.id)
    )


def can_edit_test_case(user, test_case):
    if user.is_client:
        return False
    if user.is_admin or test_case.application.owner_id == user.id:
        return True
    return test_case.assigned_to == user.id


def visible_vulnerabilities(user=None):
    user = user or current_user
    query = Vulnerability.query.order_by(Vulnerability.id.desc())
    if user.is_admin:
        return query
    owned_ids = db.session.query(Application.id).filter_by(owner_id=user.id)
    assigned_ids = db.session.query(TestCase.app_id).filter_by(assigned_to=user.id)
    return query.filter(
        or_(Vulnerability.app_id.in_(owned_ids), Vulnerability.app_id.in_(assigned_ids))
    )


def application_choices(user=None):
    user = user or current_user
    if user.is_admin:
        return Application.query.order_by(Application.name).all()
    return Application.query.filter_by(owner_id=user.id).order_by(Application.name).all()
