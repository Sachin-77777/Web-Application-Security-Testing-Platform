from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import or_

from access import (
    can_conduct_testing,
    can_manage_application,
    get_application_or_403,
    visible_applications,
)
from auth import login_required
from extensions import db
from models import Application
from util import contains_filter, form_str, is_http_url, paginate, search_query

applications_bp = Blueprint("applications", __name__, url_prefix="/applications")


def _validate(name, target_url):
    errors = []
    if not name or len(name) > 150:
        errors.append("Name is required and must be 150 characters or fewer.")
    if not is_http_url(target_url) or len(target_url) > 2048:
        errors.append("Target URL must be a valid http or https address.")
    return errors


def status_timeline(application):
    """Return the engagement progress as a list of ``{label, done}`` steps.

    Shown on the application page so a client can see where their submission
    has got to instead of just a "Pending" badge.
    """
    tests = application.test_cases
    has_tests = bool(tests)
    testing_done = has_tests and all(item.status != "Pending" for item in tests)
    return [
        {"label": "Submitted", "done": True},
        {"label": "Tests planned", "done": has_tests},
        {"label": "Testing complete", "done": testing_done},
        {"label": "Report ready", "done": bool(application.reports)},
    ]


@applications_bp.route("/")
@login_required
def index():
    query_text = search_query()
    query = visible_applications()
    if query_text:
        query = query.filter(
            or_(
                contains_filter(Application.name, query_text),
                contains_filter(Application.target_url, query_text),
                contains_filter(Application.description, query_text),
            )
        )
    apps = paginate(query)
    return render_template(
        "dashboard/applications.html",
        applications=apps.items,
        pagination=apps,
        q=query_text,
    )


@applications_bp.route("/new", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        name = form_str("name")
        target_url = form_str("target_url")
        description = form_str("description") or None
        errors = _validate(name, target_url)
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template(
                "dashboard/application_form.html",
                application=None,
                name=name,
                target_url=target_url,
                description=description or "",
            )
        application = Application(
            name=name,
            target_url=target_url,
            description=description,
            owner_id=current_user.id,
        )
        db.session.add(application)
        db.session.commit()
        flash("Application added.", "success")
        return redirect(url_for("applications.detail", app_id=application.id))
    return render_template("dashboard/application_form.html", application=None)


@applications_bp.route("/<int:app_id>")
@login_required
def detail(app_id):
    application = get_application_or_403(app_id)
    return render_template(
        "dashboard/application_detail.html",
        application=application,
        timeline=status_timeline(application),
        can_manage=can_manage_application(current_user, application),
        can_test=can_conduct_testing(current_user, application),
    )


@applications_bp.route("/<int:app_id>/edit", methods=["GET", "POST"])
@login_required
def edit(app_id):
    application = get_application_or_403(app_id)
    if not can_manage_application(current_user, application):
        flash("You can view this application but cannot edit it.", "error")
        return redirect(url_for("applications.detail", app_id=app_id))

    if request.method == "POST":
        name = form_str("name")
        target_url = form_str("target_url")
        description = form_str("description") or None
        errors = _validate(name, target_url)
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template(
                "dashboard/application_form.html",
                application=application,
                name=name,
                target_url=target_url,
                description=description or "",
            )
        application.name = name
        application.target_url = target_url
        application.description = description
        db.session.commit()
        flash("Application updated.", "success")
        return redirect(url_for("applications.detail", app_id=application.id))

    return render_template("dashboard/application_form.html", application=application)


@applications_bp.route("/<int:app_id>/delete", methods=["POST"])
@login_required
def delete(app_id):
    application = get_application_or_403(app_id)
    if not can_manage_application(current_user, application):
        flash("You cannot delete this application.", "error")
        return redirect(url_for("applications.detail", app_id=app_id))
    db.session.delete(application)
    db.session.commit()
    flash("Application deleted.", "success")
    return redirect(url_for("applications.index"))
