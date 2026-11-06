from flask import Blueprint, render_template
from flask_login import current_user

from access import application_choices, visible_applications, visible_test_cases, visible_vulnerabilities
from auth import login_required
from models import Report

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@login_required
def home():
    apps = visible_applications().all()
    tests = visible_test_cases().all()
    vulns = visible_vulnerabilities().all()
    allowed_ids = [application.id for application in application_choices()]
    reports_query = Report.query.order_by(Report.created_at.desc())
    if not current_user.is_admin:
        reports_query = reports_query.filter(Report.app_id.in_(allowed_ids or [0]))
    reports = reports_query.limit(8).all()

    return render_template(
        "dashboard/home.html",
        applications=apps,
        test_cases=tests,
        vulnerabilities=vulns,
        reports=reports,
        open_vulns=sum(1 for item in vulns if item.status == "Open"),
        failed_tests=sum(1 for item in tests if item.status == "Failed"),
        severity_counts={
            level: sum(1 for item in vulns if item.severity == level)
            for level in ("Critical", "High", "Medium", "Low")
        },
    )
