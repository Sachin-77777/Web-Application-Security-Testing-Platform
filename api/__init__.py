"""JSON REST API, mounted under ``/api``.

Authentication is JWT bearer tokens, separate from the session cookie used by
the Jinja pages. Authorisation reuses ``access.py``, so the API and the HTML
UI always agree on visibility and write permissions.

Exposed URL space::

    POST   /api/auth/login
    POST   /api/auth/refresh
    GET    /api/auth/me
    POST   /api/auth/logout

    GET    /api/applications
    POST   /api/applications
    GET    /api/applications/<id>
    PUT    /api/applications/<id>
    PATCH  /api/applications/<id>
    DELETE /api/applications/<id>

    ... the same shape for /api/test-cases, /api/vulnerabilities and /api/reports
"""

from flask import Blueprint, jsonify
from werkzeug.exceptions import HTTPException

from extensions import csrf

from api.applications import applications_api_bp
from api.auth import auth_api_bp
from api.reports import reports_api_bp
from api.test_cases import test_cases_api_bp
from api.vulnerabilities import vulnerabilities_api_bp

api_bp = Blueprint("api", __name__, url_prefix="/api")

_api_blueprints = (
    auth_api_bp,
    applications_api_bp,
    test_cases_api_bp,
    vulnerabilities_api_bp,
    reports_api_bp,
)

for _blueprint in _api_blueprints:
    api_bp.register_blueprint(_blueprint)
    # Bearer-token clients cannot read a CSRF cookie, and they do not rely on
    # the browser automatically attaching credentials, so CSRF does not apply.
    csrf.exempt(_blueprint)


@api_bp.errorhandler(HTTPException)
def handle_http_error(exc):
    return jsonify({"error": exc.name, "status": exc.code}), exc.code
