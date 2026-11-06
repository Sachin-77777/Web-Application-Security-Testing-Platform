import os

from flask import Flask, flash, jsonify, redirect, request, url_for
from flask_login import current_user
from werkzeug.exceptions import HTTPException

from api import api_bp
from api.security import register_jwt_callbacks
from applications import applications_bp
from auth import auth_bp
from config import configuration_problems, get_config
from dashboard import dashboard_bp
from extensions import csrf, db, jwt, login_manager
from models import User  # noqa: F401
from report_service import application_score
from reports import reports_bp
from test_cases import test_cases_bp
from vulnerabilities import vulnerabilities_bp


def _is_api_request():
    """True when the request targets the JSON API instead of the HTML UI."""
    return request.path == "/api" or request.path.startswith("/api/")


def create_app(config_name=None):
    environment = config_name or os.environ.get("FLASK_ENV", "development")
    app = Flask(__name__)
    app.config.from_object(get_config(environment))

    # Fail loudly in production if secrets or other hardening flags are missing.
    problems = configuration_problems(app)
    if environment == "production" and problems:
        raise RuntimeError(
            "Refusing to start with insecure configuration: " + " ".join(problems)
        )
    for problem in problems:
        app.logger.warning("Security warning: %s", problem)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    jwt.init_app(app)
    register_jwt_callbacks(jwt)

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(applications_bp)
    app.register_blueprint(test_cases_bp)
    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(api_bp)

    # One scoring function for the report, the dashboard and the list views.
    app.jinja_env.globals["application_score"] = application_score

    uri = app.config.get("SQLALCHEMY_DATABASE_URI") or ""
    if uri.startswith("sqlite"):
        with app.app_context():
            db.create_all()

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.home"))
        return redirect(url_for("auth.login"))

    @app.after_request
    def apply_security_headers(response):
        if not app.config.get("SECURITY_HEADERS_ENABLED", True):
            return response
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "font-src 'self' data: https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'",
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    @app.errorhandler(403)
    def forbidden(error):
        if _is_api_request():
            return jsonify({"error": error.description or "Forbidden.", "status": 403}), 403
        flash("You do not have permission to access that page.", "error")
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.home"))
        return redirect(url_for("auth.login"))

    @app.errorhandler(HTTPException)
    def http_error(error):
        # Unknown /api/... URLs never reach the api blueprint, so answer them
        # with JSON too instead of an HTML error page.
        if _is_api_request():
            return jsonify({"error": error.name, "status": error.code}), error.code
        return error.get_response()

    @app.errorhandler(500)
    def internal_error(error):
        if _is_api_request():
            app.logger.exception("Unhandled API error")
            return jsonify({"error": "Internal server error.", "status": 500}), 500
        return error.get_response()

    return app


app = create_app()


if __name__ == "__main__":
    # Debug is driven by the config, so production never exposes the Werkzeug
    # debugger (Remote Code Execution risk if it were left enabled).
    app.run(debug=app.config.get("DEBUG", False))
