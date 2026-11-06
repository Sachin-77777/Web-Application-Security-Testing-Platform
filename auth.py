import re
import secrets
from datetime import timedelta
from functools import wraps

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user,
)
from sqlalchemy import or_

from constants import USER_ROLES
from extensions import db, login_manager
from mailer import send_password_reset_code
from models import PasswordResetOTP, User, utcnow_naive
from rate_limit import key_for, locked_seconds, register_failure, reset

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,80}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LENGTH = 8
UPPERCASE_RE = re.compile(r"[A-Z]")
DIGIT_RE = re.compile(r"[0-9]")
SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")
OTP_RE = re.compile(r"^[0-9]{6}$")


@login_manager.user_loader
def load_user(user_id):
    if not user_id:
        return None
    return db.session.get(User, int(user_id))


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def _field(name):
    return (request.form.get(name) or "").strip()


def password_policy_errors(password):
    """Strength rules shared by signup and password reset.

    Returned one rule at a time so the user sees every problem at once rather
    than fixing them one round trip at a time.
    """
    errors = []

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")

    if not UPPERCASE_RE.search(password):
        errors.append("Password must include at least one uppercase letter.")

    if not DIGIT_RE.search(password):
        errors.append("Password must include at least one number.")

    if not SPECIAL_RE.search(password):
        errors.append("Password must include at least one special character.")

    return errors


def validate_registration(username, email, password, confirm_password):
    errors = []

    if not USERNAME_RE.match(username):
        errors.append(
            "Username must be 3–80 characters and contain only letters, numbers, or underscores."
        )

    if not EMAIL_RE.match(email) or len(email) > 255:
        errors.append("Enter a valid email address.")

    errors.extend(password_policy_errors(password))

    if password != confirm_password:
        errors.append("Password confirmation does not match.")

    if username and User.query.filter_by(username=username).first():
        errors.append("That username is already taken.")

    if email and User.query.filter_by(email=email).first():
        errors.append("That email is already registered.")

    return errors


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        username = _field("username")
        email = _field("email").lower()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        errors = validate_registration(username, email, password, confirm_password)
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template(
                "auth/register.html",
                username=username,
                email=email,
            )

        # Public signup always gets the least-privilege role. The security team
        # ("user") and admins are provisioned deliberately, never self-assigned.
        user = User(username=username, email=email, role="client")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created. You can now sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        identifier = _field("identifier")
        password = request.form.get("password") or ""
        remember = request.form.get("remember") == "on"
        attempt_key = key_for(identifier)

        remaining = locked_seconds(attempt_key)
        if remaining:
            flash(
                f"Too many failed attempts. Please try again in {remaining} seconds.",
                "error",
            )
            return render_template("auth/login.html", identifier=identifier), 429

        user = User.query.filter(
            or_(User.username == identifier, User.email == identifier.lower())
        ).first()

        if user is None or not user.check_password(password):
            if register_failure(attempt_key):
                flash(
                    "Too many failed attempts. This account is temporarily locked.",
                    "error",
                )
                return render_template("auth/login.html", identifier=identifier), 429
            flash("Invalid username/email or password.", "error")
            return render_template("auth/login.html", identifier=identifier), 401

        reset(attempt_key)
        login_user(user, remember=remember)
        flash(f"Welcome back, {user.username}.", "success")
        next_url = request.args.get("next")
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("dashboard.home"))

    return render_template("auth/login.html")


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        email = _field("email").lower()

        if not EMAIL_RE.match(email) or len(email) > 255:
            flash("Enter the email address on your account.", "error")
            return render_template("auth/forgot_password.html", email=email)

        # Its own counter, separate from the login one, so a burst of reset
        # requests can never be used to lock somebody out of signing in.
        throttle_key = key_for(f"password-reset:{email}")
        if locked_seconds(throttle_key) or register_failure(throttle_key):
            flash("Too many reset requests. Please wait a few minutes.", "error")
            return render_template("auth/forgot_password.html", email=email), 429

        user = User.query.filter_by(email=email).first()
        if user is not None:
            code = f"{secrets.randbelow(1_000_000):06d}"
            record = PasswordResetOTP(
                user_id=user.id,
                expires_at=utcnow_naive()
                + timedelta(minutes=current_app.config["PASSWORD_RESET_OTP_MINUTES"]),
            )
            record.set_code(code)
            db.session.add(record)
            db.session.commit()
            send_password_reset_code(user.email, code)

        # Identical response whether or not the address exists, so this page
        # cannot be used to work out which emails are registered.
        flash(
            "If that email address belongs to an account, a reset code is on its way.",
            "success",
        )
        return redirect(url_for("auth.reset_password", email=email))

    return render_template("auth/forgot_password.html")


@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    email = _field("email").lower() or (request.args.get("email") or "").strip().lower()

    if request.method == "POST":
        code = _field("code")
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not OTP_RE.match(code):
            flash("Enter the six-digit code from your email.", "error")
            return render_template("auth/reset_password.html", email=email)

        errors = password_policy_errors(password)
        if password != confirm_password:
            errors.append("Password confirmation does not match.")
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("auth/reset_password.html", email=email)

        user = User.query.filter_by(email=email).first()
        # Only the newest code counts: once it expires or runs out of attempts
        # the user has to request a fresh one, rather than falling back to an
        # older code that is still lying around.
        record = (
            max(user.password_reset_codes, key=lambda item: item.id) if user else None
        )
        max_attempts = current_app.config["PASSWORD_RESET_MAX_ATTEMPTS"]

        if record is None or not record.is_usable(max_attempts):
            flash("That code is invalid or has expired. Request a new one.", "error")
            return render_template("auth/reset_password.html", email=email), 400

        if not record.check_code(code):
            record.attempts += 1
            db.session.commit()
            flash("That code is invalid or has expired. Request a new one.", "error")
            return render_template("auth/reset_password.html", email=email), 400

        record.consumed_at = utcnow_naive()
        user.set_password(password)
        db.session.commit()

        flash("Your password has been updated. You can sign in now.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", email=email)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/users")
@admin_required
def users():
    accounts = User.query.order_by(User.created_at.desc()).all()
    return render_template("auth/users.html", users=accounts, roles=USER_ROLES)


@auth_bp.route("/users/<int:user_id>/role", methods=["POST"])
@admin_required
def update_role(user_id):
    account = db.session.get(User, user_id)
    if account is None:
        abort(404)

    role = _field("role")
    if role not in USER_ROLES:
        flash("Select a valid role.", "error")
        return redirect(url_for("auth.users"))

    if account.id == current_user.id and role != "admin":
        flash("You cannot remove your own admin access.", "error")
        return redirect(url_for("auth.users"))

    account.role = role
    db.session.commit()
    flash(f"{account.username} is now a {role}.", "success")
    return redirect(url_for("auth.users"))
