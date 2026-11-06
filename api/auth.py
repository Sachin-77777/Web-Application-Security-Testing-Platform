"""JWT authentication endpoints for the JSON API.

Flow: ``POST /api/auth/login`` returns a short-lived access token and a
long-lived refresh token. Send the access token as
``Authorization: Bearer <token>`` on every other API call, and use
``POST /api/auth/refresh`` to get a new access token without sending the
password again.
"""

from flask import Blueprint, current_app, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from sqlalchemy import or_

from api.blocklist import revoke
from api.helpers import error, field_str, json_body
from api.serializers import user_dict
from extensions import db
from models import User
from rate_limit import key_for, locked_seconds, register_failure, reset

auth_api_bp = Blueprint("api_auth", __name__, url_prefix="/auth")


def _access_token(user):
    return create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "username": user.username},
    )


def _resolve_user():
    """Load the account named by the token, or None if it has been deleted."""
    identity = get_jwt_identity()
    try:
        user_id = int(identity)
    except (TypeError, ValueError):
        return None
    return db.session.get(User, user_id)


@auth_api_bp.post("/login")
def login():
    data = json_body()
    identifier = field_str(data, "username") or field_str(data, "email")
    raw_password = data.get("password")
    password = raw_password if isinstance(raw_password, str) else ""

    if not identifier or not password:
        return error("A username (or email) and password are required.")

    attempt_key = key_for(identifier)
    remaining = locked_seconds(attempt_key)
    if remaining:
        return error(
            "Too many failed attempts. Try again later.",
            429,
            details={"retry_after": remaining},
        )

    user = User.query.filter(
        or_(User.username == identifier, User.email == identifier.lower())
    ).first()

    if user is None or not user.check_password(password):
        if register_failure(attempt_key):
            return error(
                "Too many failed attempts. This account is temporarily locked.",
                429,
                details={"retry_after": locked_seconds(attempt_key)},
            )
        return error("Invalid credentials.", 401)

    reset(attempt_key)
    expires = current_app.config["JWT_ACCESS_TOKEN_EXPIRES"]
    return jsonify(
        {
            "access_token": _access_token(user),
            "refresh_token": create_refresh_token(identity=str(user.id)),
            "token_type": "Bearer",
            "expires_in": int(expires.total_seconds()),
            "user": user_dict(user),
        }
    )


@auth_api_bp.post("/refresh")
@jwt_required(refresh=True)
def refresh():
    user = _resolve_user()
    if user is None:
        return error("The account for this token no longer exists.", 401)
    return jsonify({"access_token": _access_token(user)})


@auth_api_bp.get("/me")
@jwt_required()
def me():
    user = _resolve_user()
    if user is None:
        return error("The account for this token no longer exists.", 401)
    return jsonify({"user": user_dict(user)})


@auth_api_bp.post("/logout")
@jwt_required(verify_type=False)
def logout():
    revoke(get_jwt())
    return jsonify({"message": "Token revoked. It will no longer be accepted."})
