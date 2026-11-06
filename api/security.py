"""JWT callbacks for the JSON API.

Wires the token manager to the existing ``User`` model and makes every token
failure return JSON instead of the HTML error pages used by the browser app.
"""

from flask import jsonify

from api.blocklist import is_revoked
from extensions import db
from models import User


def register_jwt_callbacks(jwt):
    @jwt.user_lookup_loader
    def load_user_from_token(_header, payload):
        identity = payload.get("sub")
        try:
            user_id = int(identity)
        except (TypeError, ValueError):
            return None
        return db.session.get(User, user_id)

    @jwt.user_lookup_error_loader
    def user_lookup_failed(_header, _payload):
        return jsonify({"error": "The account for this token no longer exists.", "status": 401}), 401

    @jwt.token_in_blocklist_loader
    def token_is_revoked(_header, payload):
        return is_revoked(payload.get("jti"))

    @jwt.unauthorized_loader
    def missing_token(reason):
        return jsonify({"error": "Authorization required.", "details": reason, "status": 401}), 401

    @jwt.invalid_token_loader
    def invalid_token(reason):
        return jsonify({"error": "Invalid token.", "details": reason, "status": 422}), 422

    @jwt.expired_token_loader
    def expired_token(_header, _payload):
        return jsonify({"error": "Token has expired.", "status": 401}), 401

    @jwt.revoked_token_loader
    def revoked_token(_header, _payload):
        return jsonify({"error": "Token has been revoked.", "status": 401}), 401
