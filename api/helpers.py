"""Request/response helpers for the JSON REST API.

The HTML blueprints read form fields through ``util.py``. The API receives JSON
bodies instead, so it needs its own accessors that are just as strict: no bare
``data["field"]`` lookups, no implicit type coercion that could raise.
"""

from flask import jsonify, request


def json_body():
    """Return the JSON body as a dict, or an empty dict when it is missing/invalid."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def field_str(data, name, default=""):
    value = data.get(name, default)
    if value is None:
        return ""
    return str(value).strip()


def field_int(data, name, default=None):
    value = data.get(name)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def field_float(data, name, default=None):
    value = data.get(name)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def error(message, status=400, details=None):
    """Build a JSON error response with a consistent shape."""
    payload = {"error": message, "status": status}
    if details:
        payload["details"] = details
    return jsonify(payload), status
