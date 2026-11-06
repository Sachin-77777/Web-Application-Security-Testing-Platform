from urllib.parse import urlparse

from flask import current_app, request


def form_str(name):
    return (request.form.get(name) or "").strip()


def form_int(name, default=None):
    raw = form_str(name)
    if raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def form_float(name, default=None):
    raw = form_str(name)
    if raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def is_http_url(value):
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def search_query(name="q", max_length=100):
    """Return a trimmed search string from the query string."""
    value = (request.args.get(name) or "").strip()
    if len(value) > max_length:
        return value[:max_length]
    return value


def contains_filter(column, term):
    """Case-insensitive containment with a bound parameter, not string SQL.

    SQLAlchemy sends the term as a query parameter. Do not build SQL with
    f-strings or concatenation of request data; that is how injection happens.
    """
    return column.ilike(f"%{term}%")


def paginate(query):
    """Page a query using the ?page= argument and the configured page size."""
    page = request.args.get("page", 1, type=int)
    if not page or page < 1:
        page = 1
    return query.paginate(
        page=page,
        per_page=current_app.config.get("PER_PAGE", 10),
        error_out=False,
    )
