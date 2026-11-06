"""In-memory brute-force protection for the login forms.

Both the session login (``auth.py``) and the JWT login (``api/auth.py``) call
into this module so the two entry points share one attempt counter. State lives
in the process memory, which is fine for a single-worker coursework deployment;
a production setup would move the same counters into Redis or the database.
"""

import time
from threading import Lock

from flask import current_app

_attempts = {}
_lock = Lock()

# Hard cap on tracked keys. A username/IP spray would otherwise grow the dict
# without bound, which is itself a memory-exhaustion denial of service.
MAX_TRACKED_KEYS = 10_000


def _settings():
    return (
        current_app.config.get("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", 5),
        current_app.config.get("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 300),
        current_app.config.get("LOGIN_RATE_LIMIT_LOCKOUT_SECONDS", 300),
    )


def _prune_stale(now, window):
    """Drop counters that have no recent failures and no active lock.

    Called with ``_lock`` held, once the dict reaches ``MAX_TRACKED_KEYS``.
    """
    for key, record in list(_attempts.items()):
        if record.get("locked_until", 0) > now:
            continue
        if any(now - started < window for started in record.get("failures", [])):
            continue
        _attempts.pop(key, None)


def key_for(identifier):
    """Build a counter key from the client IP and the submitted identifier."""
    from flask import request

    ip = request.remote_addr or "unknown"
    return f"{ip}:{(identifier or '').lower()}"


def locked_seconds(key):
    """Seconds left before ``key`` may try again; 0 when it is not locked."""
    now = time.time()
    with _lock:
        record = _attempts.get(key)
        if not record:
            return 0
        locked_until = record.get("locked_until", 0)
        if locked_until > now:
            return int(locked_until - now) + 1
        if locked_until:
            record["locked_until"] = 0
        return 0


def register_failure(key):
    """Record a failed attempt. Returns True when the key just got locked."""
    max_attempts, window, lockout = _settings()
    now = time.time()
    with _lock:
        if len(_attempts) >= MAX_TRACKED_KEYS:
            _prune_stale(now, window)
        record = _attempts.setdefault(key, {"failures": [], "locked_until": 0})
        record["failures"] = [t for t in record["failures"] if now - t < window]
        record["failures"].append(now)
        if len(record["failures"]) >= max_attempts:
            record["failures"] = []
            record["locked_until"] = now + lockout
            return True
    return False


def reset(key):
    """Clear the counter for ``key`` after a successful login."""
    with _lock:
        _attempts.pop(key, None)
