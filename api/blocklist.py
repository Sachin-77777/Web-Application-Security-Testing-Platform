"""Revoked JWT identifiers.

A signed token cannot be "un-signed", so logging out has to be handled by
remembering the tokens that the server no longer accepts. Tokens are stored by
their ``jti`` (unique token id) claim.

This store lives in process memory, so it is cleared on every restart and is
not shared between workers. That is fine for a single-process localhost demo;
a real deployment would keep the same set in Redis or a database table.
"""

_revoked_ids = set()


def revoke(token_payload):
    jti = token_payload.get("jti")
    if jti:
        _revoked_ids.add(jti)


def is_revoked(jti):
    return jti in _revoked_ids
