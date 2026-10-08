"""CSRF protection: double-submit token bound to the server-side session.

At sign-in the server creates a random CSRF token, stores it on the session row and sets it in a
JavaScript-readable cookie (``securescan_csrf``). Every state-changing request must send the same
value in the ``X-CSRF-Token`` header. ``enforce_csrf`` is called by the ``current_user`` dependency,
so every endpoint that needs a signed-in user is covered without extra code.
"""

from __future__ import annotations

import hmac
import secrets

from fastapi import Request

from securescan.api.problems import Forbidden
from securescan.config import get_settings

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_ok(method: str, cookie_value: str | None, header_value: str | None, expected: str) -> bool:
    """True when the method is safe, or cookie, header and the session's token all agree."""
    if method.upper() in SAFE_METHODS:
        return True
    if not cookie_value or not header_value or not expected:
        return False
    return hmac.compare_digest(cookie_value, expected) and hmac.compare_digest(header_value, expected)


def enforce_csrf(request: Request, expected: str) -> None:
    settings = get_settings()
    ok = csrf_ok(
        request.method,
        request.cookies.get(settings.csrf_cookie_name),
        request.headers.get(settings.csrf_header_name),
        expected,
    )
    if not ok:
        raise Forbidden(
            "Missing or invalid CSRF token. Send the value of the "
            f"{settings.csrf_cookie_name} cookie in the {settings.csrf_header_name} header.",
            code="csrf.invalid",
        )
