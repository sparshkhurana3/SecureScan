from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import pytest
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from securescan.api.problems import install_problem_handlers
from securescan.auth import session as sessions
from securescan.auth.csrf import csrf_ok, new_csrf_token
from securescan.auth.roles import AnalystUser
from securescan.db.models.enums import UserRole
from securescan.db.session import get_session
from securescan.util import utcnow

# --------------------------------------------------------------------------- CSRF rule


def test_safe_methods_need_no_token() -> None:
    for method in ("GET", "HEAD", "OPTIONS", "get"):
        assert csrf_ok(method, None, None, "expected")


def test_state_changing_needs_matching_cookie_and_header() -> None:
    token = new_csrf_token()
    assert csrf_ok("POST", token, token, token)
    assert not csrf_ok("POST", token, None, token)
    assert not csrf_ok("POST", None, token, token)
    assert not csrf_ok("POST", token, "other", token)
    assert not csrf_ok("DELETE", "other", "other", token)  # matches each other, not the session
    assert not csrf_ok("PATCH", "", "", "")


def test_tokens_are_unique_and_long() -> None:
    assert new_csrf_token() != new_csrf_token()
    assert len(new_csrf_token()) >= 32


# --------------------------------------------------------------------------- endpoint integration


def _client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    app = FastAPI()
    install_problem_handlers(app)

    @app.post("/change")
    async def change(user: AnalystUser) -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/read")
    async def read(user: AnalystUser) -> dict[str, str]:
        return {"ok": "yes"}

    async def no_db() -> AsyncIterator[None]:
        yield None

    app.dependency_overrides[get_session] = no_db
    csrf = "csrf-secret-value"

    async def fake_load(_db: Any, token: str) -> sessions.ActiveSession | None:
        return sessions.ActiveSession(
            session_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            oid="o",
            name="n",
            email="e@example.com",
            role=UserRole.ANALYST,
            csrf_token=csrf,
            expires_at=utcnow() + timedelta(hours=1),
            last_seen_at=utcnow(),
        )

    monkeypatch.setattr(sessions, "load_active_session", fake_load)
    client = TestClient(app)
    client.cookies.set("securescan_session", "tok")
    return client


def test_post_without_csrf_header_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch)
    client.cookies.set("securescan_csrf", "csrf-secret-value")
    response = client.post("/change")
    assert response.status_code == 403
    assert response.json()["code"] == "csrf.invalid"


def test_post_with_matching_header_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch)
    client.cookies.set("securescan_csrf", "csrf-secret-value")
    response = client.post("/change", headers={"X-CSRF-Token": "csrf-secret-value"})
    assert response.status_code == 200


def test_forged_cookie_and_header_pair_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch)
    client.cookies.set("securescan_csrf", "attacker")
    response = client.post("/change", headers={"X-CSRF-Token": "attacker"})
    assert response.status_code == 403


def test_get_needs_no_csrf(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _client(monkeypatch).get("/read").status_code == 200


# --------------------------------------------------------------------------- session expiry rule

NOW = utcnow()


def test_session_active_within_idle_and_absolute_limits() -> None:
    assert sessions.is_session_active(
        NOW,
        last_seen_at=NOW - timedelta(hours=7),
        expires_at=NOW + timedelta(hours=10),
        revoked_at=None,
    )


def test_session_idle_for_more_than_eight_hours_is_expired() -> None:
    assert not sessions.is_session_active(
        NOW,
        last_seen_at=NOW - timedelta(hours=8, minutes=1),
        expires_at=NOW + timedelta(hours=10),
        revoked_at=None,
    )


def test_session_past_absolute_limit_is_expired() -> None:
    assert not sessions.is_session_active(
        NOW,
        last_seen_at=NOW - timedelta(minutes=1),
        expires_at=NOW - timedelta(seconds=1),
        revoked_at=None,
    )


def test_revoked_session_is_inactive() -> None:
    assert not sessions.is_session_active(
        NOW, last_seen_at=NOW, expires_at=NOW + timedelta(hours=5), revoked_at=NOW
    )


def test_custom_idle_limit() -> None:
    assert not sessions.is_session_active(
        NOW,
        last_seen_at=NOW - timedelta(minutes=31),
        expires_at=NOW + timedelta(hours=5),
        revoked_at=None,
        idle=timedelta(minutes=30),
    )


def test_token_hash_is_stable_and_not_the_token() -> None:
    token = sessions.new_token()
    assert sessions.hash_token(token) == sessions.hash_token(token)
    assert sessions.hash_token(token) != token
    assert len(sessions.hash_token(token)) == 64
    assert sessions.new_token() != sessions.new_token()


def test_session_cookie_attributes() -> None:
    response = Response()
    sessions.set_session_cookies(response, "the-token", "the-csrf")
    cookies = response.headers.getlist("set-cookie")
    session_cookie = next(c for c in cookies if c.startswith("securescan_session="))
    csrf_cookie = next(c for c in cookies if c.startswith("securescan_csrf="))
    assert "HttpOnly" in session_cookie
    assert "Secure" in session_cookie
    assert "samesite=lax" in session_cookie.lower()
    assert "Domain=securescan.localtest.me" in session_cookie
    assert "HttpOnly" not in csrf_cookie  # the portal must read it
    assert "Secure" in csrf_cookie
