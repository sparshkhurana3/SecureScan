from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from securescan.api.problems import install_problem_handlers
from securescan.auth import session as sessions
from securescan.auth.roles import (
    AdminUser,
    AnalystUser,
    AnyUser,
    CurrentUser,
    current_user,
    resolve_role,
    role_satisfies,
)
from securescan.db.models.enums import UserRole
from securescan.db.session import get_session
from securescan.util import utcnow


def make_user(role: UserRole) -> CurrentUser:
    return CurrentUser(
        id=uuid.uuid4(),
        oid="oid-1",
        name="Test User",
        email="test@example.com",
        role=role,
        session_id=uuid.uuid4(),
        csrf_token="csrf-token-value",
    )


def build_app() -> FastAPI:
    app = FastAPI()
    install_problem_handlers(app)

    @app.get("/any")
    async def any_route(user: AnyUser) -> dict[str, str]:
        return {"role": user.role.value}

    @app.get("/analyst")
    async def analyst_route(user: AnalystUser) -> dict[str, str]:
        return {"role": user.role.value}

    @app.get("/admin")
    async def admin_route(user: AdminUser) -> dict[str, str]:
        return {"role": user.role.value}

    @app.post("/change")
    async def change_route(user: AnalystUser) -> dict[str, str]:
        return {"ok": "yes"}

    return app


def test_resolve_role_admin_wins() -> None:
    assert resolve_role(["Analyst", "Admin"]) == UserRole.ADMIN


def test_resolve_role_analyst() -> None:
    assert resolve_role(["Analyst"]) == UserRole.ANALYST


@pytest.mark.parametrize("claims", [[], ["admin"], ["Reader"], ["ADMIN", "analyst"]])
def test_resolve_role_refuses_unknown_roles(claims: list[str]) -> None:
    assert resolve_role(claims) is None


def test_admin_satisfies_analyst_but_not_the_reverse() -> None:
    assert role_satisfies(UserRole.ADMIN, UserRole.ANALYST)
    assert role_satisfies(UserRole.ADMIN, UserRole.ADMIN)
    assert role_satisfies(UserRole.ANALYST, UserRole.ANALYST)
    assert not role_satisfies(UserRole.ANALYST, UserRole.ADMIN)


def test_anonymous_gets_401_problem() -> None:
    app = build_app()

    async def no_db() -> AsyncIterator[None]:
        yield None

    app.dependency_overrides[get_session] = no_db
    response = TestClient(app).get("/analyst")
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "auth.required"


@pytest.mark.parametrize(
    ("role", "path", "expected"),
    [
        (UserRole.ANALYST, "/any", 200),
        (UserRole.ANALYST, "/analyst", 200),
        (UserRole.ANALYST, "/admin", 403),
        (UserRole.ADMIN, "/analyst", 200),
        (UserRole.ADMIN, "/admin", 200),
    ],
)
def test_role_dependencies(role: UserRole, path: str, expected: int) -> None:
    app = build_app()
    app.dependency_overrides[current_user] = lambda: make_user(role)
    response = TestClient(app).get(path)
    assert response.status_code == expected
    if expected == 403:
        assert response.json()["code"] == "auth.insufficient_role"


def _app_with_session(monkeypatch: pytest.MonkeyPatch, role: UserRole) -> TestClient:
    """The real current_user dependency with the session lookup replaced."""
    app = build_app()

    async def no_db() -> AsyncIterator[None]:
        yield None

    app.dependency_overrides[get_session] = no_db
    user = make_user(role)

    async def fake_load(_db: Any, token: str) -> sessions.ActiveSession | None:
        if token != "good-token":
            return None
        return sessions.ActiveSession(
            session_id=user.session_id,
            user_id=user.id,
            oid=user.oid,
            name=user.name,
            email=user.email,
            role=user.role,
            csrf_token=user.csrf_token,
            expires_at=utcnow() + timedelta(hours=1),
            last_seen_at=utcnow(),
        )

    monkeypatch.setattr(sessions, "load_active_session", fake_load)
    client = TestClient(app)
    client.cookies.set("securescan_session", "good-token")
    return client


def test_valid_session_cookie_authenticates(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _app_with_session(monkeypatch, UserRole.ANALYST)
    assert client.get("/analyst").status_code == 200


def test_unknown_session_cookie_is_401(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _app_with_session(monkeypatch, UserRole.ANALYST)
    client.cookies.set("securescan_session", "bad-token")
    assert client.get("/analyst").status_code == 401
