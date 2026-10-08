"""Roles and the dependencies that protect endpoints.

Two roles exist, ``Admin`` and ``Analyst``, taken from the Entra ID ``roles`` claim at sign-in.
Admin satisfies every Analyst requirement. Use the annotated aliases in routers::

    @router.get("/things")
    async def list_things(user: AnalystUser, db: DbSession): ...

    @router.delete("/things/{id}")
    async def delete_thing(user: AdminUser, db: DbSession): ...

``current_user`` validates the session cookie and, for state-changing methods, the CSRF token.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.api.problems import Forbidden, Unauthorized
from securescan.auth import session as sessions
from securescan.auth.csrf import enforce_csrf
from securescan.config import get_settings
from securescan.db.models.enums import UserRole
from securescan.db.session import get_session

Role = UserRole
ADMIN_ROLE = "Admin"
ANALYST_ROLE = "Analyst"


@dataclass(frozen=True)
class CurrentUser:
    id: uuid.UUID
    oid: str
    name: str | None
    email: str | None
    role: UserRole
    session_id: uuid.UUID
    csrf_token: str

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN

    @property
    def label(self) -> str:
        return self.email or self.name or self.oid


def resolve_role(role_claims: Iterable[str]) -> UserRole | None:
    """The effective role for the values of the roles claim: Admin wins, then Analyst, else None."""
    values = set(role_claims)
    if ADMIN_ROLE in values:
        return UserRole.ADMIN
    if ANALYST_ROLE in values:
        return UserRole.ANALYST
    return None


def role_satisfies(actual: UserRole, required: UserRole) -> bool:
    """Admin satisfies Admin and Analyst; Analyst satisfies Analyst only."""
    if required == UserRole.ANALYST:
        return actual in (UserRole.ANALYST, UserRole.ADMIN)
    return actual == UserRole.ADMIN


def _authenticated(active: sessions.ActiveSession) -> CurrentUser:
    return CurrentUser(
        id=active.user_id,
        oid=active.oid,
        name=active.name,
        email=active.email,
        role=active.role,
        session_id=active.session_id,
        csrf_token=active.csrf_token,
    )


async def current_user_optional(
    request: Request, db: Annotated[AsyncSession, Depends(get_session)]
) -> CurrentUser | None:
    """The signed-in user, or None without a valid session. Still enforces CSRF when signed in."""
    token = request.cookies.get(get_settings().session_cookie_name)
    if not token:
        return None
    active = await sessions.load_active_session(db, token)
    if active is None:
        return None
    enforce_csrf(request, active.csrf_token)
    user = _authenticated(active)
    state = request.state
    state.actor_id = user.id
    state.actor_label = user.label
    return user


async def current_user(
    user: Annotated[CurrentUser | None, Depends(current_user_optional)],
) -> CurrentUser:
    if user is None:
        raise Unauthorized("Sign in to continue", code="auth.required")
    return user


def require_role(required: UserRole) -> Callable[..., Awaitable[CurrentUser]]:
    """Dependency factory: the user must have ``required`` (or Admin)."""

    async def dependency(user: Annotated[CurrentUser, Depends(current_user)]) -> CurrentUser:
        if not role_satisfies(user.role, required):
            raise Forbidden(
                f"This action needs the {required.value} role", code="auth.insufficient_role"
            )
        return user

    return dependency


require_analyst = require_role(UserRole.ANALYST)
require_admin = require_role(UserRole.ADMIN)

AnyUser = Annotated[CurrentUser, Depends(current_user)]
AnalystUser = Annotated[CurrentUser, Depends(require_analyst)]
AdminUser = Annotated[CurrentUser, Depends(require_admin)]
OptionalUser = Annotated[CurrentUser | None, Depends(current_user_optional)]
