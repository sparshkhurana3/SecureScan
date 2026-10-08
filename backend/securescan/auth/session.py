"""Server-side sessions.

The browser holds a random token in the ``securescan_session`` cookie (``HttpOnly; Secure;
SameSite=Lax; Domain=<SECURESCAN_COOKIE_DOMAIN>`` so the DefectDojo host sees it). The database
holds only the SHA-256 of the token. A session ends when it has been idle for
``session_idle_hours`` (8), when it passes ``session_max_hours`` (24), or when it is revoked.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import Response
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.auth.csrf import new_csrf_token
from securescan.config import get_settings
from securescan.db.models.enums import UserRole
from securescan.db.models.sessions import Session as LoginSession
from securescan.db.models.users import User
from securescan.db.session import session_scope
from securescan.util import ensure_utc, new_id, utcnow

TOUCH_INTERVAL = timedelta(seconds=60)


@dataclass(frozen=True)
class ActiveSession:
    """What the request dependencies need to know about a valid session."""

    session_id: uuid.UUID
    user_id: uuid.UUID
    oid: str
    name: str | None
    email: str | None
    role: UserRole
    csrf_token: str
    expires_at: datetime
    last_seen_at: datetime


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_session_active(
    now: datetime,
    *,
    last_seen_at: datetime,
    expires_at: datetime,
    revoked_at: datetime | None,
    idle: timedelta | None = None,
) -> bool:
    """Pure expiry rule: not revoked, before the absolute limit, and not idle for too long."""
    if revoked_at is not None:
        return False
    idle_limit = idle if idle is not None else timedelta(hours=get_settings().session_idle_hours)
    now = ensure_utc(now)
    if now >= ensure_utc(expires_at):
        return False
    return now < ensure_utc(last_seen_at) + idle_limit


async def create_session(
    db: AsyncSession,
    user: User,
    *,
    ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, LoginSession]:
    """Create a session for ``user``; returns the cookie token (never stored) and the row."""
    settings = get_settings()
    now = utcnow()
    token = new_token()
    row = LoginSession(
        id=new_id(),
        user_id=user.id,
        token_hash=hash_token(token),
        csrf_token=new_csrf_token(),
        role=user.role,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=settings.session_max_hours),
        ip=ip,
        user_agent=(user_agent or "")[:255] or None,
    )
    db.add(row)
    await db.flush()
    return token, row


async def load_active_session(db: AsyncSession, token: str) -> ActiveSession | None:
    """Look up the session for a cookie token; None when unknown, expired, idle or revoked."""
    stmt = (
        select(LoginSession, User)
        .join(User, User.id == LoginSession.user_id)
        .where(LoginSession.token_hash == hash_token(token))
    )
    found = (await db.execute(stmt)).first()
    if found is None:
        return None
    row, user = found
    now = utcnow()
    if not is_session_active(
        now, last_seen_at=row.last_seen_at, expires_at=row.expires_at, revoked_at=row.revoked_at
    ):
        return None
    if now - ensure_utc(row.last_seen_at) >= TOUCH_INTERVAL:
        await touch_session(row.id)
    return ActiveSession(
        session_id=row.id,
        user_id=user.id,
        oid=user.oid,
        name=user.name,
        email=user.email,
        role=row.role,
        csrf_token=row.csrf_token,
        expires_at=row.expires_at,
        last_seen_at=row.last_seen_at,
    )


async def touch_session(session_id: uuid.UUID) -> None:
    """Record activity in its own short transaction (never commits the request's session)."""
    async with session_scope() as db:
        await db.execute(
            update(LoginSession).where(LoginSession.id == session_id).values(last_seen_at=utcnow())
        )


async def revoke_session(db: AsyncSession, session_id: uuid.UUID) -> None:
    await db.execute(
        update(LoginSession)
        .where(LoginSession.id == session_id, LoginSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )


async def delete_expired_sessions(db: AsyncSession, *, older_than: timedelta | None = None) -> int:
    """Delete sessions that can no longer be used (called by the ``session_cleanup`` task)."""
    settings = get_settings()
    now = utcnow()
    grace = older_than if older_than is not None else timedelta(days=1)
    idle_cutoff = now - timedelta(hours=settings.session_idle_hours) - grace
    result = await db.execute(
        delete(LoginSession).where(
            (LoginSession.expires_at < now - grace) | (LoginSession.last_seen_at < idle_cutoff)
        )
    )
    return int(getattr(result, "rowcount", 0) or 0)


def set_session_cookies(response: Response, token: str, csrf_token: str) -> None:
    """Set the session cookie (HttpOnly) and the CSRF cookie (readable by the portal)."""
    settings = get_settings()
    max_age = settings.session_max_hours * 3600
    domain = settings.cookie_domain or None
    response.set_cookie(
        settings.session_cookie_name,
        token,
        max_age=max_age,
        domain=domain,
        path="/",
        secure=settings.cookies_secure,
        httponly=True,
        samesite="lax",
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        max_age=max_age,
        domain=domain,
        path="/",
        secure=settings.cookies_secure,
        httponly=False,
        samesite="lax",
    )


def clear_session_cookies(response: Response) -> None:
    settings = get_settings()
    domain = settings.cookie_domain or None
    for name in (settings.session_cookie_name, settings.csrf_cookie_name):
        response.delete_cookie(name, domain=domain, path="/")
