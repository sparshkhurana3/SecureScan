"""User queries."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.auth.oidc import Identity
from securescan.db.models.enums import UserRole
from securescan.db.models.users import User
from securescan.util import new_id, utcnow


async def upsert_user(session: AsyncSession, identity: Identity, role: UserRole) -> User:
    """Create the user on first sign-in, otherwise refresh name, e-mail and roles."""
    now = utcnow()
    values = {
        "name": identity.name,
        "email": identity.email,
        "upn": identity.upn,
        "role": role,
        "roles": identity.roles,
        "last_login": now,
        "updated_at": now,
    }
    stmt = (
        pg_insert(User)
        .values(id=new_id(), oid=identity.oid, created_at=now, **values)
        .on_conflict_do_update(index_elements=[User.oid], set_=values)
        .returning(User.id)
    )
    user_id = (await session.execute(stmt)).scalar_one()
    user = await session.get(User, user_id, populate_existing=True)
    assert user is not None  # noqa: S101 - the row was just written
    return user


async def get_user(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    return await session.get(User, user_id)


async def find_by_oid(session: AsyncSession, oid: str) -> User | None:
    return await session.scalar(select(User).where(User.oid == oid))
