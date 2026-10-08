"""Query helpers shared by the repositories and routers."""

from __future__ import annotations

import uuid
from typing import Any, TypeVar

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.api.problems import NotFound

M = TypeVar("M")


async def get_or_404(
    session: AsyncSession, model: type[M], object_id: uuid.UUID, what: str | None = None
) -> M:
    """Load a row by primary key or raise a 404 problem."""
    row = await session.get(model, object_id)
    if row is None:
        label = what or model.__name__
        raise NotFound(f"{label} not found", code=f"{label.lower().replace(' ', '_')}.not_found")
    return row


def escape_like(value: str) -> str:
    """Escape ``%``, ``_`` and the escape character for use with ``ilike(..., escape="\\\\")``."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def exists_ci(session: AsyncSession, column: Any, value: str, exclude_id: Any = None) -> bool:
    """True when a row exists whose ``column`` equals ``value`` ignoring case."""
    stmt = select(func.count()).select_from(column.class_).where(func.lower(column) == value.lower())
    if exclude_id is not None:
        stmt = stmt.where(column.class_.id != exclude_id)
    return bool((await session.scalar(stmt)) or 0)
