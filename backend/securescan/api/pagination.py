"""Cursor (keyset) pagination for every list endpoint.

The cursor is opaque to clients: base64url of a small JSON document holding the sort key of the
last row of the previous page. Usage in a router::

    @router.get("/things", response_model=CursorPage[ThingOut])
    async def list_things(db: DbSession, user: AnalystUser, page: PageDep) -> CursorPage[ThingOut]:
        stmt = select(Thing).where(...)
        result = await paginate(db, stmt, key=[Thing.created_at, Thing.id], params=page)
        return CursorPage(items=[ThingOut.model_validate(r) for r in result.items],
                          next_cursor=result.next_cursor)

``key`` is the total order: every column ascending or every column descending (``descending=True``
is the default, newest first), ending in a unique column such as ``id``.
"""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Generic, TypeVar

from fastapi import Depends, Query
from pydantic import BaseModel
from sqlalchemy import Select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from securescan.api.problems import BadRequest

T = TypeVar("T")

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


class CursorPage(BaseModel, Generic[T]):
    """A page of results. ``next_cursor`` is null on the last page."""

    items: list[T]
    next_cursor: str | None = None


@dataclass(frozen=True)
class PageParams:
    after: str | None
    limit: int


def page_params(
    after: Annotated[str | None, Query(description="Opaque cursor from the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT, description="Page size")] = DEFAULT_LIMIT,
) -> PageParams:
    return PageParams(after=after, limit=limit)


PageDep = Annotated[PageParams, Depends(page_params)]


def encode_cursor(values: Sequence[Any]) -> str:
    """Encode the sort key of a row (datetimes, UUIDs, numbers and strings are supported)."""
    payload = json.dumps([_to_json(v) for v in values], separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> list[Any]:
    """Inverse of ``encode_cursor`` (values come back as JSON types)."""
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        values = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BadRequest("The cursor is not valid", code="pagination.invalid_cursor") from exc
    if not isinstance(values, list) or not values:
        raise BadRequest("The cursor is not valid", code="pagination.invalid_cursor")
    return values


def _to_json(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if hasattr(value, "value") and not isinstance(value, (int, float, str)):
        return value.value  # enums
    return value


def coerce_cursor_value(column: Any, value: Any) -> Any:
    """Convert a decoded JSON value back to the Python type of the sort column."""
    try:
        python_type = column.type.python_type
    except NotImplementedError:
        return value
    try:
        if python_type is datetime:
            return datetime.fromisoformat(str(value))
        if python_type is uuid.UUID:
            return uuid.UUID(str(value))
        if python_type is int:
            return int(value)
        if python_type is float:
            return float(value)
    except (TypeError, ValueError) as exc:
        raise BadRequest("The cursor is not valid", code="pagination.invalid_cursor") from exc
    return value


@dataclass
class Page(Generic[T]):
    items: list[T]
    next_cursor: str | None


async def paginate(
    session: AsyncSession,
    stmt: Select[Any],
    *,
    key: Sequence[InstrumentedAttribute[Any]],
    params: PageParams,
    descending: bool = True,
) -> Page[Any]:
    """Run ``stmt`` (a ``select`` of one ORM entity) ordered by ``key`` and return one page."""
    if not key:
        raise ValueError("paginate needs at least one sort column")
    if params.after:
        values = decode_cursor(params.after)
        if len(values) != len(key):
            raise BadRequest("The cursor does not match this list", code="pagination.invalid_cursor")
        bound = tuple_(*key)
        point = tuple_(*[coerce_cursor_value(col, val) for col, val in zip(key, values)])
        stmt = stmt.where(bound < point if descending else bound > point)
    ordering = [col.desc() if descending else col.asc() for col in key]
    stmt = stmt.order_by(*ordering).limit(params.limit + 1)
    rows = list((await session.scalars(stmt)).all())
    next_cursor: str | None = None
    if len(rows) > params.limit:
        rows = rows[: params.limit]
        last = rows[-1]
        next_cursor = encode_cursor([getattr(last, col.key) for col in key])
    return Page(items=rows, next_cursor=next_cursor)
