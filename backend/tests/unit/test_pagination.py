from __future__ import annotations

import types
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from securescan.api.pagination import (
    CursorPage,
    PageParams,
    coerce_cursor_value,
    decode_cursor,
    encode_cursor,
    paginate,
)
from securescan.api.problems import BadRequest
from securescan.db.models.vendors import Vendor
from tests.unit.conftest import FakeSession


def test_cursor_round_trip() -> None:
    moment = datetime(2026, 10, 7, 12, 30, tzinfo=timezone.utc)
    ident = uuid.uuid4()
    cursor = encode_cursor([moment, ident, 5, "text"])
    assert "=" not in cursor
    assert decode_cursor(cursor) == [moment.isoformat(), str(ident), 5, "text"]


@pytest.mark.parametrize("cursor", ["", "!!!", "bm90LWpzb24", "e30", "W10"])
def test_invalid_cursors_are_rejected(cursor: str) -> None:
    with pytest.raises(BadRequest):
        decode_cursor(cursor)


def test_values_are_coerced_to_the_column_type() -> None:
    moment = datetime(2026, 10, 7, 12, 30, tzinfo=timezone.utc)
    ident = uuid.uuid4()
    assert coerce_cursor_value(Vendor.created_at, moment.isoformat()) == moment
    assert coerce_cursor_value(Vendor.id, str(ident)) == ident
    assert coerce_cursor_value(Vendor.name, "abc") == "abc"
    with pytest.raises(BadRequest):
        coerce_cursor_value(Vendor.id, "not-a-uuid")


def _vendors(count: int) -> list[types.SimpleNamespace]:
    return [types.SimpleNamespace(name=f"v{i:02d}", id=uuid.uuid4()) for i in range(count)]


async def test_last_page_has_no_cursor() -> None:
    session = FakeSession(rows=_vendors(2))
    page = await paginate(
        session,  # type: ignore[arg-type]
        select(Vendor),
        key=[Vendor.name, Vendor.id],
        params=PageParams(after=None, limit=5),
        descending=False,
    )
    assert len(page.items) == 2
    assert page.next_cursor is None


async def test_full_page_returns_a_cursor_for_the_last_item() -> None:
    rows = _vendors(3)  # limit + 1 rows come back: one more page exists
    session = FakeSession(rows=rows)
    page = await paginate(
        session,  # type: ignore[arg-type]
        select(Vendor),
        key=[Vendor.name, Vendor.id],
        params=PageParams(after=None, limit=2),
        descending=False,
    )
    assert page.items == rows[:2]
    assert page.next_cursor is not None
    assert decode_cursor(page.next_cursor) == [rows[1].name, str(rows[1].id)]


async def test_statement_uses_keyset_condition_order_and_limit() -> None:
    after = encode_cursor(["v05", uuid.uuid4()])
    session = FakeSession(rows=[])
    await paginate(
        session,  # type: ignore[arg-type]
        select(Vendor),
        key=[Vendor.name, Vendor.id],
        params=PageParams(after=after, limit=10),
        descending=False,
    )
    sql = str(session.last_statement.compile(dialect=postgresql.dialect()))
    assert "(vendors.name, vendors.id) >" in sql
    assert "ORDER BY vendors.name ASC, vendors.id ASC" in sql
    assert "LIMIT" in sql


async def test_descending_uses_less_than() -> None:
    after = encode_cursor([datetime(2026, 1, 1, tzinfo=timezone.utc), uuid.uuid4()])
    session = FakeSession(rows=[])
    await paginate(
        session,  # type: ignore[arg-type]
        select(Vendor),
        key=[Vendor.created_at, Vendor.id],
        params=PageParams(after=after, limit=10),
    )
    sql = str(session.last_statement.compile(dialect=postgresql.dialect()))
    assert "(vendors.created_at, vendors.id) <" in sql
    assert "DESC" in sql


async def test_cursor_for_another_list_is_rejected() -> None:
    with pytest.raises(BadRequest):
        await paginate(
            FakeSession(),  # type: ignore[arg-type]
            select(Vendor),
            key=[Vendor.name, Vendor.id],
            params=PageParams(after=encode_cursor(["only-one"]), limit=10),
        )


def test_cursor_page_model() -> None:
    page = CursorPage[int](items=[1, 2], next_cursor="abc")
    assert page.model_dump() == {"items": [1, 2], "next_cursor": "abc"}
    assert CursorPage[int](items=[]).next_cursor is None
