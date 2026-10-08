"""Audit log viewer (Admin)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.schemas import ORMModel
from securescan.auth.roles import AdminUser
from securescan.db.models.audit import AuditEvent
from securescan.db.repositories.common import escape_like
from securescan.db.session import DbSession

router = APIRouter(tags=["audit"])


class AuditEventOut(ORMModel):
    id: uuid.UUID
    created_at: datetime
    actor_id: uuid.UUID | None
    actor_label: str
    action: str
    object_type: str | None
    object_id: str | None
    source_ip: str | None
    request_id: str | None
    detail: dict[str, Any]


@router.get("/audit-events", response_model=CursorPage[AuditEventOut], summary="List audit events (Admin)")
async def list_audit_events(
    db: DbSession,
    user: AdminUser,
    page: PageDep,
    actor_id: uuid.UUID | None = None,
    actor: str | None = None,
    action: str | None = None,
    action_prefix: str | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
) -> CursorPage[AuditEventOut]:
    stmt = select(AuditEvent)
    if actor_id:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)
    if actor:
        stmt = stmt.where(AuditEvent.actor_label.ilike(f"%{escape_like(actor)}%", escape="\\"))
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if action_prefix:
        stmt = stmt.where(AuditEvent.action.like(f"{escape_like(action_prefix)}%", escape="\\"))
    if object_type:
        stmt = stmt.where(AuditEvent.object_type == object_type)
    if object_id:
        stmt = stmt.where(AuditEvent.object_id == object_id)
    if created_after:
        stmt = stmt.where(AuditEvent.created_at >= created_after)
    if created_before:
        stmt = stmt.where(AuditEvent.created_at <= created_before)
    result = await paginate(db, stmt, key=[AuditEvent.created_at, AuditEvent.id], params=page)
    return CursorPage(
        items=[AuditEventOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )
