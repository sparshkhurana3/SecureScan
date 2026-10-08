"""Audit log helper.

``record_audit`` adds an ``AuditEvent`` to the caller's session (so it commits or rolls back with
the change it describes) and emits the same event as a structlog line with ``event=audit``, which
is how the corporate SIEM receives it. Never put secrets in ``detail``; known secret shapes and
keys such as ``password`` or ``token`` are masked anyway.

Action names are ``<object>.<verb>``: ``application.create``, ``target.environment_change``,
``auth.login``, ``report.download``, ``export.history_csv``, ...
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import get_settings
from securescan.db.models.audit import AuditEvent
from securescan.logging import get_logger, scrub_value
from securescan.util import new_id, utcnow

log = get_logger("audit")

SYSTEM_ACTOR = "system"


def client_ip(request: Request | None) -> str | None:
    """Source address; behind the gateway the first ``X-Forwarded-For`` entry."""
    if request is None:
        return None
    if get_settings().trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64] or None
    return request.client.host[:64] if request.client else None


def _actor_parts(actor: Any) -> tuple[uuid.UUID | None, str]:
    if actor is None or actor == SYSTEM_ACTOR:
        return None, SYSTEM_ACTOR
    if isinstance(actor, uuid.UUID):
        return actor, str(actor)
    if isinstance(actor, str):
        return None, actor[:320]
    actor_id = getattr(actor, "id", None)
    label = (
        getattr(actor, "label", None)
        or getattr(actor, "email", None)
        or getattr(actor, "name", None)
        or str(actor_id)
    )
    return actor_id, str(label)[:320]


async def record_audit(
    session: AsyncSession,
    actor: Any,
    action: str,
    object_type: str | None,
    object_id: Any,
    detail: dict[str, Any] | None = None,
    request: Request | None = None,
) -> AuditEvent:
    """Write one audit event. ``actor``: a CurrentUser or User, a user id, ``"system"`` or None."""
    actor_id, label = _actor_parts(actor)
    request_id = getattr(request.state, "request_id", None) if request is not None else None
    event = AuditEvent(
        id=new_id(),
        created_at=utcnow(),
        actor_id=actor_id,
        actor_label=label,
        action=action[:100],
        object_type=object_type[:64] if object_type else None,
        object_id=str(object_id)[:128] if object_id is not None else None,
        source_ip=client_ip(request),
        user_agent=(request.headers.get("user-agent", "")[:255] or None) if request else None,
        request_id=request_id,
        detail=scrub_value(detail or {}),
    )
    session.add(event)
    if request is not None:
        request.state.audited = True
    log.info(
        "audit",
        action=event.action,
        actor=label,
        actor_id=str(actor_id) if actor_id else None,
        object_type=event.object_type,
        object_id=event.object_id,
        source_ip=event.source_ip,
        request_id=request_id,
        detail=event.detail,
    )
    return event
