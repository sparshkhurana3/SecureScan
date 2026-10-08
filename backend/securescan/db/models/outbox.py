"""DefectDojo import outbox."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, Text, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, pg_enum, utcnow
from securescan.db.models.enums import OutboxState


class SyncOutbox(Base):
    """Transactional outbox that drives the DefectDojo import of a finished job."""

    __tablename__ = "sync_outbox"
    __table_args__ = (
        Index("ix_sync_outbox_state_next_attempt_at", "state", "next_attempt_at"),
        Index("ix_sync_outbox_job_id", "job_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("scan_jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    state: Mapped[OutboxState] = mapped_column(
        pg_enum(OutboxState, "outbox_state"),
        nullable=False,
        default=OutboxState.PENDING,
        server_default=text("'pending'"),
    )
    attempts: Mapped[int] = mapped_column(
        Integer(),
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
    )
    last_error: Mapped[str | None] = mapped_column(Text(), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
        onupdate=utcnow,
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
