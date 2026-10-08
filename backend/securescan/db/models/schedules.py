"""Schedules."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, pg_enum, utcnow
from securescan.db.models.enums import ScheduleKind


class Schedule(Base):
    """A recurring job definition: weekly repository scans, DAST crons, poll settings."""

    __tablename__ = "schedules"
    __table_args__ = (
        Index("ix_schedules_kind_enabled", "kind", "enabled"),
        Index("ix_schedules_target_id", "target_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[ScheduleKind] = mapped_column(
        pg_enum(ScheduleKind, "schedule_kind"),
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    cron: Mapped[str | None] = mapped_column(String(100), nullable=True)
    poll_interval_minutes: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    blackout_windows: Mapped[list[Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    repository_set: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    """{"mode": "automatic"} or {"application_ids": [...]}"""
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=True,
    )
    profile_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
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
