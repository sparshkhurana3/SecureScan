"""Scans."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, pg_enum, utcnow
from securescan.db.models.enums import ScanKind, ScanState, ScanTrigger, Verdict


class Scan(Base):
    """One scan request: a set of tool jobs against one target."""

    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_application_id_created_at", "application_id", "created_at"),
        Index("ix_scans_state", "state"),
        Index("ix_scans_version_id", "version_id"),
        Index("ix_scans_created_at", "created_at"),
        UniqueConstraint("idempotency_key", name="uq_scans_idempotency_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("applications.id", ondelete="RESTRICT"),
        nullable=False,
    )
    version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("application_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("targets.id", ondelete="RESTRICT"),
        nullable=True,
    )
    profile_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("scan_profiles.id", ondelete="RESTRICT"),
        nullable=True,
    )
    profile_name: Mapped[str] = mapped_column(String(100), nullable=False)
    profile_version: Mapped[int] = mapped_column(Integer(), nullable=False)
    kind: Mapped[ScanKind] = mapped_column(pg_enum(ScanKind, "scan_kind"), nullable=False)
    mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    """DAST: baseline | full | api | nuclei"""
    trigger: Mapped[ScanTrigger] = mapped_column(
        pg_enum(ScanTrigger, "scan_trigger"),
        nullable=False,
    )
    trigger_detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state: Mapped[ScanState] = mapped_column(
        pg_enum(ScanState, "scan_state"),
        nullable=False,
        default=ScanState.QUEUED,
        server_default=text("'queued'"),
    )
    verdict: Mapped[Verdict] = mapped_column(
        pg_enum(Verdict, "verdict"),
        nullable=False,
        default=Verdict.PENDING,
        server_default=text("'pending'"),
    )
    verdict_detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("policies.id", ondelete="SET NULL"),
        nullable=True,
    )
    started_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    """NULL for scans started by the system (poller, schedules)"""
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    """namespaced '<user id>:<Idempotency-Key>' by the API"""
    requested_tools: Mapped[list[Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    options: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    """image digest of an image scan"""
    counts: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    """roll-up of open counts by severity over all jobs"""
    coverage_notes: Mapped[list[Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    error: Mapped[str | None] = mapped_column(Text(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    cancelled_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
        onupdate=utcnow,
    )
