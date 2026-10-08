"""Scan jobs (one tool run)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, pg_enum, utcnow
from securescan.db.models.enums import ImportState, JobState


class ScanJob(Base):
    """One tool run inside a scan."""

    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_state", "state"),
        Index("ix_scan_jobs_scan_id", "scan_id"),
        Index("ix_scan_jobs_import_state", "import_state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("scans.id", ondelete="RESTRICT"),
        nullable=False,
    )
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[JobState] = mapped_column(
        pg_enum(JobState, "job_state"),
        nullable=False,
        default=JobState.QUEUED,
        server_default=text("'queued'"),
    )
    import_state: Mapped[ImportState] = mapped_column(
        pg_enum(ImportState, "import_state"),
        nullable=False,
        default=ImportState.PENDING,
        server_default=text("'pending'"),
    )
    attempts: Mapped[int] = mapped_column(
        Integer(),
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    procrastinate_job_id: Mapped[int | None] = mapped_column(BigInteger(), nullable=True)
    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    worker_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    image: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image_digest: Mapped[str | None] = mapped_column(String(160), nullable=True)
    tool_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    content_versions: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    """{semgrep_rules: version, grype_db: version, ...} used by this run"""
    exit_code: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    outcome_reason: Mapped[str | None] = mapped_column(Text(), nullable=True)
    partial: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    counts: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    """open counts by severity after import"""
    dd_test_id: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    dd_imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dd_import_stats: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    log_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    """path of the job log under the artifacts root"""
    applied_exclusions: Mapped[list[Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    coverage_note: Mapped[str | None] = mapped_column(Text(), nullable=True)
    options: Mapped[dict[str, Any]] = mapped_column(
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
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
        onupdate=utcnow,
    )
