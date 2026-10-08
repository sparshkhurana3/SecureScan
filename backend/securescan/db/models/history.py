"""Finding history (append-only)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
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
from securescan.db.models.enums import Severity


class FindingHistory(Base):
    """Append-only copy of a DefectDojo finding as it stood when its scan job was imported."""

    __tablename__ = "finding_history"
    __table_args__ = (
        Index(
            "ix_finding_history_application_id_severity_scanned_at",
            "application_id",
            "severity",
            "scanned_at",
        ),
        Index("ix_finding_history_scan_id", "scan_id"),
        Index("ix_finding_history_dd_finding_id", "dd_finding_id"),
        Index("ix_finding_history_hash_code", "hash_code"),
        Index("ix_finding_history_scanned_at", "scanned_at"),
        Index("ix_finding_history_tool_scanned_at", "tool", "scanned_at"),
        UniqueConstraint("job_id", "dd_finding_id", name="uq_finding_history_job_id_dd_finding_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("scans.id", ondelete="RESTRICT"),
        nullable=False,
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("scan_jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
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
    vendor_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("vendors.id", ondelete="RESTRICT"),
        nullable=True,
    )
    started_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    """target kind of the scan"""
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    dd_finding_id: Mapped[int] = mapped_column(BigInteger(), nullable=False)
    hash_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    dd_test_id: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    severity: Mapped[Severity] = mapped_column(pg_enum(Severity, "severity"), nullable=False)
    title: Mapped[str] = mapped_column(Text(), nullable=False)
    cwe: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cvss: Mapped[float | None] = mapped_column(Float(), nullable=True)
    component: Mapped[str | None] = mapped_column(String(500), nullable=True)
    component_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text(), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    url: Mapped[str | None] = mapped_column(Text(), nullable=True)
    state_at_scan: Mapped[str] = mapped_column(String(32), nullable=False)
    """open | false_positive | risk_accepted | out_of_scope | duplicate | mitigated | closed"""
    flags_at_scan: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    """DefectDojo booleans at import time"""
    state_now: Mapped[str] = mapped_column(String(32), nullable=False)
    """same vocabulary; refreshed nightly - the only mutable column"""
    flags_now: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    state_now_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
    )
