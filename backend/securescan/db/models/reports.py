"""Reports."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
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
from securescan.db.models.enums import ReportKind, ReviewState, Verdict


class Report(Base):
    """A generated report rendered from a frozen snapshot."""

    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_version_id_created_at", "version_id", "created_at"),
        Index("ix_reports_scan_id", "scan_id"),
        Index("ix_reports_application_id", "application_id"),
        UniqueConstraint("ref", name="uq_reports_ref"),
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
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("scans.id", ondelete="RESTRICT"),
        nullable=True,
    )
    kind: Mapped[ReportKind] = mapped_column(pg_enum(ReportKind, "report_kind"), nullable=False)
    ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    """human readable report id"""
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    template_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("report_templates.id", ondelete="SET NULL"),
        nullable=True,
    )
    template_version: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    snapshot_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("artifacts.id", ondelete="SET NULL"),
        nullable=True,
    )
    snapshot_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    html_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("artifacts.id", ondelete="SET NULL"),
        nullable=True,
    )
    pdf_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("artifacts.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    """pending | ready | failed"""
    error: Mapped[str | None] = mapped_column(Text(), nullable=True)
    review_state: Mapped[ReviewState] = mapped_column(
        pg_enum(ReviewState, "review_state"),
        nullable=False,
        default=ReviewState.AUTOMATIC,
        server_default=text("'automatic'"),
    )
    proposed_verdict: Mapped[Verdict | None] = mapped_column(
        pg_enum(Verdict, "verdict"),
        nullable=True,
    )
    verdict: Mapped[Verdict] = mapped_column(
        pg_enum(Verdict, "verdict"),
        nullable=False,
        default=Verdict.PENDING,
        server_default=text("'pending'"),
    )
    verdict_overridden: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    override_reason: Mapped[str | None] = mapped_column(Text(), nullable=True)
    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    conditions: Mapped[list[Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    """[{finding_hash, deadline}]"""
    vendor_copy: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    """copy for the vendor without internal notes"""
    internal_notes: Mapped[str | None] = mapped_column(Text(), nullable=True)
    mapping_versions: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    previous_report_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("reports.id", ondelete="SET NULL"),
        nullable=True,
    )
    generated_by_id: Mapped[uuid.UUID | None] = mapped_column(
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
