"""Artifacts and chunked uploads."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, pg_enum, utcnow
from securescan.db.models.enums import ArtifactKind, UploadState


class Artifact(Base):
    """A file on the artifact volume: upload, raw report, SBOM, log, rendered report, template."""

    __tablename__ = "artifacts"
    __table_args__ = (
        Index("ix_artifacts_scan_id", "scan_id"),
        Index("ix_artifacts_job_id", "job_id"),
        Index("ix_artifacts_owner_type_owner_id", "owner_type", "owner_id"),
        Index("ix_artifacts_kind", "kind"),
        UniqueConstraint("storage_key", name="uq_artifacts_storage_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    kind: Mapped[ArtifactKind] = mapped_column(
        pg_enum(ArtifactKind, "artifact_kind"),
        nullable=False,
    )
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False)
    """path relative to the artifacts root"""
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger(), nullable=False)
    owner_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(), nullable=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(), nullable=True)
    """soft reference to scans.id (no foreign key by design)"""
    job_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(), nullable=True)
    """soft reference to scan_jobs.id"""
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
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Upload(Base):
    """A chunked upload in progress (or finished)."""

    __tablename__ = "uploads"
    __table_args__ = (
        Index("ix_uploads_state_updated_at", "state", "updated_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger(), nullable=False)
    received_bytes: Mapped[int] = mapped_column(
        BigInteger(),
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    chunk_bytes: Mapped[int] = mapped_column(Integer(), nullable=False)
    state: Mapped[UploadState] = mapped_column(
        pg_enum(UploadState, "upload_state"),
        nullable=False,
        default=UploadState.RECEIVING,
        server_default=text("'receiving'"),
    )
    sha256_expected: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    partial_key: Mapped[str] = mapped_column(String(512), nullable=False)
    artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("artifacts.id", ondelete="SET NULL"),
        nullable=True,
    )
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
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
