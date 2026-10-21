"""Application versions."""

from __future__ import annotations

import uuid
from datetime import datetime

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
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, utcnow


class ApplicationVersion(Base):
    """A version (branch, tag, upload, image digest or vendor release) of an application."""

    __tablename__ = "application_versions"
    __table_args__ = (
        Index("ix_application_versions_created_at", "created_at"),
        UniqueConstraint(
            "application_id",
            "label",
            name="uq_application_versions_application_id_label",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("applications.id", ondelete="RESTRICT"),
        nullable=False,
    )
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    label_kind: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="branch",
        server_default=text("'branch'"),
    )
    """branch | tag | upload | image_digest | release"""
    description: Mapped[str | None] = mapped_column(Text(), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dd_engagement_id: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    # Unused since SonarQube was removed (docs/decisions.md, 2026-10-21); the column stays for old rows.
    sonar_project_key: Mapped[str | None] = mapped_column(String(400), nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
