"""Updatable scanner content versions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Index, String, UniqueConstraint, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, pg_enum, utcnow
from securescan.db.models.enums import ContentFeed


class ContentVersion(Base):
    """A version of updatable scanner content (rules, templates, vulnerability databases)."""

    __tablename__ = "content_versions"
    __table_args__ = (
        Index("ix_content_versions_feed_fetched_at", "feed", "fetched_at"),
        UniqueConstraint("feed", "version", name="uq_content_versions_feed_version"),
        Index(
            "uq_content_versions_active_feed",
            "feed",
            unique=True,
            postgresql_where=text("active"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    feed: Mapped[ContentFeed] = mapped_column(pg_enum(ContentFeed, "content_feed"), nullable=False)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    built_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    """when the upstream feed was built (feed age)"""
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
    )
    regression_result: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    """pending | passed | failed | skipped"""
    regression_detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    active: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
    )
