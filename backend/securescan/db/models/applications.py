"""Applications (the inventory unit)."""

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
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, pg_enum, utcnow
from securescan.db.models.enums import AppType, Verdict


class Application(Base):
    """The inventory unit: an internal application or a vendor product."""

    __tablename__ = "applications"
    __table_args__ = (
        Index("ix_applications_type", "type"),
        Index("ix_applications_vendor_id", "vendor_id"),
        Index("ix_applications_last_scan_at", "last_scan_at"),
        Index("ix_applications_created_at", "created_at"),
        UniqueConstraint("name", name="uq_applications_name"),
        UniqueConstraint("github_repo_id", name="uq_applications_github_repo_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    type: Mapped[AppType] = mapped_column(pg_enum(AppType, "app_type"), nullable=False)
    vendor_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("vendors.id", ondelete="RESTRICT"),
        nullable=True,
    )
    vendor_product: Mapped[str | None] = mapped_column(String(200), nullable=True)
    hosting: Mapped[str | None] = mapped_column(String(16), nullable=True)
    """vendor products: deployable | saas"""
    description: Mapped[str | None] = mapped_column(Text(), nullable=True)
    criticality: Mapped[str | None] = mapped_column(String(16), nullable=True)
    """low | medium | high | critical"""
    data_classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
    """public | internal | confidential | restricted"""
    tags: Mapped[list[Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    confirmed: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    """false for repositories discovered from GitHub until an analyst confirms them"""
    automatic: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    """member of the automatic scan set"""
    github_repo_id: Mapped[int | None] = mapped_column(BigInteger(), nullable=True)
    github_full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    default_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    github_removed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    """set when discovery no longer sees the repository"""
    dd_product_id: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    """DefectDojo Product (Asset) id"""
    cached_counts: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    """open finding counts by severity {critical, high, medium, low, info}"""
    cached_counts_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(), nullable=True)
    """soft reference to scans.id"""
    last_verdict: Mapped[Verdict | None] = mapped_column(pg_enum(Verdict, "verdict"), nullable=True)
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
