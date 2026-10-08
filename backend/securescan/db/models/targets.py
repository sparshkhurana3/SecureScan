"""Scan targets."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, pg_enum, utcnow
from securescan.db.models.enums import TargetEnvironment, TargetKind


class Target(Base):
    """What gets scanned: a repository, an upload, an image or a URL, with DAST settings."""

    __tablename__ = "targets"
    __table_args__ = (
        Index("ix_targets_version_id", "version_id"),
        Index("ix_targets_kind_environment", "kind", "environment"),
        Index("ix_targets_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("application_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    kind: Mapped[TargetKind] = mapped_column(pg_enum(TargetKind, "target_kind"), nullable=False)
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    locator: Mapped[str] = mapped_column(Text(), nullable=False)
    """repo (owner/name or URL), upload:<artifact id>, image reference, URL"""
    environment: Mapped[TargetEnvironment | None] = mapped_column(
        pg_enum(TargetEnvironment, "target_environment"),
        nullable=True,
    )
    """url targets only"""
    environment_set_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    environment_set_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("credentials.id", ondelete="SET NULL"),
        nullable=True,
    )
    """clone/registry credential"""
    login_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("credentials.id", ondelete="SET NULL"),
        nullable=True,
    )
    """DAST login profile (credential kind dast_login), uat only"""
    upload_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("artifacts.id", ondelete="SET NULL"),
        nullable=True,
    )
    default_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scope_includes: Mapped[list[Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    """DAST in-scope regexes"""
    scope_excludes: Mapped[list[Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    """DAST excluded paths"""
    api_spec_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    """openapi | graphql | soap"""
    api_spec_locator: Mapped[str | None] = mapped_column(Text(), nullable=True)
    api_spec_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("artifacts.id", ondelete="SET NULL"),
        nullable=True,
    )
    rate_limit_rps: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    blackout_windows: Mapped[list[Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    dast_cron: Mapped[str | None] = mapped_column(String(100), nullable=True)
    host_approved: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    """explicit Admin approval of the host outside the CIDR allowlist"""
    vendor_authorization_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("artifacts.id", ondelete="SET NULL"),
        nullable=True,
    )
    vendor_authorized_from: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    vendor_authorized_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    vendor_contact: Mapped[str | None] = mapped_column(Text(), nullable=True)
    vendor_authorization_notes: Mapped[str | None] = mapped_column(Text(), nullable=True)
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
