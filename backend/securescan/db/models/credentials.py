"""Encrypted credentials."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, pg_enum, utcnow
from securescan.db.models.enums import CredentialKind


class Credential(Base):
    """An encrypted secret (AES-256-GCM, see securescan.security.secrets) with its expiry."""

    __tablename__ = "credentials"
    __table_args__ = (
        Index("ix_credentials_kind", "kind"),
        Index("ix_credentials_expires_at", "expires_at"),
        Index("ix_credentials_version_id", "version_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    kind: Mapped[CredentialKind] = mapped_column(
        pg_enum(CredentialKind, "credential_kind"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    ciphertext: Mapped[str] = mapped_column(Text(), nullable=False)
    key_id: Mapped[str] = mapped_column(String(32), nullable=False)
    public_material: Mapped[str | None] = mapped_column(Text(), nullable=True)
    """deploy keys: the public key to hand out"""
    application_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("applications.id", ondelete="RESTRICT"),
        nullable=True,
    )
    version_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("application_versions.id", ondelete="RESTRICT"),
        nullable=True,
    )
    extra: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    """non-secret details (host, username, slot)"""
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expiry_alert_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
