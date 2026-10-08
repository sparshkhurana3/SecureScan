"""Verdict policies."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, utcnow


class Policy(Base):
    """Verdict thresholds by data classification or application."""

    __tablename__ = "policies"
    __table_args__ = (
        Index("ix_policies_data_classification", "data_classification"),
        Index("ix_policies_application_id", "application_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    data_classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
    application_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("applications.id", ondelete="RESTRICT"),
        nullable=True,
    )
    is_default: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    thresholds: Mapped[dict[str, Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    version: Mapped[int] = mapped_column(
        Integer(),
        nullable=False,
        default=1,
        server_default=text("1"),
    )
    active: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=True,
        server_default=text("true"),
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
