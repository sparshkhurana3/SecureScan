"""Report templates."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, utcnow


class ReportTemplate(Base):
    """A report template (zip of HTML/CSS/brand files); the SonaComstar one ships built in."""

    __tablename__ = "report_templates"
    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_report_templates_name_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[int] = mapped_column(
        Integer(),
        nullable=False,
        default=1,
        server_default=text("1"),
    )
    builtin: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    default_for_application: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    default_for_vendor: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    zip_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("artifacts.id", ondelete="SET NULL"),
        nullable=True,
    )
    directory: Mapped[str | None] = mapped_column(String(512), nullable=True)
    """extracted template directory"""
    entry_file: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="template.html",
        server_default=text("'template.html'"),
    )
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    validation_error: Mapped[str | None] = mapped_column(Text(), nullable=True)
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
