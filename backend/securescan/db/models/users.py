"""Users."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, UniqueConstraint, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from securescan.db.base import Base, new_id, pg_enum, utcnow
from securescan.db.models.enums import UserRole


class User(Base):
    """A person who signed in through Entra ID (or the dev provider). No passwords are stored."""

    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_last_login", "last_login"),
        UniqueConstraint("oid", name="uq_users_oid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    oid: Mapped[str] = mapped_column(String(255), nullable=False)
    """Entra object id (or the OIDC subject) - the stable identity"""
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    upn: Mapped[str | None] = mapped_column(String(320), nullable=True)
    """user principal name; DefectDojo username source"""
    role: Mapped[UserRole] = mapped_column(pg_enum(UserRole, "user_role"), nullable=False)
    """effective role at the last sign-in"""
    roles: Mapped[list[Any]] = mapped_column(
        JSONB(),
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    """all role values of the roles claim at the last sign-in"""
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dd_user_id: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    """DefectDojo user id (M4)"""
    dd_username: Mapped[str | None] = mapped_column(String(150), nullable=True)
    dd_initial_secret: Mapped[str | None] = mapped_column(Text(), nullable=True)
    """encrypted initial DefectDojo password, shown once"""
    dd_secret_shown_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    dd_disabled: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    dd_disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
