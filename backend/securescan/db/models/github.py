"""GitHub connection and repository poller state."""

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


class GitHubConnection(Base):
    """The GitHub App connection of one organisation."""

    __tablename__ = "github_connections"
    __table_args__ = (
        UniqueConstraint("org_login", name="uq_github_connections_org_login"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    org_login: Mapped[str | None] = mapped_column(String(200), nullable=True)
    app_id: Mapped[str] = mapped_column(String(64), nullable=False)
    client_id: Mapped[str] = mapped_column(String(128), nullable=False)
    installation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    api_base_url: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="https://api.github.com",
        server_default=text("'https://api.github.com'"),
    )
    git_host: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="github.com",
        server_default=text("'github.com'"),
    )
    api_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="2026-03-10",
        server_default=text("'2026-03-10'"),
    )
    key_1_credential_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("credentials.id", ondelete="SET NULL"),
        nullable=True,
    )
    key_2_credential_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(),
        ForeignKey("credentials.id", ondelete="SET NULL"),
        nullable=True,
    )
    active_key: Mapped[int] = mapped_column(
        Integer(),
        nullable=False,
        default=1,
        server_default=text("1"),
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean(), nullable=True)
    last_test_message: Mapped[str | None] = mapped_column(Text(), nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_poll_ok: Mapped[bool | None] = mapped_column(Boolean(), nullable=True)
    last_poll_message: Mapped[str | None] = mapped_column(Text(), nullable=True)
    rate_limit_remaining: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    rate_limit_reset_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
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


class RepositoryHead(Base):
    """Poller state per repository branch."""

    __tablename__ = "repository_heads"
    __table_args__ = (
        UniqueConstraint(
            "application_id",
            "branch",
            name="uq_repository_heads_application_id_branch",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=new_id)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("applications.id", ondelete="RESTRICT"),
        nullable=False,
    )
    repository: Mapped[str] = mapped_column(String(255), nullable=False)
    branch: Mapped[str] = mapped_column(String(255), nullable=False)
    last_seen_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_scanned_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(), nullable=True)
    """soft reference to scans.id"""
    last_poll_error: Mapped[str | None] = mapped_column(Text(), nullable=True)
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
