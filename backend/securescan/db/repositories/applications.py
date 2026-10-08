"""Queries for applications, versions, targets and vendors."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ColumnElement, Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.db.models.applications import Application
from securescan.db.models.enums import AppType, TargetEnvironment, TargetKind
from securescan.db.models.targets import Target
from securescan.db.models.vendors import Vendor
from securescan.db.models.versions import ApplicationVersion
from securescan.db.repositories.common import escape_like


def application_filters(
    *,
    app_type: AppType | None = None,
    vendor_id: uuid.UUID | None = None,
    q: str | None = None,
    confirmed: bool | None = None,
    automatic: bool | None = None,
    last_scan_after: datetime | None = None,
    last_scan_before: datetime | None = None,
    never_scanned: bool | None = None,
    min_critical: int | None = None,
    min_high: int | None = None,
    include_archived: bool = False,
) -> list[ColumnElement[bool]]:
    """WHERE conditions for ``GET /applications``."""
    conditions: list[ColumnElement[bool]] = []
    if not include_archived:
        conditions.append(Application.archived_at.is_(None))
    if app_type is not None:
        conditions.append(Application.type == app_type)
    if vendor_id is not None:
        conditions.append(Application.vendor_id == vendor_id)
    if q:
        conditions.append(Application.name.ilike(f"%{escape_like(q)}%", escape="\\"))
    if confirmed is not None:
        conditions.append(Application.confirmed.is_(confirmed))
    if automatic is not None:
        conditions.append(Application.automatic.is_(automatic))
    if last_scan_after is not None:
        conditions.append(Application.last_scan_at >= last_scan_after)
    if last_scan_before is not None:
        conditions.append(Application.last_scan_at <= last_scan_before)
    if never_scanned:
        conditions.append(Application.last_scan_at.is_(None))
    if min_critical is not None:
        conditions.append(Application.cached_counts["critical"].as_integer() >= min_critical)
    if min_high is not None:
        conditions.append(Application.cached_counts["high"].as_integer() >= min_high)
    return conditions


def select_applications(conditions: list[ColumnElement[bool]]) -> Select[tuple[Application]]:
    return select(Application).where(*conditions)


async def find_application_by_name(
    session: AsyncSession, name: str, exclude_id: uuid.UUID | None = None
) -> Application | None:
    stmt = select(Application).where(func.lower(Application.name) == name.lower())
    if exclude_id is not None:
        stmt = stmt.where(Application.id != exclude_id)
    return await session.scalar(stmt)


async def find_version_by_label(
    session: AsyncSession, application_id: uuid.UUID, label: str
) -> ApplicationVersion | None:
    return await session.scalar(
        select(ApplicationVersion).where(
            ApplicationVersion.application_id == application_id, ApplicationVersion.label == label
        )
    )


def target_filters(
    *,
    version_id: uuid.UUID | None = None,
    application_id: uuid.UUID | None = None,
    kind: TargetKind | None = None,
    environment: TargetEnvironment | None = None,
    include_archived: bool = False,
) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    if not include_archived:
        conditions.append(Target.archived_at.is_(None))
    if version_id is not None:
        conditions.append(Target.version_id == version_id)
    if application_id is not None:
        conditions.append(
            Target.version_id.in_(
                select(ApplicationVersion.id).where(ApplicationVersion.application_id == application_id)
            )
        )
    if kind is not None:
        conditions.append(Target.kind == kind)
    if environment is not None:
        conditions.append(Target.environment == environment)
    return conditions


async def application_of_version(session: AsyncSession, version_id: uuid.UUID) -> Application | None:
    return await session.scalar(
        select(Application)
        .join(ApplicationVersion, ApplicationVersion.application_id == Application.id)
        .where(ApplicationVersion.id == version_id)
    )


async def find_vendor_by_name(
    session: AsyncSession, name: str, exclude_id: uuid.UUID | None = None
) -> Vendor | None:
    stmt = select(Vendor).where(func.lower(Vendor.name) == name.lower())
    if exclude_id is not None:
        stmt = stmt.where(Vendor.id != exclude_id)
    return await session.scalar(stmt)
