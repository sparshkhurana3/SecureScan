"""Schedules (Admin): weekly repository scans, DAST crons and the poller settings.

* ``weekly``: a cron (default Sunday 02:00 UTC), a repository set (``{"mode": "automatic"}`` or
  ``{"application_ids": [...]}``) and the scan profile (default ``code-standard``).
* ``dast``: a cron, a URL target and a scan profile; blackout windows keep scans out of busy hours.
* ``poll``: switch the change poller on or off and set its minimum interval.

The evaluator that starts the scans is ``securescan/jobs/schedules.py``. Times are UTC.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import Conflict, UnprocessableEntity
from securescan.api.schemas import BlackoutWindow, ORMModel
from securescan.auth.roles import AdminUser
from securescan.db.models.applications import Application
from securescan.db.models.enums import ScheduleKind, TargetKind
from securescan.db.models.schedules import Schedule
from securescan.db.models.targets import Target
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.integrations.github.poller import CODE_PROFILE
from securescan.integrations.github.scheduling import (
    DEFAULT_WEEKLY_CRON,
    CronError,
    next_run,
    validate_blackout_windows,
    validate_cron_expression,
)
from securescan.util import utcnow

router = APIRouter(tags=["schedules"])

MAX_REPOSITORY_SET = 5000


class ScheduleOut(ORMModel):
    id: uuid.UUID
    name: str
    kind: ScheduleKind
    enabled: bool
    cron: str | None
    poll_interval_minutes: int | None
    blackout_windows: list[dict[str, Any]]
    repository_set: dict[str, Any]
    target_id: uuid.UUID | None
    profile_name: str | None
    last_run_at: datetime | None
    next_run_at: datetime | None
    last_status: str | None
    created_at: datetime
    updated_at: datetime


class ScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: Literal["weekly", "dast", "poll"]
    enabled: bool = True
    cron: str | None = Field(default=None, max_length=100)
    poll_interval_minutes: int | None = Field(default=None, ge=1, le=1440)
    blackout_windows: list[BlackoutWindow] = Field(default_factory=list, max_length=50)
    repository_set: dict[str, Any] | None = None
    target_id: uuid.UUID | None = None
    profile_name: str | None = Field(default=None, min_length=1, max_length=100)


class ScheduleUpdate(BaseModel):
    """Only the fields present in the request are changed (the kind cannot change)."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    enabled: bool | None = None
    cron: str | None = Field(default=None, max_length=100)
    poll_interval_minutes: int | None = Field(default=None, ge=1, le=1440)
    blackout_windows: list[BlackoutWindow] | None = Field(default=None, max_length=50)
    repository_set: dict[str, Any] | None = None
    target_id: uuid.UUID | None = None
    profile_name: str | None = Field(default=None, min_length=1, max_length=100)


# --------------------------------------------------------------------------- validation
def _cron(expression: str) -> str:
    try:
        return validate_cron_expression(expression)
    except CronError as exc:
        raise UnprocessableEntity(str(exc), code="schedule.invalid_cron") from exc


def _windows(windows: list[BlackoutWindow]) -> list[dict[str, Any]]:
    result = [w.model_dump(mode="json", exclude_none=True) for w in windows]
    try:
        validate_blackout_windows(result)
    except CronError as exc:
        raise UnprocessableEntity(str(exc), code="schedule.invalid_blackout") from exc
    return result


async def _repository_set(db: DbSession, value: dict[str, Any] | None) -> dict[str, Any]:
    """Normalise and check a repository set; the default is the automatic set."""
    if not value:
        return {"mode": "automatic"}
    if set(value) - {"mode", "application_ids"}:
        raise UnprocessableEntity(
            "A repository set has 'mode' (automatic) or 'application_ids'",
            code="schedule.invalid_repository_set",
        )
    ids = value.get("application_ids")
    if ids is None:
        if value.get("mode", "automatic") != "automatic":
            raise UnprocessableEntity(
                "The only repository mode is 'automatic'", code="schedule.invalid_repository_set"
            )
        return {"mode": "automatic"}
    if not isinstance(ids, list) or not ids or len(ids) > MAX_REPOSITORY_SET:
        raise UnprocessableEntity(
            "application_ids must be a list of 1 to %d application ids" % MAX_REPOSITORY_SET,
            code="schedule.invalid_repository_set",
        )
    try:
        parsed = sorted({uuid.UUID(str(i)) for i in ids}, key=str)
    except ValueError as exc:
        raise UnprocessableEntity(
            "application_ids must be application ids", code="schedule.invalid_repository_set"
        ) from exc
    found = await db.scalars(select(Application.id).where(Application.id.in_(parsed)))
    missing = set(parsed) - set(found.all())
    if missing:
        raise UnprocessableEntity(
            "%d of the applications do not exist" % len(missing),
            code="schedule.unknown_application",
        )
    return {"application_ids": [str(i) for i in parsed]}


async def _check_dast_target(db: DbSession, target_id: uuid.UUID | None) -> None:
    if target_id is None:
        raise UnprocessableEntity("A DAST schedule needs a URL target", code="schedule.target_required")
    target = await get_or_404(db, Target, target_id, "Target")
    if target.kind != TargetKind.URL or target.archived_at is not None:
        raise UnprocessableEntity(
            "A DAST schedule needs an active URL target", code="schedule.target_kind"
        )


def _compute_next(cron: str | None, enabled: bool, now: datetime) -> datetime | None:
    if not enabled or not cron:
        return None
    return next_run(cron, now)


# --------------------------------------------------------------------------- endpoints
@router.get("/schedules", response_model=CursorPage[ScheduleOut], summary="List schedules (Admin)")
async def list_schedules(
    db: DbSession,
    user: AdminUser,
    page: PageDep,
    kind: ScheduleKind | None = None,
    enabled: bool | None = None,
) -> CursorPage[ScheduleOut]:
    stmt = select(Schedule)
    if kind is not None:
        stmt = stmt.where(Schedule.kind == kind)
    if enabled is not None:
        stmt = stmt.where(Schedule.enabled.is_(enabled))
    result = await paginate(db, stmt, key=[Schedule.created_at, Schedule.id], params=page)
    return CursorPage(
        items=[ScheduleOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@router.post(
    "/schedules", response_model=ScheduleOut, status_code=201, summary="Create a schedule (Admin)"
)
async def create_schedule(
    body: ScheduleCreate, request: Request, db: DbSession, user: AdminUser
) -> ScheduleOut:
    kind = ScheduleKind(body.kind)
    now = utcnow()
    cron: str | None = None
    profile = body.profile_name
    repository_set: dict[str, Any] = {}
    target_id: uuid.UUID | None = None
    if kind == ScheduleKind.WEEKLY:
        cron = _cron(body.cron or DEFAULT_WEEKLY_CRON)
        profile = profile or CODE_PROFILE
        repository_set = await _repository_set(db, body.repository_set)
        if body.target_id is not None:
            raise UnprocessableEntity("A weekly schedule has no target", code="schedule.target_not_allowed")
    elif kind == ScheduleKind.DAST:
        if not body.cron:
            raise UnprocessableEntity("A DAST schedule needs a cron expression", code="schedule.cron_required")
        cron = _cron(body.cron)
        if not profile:
            raise UnprocessableEntity("A DAST schedule needs a scan profile", code="schedule.profile_required")
        await _check_dast_target(db, body.target_id)
        target_id = body.target_id
    else:
        if body.poll_interval_minutes is None:
            raise UnprocessableEntity(
                "A poll schedule needs poll_interval_minutes", code="schedule.interval_required"
            )
        existing = await db.scalar(select(Schedule.id).where(Schedule.kind == ScheduleKind.POLL).limit(1))
        if existing is not None:
            raise Conflict(
                "There is already a poll schedule; change that one", code="schedule.poll_exists"
            )
        profile = None
    row = Schedule(
        name=body.name.strip(),
        kind=kind,
        enabled=body.enabled,
        cron=cron,
        poll_interval_minutes=body.poll_interval_minutes if kind == ScheduleKind.POLL else None,
        blackout_windows=_windows(body.blackout_windows),
        repository_set=repository_set,
        target_id=target_id,
        profile_name=profile,
        next_run_at=_compute_next(cron, body.enabled, now),
        created_by_id=user.id,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.flush()
    await record_audit(
        db,
        user,
        "schedule.create",
        "schedule",
        row.id,
        {"name": row.name, "kind": kind.value, "cron": cron, "target_id": str(target_id) if target_id else None},
        request,
    )
    await db.commit()
    return ScheduleOut.model_validate(row)


@router.get("/schedules/{schedule_id}", response_model=ScheduleOut, summary="Get a schedule (Admin)")
async def get_schedule(schedule_id: uuid.UUID, db: DbSession, user: AdminUser) -> ScheduleOut:
    return ScheduleOut.model_validate(await get_or_404(db, Schedule, schedule_id, "Schedule"))


@router.patch(
    "/schedules/{schedule_id}", response_model=ScheduleOut, summary="Change a schedule (Admin)"
)
async def update_schedule(
    schedule_id: uuid.UUID,
    body: ScheduleUpdate,
    request: Request,
    db: DbSession,
    user: AdminUser,
) -> ScheduleOut:
    row = await get_or_404(db, Schedule, schedule_id, "Schedule")
    changes = body.model_dump(exclude_unset=True)
    now = utcnow()
    recompute = False
    if "name" in changes and changes["name"] is not None:
        row.name = changes["name"].strip()
    if "enabled" in changes and changes["enabled"] is not None:
        recompute = recompute or changes["enabled"] != row.enabled
        row.enabled = changes["enabled"]
    if "cron" in changes:
        if row.kind == ScheduleKind.POLL:
            raise UnprocessableEntity("A poll schedule has no cron", code="schedule.cron_not_allowed")
        if not changes["cron"]:
            raise UnprocessableEntity("A cron expression is required", code="schedule.cron_required")
        row.cron = _cron(changes["cron"])
        recompute = True
    if "poll_interval_minutes" in changes and changes["poll_interval_minutes"] is not None:
        if row.kind != ScheduleKind.POLL:
            raise UnprocessableEntity(
                "Only a poll schedule has a poll interval", code="schedule.interval_not_allowed"
            )
        row.poll_interval_minutes = changes["poll_interval_minutes"]
    if body.blackout_windows is not None:
        row.blackout_windows = _windows(body.blackout_windows)
    if "repository_set" in changes:
        if row.kind != ScheduleKind.WEEKLY:
            raise UnprocessableEntity(
                "Only a weekly schedule has a repository set", code="schedule.repository_set_not_allowed"
            )
        row.repository_set = await _repository_set(db, changes["repository_set"])
    if "target_id" in changes:
        if row.kind != ScheduleKind.DAST:
            raise UnprocessableEntity("Only a DAST schedule has a target", code="schedule.target_not_allowed")
        await _check_dast_target(db, changes["target_id"])
        row.target_id = changes["target_id"]
    if "profile_name" in changes and changes["profile_name"]:
        if row.kind == ScheduleKind.POLL:
            raise UnprocessableEntity("A poll schedule has no profile", code="schedule.profile_not_allowed")
        row.profile_name = changes["profile_name"]
    if recompute:
        row.next_run_at = _compute_next(row.cron, row.enabled, now)
    row.updated_at = now
    await record_audit(
        db, user, "schedule.update", "schedule", row.id, {"changed": sorted(changes)}, request
    )
    await db.commit()
    return ScheduleOut.model_validate(row)


@router.delete("/schedules/{schedule_id}", status_code=204, summary="Delete a schedule (Admin)")
async def delete_schedule(
    schedule_id: uuid.UUID, request: Request, db: DbSession, user: AdminUser
) -> Response:
    row = await get_or_404(db, Schedule, schedule_id, "Schedule")
    await record_audit(
        db, user, "schedule.delete", "schedule", row.id, {"name": row.name, "kind": row.kind.value}, request
    )
    await db.delete(row)
    await db.commit()
    return Response(status_code=204)
