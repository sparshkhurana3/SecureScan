"""The schedule evaluator: weekly repository scans and DAST schedules (periodic task, every minute).

For every enabled ``Schedule`` of kind ``weekly`` or ``dast`` it asks ``evaluate_schedule`` what to do
(rules and blackout windows are in ``integrations/github/scheduling.py``):

* ``weekly``: when due, one ``code-standard`` scan (trigger ``weekly``) per repository of the set
  (``repository_set``: ``{"mode": "automatic"}`` or ``{"application_ids": [...]}``).
* ``dast``: when due, one scan of the schedule's target with the schedule's profile (trigger
  ``schedule``). The production rule (baseline only) is enforced by scan creation, not here.

Missed runs collapse into one; a run due inside a blackout window waits for it to end (at most 24
hours), then the occurrence is skipped. Every scan carries an idempotency key built from the schedule,
the application and the due time, so a retried evaluation never creates a second scan.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.db.models.applications import Application
from securescan.db.models.enums import ScanTrigger, ScheduleKind
from securescan.db.models.schedules import Schedule
from securescan.db.models.targets import Target
from securescan.db.session import session_scope
from securescan.integrations.github.discovery import ensure_default_version
from securescan.integrations.github.poller import (
    CODE_PROFILE,
    automatic_conditions,
    failure_reason,
    has_active_sast_scan,
)
from securescan.integrations.github.scheduling import (
    DEFAULT_WEEKLY_CRON,
    CronError,
    evaluate_schedule,
)
from securescan.jobs.app import app
from securescan.logging import get_logger
from securescan.util import utcnow

log = get_logger(__name__)

STATUS_MAX = 250


@app.periodic(cron="* * * * *")
@app.task(name="schedule_evaluator", queue="maintenance", queueing_lock="schedule_evaluator")
async def schedule_evaluator(timestamp: int) -> None:
    """Start every schedule that is due."""
    await evaluate_due_schedules(utcnow())


async def evaluate_due_schedules(now: datetime) -> int:
    """Evaluate all enabled schedules; returns how many started scans this minute."""
    async with session_scope() as session:
        ids = list(
            (
                await session.scalars(
                    select(Schedule.id).where(
                        Schedule.enabled.is_(True),
                        Schedule.kind.in_([ScheduleKind.WEEKLY, ScheduleKind.DAST]),
                    )
                )
            ).all()
        )
    started = 0
    for schedule_id in ids:
        try:
            if await evaluate_one(schedule_id, now):
                started += 1
        except Exception as exc:  # noqa: BLE001 - one broken schedule must not stop the others
            log.warning(
                "schedule_evaluation_failed", schedule_id=str(schedule_id), error=type(exc).__name__
            )
    return started


async def evaluate_one(schedule_id: uuid.UUID, now: datetime) -> bool:
    """Evaluate one schedule in its own transaction. True when it started scans."""
    async with session_scope() as session:
        schedule = await session.get(Schedule, schedule_id, with_for_update=True)
        if schedule is None or not schedule.enabled:
            return False
        cron = schedule.cron or (DEFAULT_WEEKLY_CRON if schedule.kind == ScheduleKind.WEEKLY else None)
        if not cron:
            _set_status(schedule, "This schedule has no cron expression.")
            return False
        windows: list[Any] = list(schedule.blackout_windows or [])
        target: Target | None = None
        if schedule.kind == ScheduleKind.DAST:
            target = await session.get(Target, schedule.target_id) if schedule.target_id else None
            if target is None or target.archived_at is not None:
                _set_status(schedule, "The target of this schedule no longer exists.")
                return False
            windows.extend(target.blackout_windows or [])
        due = schedule.next_run_at or now
        try:
            decision = evaluate_schedule(
                cron=cron, next_run_at=schedule.next_run_at, now=now, blackout_windows=windows
            )
        except CronError as exc:
            _set_status(schedule, "Invalid schedule: %s" % exc)
            return False
        if decision.action == "wait":
            if schedule.next_run_at != decision.next_run_at:
                schedule.next_run_at = decision.next_run_at
                schedule.updated_at = now
            return False
        if decision.action in ("delay", "skip"):
            schedule.next_run_at = decision.next_run_at
            _set_status(schedule, decision.reason)
            return False
        summary = await _start_scans(session, schedule, target, due)
        schedule.last_run_at = now
        schedule.next_run_at = decision.next_run_at
        _set_status(schedule, summary)
        log.info("schedule_started", schedule_id=str(schedule.id), kind=schedule.kind.value, summary=summary)
        return True


def _set_status(schedule: Schedule, status: str) -> None:
    if schedule.last_status != status[:STATUS_MAX]:
        schedule.last_status = status[:STATUS_MAX]
        schedule.updated_at = utcnow()


def _stamp(due: datetime) -> str:
    return due.strftime("%Y%m%d%H%M")


async def _start_scans(
    session: AsyncSession, schedule: Schedule, target: Target | None, due: datetime
) -> str:
    if schedule.kind == ScheduleKind.DAST:
        assert target is not None  # noqa: S101 - checked by the caller
        return await _start_dast(session, schedule, target, due)
    return await _start_weekly(session, schedule, due)


async def _weekly_applications(session: AsyncSession, schedule: Schedule) -> list[Application]:
    repository_set = schedule.repository_set or {}
    ids = repository_set.get("application_ids")
    if ids:
        parsed = [uuid.UUID(str(i)) for i in ids]
        stmt = select(Application).where(
            Application.id.in_(parsed),
            Application.archived_at.is_(None),
            Application.github_full_name.is_not(None),
            Application.default_branch.is_not(None),
        )
    else:
        stmt = select(Application).where(*automatic_conditions())
    return list((await session.scalars(stmt.order_by(Application.name))).all())


async def _start_weekly(session: AsyncSession, schedule: Schedule, due: datetime) -> str:
    from securescan.domain.scans import create_scan  # M3; imported here to keep imports light

    applications = await _weekly_applications(session, schedule)
    queued = busy = failed = 0
    first_failure = ""
    for application in applications:
        try:
            if await has_active_sast_scan(session, application.id):
                busy += 1
                continue
            prepared = await ensure_default_version(session, application)
            if prepared is None:
                failed += 1
                first_failure = first_failure or "a default-branch version is archived"
                continue
            version, target = prepared
            async with session.begin_nested():
                await create_scan(
                    session,
                    version_id=version.id,
                    profile_name=schedule.profile_name or CODE_PROFILE,
                    trigger=ScanTrigger.WEEKLY,
                    requested_by=None,
                    target_ids=[target.id],
                    options={
                        "schedule_id": str(schedule.id),
                        "trigger_detail": "weekly schedule %s" % schedule.name,
                    },
                    idempotency_key="system:weekly:%s:%s:%s" % (schedule.id, application.id, _stamp(due)),
                )
            queued += 1
            await session.commit()  # state first, queue second: the scan row is durable before it runs
        except Exception as exc:  # noqa: BLE001 - one repository must not stop the others
            failed += 1
            first_failure = first_failure or failure_reason(exc)
            log.warning(
                "weekly_scan_not_started",
                application_id=str(application.id),
                error=type(exc).__name__,
            )
    status = "%d scans queued, %d skipped (scan already running), %d not started" % (
        queued,
        busy,
        failed,
    )
    if first_failure:
        status += ": " + first_failure
    return status


async def _start_dast(
    session: AsyncSession, schedule: Schedule, target: Target, due: datetime
) -> str:
    from securescan.domain.scans import create_scan

    if not schedule.profile_name:
        return "not started: the schedule names no scan profile"
    try:
        async with session.begin_nested():
            scan = await create_scan(
                session,
                version_id=target.version_id,
                profile_name=schedule.profile_name,
                trigger=ScanTrigger.SCHEDULE,
                requested_by=None,
                target_ids=[target.id],
                options={
                    "schedule_id": str(schedule.id),
                    "trigger_detail": "schedule %s" % schedule.name,
                },
                idempotency_key="system:schedule:%s:%s" % (schedule.id, _stamp(due)),
            )
    except Exception as exc:  # noqa: BLE001 - reported in the schedule's status
        return ("not started: %s" % failure_reason(exc))[:STATUS_MAX]
    return "scan %s queued" % scan.id
