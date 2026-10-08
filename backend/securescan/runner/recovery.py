"""Crash recovery and housekeeping for scan jobs (periodic hooks ``stalled_jobs`` and ``workspace_gc``).

``recover_jobs`` is safe to run at any time and repeatedly:

1. *Stalled jobs*: a job in ``preparing`` or ``running`` whose heartbeat is older than ``stale_after_s``
   belongs to a worker that died. A container with the job's name (``securescan-job-<id>``; found by
   name because the socket proxy does not allow filtered listings of other containers) is removed, the
   Procrastinate row that still says ``doing`` is failed (otherwise its ``lock`` would block the tool
   forever), and the job is queued again, or failed when it already had two attempts.
2. *Lost queue entries*: a ``queued`` job older than ``job_queued_grace_seconds`` without a ``todo`` or
   ``doing`` Procrastinate row (the process died between the commit and the defer) is deferred again.
3. *Open scans*: a scan whose jobs are all final but whose own state is not gets its roll-up.
4. *Import hand-over*: a final job that never reached the DefectDojo import bookkeeping (M4) gets it.

At worker start-up ``stale_after_s=0`` treats every in-flight job as orphaned: the worker is the only
process that runs jobs, so after a restart none of them is alive.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import exists, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import get_settings
from securescan.db.models.enums import JOB_TERMINAL_STATES, ImportState, JobState, ScanState
from securescan.db.models.jobs import ScanJob
from securescan.db.models.outbox import SyncOutbox
from securescan.db.models.scans import Scan
from securescan.db.session import session_scope
from securescan.domain.scans import enqueue_scan_jobs, finalize_scan, lock_scan
from securescan.logging import get_logger
from securescan.runner.launcher import Launcher, LauncherError, get_launcher
from securescan.runner.tools.base import container_name
from securescan.runner.workspace import Workspace, remove_tree, workspaces_root
from securescan.util import ensure_utc, utcnow

log = get_logger(__name__)

MAX_ATTEMPTS = 2
IN_FLIGHT = (JobState.PREPARING, JobState.RUNNING)
HANDOVER_BATCH = 50


@dataclass
class RecoveryReport:
    requeued: list[uuid.UUID] = field(default_factory=list)
    failed: list[uuid.UUID] = field(default_factory=list)
    redeferred: list[uuid.UUID] = field(default_factory=list)
    scans_finalized: list[uuid.UUID] = field(default_factory=list)
    handed_over: list[uuid.UUID] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        return {
            "requeued": len(self.requeued),
            "failed": len(self.failed),
            "redeferred": len(self.redeferred),
            "scans_finalized": len(self.scans_finalized),
            "handed_over": len(self.handed_over),
        }


def decide_stalled(attempts: int, max_attempts: int = MAX_ATTEMPTS) -> JobState:
    """What happens to a stalled job: queued again while it has attempts left, else failed."""
    return JobState.QUEUED if attempts < max_attempts else JobState.FAILED


def is_stale(heartbeat_at: datetime | None, updated_at: datetime, now: datetime, stale_after_s: float) -> bool:
    """True when nothing was heard from a job for ``stale_after_s`` (0 = always)."""
    if stale_after_s <= 0:
        return True
    last = ensure_utc(heartbeat_at or updated_at)
    return (now - last).total_seconds() >= stale_after_s


async def _fail_queue_row(db: AsyncSession, procrastinate_job_id: int | None) -> None:
    """A ``doing`` Procrastinate row of a dead worker would hold the tool's lock forever."""
    if procrastinate_job_id is None:
        return
    await db.execute(
        text(
            "UPDATE procrastinate_jobs SET status = 'failed' "
            "WHERE id = :id AND status::text = 'doing'"
        ),
        {"id": procrastinate_job_id},
    )


async def _has_live_entry(db: AsyncSession, job_id: uuid.UUID) -> bool:
    found = await db.scalar(
        text(
            "SELECT 1 FROM procrastinate_jobs WHERE task_name = 'scan_job' "
            "AND status::text IN ('todo', 'doing') AND args ->> 'job_id' = :job_id LIMIT 1"
        ),
        {"job_id": str(job_id)},
    )
    return found is not None


async def recover_jobs(
    *,
    stale_after_s: float | None = None,
    launcher: Launcher | None = None,
    now: datetime | None = None,
) -> RecoveryReport:
    """Run all four recovery steps. See the module docstring."""
    settings = get_settings()
    stale_for = settings.job_stale_after_seconds if stale_after_s is None else stale_after_s
    clock = now or utcnow()
    report = RecoveryReport()
    docker = launcher or get_launcher()
    await _recover_in_flight(report, docker, stale_for, clock)
    await _redefer_lost(report, clock, settings.job_queued_grace_seconds)
    await _finalize_open_scans(report)
    await _hand_over_final_jobs(report, clock)
    if any(report.summary().values()):
        log.info("recovery_done", **report.summary())
    return report


async def _recover_in_flight(
    report: RecoveryReport, docker: Launcher, stale_for: float, now: datetime
) -> None:
    async with session_scope() as db:
        rows = (
            await db.scalars(select(ScanJob).where(ScanJob.state.in_(IN_FLIGHT)).order_by(ScanJob.created_at))
        ).all()
        candidates = [
            (job.id, job.scan_id, job.attempts or 0, job.procrastinate_job_id)
            for job in rows
            if is_stale(job.heartbeat_at, job.updated_at, now, stale_for)
        ]
    requeue_scans: dict[uuid.UUID, list[uuid.UUID]] = {}
    for job_id, scan_id, attempts, procrastinate_id in candidates:
        try:
            info = await docker.inspect(container_name(job_id))
            if info is not None:
                await docker.remove(str(info.get("Id") or container_name(job_id)), force=True)
        except LauncherError as exc:
            log.warning("recovery_docker_unavailable", job_id=str(job_id), error=str(exc)[:200])
            continue  # try again at the next run; never guess about a container we cannot see
        target = decide_stalled(attempts)
        async with session_scope() as db:
            await lock_scan(db, scan_id)
            job = await db.scalar(select(ScanJob).where(ScanJob.id == job_id).with_for_update())
            if job is None or job.state not in IN_FLIGHT:
                continue
            await _fail_queue_row(db, procrastinate_id)
            current = utcnow()
            job.updated_at = current
            job.container_id = None
            job.heartbeat_at = None
            if target == JobState.QUEUED:
                job.state = JobState.QUEUED
                job.outcome_reason = "The worker stopped while this job ran; it was queued again."
                requeue_scans.setdefault(scan_id, []).append(job_id)
                report.requeued.append(job_id)
            else:
                job.state = JobState.FAILED
                job.finished_at = current
                job.outcome_reason = (
                    "The worker stopped while this job ran, and it already had its second attempt."
                )
                report.failed.append(job_id)
            await finalize_scan(db, scan_id)
        await asyncio.to_thread(remove_tree, Workspace.path_for(job_id))
    for scan_id, job_ids in requeue_scans.items():
        await enqueue_scan_jobs(scan_id, only_jobs=set(job_ids))


async def _redefer_lost(report: RecoveryReport, now: datetime, grace_s: int) -> None:
    cutoff = now - timedelta(seconds=grace_s)
    by_scan: dict[uuid.UUID, list[uuid.UUID]] = {}
    async with session_scope() as db:
        rows = (
            await db.scalars(
                select(ScanJob).where(ScanJob.state == JobState.QUEUED, ScanJob.updated_at < cutoff)
            )
        ).all()
        for job in rows:
            if job.id in report.requeued:
                continue
            scan = await db.get(Scan, job.scan_id)
            if scan is None or scan.cancel_requested_at is not None:
                continue
            if not await _has_live_entry(db, job.id):
                by_scan.setdefault(job.scan_id, []).append(job.id)
    for scan_id, job_ids in by_scan.items():
        await enqueue_scan_jobs(scan_id, only_jobs=set(job_ids))
        report.redeferred.extend(job_ids)


async def _finalize_open_scans(report: RecoveryReport) -> None:
    async with session_scope() as db:
        open_job = (
            select(ScanJob.id)
            .where(ScanJob.scan_id == Scan.id, ScanJob.state.not_in(list(JOB_TERMINAL_STATES)))
            .exists()
        )
        any_job = select(ScanJob.id).where(ScanJob.scan_id == Scan.id).exists()
        ids = (
            await db.scalars(
                select(Scan.id).where(
                    Scan.state.in_([ScanState.QUEUED, ScanState.RUNNING]), ~open_job, any_job
                )
            )
        ).all()
        for scan_id in ids:
            await finalize_scan(db, scan_id)
            report.scans_finalized.append(scan_id)


async def _hand_over_final_jobs(report: RecoveryReport, now: datetime) -> None:
    """Final jobs that never reached the import bookkeeping (the process died right after the commit)."""
    cutoff = now - timedelta(minutes=2)
    async with session_scope() as db:
        has_outbox = exists().where(SyncOutbox.job_id == ScanJob.id)
        ids = (
            await db.scalars(
                select(ScanJob.id)
                .where(
                    ScanJob.state.in_(list(JOB_TERMINAL_STATES)),
                    ScanJob.import_state == ImportState.PENDING,
                    ScanJob.finished_at.is_not(None),
                    ScanJob.finished_at < cutoff,
                    ~has_outbox,
                )
                .order_by(ScanJob.finished_at)
                .limit(HANDOVER_BATCH)
            )
        ).all()
    if not ids:
        return
    try:
        from securescan.jobs.import_job import enqueue_import
    except ImportError:  # pragma: no cover - the DefectDojo milestone is not installed
        return
    for job_id in ids:
        try:
            async with session_scope() as db:
                await enqueue_import(db, job_id)
            report.handed_over.append(job_id)
        except Exception as exc:  # noqa: BLE001 - one bad job must not stop the sweep
            log.warning("handover_failed", job_id=str(job_id), error=type(exc).__name__)


# --------------------------------------------------------------------------- workspace garbage collection
def workspace_age_hours(path: object, now_ts: float) -> float:
    try:
        return (now_ts - os.stat(str(path)).st_mtime) / 3600.0
    except OSError:
        return 0.0


async def gc_workspaces(max_age_hours: float | None = None) -> list[str]:
    """Remove workspace directories older than ``max_age_hours`` that no live job owns."""
    settings = get_settings()
    limit = settings.workspace_max_age_hours if max_age_hours is None else max_age_hours
    root = workspaces_root()
    if not root.is_dir():
        return []
    removed: list[str] = []
    now = utcnow()
    now_ts = time.time()
    for path in sorted(root.iterdir()):
        try:
            job_id = uuid.UUID(path.name)
        except ValueError:
            continue  # not ours: never delete what we did not create
        if not path.is_dir() or workspace_age_hours(path, now_ts) < limit:
            continue
        async with session_scope() as db:
            job = await db.get(ScanJob, job_id)
            alive = (
                job is not None
                and job.state in IN_FLIGHT
                and not is_stale(job.heartbeat_at, job.updated_at, now, settings.job_stale_after_seconds)
            )
        if alive:
            continue
        if await asyncio.to_thread(remove_tree, path):
            removed.append(path.name)
    if removed:
        log.info("workspace_gc", removed=len(removed))
    return removed
