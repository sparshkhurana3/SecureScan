"""``GET /summary``: what the Home page shows (running and queued scans, latest results, open counts)."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.auth.roles import AnalystUser
from securescan.config import get_settings
from securescan.db.models.applications import Application
from securescan.db.models.enums import JobState, OutboxState, ScanKind, ScanState, Verdict
from securescan.db.models.jobs import ScanJob
from securescan.db.models.outbox import SyncOutbox
from securescan.db.models.scans import Scan
from securescan.db.models.versions import ApplicationVersion
from securescan.db.session import DbSession
from securescan.integrations.defectdojo.findings import SEVERITY_NAMES, empty_counts

router = APIRouter(tags=["results"])

LIST_LIMIT = 20
LATEST_LIMIT = 10
_FINISHED = (ScanState.COMPLETED, ScanState.COMPLETED_PARTIAL, ScanState.FAILED)
_JOB_FINAL = (
    JobState.COMPLETED,
    JobState.COMPLETED_PARTIAL,
    JobState.FAILED,
    JobState.CANCELLED,
    JobState.TIMED_OUT,
)


class SummaryScanOut(BaseModel):
    scan_id: uuid.UUID
    application_id: uuid.UUID
    application_name: str
    version_label: str
    kind: ScanKind
    state: ScanState
    verdict: Verdict
    counts: dict[str, Any]
    tools: list[str]
    jobs_total: int
    jobs_done: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ImportQueueOut(BaseModel):
    pending: int
    dead_letters: int


class SummaryOut(BaseModel):
    running: list[SummaryScanOut]
    queued: list[SummaryScanOut]
    latest: list[SummaryScanOut]
    open_counts: dict[str, int]
    applications: int
    applications_scanned: int
    import_queue: ImportQueueOut
    defectdojo_url: str


async def _scans_out(db: AsyncSession, scans: list[Scan]) -> list[SummaryScanOut]:
    if not scans:
        return []
    app_ids = {s.application_id for s in scans}
    version_ids = {s.version_id for s in scans}
    names = dict(
        (await db.execute(select(Application.id, Application.name).where(Application.id.in_(app_ids)))).all()
    )
    labels = dict(
        (
            await db.execute(
                select(ApplicationVersion.id, ApplicationVersion.label).where(
                    ApplicationVersion.id.in_(version_ids)
                )
            )
        ).all()
    )
    tools: dict[uuid.UUID, list[str]] = defaultdict(list)
    done: dict[uuid.UUID, int] = defaultdict(int)
    for scan_id, tool, state in (
        await db.execute(
            select(ScanJob.scan_id, ScanJob.tool, ScanJob.state).where(
                ScanJob.scan_id.in_([s.id for s in scans])
            )
        )
    ).all():
        tools[scan_id].append(tool)
        if state in _JOB_FINAL:
            done[scan_id] += 1
    return [
        SummaryScanOut(
            scan_id=s.id,
            application_id=s.application_id,
            application_name=names.get(s.application_id, "?"),
            version_label=labels.get(s.version_id, "?"),
            kind=s.kind,
            state=s.state,
            verdict=s.verdict,
            counts=s.counts or empty_counts(),
            tools=sorted(tools[s.id]),
            jobs_total=len(tools[s.id]),
            jobs_done=done[s.id],
            created_at=s.created_at,
            started_at=s.started_at,
            finished_at=s.finished_at,
        )
        for s in scans
    ]


@router.get("/summary", response_model=SummaryOut, summary="Home page: running scans, latest results")
async def summary(db: DbSession, user: AnalystUser) -> SummaryOut:
    running = list(
        (
            await db.scalars(
                select(Scan).where(Scan.state == ScanState.RUNNING).order_by(Scan.created_at.desc()).limit(LIST_LIMIT)
            )
        ).all()
    )
    queued = list(
        (
            await db.scalars(
                select(Scan).where(Scan.state == ScanState.QUEUED).order_by(Scan.created_at).limit(LIST_LIMIT)
            )
        ).all()
    )
    latest = list(
        (
            await db.scalars(
                select(Scan)
                .where(Scan.state.in_(_FINISHED))
                .order_by(func.coalesce(Scan.finished_at, Scan.created_at).desc(), Scan.id)
                .limit(LATEST_LIMIT)
            )
        ).all()
    )
    open_counts = empty_counts()
    for name in SEVERITY_NAMES:
        total = await db.scalar(
            select(func.coalesce(func.sum(Application.cached_counts[name].as_integer()), 0)).where(
                Application.archived_at.is_(None)
            )
        )
        open_counts[name] = int(total or 0)
    open_counts["total"] = sum(open_counts[n] for n in SEVERITY_NAMES)
    applications = int(
        await db.scalar(select(func.count()).select_from(Application).where(Application.archived_at.is_(None)))
        or 0
    )
    scanned = int(
        await db.scalar(
            select(func.count())
            .select_from(Application)
            .where(Application.archived_at.is_(None), Application.last_scan_id.is_not(None))
        )
        or 0
    )
    pending = int(
        await db.scalar(
            select(func.count())
            .select_from(SyncOutbox)
            .where(SyncOutbox.state.in_([OutboxState.PENDING, OutboxState.PROCESSING]))
        )
        or 0
    )
    dead = int(
        await db.scalar(
            select(func.count()).select_from(SyncOutbox).where(SyncOutbox.state == OutboxState.DEAD_LETTER)
        )
        or 0
    )
    return SummaryOut(
        running=await _scans_out(db, running),
        queued=await _scans_out(db, queued),
        latest=await _scans_out(db, latest),
        open_counts=open_counts,
        applications=applications,
        applications_scanned=scanned,
        import_queue=ImportQueueOut(pending=pending, dead_letters=dead),
        defectdojo_url=get_settings().defectdojo_public_url,
    )
