"""Scans: start, list, inspect, cancel and watch them live.

``POST /scans`` creates a ``Scan`` and one ``ScanJob`` per tool of the profile and answers ``202``; the jobs
are queued right after the transaction commits. ``Idempotency-Key`` makes the call safe to repeat: the
same key (per user) returns the first scan again with the header ``Idempotent-Replayed: true``.
``GET /scans/{id}/events`` is a server-sent event stream: a snapshot, the tail of each job log, then
state changes and log lines as they happen (PostgreSQL ``LISTEN``/``NOTIFY``, see ``runner/events.py``).
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Header, Query, Request, Response
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import NotFound
from securescan.api.schemas import ORMModel
from securescan.auth.roles import AnalystUser
from securescan.db.engine import psycopg_conninfo
from securescan.db.models.artifacts import Artifact
from securescan.db.models.enums import (
    ArtifactKind,
    ImportState,
    JobState,
    ScanKind,
    ScanState,
    ScanTrigger,
    Verdict,
)
from securescan.db.models.jobs import ScanJob
from securescan.db.models.scans import Scan
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession, session_scope
from securescan.domain.audit import record_audit
from securescan.domain.scans import (
    check_idempotency_key,
    create_scan_result,
    request_cancel,
    settle_cancelled_jobs,
)
from securescan.logging import get_logger
from securescan.runner.events import job_log_path, scan_channel, state_event, tail_lines

log = get_logger(__name__)

router = APIRouter(tags=["scans"])

KEEPALIVE_SECONDS = 5.0
FINAL_DRAIN_SECONDS = 1.0
BACKLOG_LINES = 200
STREAM_MAX_SECONDS = 12 * 3600
FINAL_SCAN_STATES = (
    ScanState.COMPLETED,
    ScanState.COMPLETED_PARTIAL,
    ScanState.FAILED,
    ScanState.CANCELLED,
)


# --------------------------------------------------------------------------- schemas
class ScanCreate(BaseModel):
    version_id: uuid.UUID
    target_id: uuid.UUID
    profile: str = Field(default="code-standard", min_length=2, max_length=100)
    profile_version: int | None = Field(default=None, ge=1)
    tools: list[str] | None = Field(default=None, description="A subset of the profile's tools")
    ref: str | None = Field(default=None, max_length=255, description="Branch, tag or commit (repositories)")
    options: dict[str, Any] = Field(default_factory=dict)


class JobOut(ORMModel):
    id: uuid.UUID
    tool: str
    state: JobState
    import_state: ImportState
    attempts: int
    exit_code: int | None
    outcome_reason: str | None
    partial: bool
    counts: dict[str, Any]
    image: str | None
    image_digest: str | None
    tool_version: str | None
    content_versions: dict[str, Any]
    applied_exclusions: list[Any]
    coverage_note: str | None
    dd_test_id: int | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ArtifactOut(ORMModel):
    id: uuid.UUID
    kind: ArtifactKind
    job_id: uuid.UUID | None
    filename: str | None
    sha256: str
    size_bytes: int
    created_at: datetime


class ScanOut(ORMModel):
    id: uuid.UUID
    application_id: uuid.UUID
    version_id: uuid.UUID
    target_id: uuid.UUID | None
    profile_name: str
    profile_version: int
    kind: ScanKind
    mode: str | None
    trigger: ScanTrigger
    trigger_detail: str | None
    state: ScanState
    verdict: Verdict
    started_by_id: uuid.UUID | None
    requested_tools: list[Any]
    commit_sha: str | None
    source_ref: str | None
    counts: dict[str, Any]
    coverage_notes: list[Any]
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    cancel_requested_at: datetime | None


class ScanDetail(ScanOut):
    jobs: list[JobOut] = Field(default_factory=list)
    artifacts: list[ArtifactOut] = Field(default_factory=list)
    replayed: bool = False
    collapsed: bool = False


async def load_detail(db: Any, scan: Scan, *, replayed: bool = False, collapsed: bool = False) -> ScanDetail:
    jobs = (
        await db.scalars(
            select(ScanJob).where(ScanJob.scan_id == scan.id).order_by(ScanJob.created_at, ScanJob.id)
        )
    ).all()
    artifacts = (
        await db.scalars(
            select(Artifact)
            .where(
                Artifact.scan_id == scan.id,
                Artifact.deleted_at.is_(None),
                Artifact.kind.in_([ArtifactKind.RAW_REPORT, ArtifactKind.SBOM, ArtifactKind.LOG]),
            )
            .order_by(Artifact.created_at, Artifact.id)
        )
    ).all()
    detail = ScanDetail.model_validate(scan)
    detail.jobs = [JobOut.model_validate(j) for j in jobs]
    detail.artifacts = [ArtifactOut.model_validate(a) for a in artifacts]
    detail.replayed = replayed
    detail.collapsed = collapsed
    return detail


# --------------------------------------------------------------------------- endpoints
@router.post(
    "/scans",
    response_model=ScanDetail,
    status_code=202,
    summary="Start a scan",
    description="Creates the scan and its jobs and returns 202. Send an Idempotency-Key to make repeats safe.",
)
async def start_scan(
    body: ScanCreate,
    request: Request,
    response: Response,
    db: DbSession,
    user: AnalystUser,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> ScanDetail:
    key = f"{user.id}:{check_idempotency_key(idempotency_key)}" if idempotency_key else None
    result = await create_scan_result(
        db,
        version_id=body.version_id,
        profile_name=body.profile,
        trigger=ScanTrigger.USER,
        requested_by=user,
        target_ids=[body.target_id],
        options=body.options,
        idempotency_key=key,
        profile_version=body.profile_version,
        tools=body.tools,
        ref=body.ref,
    )
    detail = await load_detail(db, result.scan, replayed=result.replayed, collapsed=result.collapsed)
    await db.commit()
    if result.replayed:
        response.headers["Idempotent-Replayed"] = "true"
    if result.collapsed:
        response.headers["X-Scan-Collapsed"] = "true"
    return detail


@router.get("/scans", response_model=CursorPage[ScanOut], summary="List scans, newest first")
async def list_scans(
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    application_id: uuid.UUID | None = None,
    version_id: uuid.UUID | None = None,
    state: ScanState | None = None,
    kind: ScanKind | None = None,
    trigger: ScanTrigger | None = None,
    active: Annotated[bool | None, Query(description="Only queued or running scans")] = None,
) -> CursorPage[ScanOut]:
    stmt = select(Scan)
    if application_id is not None:
        stmt = stmt.where(Scan.application_id == application_id)
    if version_id is not None:
        stmt = stmt.where(Scan.version_id == version_id)
    if state is not None:
        stmt = stmt.where(Scan.state == state)
    if kind is not None:
        stmt = stmt.where(Scan.kind == kind)
    if trigger is not None:
        stmt = stmt.where(Scan.trigger == trigger)
    if active:
        stmt = stmt.where(Scan.state.in_([ScanState.QUEUED, ScanState.RUNNING]))
    result = await paginate(db, stmt, key=[Scan.created_at, Scan.id], params=page)
    return CursorPage(
        items=[ScanOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@router.get("/scans/{scan_id}", response_model=ScanDetail, summary="Get a scan with its jobs")
async def get_scan(scan_id: uuid.UUID, db: DbSession, user: AnalystUser) -> ScanDetail:
    scan = await get_or_404(db, Scan, scan_id, "Scan")
    return await load_detail(db, scan)


@router.post(
    "/scans/{scan_id}/cancel",
    response_model=ScanDetail,
    status_code=202,
    summary="Cancel a scan",
    description="Queued jobs end at once; running jobs stop their container within a few seconds.",
)
async def cancel_scan(
    scan_id: uuid.UUID, request: Request, db: DbSession, user: AnalystUser
) -> ScanDetail:
    scan = await get_or_404(db, Scan, scan_id, "Scan")
    scan, cancelled_jobs = await request_cancel(db, scan, user)
    await record_audit(
        db, user, "scan.cancel", "scan", scan.id, {"jobs_cancelled_before_start": len(cancelled_jobs)}, request
    )
    detail = await load_detail(db, scan)
    await db.commit()
    await settle_cancelled_jobs(cancelled_jobs)
    await state_event(scan.id, None, None, "cancel_requested", detail.state.value)
    return detail


@router.get(
    "/scans/{scan_id}/jobs/{job_id}/log",
    response_class=PlainTextResponse,
    summary="The log of one job (the last 2 MB)",
)
async def job_log(scan_id: uuid.UUID, job_id: uuid.UUID, db: DbSession, user: AnalystUser) -> PlainTextResponse:
    job = await get_or_404(db, ScanJob, job_id, "Job")
    if job.scan_id != scan_id:
        raise NotFound("Job not found", code="job.not_found")
    path = job_log_path(scan_id, job_id)
    lines = await asyncio.to_thread(tail_lines, path, 20000, 2 * 1024 * 1024)
    return PlainTextResponse("\n".join(lines) + ("\n" if lines else ""))


# --------------------------------------------------------------------------- server-sent events
def sse(event: str, data: Any) -> str:
    """One server-sent event."""
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'), default=str)}\n\n"


async def _snapshot(scan_id: uuid.UUID) -> tuple[dict[str, Any] | None, list[ScanJob]]:
    async with session_scope() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            return None, []
        detail = await load_detail(db, scan)
        jobs = list(
            (await db.scalars(select(ScanJob).where(ScanJob.scan_id == scan_id).order_by(ScanJob.created_at))).all()
        )
    return json.loads(detail.model_dump_json()), jobs


def _fingerprint(snapshot: dict[str, Any]) -> tuple[Any, ...]:
    return (
        snapshot["state"],
        tuple((j["id"], j["state"], j["import_state"]) for j in snapshot["jobs"]),
    )


async def event_stream(scan_id: uuid.UUID, request: Request) -> AsyncIterator[str]:
    """Snapshot, log backlog, then live events until the scan is final (or the client leaves)."""
    from psycopg import AsyncConnection

    yield "retry: 3000\n\n"
    conn = await AsyncConnection.connect(psycopg_conninfo(), autocommit=True)
    try:
        await conn.execute(f'LISTEN "{scan_channel(scan_id)}"')  # the channel name is generated here
        snapshot, jobs = await _snapshot(scan_id)
        if snapshot is None:
            yield sse("error", {"detail": "Scan not found"})
            return
        yield sse("snapshot", snapshot)
        for job in jobs:
            lines = await asyncio.to_thread(tail_lines, job_log_path(scan_id, job.id), BACKLOG_LINES)
            if lines:
                yield sse(
                    "log",
                    {"scan_id": str(scan_id), "job_id": str(job.id), "tool": job.tool, "lines": lines, "backlog": True},
                )
        seen = _fingerprint(snapshot)
        if ScanState(snapshot["state"]) in FINAL_SCAN_STATES:
            yield sse("done", {"scan_id": str(scan_id), "state": snapshot["state"]})
            return
        started = time.monotonic()
        final_seen = False
        while True:
            if await request.is_disconnected() or time.monotonic() - started > STREAM_MAX_SECONDS:
                return
            emitted = False
            wait = FINAL_DRAIN_SECONDS if final_seen else KEEPALIVE_SECONDS
            async for notice in conn.notifies(timeout=wait):
                try:
                    message = json.loads(notice.payload)
                except ValueError:
                    continue
                yield sse(str(message.get("event", "message")), message)
                emitted = True
            current, _ = await _snapshot(scan_id)
            if current is None:
                yield sse("error", {"detail": "Scan not found"})
                return
            if _fingerprint(current) != seen:
                seen = _fingerprint(current)
                yield sse("snapshot", current)
                emitted = True
            if ScanState(current["state"]) in FINAL_SCAN_STATES:
                if final_seen:
                    yield sse("done", {"scan_id": str(scan_id), "state": current["state"]})
                    return
                final_seen = True  # one more short round delivers the last log lines
                continue
            if not emitted:
                yield ": keepalive\n\n"
    finally:
        await conn.close()


@router.get(
    "/scans/{scan_id}/events",
    summary="Live progress of a scan (server-sent events)",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}}}},
)
async def scan_events(scan_id: uuid.UUID, request: Request, db: DbSession, user: AnalystUser) -> StreamingResponse:
    await get_or_404(db, Scan, scan_id, "Scan")
    await db.rollback()  # release the request's connection; the stream opens its own
    return StreamingResponse(
        event_stream(scan_id, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
