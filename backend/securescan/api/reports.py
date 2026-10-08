"""Reports: list, regenerate, read as HTML, download as PDF or CSV, review.

Both roles read every report. Every view and download is audited. The HTML is served with a strict
Content-Security-Policy (no scripts, no network, data: images and inline styles only) and the portal
shows it in a sandboxed frame; the PDF is stamped with the downloader's name and the UTC time at
download time, while the stored PDF stays unstamped.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from datetime import date, datetime
from typing import Any, Literal

from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import Conflict, NotFound, ServiceUnavailable, UnprocessableEntity
from securescan.api.schemas import ORMModel
from securescan.auth.roles import AnalystUser
from securescan.db.models.applications import Application
from securescan.db.models.artifacts import Artifact
from securescan.db.models.enums import ReportKind, ReviewState, Verdict
from securescan.db.models.reports import Report
from securescan.db.models.scans import Scan
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain import reports as report_service
from securescan.domain.audit import record_audit
from securescan.jobs.enqueue import defer
from securescan.jobs.report_job import render_report_job
from securescan.logging import get_logger
from securescan.reports.snapshot import load_snapshot
from securescan.reports.watermark import stamp_pdf
from securescan.storage.artifacts import StorageError, read_bytes
from securescan.util import utcnow

log = get_logger(__name__)

router = APIRouter(tags=["reports"])

# The Content-Security-Policy of the plan (M5 task 4): nothing runs, nothing is fetched.
HTML_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'"
HTML_HEADERS = {
    "Content-Security-Policy": HTML_CSP,
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "private, no-store",
}
DOWNLOAD_HEADERS = {"X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store"}


class ReportOut(ORMModel):
    id: uuid.UUID
    application_id: uuid.UUID
    version_id: uuid.UUID
    scan_id: uuid.UUID | None
    kind: ReportKind
    ref: str | None
    title: str | None
    template_id: uuid.UUID | None
    template_version: int | None
    snapshot_sha256: str | None
    status: str
    error: str | None
    review_state: ReviewState
    proposed_verdict: Verdict | None
    verdict: Verdict
    verdict_overridden: bool
    override_reason: str | None
    reviewer_id: uuid.UUID | None
    reviewed_at: datetime | None
    conditions: list[Any]
    vendor_copy: bool
    internal_notes: str | None
    mapping_versions: dict[str, Any]
    previous_report_id: uuid.UUID | None
    generated_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    html_ready: bool = False
    pdf_ready: bool = False


def to_out(row: Report) -> ReportOut:
    out = ReportOut.model_validate(row)
    out.html_ready = row.html_artifact_id is not None
    out.pdf_ready = row.pdf_artifact_id is not None
    return out


class ReportCreate(BaseModel):
    """Regenerate a report for a scan, or for the newest finished scan of a version."""

    scan_id: uuid.UUID | None = None
    version_id: uuid.UUID | None = None
    template_id: uuid.UUID | None = Field(
        default=None, description="Default template of the kind when empty"
    )
    kind: ReportKind | None = Field(default=None, description="Default: by application type")
    vendor_copy: bool = False

    @model_validator(mode="after")
    def _one_target(self) -> ReportCreate:
        if (self.scan_id is None) == (self.version_id is None):
            raise ValueError("give either scan_id or version_id")
        return self


class ConditionIn(BaseModel):
    finding_hash: str = Field(min_length=1, max_length=128)
    deadline: date


class ReviewIn(BaseModel):
    decision: Literal["confirm", "override"]
    verdict: Literal["pass", "conditional", "fail"] | None = Field(
        default=None, description="Required to override the proposed verdict"
    )
    reason: str | None = Field(default=None, max_length=2000)
    conditions: list[ConditionIn] = Field(default_factory=list, max_length=100)
    internal_notes: str | None = Field(default=None, max_length=4000)
    vendor_copy: bool | None = None


async def _stored_file(db: DbSession, report: Report, which: str) -> tuple[Artifact, bytes]:
    if report.status != "ready":
        raise Conflict("The report is not ready yet", code="report.not_ready")
    artifact_id = {
        "html": report.html_artifact_id,
        "pdf": report.pdf_artifact_id,
        "snapshot": report.snapshot_artifact_id,
    }[which]
    artifact = await db.get(Artifact, artifact_id) if artifact_id else None
    if artifact is None:
        raise NotFound("The report file does not exist", code="report.file_missing")
    try:
        return artifact, await read_bytes(artifact)
    except StorageError as exc:
        log.error("report_file_missing", report_id=str(report.id), which=which)
        raise NotFound(
            "The report file is missing from storage", code="report.file_missing"
        ) from exc


@router.get("/reports", response_model=CursorPage[ReportOut], summary="List reports")
async def list_reports(
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    application_id: uuid.UUID | None = None,
    version_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    kind: ReportKind | None = None,
    status: Literal["pending", "ready", "failed"] | None = None,
) -> CursorPage[ReportOut]:
    stmt = select(Report)
    if application_id:
        stmt = stmt.where(Report.application_id == application_id)
    if version_id:
        stmt = stmt.where(Report.version_id == version_id)
    if scan_id:
        stmt = stmt.where(Report.scan_id == scan_id)
    if kind:
        stmt = stmt.where(Report.kind == kind)
    if status:
        stmt = stmt.where(Report.status == status)
    result = await paginate(db, stmt, key=[Report.created_at, Report.id], params=page)
    return CursorPage(
        items=[to_out(r) for r in result.items], next_cursor=result.next_cursor
    )


@router.post(
    "/reports", response_model=ReportOut, status_code=202, summary="Generate a report again"
)
async def create_report(
    body: ReportCreate, request: Request, db: DbSession, user: AnalystUser
) -> ReportOut:
    """Freeze the current findings of a scan into a new report. Rendering runs in the worker; poll
    the report until ``status`` is ``ready``. Earlier reports stay available."""
    if body.scan_id is not None:
        scan = await db.get(Scan, body.scan_id)
    else:
        scan = await db.scalar(
            select(Scan)
            .where(
                Scan.version_id == body.version_id,
                Scan.state.not_in(report_service.UNFINISHED_SCAN_STATES),
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
    if scan is None:
        raise NotFound("No finished scan found to report on", code="scan.not_found")
    if scan.state in report_service.UNFINISHED_SCAN_STATES:
        raise Conflict("The scan has not finished yet", code="report.scan_not_finished")
    application = await get_or_404(db, Application, scan.application_id, "Application")
    kind = body.kind or report_service.report_kind_for(application)
    if body.template_id is not None:
        template = await report_service.usable_template(db, body.template_id)
    else:
        template = await report_service.get_default_template(db, kind)
    report = await report_service.create_report_row(
        db,
        scan=scan,
        application=application,
        template=template,
        created_by_id=user.id,
        kind=kind,
        vendor_copy=body.vendor_copy,
    )
    await record_audit(
        db,
        user,
        "report.request",
        "report",
        report.id,
        {"ref": report.ref, "scan_id": str(scan.id), "template": template.name, "kind": kind.value},
        request,
    )
    await db.commit()
    try:
        await defer(render_report_job, report_id=str(report.id))
    except Exception as exc:
        log.error("report_enqueue_failed", report_id=str(report.id), error_type=type(exc).__name__)
        report.status = "failed"
        report.error = "The report could not be queued. Try again."
        await db.commit()
        raise ServiceUnavailable(
            "The report could not be queued; try again in a moment", code="report.enqueue_failed"
        ) from exc
    return to_out(report)


@router.get("/reports/{report_id}", response_model=ReportOut, summary="Get a report")
async def get_report(report_id: uuid.UUID, db: DbSession, user: AnalystUser) -> ReportOut:
    return to_out(await get_or_404(db, Report, report_id, "Report"))


@router.get("/reports/{report_id}/html", summary="The report as an HTML page")
async def report_html(
    report_id: uuid.UUID, request: Request, db: DbSession, user: AnalystUser
) -> Response:
    report = await get_or_404(db, Report, report_id, "Report")
    artifact, data = await _stored_file(db, report, "html")
    await record_audit(
        db, user, "report.view", "report", report.id, {"ref": report.ref, "format": "html"}, request
    )
    await db.commit()
    return Response(content=data, media_type="text/html; charset=utf-8", headers=dict(HTML_HEADERS))


@router.get("/reports/{report_id}/pdf", summary="Download the report as a stamped PDF")
async def report_pdf(
    report_id: uuid.UUID, request: Request, db: DbSession, user: AnalystUser
) -> Response:
    report = await get_or_404(db, Report, report_id, "Report")
    artifact, data = await _stored_file(db, report, "pdf")
    who = user.name or user.email or user.oid
    if user.name and user.email:
        who = f"{user.name} ({user.email})"
    moment = utcnow()
    try:
        stamped = await asyncio.to_thread(stamp_pdf, data, who, moment)
    except Exception as exc:  # noqa: BLE001 - a damaged stored PDF must not be handed out unstamped
        log.error("report_stamp_failed", report_id=str(report.id), error_type=type(exc).__name__)
        raise ServiceUnavailable(
            "The PDF could not be prepared for download", code="report.stamp_failed"
        ) from exc
    await record_audit(
        db,
        user,
        "report.download",
        "report",
        report.id,
        {"ref": report.ref, "format": "pdf", "artifact_sha256": artifact.sha256},
        request,
    )
    await db.commit()
    filename = f"{report.ref or report.id}.pdf"
    headers = {**DOWNLOAD_HEADERS, "Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=stamped, media_type="application/pdf", headers=headers)


@router.get("/reports/{report_id}/snapshot", summary="The frozen data the report was made from")
async def report_snapshot(report_id: uuid.UUID, db: DbSession, user: AnalystUser) -> Response:
    report = await get_or_404(db, Report, report_id, "Report")
    _, data = await _stored_file(db, report, "snapshot")
    return Response(content=data, media_type="application/json", headers=dict(DOWNLOAD_HEADERS))


@router.get("/reports/{report_id}/findings.csv", summary="The finding list of a report as CSV")
async def report_findings_csv(
    report_id: uuid.UUID, request: Request, db: DbSession, user: AnalystUser
) -> Response:
    report = await get_or_404(db, Report, report_id, "Report")
    _, data = await _stored_file(db, report, "snapshot")
    try:
        snapshot = load_snapshot(data)
    except ValueError as exc:
        raise UnprocessableEntity(
            "The stored snapshot cannot be read", code="report.snapshot_invalid"
        ) from exc
    await record_audit(
        db,
        user,
        "export.report_csv",
        "report",
        report.id,
        {"ref": report.ref, "rows": len(snapshot.findings) + len(snapshot.triaged)},
        request,
    )
    await db.commit()

    def body() -> Iterator[str]:
        yield "﻿"  # lets Excel read the file as UTF-8
        yield from report_service.findings_csv(snapshot)

    filename = f"{report.ref or report.id}-findings.csv"
    headers = {**DOWNLOAD_HEADERS, "Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(body(), media_type="text/csv; charset=utf-8", headers=headers)


@router.post("/reports/{report_id}/review", response_model=ReportOut, summary="Review a report")
async def review_report(
    report_id: uuid.UUID, body: ReviewIn, request: Request, db: DbSession, user: AnalystUser
) -> ReportOut:
    """Confirm the proposed verdict or override it with a reason, attach remediation conditions and
    mark the report reviewed. The report is rendered again so HTML and PDF show the review."""
    report = await get_or_404(db, Report, report_id, "Report")
    proposed = report.proposed_verdict.value if report.proposed_verdict else None
    reviewed = await report_service.apply_review(
        db,
        report,
        user,
        report_service.ReviewRequest(
            decision=body.decision,
            verdict=body.verdict,
            reason=body.reason,
            conditions=[c.model_dump() for c in body.conditions],
            internal_notes=body.internal_notes,
            vendor_copy=body.vendor_copy,
        ),
    )
    await record_audit(
        db,
        user,
        "report.review",
        "report",
        report.id,
        {
            "ref": report.ref,
            "decision": body.decision,
            "proposed_verdict": proposed,
            "verdict": report.verdict.value,
            "overridden": report.verdict_overridden,
            "reason": report.override_reason,
            "conditions": report.conditions,
        },
        request,
    )
    await db.commit()
    try:
        await report_service.rerender(db, report, reviewed)
        await db.commit()
    except Exception as exc:  # noqa: BLE001 - the review is saved; report the failed render
        await db.rollback()
        log.error("report_rerender_failed", report_id=str(report_id), error_type=type(exc).__name__)
        reloaded = await db.get(Report, report_id, populate_existing=True)
        if reloaded is not None:
            report = reloaded
            report.error = "The review was saved, but the report could not be rendered again."
            await db.commit()
    return to_out(report)
