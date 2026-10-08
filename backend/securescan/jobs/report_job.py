"""Report tasks (queue ``reports``).

* ``securescan.jobs.report_job.build_report(scan_id)``: the report of a finished scan. M4
  enqueues it by this exact name once the scan's jobs have been imported (or the wait timed out and the coverage
  says so). It creates a ``Report`` row with the default template of the report kind, then renders.
* ``securescan.jobs.report_job.render_report(report_id)``: renders a report row that ``POST
  /api/v1/reports`` created for a regeneration with a chosen template.

Both are idempotent. A rendering failure that retrying cannot fix (a broken template, a missing
file) marks the report ``failed`` with the reason and finishes normally; any other error marks it
``failed``, raises, and the retry resumes the same row.
"""

from __future__ import annotations

import uuid

from procrastinate import RetryStrategy

from securescan.api.problems import Problem
from securescan.db.models.applications import Application
from securescan.db.models.reports import Report
from securescan.db.models.scans import Scan
from securescan.db.session import session_scope
from securescan.domain import reports as report_service
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.jobs.app import app
from securescan.logging import bind_job_context, clear_job_context, get_logger, scrub
from securescan.storage.artifacts import StorageError

log = get_logger(__name__)

BUILD_REPORT_TASK = "securescan.jobs.report_job.build_report"
RENDER_REPORT_TASK = "securescan.jobs.report_job.render_report"
MAX_ERROR_CHARS = 2000


def _not_retryable(exc: BaseException) -> bool:
    return isinstance(exc, (report_service.ReportError, StorageError, Problem))


async def _prepare_report(scan_id: uuid.UUID) -> uuid.UUID | None:
    """The report row to render for a scan, or None when there is nothing to do."""
    async with session_scope() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            log.warning("report_scan_missing", scan_id=str(scan_id))
            return None
        existing = await report_service.recent_system_report(session, scan_id)
        if existing is not None:
            if existing.status == "ready":
                log.info("report_already_built", scan_id=str(scan_id), report_id=str(existing.id))
                return None
            existing.status = "pending"
            existing.error = None
            return existing.id
        application = await session.get(Application, scan.application_id)
        if application is None:
            log.warning("report_application_missing", scan_id=str(scan_id))
            return None
        kind = report_service.report_kind_for(application)
        template = await report_service.get_default_template(session, kind)
        report = await report_service.create_report_row(
            session,
            scan=scan,
            application=application,
            template=template,
            created_by_id=None,
            kind=kind,
        )
        return report.id


async def _mark_failed(report_id: uuid.UUID, message: str) -> None:
    async with session_scope() as session:
        report = await session.get(Report, report_id)
        if report is not None and report.status != "ready":
            report.status = "failed"
            report.error = scrub(message)[:MAX_ERROR_CHARS]


async def _render(report_id: uuid.UUID) -> None:
    try:
        async with session_scope() as session:
            report = await session.get(Report, report_id)
            if report is None:
                log.warning("report_missing", report_id=str(report_id))
                return
            if report.status == "ready":
                return
            snapshot = await report_service.generate_report(session, report)
            await record_audit(
                session,
                report.generated_by_id or SYSTEM_ACTOR,
                "report.generate",
                "report",
                report.id,
                {
                    "ref": report.ref,
                    "scan_id": str(report.scan_id),
                    "template": snapshot.header.template_name,
                    "template_version": snapshot.header.template_version,
                    "verdict": snapshot.summary.verdict,
                    "open_findings": snapshot.summary.counts.total,
                },
            )
    except Exception as exc:
        text = f"{type(exc).__name__}: {exc}"
        log.error("report_failed", report_id=str(report_id), error=scrub(text)[:300])
        await _mark_failed(report_id, text)
        if _not_retryable(exc):
            return
        raise


@app.task(
    name=BUILD_REPORT_TASK,
    queue="reports",
    retry=RetryStrategy(max_attempts=3, exponential_wait=30),
)
async def build_report(scan_id: str) -> None:
    """Build the report of a finished scan (HTML, PDF and the frozen snapshot)."""
    bind_job_context(scan_id=scan_id)
    try:
        report_id = await _prepare_report(uuid.UUID(scan_id))
        if report_id is not None:
            await _render(report_id)
    finally:
        clear_job_context()


@app.task(
    name=RENDER_REPORT_TASK,
    queue="reports",
    retry=RetryStrategy(max_attempts=3, exponential_wait=30),
)
async def render_report_job(report_id: str) -> None:
    """Render a report row created for a regeneration."""
    await _render(uuid.UUID(report_id))
