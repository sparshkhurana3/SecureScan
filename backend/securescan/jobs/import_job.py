"""DefectDojo import: the outbox consumer (plan M4 tasks 3 to 5, design "Import flow").

When a scan job ends, ``enqueue_import(session, job_id)`` makes sure a ``SyncOutbox`` row exists and
defers the Procrastinate task ``import_job`` (queue ``imports``). The task:

1. claims the row (``pending`` -> ``processing``),
2. uploads the job's raw report with ``reimport-scan`` (DefectDojo parses, deduplicates, closes what
   disappeared),
3. when ``deduplication_complete`` is false waits two minutes before reading back (the row goes back to
   ``pending`` with ``payload.phase = "reread"``),
4. reads every finding of the Test, appends them to the history, stores the open counts on the job,
5. marks the job ``imported`` and, when every job of the scan is settled, evaluates the verdict and
   defers the report task (M5) by name.

Failures never fail the scan. The row goes back to ``pending`` with ``next_attempt_at`` following the
backoff 1, 5, 15, 60 minutes, then every 6 hours for up to 7 days; after that it is a ``dead_letter``
(an Admin replays it from the portal). A periodic ``import_sweep`` task defers rows that are due, so a
crash between "row written" and "task deferred" loses nothing.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from procrastinate.exceptions import AlreadyEnqueued
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import get_settings
from securescan.db.models.applications import Application
from securescan.db.models.artifacts import Artifact
from securescan.db.models.enums import (
    ArtifactKind,
    CredentialKind,
    ImportState,
    JobState,
    OutboxState,
    Verdict,
)
from securescan.db.models.jobs import ScanJob
from securescan.db.models.outbox import SyncOutbox
from securescan.db.models.scans import Scan
from securescan.db.models.targets import Target
from securescan.db.models.versions import ApplicationVersion
from securescan.db.session import session_scope
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.domain.credentials import get_active_credential_by_kind, reveal_secret
from securescan.domain.history import append_job_history
from securescan.domain.policy import evaluate_scan
from securescan.integrations.defectdojo.client import (
    DefectDojoAuthError,
    DefectDojoClient,
    DefectDojoError,
    DefectDojoNotFound,
    DefectDojoRejected,
    ReimportRequest,
)
from securescan.integrations.defectdojo.factory import DefectDojoNotConfigured
from securescan.integrations.defectdojo.findings import (
    belongs_to_scan,
    counts_from_statistics,
    severity_counts,
)
from securescan.integrations.defectdojo.mapping import (
    branch_or_tag,
    content_type_for,
    import_names,
    import_tags,
    product_tags,
)
from securescan.jobs.app import app
from securescan.jobs.enqueue import defer
from securescan.logging import bind_job_context, clear_job_context, get_logger, scrub
from securescan.storage.artifacts import StorageError, artifact_path
from securescan.util import utcnow

log = get_logger(__name__)

IMPORT_TASK_NAME = "import_job"
REPORT_TASK_NAME = "securescan.jobs.report_job.build_report"

# Backoff after the 1st, 2nd, 3rd and 4th failure; later failures wait REPEAT_DELAY.
BACKOFF_STEPS = (
    timedelta(minutes=1),
    timedelta(minutes=5),
    timedelta(minutes=15),
    timedelta(minutes=60),
)
REPEAT_DELAY = timedelta(hours=6)
# DefectDojo rejected the request itself (400 and friends): a retry rarely helps, so only a few tries.
MAX_REJECTED_ATTEMPTS = 3
# A row in ``processing`` for longer than this belongs to a worker that died.
PROCESSING_TIMEOUT = timedelta(minutes=30)
SWEEP_BATCH = 200
# mitigated findings older than the import by more than this are not "closed by this import"
CLOCK_SLACK = timedelta(minutes=1)

_NO_RESULT_STATES = frozenset({JobState.FAILED, JobState.CANCELLED, JobState.TIMED_OUT})
_FINAL_STATES = _NO_RESULT_STATES | {JobState.COMPLETED, JobState.COMPLETED_PARTIAL}


# --- backoff (pure) -----------------------------------------------------------------------------------


def backoff_delay(failures: int) -> timedelta:
    """Wait before the next attempt after ``failures`` failures in a row (1 = the first failure)."""
    if failures < 1:
        return timedelta(0)
    if failures <= len(BACKOFF_STEPS):
        return BACKOFF_STEPS[failures - 1]
    return REPEAT_DELAY


def decide_retry(
    *,
    failures: int,
    created_at: datetime,
    now: datetime,
    rejected: bool = False,
    max_age_days: int = 7,
) -> datetime | None:
    """When to try again, or None when the row has become a dead letter.

    ``failures`` counts this failure. A dead letter results when the row is older than
    ``max_age_days`` (default 7) or, for a request DefectDojo rejected, after three attempts.
    """
    if rejected and failures >= MAX_REJECTED_ATTEMPTS:
        return None
    due = now + backoff_delay(failures)
    if due - created_at > timedelta(days=max_age_days):
        return None
    return due


def import_lock(version_id: uuid.UUID, tool: str) -> str:
    """Imports into one Test (version + tool) run one at a time."""
    return f"dd-import:{version_id}:{tool}"


# --- what to upload (pure) -----------------------------------------------------------------------------------


def build_reimport_request(
    *,
    application: Application,
    version: ApplicationVersion,
    scan: Scan,
    job: ScanJob,
    scan_type: str,
    file_path: Path,
    file_name: str,
    scan_date: date,
) -> ReimportRequest:
    """The ``reimport-scan`` call for one job: product type by application type, product = application
    name, engagement = version label, test title ``<tool>:<version label>``."""
    names = import_names(application.type, application.name, version.label, job.tool)
    return ReimportRequest(
        file_path=file_path,
        file_name=file_name,
        scan_type=scan_type,
        product_type_name=names.product_type,
        product_name=names.product,
        engagement_name=names.engagement,
        test_title=names.test_title,
        version=version.label,
        commit_hash=scan.commit_sha or version.commit_sha,
        branch_tag=branch_or_tag(version.label, version.label_kind),
        tags=import_tags(scan.id, job.tool),
        scan_date=scan_date,
        content_type=content_type_for(file_name),
    )


@dataclass
class ImportPlan:
    """Everything an import attempt needs, gathered inside one short transaction."""

    outbox_id: uuid.UUID
    job_id: uuid.UUID
    scan_id: uuid.UUID
    tool: str
    phase: str  # upload | reread
    since: datetime
    test_id: int | None
    request: ReimportRequest | None
    token: str = field(repr=False, default="")


class PermanentImportError(Exception):
    """Nothing to retry: the report to upload does not exist."""


# --- applicability ----------------------------------------------------------------------------------------------


def import_applicability(job: ScanJob) -> tuple[bool, str]:
    """Whether the job's report goes to DefectDojo, with the reason when it does not."""
    from securescan.runner.catalogue import load_catalogue

    if job.state in _NO_RESULT_STATES:
        return False, f"the job ended {job.state.value}; there is no report to import"
    entry = load_catalogue().get(job.tool)
    if entry is None:
        return False, f"{job.tool} is not in the scanner catalogue"
    if not entry.defectdojo_scan_type or not entry.defectdojo_file:
        return False, f"{job.tool} has no DefectDojo parser; its output is stored, not imported"
    return True, ""


async def _find_raw_report(session: AsyncSession, job: ScanJob, file_name: str) -> Artifact | None:
    rows = (
        await session.scalars(
            select(Artifact)
            .where(
                Artifact.job_id == job.id,
                Artifact.kind.in_([ArtifactKind.RAW_REPORT, ArtifactKind.SBOM]),
                Artifact.deleted_at.is_(None),
            )
            .order_by(Artifact.created_at.desc())
        )
    ).all()
    for row in rows:
        if row.filename == file_name or row.storage_key.endswith("/" + file_name):
            return row
    return None


# --- enqueue (called by the scan job) --------------------------------------------------------------------------------


async def mark_import_skipped(session: AsyncSession, job: ScanJob, reason: str) -> None:
    """A job whose output is not imported counts as settled: ``import_state`` becomes ``imported`` with
    the reason in ``dd_import_stats`` (so the scan's verdict does not wait for it)."""
    job.import_state = ImportState.IMPORTED
    job.dd_import_stats = {"skipped": reason}


async def enqueue_import(session: AsyncSession, job_id: uuid.UUID) -> uuid.UUID | None:
    """Queue the DefectDojo import of a finished scan job. Called by ``scan_job`` after it has written
    the job's final state and stored its raw reports.

    Idempotent: an open outbox row for the job is reused. This function **commits the session**
    (state first, queue second), then defers the task. Jobs without anything to import are marked
    settled at once. Returns the outbox id, or None when nothing is imported.
    """
    job = await session.get(ScanJob, job_id)
    if job is None:
        raise LookupError(f"scan job {job_id} does not exist")
    if job.state not in _FINAL_STATES:
        raise ValueError(f"scan job {job_id} is {job.state.value}; import only finished jobs")
    scan = await session.get(Scan, job.scan_id)
    if scan is None:
        raise LookupError(f"scan {job.scan_id} does not exist")

    applicable, reason = import_applicability(job)
    if not applicable:
        await mark_import_skipped(session, job, reason)
        await session.flush()
        report = await finalize_scan_if_ready(session, job.scan_id)
        await session.commit()
        if report:
            await enqueue_report(job.scan_id)
        return None

    row = await session.scalar(
        select(SyncOutbox)
        .where(
            SyncOutbox.job_id == job.id,
            SyncOutbox.state.in_([OutboxState.PENDING, OutboxState.PROCESSING]),
        )
        .order_by(SyncOutbox.created_at.desc())
        .limit(1)
    )
    if row is None:
        row = SyncOutbox(job_id=job.id, state=OutboxState.PENDING, next_attempt_at=utcnow(), payload={})
        session.add(row)
    job.import_state = ImportState.PENDING
    await session.flush()
    outbox_id = row.id
    await session.commit()
    await defer(
        import_job,
        lock=import_lock(scan.version_id, job.tool),
        queueing_lock=f"import:{outbox_id}",
        outbox_id=str(outbox_id),
    )
    return outbox_id


async def enqueue_report(scan_id: uuid.UUID) -> None:
    """Defer the M5 report task by name (no import dependency on M5). Never raises."""
    if REPORT_TASK_NAME not in app.tasks:
        log.warning("report_task_not_registered", task=REPORT_TASK_NAME, scan_id=str(scan_id))
        return
    try:
        deferrer = app.configure_task(
            name=REPORT_TASK_NAME, queue="reports", queueing_lock=f"report:{scan_id}"
        )
        await deferrer.defer_async(scan_id=str(scan_id))
    except AlreadyEnqueued:
        log.info("report_already_queued", scan_id=str(scan_id))
    except Exception as exc:  # noqa: BLE001 - a failed hand-off must not undo the import
        log.error("report_enqueue_failed", scan_id=str(scan_id), error=str(exc)[:300])


async def finalize_scan_if_ready(session: AsyncSession, scan_id: uuid.UUID) -> bool:
    """Evaluate the scan's verdict (it stays ``pending`` until every job is settled). Returns True when
    the verdict just became final, i.e. the report should be built now. The scan row is locked so two
    jobs finishing together cannot both trigger a report. No commit."""
    scan = await session.scalar(select(Scan).where(Scan.id == scan_id).with_for_update())
    if scan is None:
        return False
    previous = scan.verdict
    verdict = await evaluate_scan(session, scan_id)
    just_final = verdict != Verdict.PENDING.value and previous == Verdict.PENDING
    if just_final:
        await record_audit(
            session,
            SYSTEM_ACTOR,
            "scan.verdict",
            "scan",
            scan_id,
            {"verdict": verdict, "counts": scan.counts},
        )
    return just_final


# --- the task ------------------------------------------------------------------------------------------------------------


async def _build_plan(session: AsyncSession, row: SyncOutbox, job: ScanJob) -> ImportPlan | None:
    """Gather the attempt's inputs. Returns None when the job turned out not to need an import (the
    job is then marked settled). Raises ``PermanentImportError`` or ``DefectDojoNotConfigured``."""
    scan = await session.get(Scan, job.scan_id)
    if scan is None:
        raise PermanentImportError(f"scan {job.scan_id} no longer exists")
    credential = await get_active_credential_by_kind(session, CredentialKind.DEFECTDOJO_TOKEN)
    if credential is None:
        raise DefectDojoNotConfigured("the DefectDojo import token is not stored yet (dojo-init)")
    token = reveal_secret(credential)
    payload = dict(row.payload or {})
    if payload.get("phase") == "reread" and isinstance(payload.get("test_id"), int):
        since = _parse_since(payload.get("since"))
        return ImportPlan(
            outbox_id=row.id,
            job_id=job.id,
            scan_id=job.scan_id,
            tool=job.tool,
            phase="reread",
            since=since,
            test_id=int(payload["test_id"]),
            request=None,
            token=token,
        )

    from securescan.runner.catalogue import load_catalogue

    entry = load_catalogue().get(job.tool)
    if entry is None or not entry.defectdojo_scan_type or not entry.defectdojo_file:
        await mark_import_skipped(session, job, "no DefectDojo parser for this tool")
        return None
    application = await session.get(Application, scan.application_id)
    version = await session.get(ApplicationVersion, scan.version_id)
    if application is None or version is None:
        raise PermanentImportError("the application or version of the scan no longer exists")
    artifact = await _find_raw_report(session, job, entry.defectdojo_file)
    if artifact is None:
        raise PermanentImportError(f"the raw report {entry.defectdojo_file} was not stored")
    try:
        path = artifact_path(artifact)
    except StorageError as exc:
        raise PermanentImportError(str(exc)) from exc
    if not path.is_file():
        raise PermanentImportError(f"the raw report file is missing: {artifact.storage_key}")
    now = utcnow()
    request = build_reimport_request(
        application=application,
        version=version,
        scan=scan,
        job=job,
        scan_type=entry.defectdojo_scan_type,
        file_path=path,
        file_name=entry.defectdojo_file,
        scan_date=now.date(),
    )
    return ImportPlan(
        outbox_id=row.id,
        job_id=job.id,
        scan_id=job.scan_id,
        tool=job.tool,
        phase="upload",
        since=now - CLOCK_SLACK,
        test_id=None,
        request=request,
        token=token,
    )


def _parse_since(value: Any) -> datetime:
    from securescan.integrations.defectdojo.findings import parse_datetime

    return parse_datetime(value) or (utcnow() - timedelta(hours=1))


async def _record_failure(
    session: AsyncSession,
    row: SyncOutbox,
    job: ScanJob | None,
    exc: BaseException,
    *,
    rejected: bool,
) -> str:
    """Count the failure and schedule the next attempt, or make the row a dead letter."""
    now = utcnow()
    settings = get_settings()
    row.attempts += 1
    row.last_error = scrub(f"{type(exc).__name__}: {exc}")[:2000]
    row.updated_at = now
    due = decide_retry(
        failures=row.attempts,
        created_at=row.created_at,
        now=now,
        rejected=rejected,
        max_age_days=settings.defectdojo_import_max_age_days,
    )
    if due is None:
        row.state = OutboxState.DEAD_LETTER
        if job is not None:
            job.import_state = ImportState.FAILED
        await record_audit(
            session,
            SYSTEM_ACTOR,
            "import.dead_letter",
            "scan_job",
            row.job_id,
            {"attempts": row.attempts, "error": row.last_error},
        )
        log.error("import_dead_letter", outbox_id=str(row.id), attempts=row.attempts)
        return "dead_letter"
    row.state = OutboxState.PENDING
    row.next_attempt_at = due
    log.warning(
        "import_retry_scheduled",
        outbox_id=str(row.id),
        attempts=row.attempts,
        next_attempt_at=due.isoformat(),
        error=row.last_error[:200],
    )
    return "retry"


def _client_for(plan: ImportPlan) -> DefectDojoClient:
    settings = get_settings()
    return DefectDojoClient(
        settings.defectdojo_url,
        plan.token,
        timeout=settings.defectdojo_timeout_seconds,
        import_timeout=settings.defectdojo_import_timeout_seconds,
        max_retries=settings.defectdojo_max_retries,
        page_size=settings.defectdojo_page_size,
    )


async def process_outbox(outbox_id: uuid.UUID) -> str:
    """Run one import attempt for an outbox row. Returns ``not_due``, ``imported``, ``skipped``,
    ``waiting`` (re-read scheduled), ``retry`` or ``dead_letter``. Failures are recorded on the row;
    only unexpected errors (for example the database being down) propagate."""
    plan: ImportPlan | None = None
    # 1. claim the row and gather inputs
    async with session_scope() as db:
        row = await db.scalar(
            select(SyncOutbox).where(SyncOutbox.id == outbox_id).with_for_update(skip_locked=True)
        )
        if row is None or row.state != OutboxState.PENDING or row.next_attempt_at > utcnow():
            return "not_due"
        job = await db.get(ScanJob, row.job_id)
        if job is None:
            row.state = OutboxState.DEAD_LETTER
            row.last_error = "the scan job no longer exists"
            return "dead_letter"
        bind_job_context(scan_id=str(job.scan_id), job_id=str(job.id), tool=job.tool)
        try:
            plan = await _build_plan(db, row, job)
        except PermanentImportError as exc:
            row.state = OutboxState.DEAD_LETTER
            row.attempts += 1
            row.last_error = scrub(str(exc))[:2000]
            job.import_state = ImportState.FAILED
            await record_audit(
                db, SYSTEM_ACTOR, "import.dead_letter", "scan_job", job.id, {"error": row.last_error}
            )
            clear_job_context()
            return "dead_letter"
        except DefectDojoNotConfigured as exc:
            outcome = await _record_failure(db, row, job, exc, rejected=False)
            clear_job_context()
            return outcome
        if plan is None:  # nothing to import after all
            row.state = OutboxState.DONE
            row.completed_at = utcnow()
            report = await finalize_scan_if_ready(db, job.scan_id)
            scan_id = job.scan_id
        else:
            row.state = OutboxState.PROCESSING
            row.updated_at = utcnow()
            report = False
            scan_id = job.scan_id
    if plan is None:
        if report:
            await enqueue_report(scan_id)
        clear_job_context()
        return "skipped"

    # 2. talk to DefectDojo (no database transaction is open)
    client = _client_for(plan)
    try:
        outcome, report = await _run_attempt(client, plan)
    except (DefectDojoAuthError, DefectDojoNotFound) as exc:
        outcome, report = await _fail(plan, exc, rejected=False), False
    except DefectDojoRejected as exc:
        outcome, report = await _fail(plan, exc, rejected=True), False
    except DefectDojoError as exc:
        outcome, report = await _fail(plan, exc, rejected=False), False
    except PermanentImportError as exc:
        outcome, report = await _fail(plan, exc, rejected=True, permanent=True), False
    except Exception as exc:  # noqa: BLE001 - recorded, then retried by the backoff
        log.exception("import_unexpected_error")
        outcome, report = await _fail(plan, exc, rejected=False), False
    finally:
        await client.aclose()
        clear_job_context()
    if report:
        await enqueue_report(plan.scan_id)
    return outcome


async def _fail(
    plan: ImportPlan, exc: BaseException, *, rejected: bool, permanent: bool = False
) -> str:
    async with session_scope() as db:
        row = await db.get(SyncOutbox, plan.outbox_id)
        job = await db.get(ScanJob, plan.job_id)
        if row is None:
            return "retry"
        if permanent:
            row.attempts += 1
            row.state = OutboxState.DEAD_LETTER
            row.last_error = scrub(str(exc))[:2000]
            row.updated_at = utcnow()
            if job is not None:
                job.import_state = ImportState.FAILED
            return "dead_letter"
        return await _record_failure(db, row, job, exc, rejected=rejected)


async def _run_attempt(client: DefectDojoClient, plan: ImportPlan) -> tuple[str, bool]:
    """Upload (phase ``upload``), then read findings back and write history. Returns the outcome and
    whether the report task should be deferred."""
    settings = get_settings()
    test_id = plan.test_id
    stats: dict[str, Any] = {}
    if plan.phase == "upload":
        assert plan.request is not None  # noqa: S101 - set together with the phase
        result = await client.reimport_scan(plan.request)
        test_id = result.test_id
        stats = {
            "statistics": result.statistics,
            "deduplication_complete": result.deduplication_complete,
        }
        await _record_upload(plan, result.test_id, result.engagement_id, result.product_id, stats)
        if not result.deduplication_complete:
            await _schedule_reread(plan, result.test_id, settings.defectdojo_dedup_recheck_minutes)
            return "waiting", False
    assert test_id is not None  # noqa: S101
    findings = await client.list_findings(test_id, include_inactive=True)
    report = await _complete(plan, test_id, findings, stats)
    await _describe_test(client, plan, test_id)
    return "imported", report


async def _record_upload(
    plan: ImportPlan,
    test_id: int,
    engagement_id: int | None,
    product_id: int | None,
    stats: dict[str, Any],
) -> None:
    async with session_scope() as db:
        job = await db.get(ScanJob, plan.job_id)
        scan = await db.get(Scan, plan.scan_id)
        if job is None or scan is None:
            return
        job.dd_test_id = test_id
        job.dd_imported_at = utcnow()
        job.dd_import_stats = {**stats, "uploaded_at": utcnow().isoformat()}
        application = await db.get(Application, scan.application_id)
        version = await db.get(ApplicationVersion, scan.version_id)
        if application is not None and product_id is not None and application.dd_product_id is None:
            application.dd_product_id = product_id
            application.updated_at = utcnow()
            await _tag_product(db, application)
        if version is not None and engagement_id is not None and version.dd_engagement_id is None:
            version.dd_engagement_id = engagement_id
            version.updated_at = utcnow()


async def _tag_product(db: AsyncSession, application: Application) -> None:
    """Tag the DefectDojo Product with the SecureScan application id (best effort)."""
    from securescan.integrations.defectdojo.factory import sync_client

    if application.dd_product_id is None:
        return
    try:
        client = await sync_client(db, quick=True)
    except DefectDojoNotConfigured:
        return
    try:
        await client.patch_product(application.dd_product_id, {"tags": product_tags(application.id)})
    except DefectDojoError as exc:
        log.warning("product_tag_failed", error=str(exc)[:200])
    finally:
        await client.aclose()


async def _schedule_reread(plan: ImportPlan, test_id: int, minutes: int) -> None:
    due = utcnow() + timedelta(minutes=minutes)
    async with session_scope() as db:
        row = await db.get(SyncOutbox, plan.outbox_id)
        if row is None:
            return
        row.payload = {"phase": "reread", "test_id": test_id, "since": plan.since.isoformat()}
        row.state = OutboxState.PENDING
        row.next_attempt_at = due
        row.updated_at = utcnow()
        job = await db.get(ScanJob, plan.job_id)
        scan = await db.get(Scan, plan.scan_id)
    if job is not None and scan is not None:
        try:
            await defer(
                import_job,
                lock=import_lock(scan.version_id, job.tool),
                queueing_lock=f"import:{plan.outbox_id}",
                schedule_in=timedelta(minutes=minutes),
                outbox_id=str(plan.outbox_id),
            )
        except Exception as exc:  # noqa: BLE001 - the sweeper picks the row up when it is due
            log.warning("reread_defer_failed", error=str(exc)[:200])


async def _complete(
    plan: ImportPlan, test_id: int, findings: list[dict[str, Any]], stats: dict[str, Any]
) -> bool:
    """Append history, store counts, mark the job imported, evaluate the scan. Returns whether the
    report should be deferred."""
    async with session_scope() as db:
        job = await db.get(ScanJob, plan.job_id)
        scan = await db.get(Scan, plan.scan_id)
        row = await db.get(SyncOutbox, plan.outbox_id)
        if job is None or scan is None:
            raise PermanentImportError("the job or scan disappeared during the import")
        application = await db.get(Application, scan.application_id)
        if application is None:
            raise PermanentImportError("the application of the scan no longer exists")
        target = await db.get(Target, scan.target_id) if scan.target_id else None
        in_scan = [f for f in findings if belongs_to_scan(f, plan.since)]
        appended = await append_job_history(
            db,
            job=job,
            scan=scan,
            application=application,
            target_kind=target.kind.value if target else None,
            findings=in_scan,
            scanned_at=job.finished_at or utcnow(),
        )
        counts = severity_counts(findings)
        after = (stats.get("statistics") or {}).get("after") if stats else None
        if isinstance(after, dict) and stats.get("deduplication_complete"):
            if counts_from_statistics(after) != counts:
                log.warning(
                    "import_counts_differ",
                    response=counts_from_statistics(after),
                    findings_api=counts,
                )
        job.counts = counts
        job.dd_test_id = test_id
        if job.dd_imported_at is None:
            job.dd_imported_at = utcnow()
        job.dd_import_stats = {
            **(job.dd_import_stats or {}),
            **{k: v for k, v in stats.items() if k != "statistics"},
            "findings_in_test": len(findings),
            "history_rows_appended": appended,
            "phase": plan.phase,
            "completed_at": utcnow().isoformat(),
        }
        job.import_state = ImportState.IMPORTED
        if row is not None:
            row.state = OutboxState.DONE
            row.completed_at = utcnow()
            row.updated_at = utcnow()
            row.last_error = None
        await db.flush()
        await record_audit(
            db,
            SYSTEM_ACTOR,
            "import.complete",
            "scan_job",
            job.id,
            {
                "scan_id": str(scan.id),
                "tool": job.tool,
                "dd_test_id": test_id,
                "findings": len(findings),
                "open": counts,
            },
        )
        return await finalize_scan_if_ready(db, scan.id)


async def _describe_test(client: DefectDojoClient, plan: ImportPlan, test_id: int) -> None:
    """Put a short summary into the Test description (design: DefectDojo gets a summary). Best effort."""
    async with session_scope() as db:
        job = await db.get(ScanJob, plan.job_id)
        scan = await db.get(Scan, plan.scan_id)
        if job is None or scan is None:
            return
        parts = [
            f"SecureScan scan {scan.id}",
            f"tool {job.tool} {job.tool_version or ''}".strip(),
            f"image {job.image_digest}" if job.image_digest else "",
            f"commit {scan.commit_sha}" if scan.commit_sha else "",
            f"imported {utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ]
        text = "; ".join(p for p in parts if p)
    try:
        await client.patch_test(test_id, {"description": text[:2000]})
    except DefectDojoError as exc:
        log.info("test_description_not_set", error=str(exc)[:200])


@app.task(name=IMPORT_TASK_NAME, queue="imports")
async def import_job(outbox_id: str) -> None:
    """Import one scan job's raw report into DefectDojo (idempotent; safe to run twice)."""
    outcome = await process_outbox(uuid.UUID(outbox_id))
    log.info("import_attempt_done", outbox_id=outbox_id, outcome=outcome)


# --- sweeper ----------------------------------------------------------------------------------------------------------------


async def sweep_outbox(now: datetime | None = None) -> int:
    """Defer the import task for every pending row that is due, and release rows stuck in
    ``processing``. Returns the number of tasks deferred."""
    moment = now or utcnow()
    due: list[tuple[uuid.UUID, uuid.UUID, str]] = []
    async with session_scope() as db:
        await db.execute(
            update(SyncOutbox)
            .where(
                SyncOutbox.state == OutboxState.PROCESSING,
                SyncOutbox.updated_at < moment - PROCESSING_TIMEOUT,
            )
            .values(state=OutboxState.PENDING, updated_at=moment)
        )
        rows = (
            await db.execute(
                select(SyncOutbox.id, Scan.version_id, ScanJob.tool)
                .join(ScanJob, ScanJob.id == SyncOutbox.job_id)
                .join(Scan, Scan.id == ScanJob.scan_id)
                .where(SyncOutbox.state == OutboxState.PENDING, SyncOutbox.next_attempt_at <= moment)
                .order_by(SyncOutbox.next_attempt_at)
                .limit(SWEEP_BATCH)
            )
        ).all()
        due = [(r[0], r[1], r[2]) for r in rows]
    deferred = 0
    for outbox_id, version_id, tool in due:
        job_id = await defer(
            import_job,
            lock=import_lock(version_id, tool),
            queueing_lock=f"import:{outbox_id}",
            outbox_id=str(outbox_id),
        )
        if job_id is not None:
            deferred += 1
    return deferred


@app.periodic(cron="* * * * *")
@app.task(name="import_sweep", queue="imports", queueing_lock="import_sweep")
async def import_sweep(timestamp: int) -> None:
    """Every minute: queue imports that are due (retries, delayed re-reads, rows whose task was lost)."""
    count = await sweep_outbox()
    if count:
        log.info("import_sweep_deferred", count=count)
