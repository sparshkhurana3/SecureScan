"""Runs one scan job from ``queued`` to a final state: the heart of the scan runner.

``execute_job`` is what the ``scan_job`` task calls. It is generic: it resolves the tool's catalogue
entry and builder by name and drives them, so a new tool needs only a catalogue entry and a builder.

State machine of a ``ScanJob``::

    queued -> preparing -> running -> completed | completed_partial | failed | timed_out | cancelled

    preparing: source acquired (clone or unpack), builder.prepare, container specification built
    running:   the container exists; logs stream to the job log file and to PostgreSQL NOTIFY

Database work happens in short transactions: no transaction stays open while a container runs. A
heartbeat task updates ``scan_jobs.heartbeat_at`` every ``job_heartbeat_seconds`` and polls for a cancel
request every two seconds; ``stalled_jobs`` (``runner/recovery.py``) acts on jobs whose heartbeat stopped.

Retry rule (plan M3 task 4): only Docker and launcher exceptions are retried (the exception propagates to
Procrastinate, ``RetryStrategy(max_attempts=2)``); on the last attempt, and for every other failure, the
job ends ``failed`` with the reason on the job. Tool exit codes are never retried.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import Any, NoReturn

from sqlalchemy import select, update

from securescan.config import Settings, get_settings
from securescan.db.models.applications import Application
from securescan.db.models.enums import JOB_TERMINAL_STATES, ArtifactKind, JobState, ScanState
from securescan.db.models.jobs import ScanJob
from securescan.db.models.scans import Scan
from securescan.db.models.targets import Target
from securescan.db.models.versions import ApplicationVersion
from securescan.db.session import session_scope
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.domain.scans import finalize_scan, lock_scan
from securescan.logging import bind_job_context, get_logger, scrub
from securescan.observability.metrics import JOB_DURATION, JOBS_TOTAL
from securescan.runner.catalogue import (
    CatalogueEntry,
    CatalogueError,
    ResolvedImage,
    find_scanners_dir,
    get_entry,
    resolve_image_with_override,
)
from securescan.runner.events import JobLog, job_log_key, state_event
from securescan.runner.launcher import Launcher, LauncherConfigError, LauncherError, get_launcher
from securescan.runner.sources import SourceError, SourceInfo, SourceRequest, acquire_source
from securescan.runner.tools import ToolBuilder, ToolContext, get_builder
from securescan.runner.tools.base import ToolPreparationError
from securescan.runner.validate import ValidatedOutput, validate_outputs
from securescan.runner.workspace import Workspace
from securescan.storage.artifacts import save_file
from securescan.util import utcnow

log = get_logger(__name__)

TERMINAL = frozenset(JOB_TERMINAL_STATES)
CANCEL_POLL_SECONDS = 2.0
MAX_REASON = 1500


# --------------------------------------------------------------------------- pure helpers
def describe_exit(exit_code: int | None, logs: str) -> str:
    """A plain reason for a tool that ended with a failing exit code."""
    if exit_code is None:
        return "The tool did not report an exit code."
    if exit_code == 137:
        return "The tool was killed (exit code 137), most likely because it ran out of memory."
    text = f"The tool failed with exit code {exit_code}."
    last = next((ln.strip() for ln in reversed(logs.splitlines()) if ln.strip()), "")
    if last:
        text += f" Last output: {scrub(last)[:300]}"
    return text


class _Finish(Exception):  # noqa: N818 - control flow, not an error
    """Ends the job with a state and reason (raised inside ``JobRun`` stages)."""

    def __init__(
        self,
        state: JobState,
        reason: str | None = None,
        *,
        skipped: bool = False,
        outputs: list[ValidatedOutput] | None = None,
    ) -> None:
        super().__init__(f"{state.value}: {reason or ''}")
        self.state = state
        self.reason = reason
        self.skipped = skipped
        self.outputs: list[ValidatedOutput] = outputs or []


@dataclass
class LoadedJob:
    job: ScanJob
    scan: Scan
    version: ApplicationVersion
    application: Application
    target: Target | None


async def _load(db: Any, job_id: uuid.UUID) -> LoadedJob | None:
    job = await db.get(ScanJob, job_id)
    if job is None:
        return None
    scan = await db.get(Scan, job.scan_id)
    if scan is None:
        return None
    version = await db.get(ApplicationVersion, scan.version_id)
    application = await db.get(Application, scan.application_id)
    if version is None or application is None:
        return None
    target = await db.get(Target, scan.target_id) if scan.target_id else None
    return LoadedJob(job, scan, version, application, target)


# --------------------------------------------------------------------------- the run of one job
class JobRun:
    def __init__(
        self,
        loaded: LoadedJob,
        *,
        settings: Settings,
        launcher: Launcher,
        last_attempt: bool,
        procrastinate_job_id: int | None,
        worker_name: str,
    ) -> None:
        self.loaded = loaded
        self.job_id = loaded.job.id
        self.scan_id = loaded.scan.id
        self.tool = loaded.job.tool
        self.settings = settings
        self.launcher = launcher
        self.last_attempt = last_attempt
        self.procrastinate_job_id = procrastinate_job_id
        self.worker_name = worker_name
        self.cancel = asyncio.Event()
        self.joblog: JobLog | None = None
        self.workspace: Workspace | None = None
        self.ctx: ToolContext | None = None
        self.entry: CatalogueEntry | None = None
        self.builder: ToolBuilder | None = None
        self.image: ResolvedImage | None = None
        self.exit_code: int | None = None
        self.timeout_s: float = 0.0
        self.container_id: str | None = None
        self._heartbeat: asyncio.Task[None] | None = None
        self._concluded = False
        self._started = time.monotonic()

    # ------------------------------------------------------------------ driver
    async def execute(self) -> JobState | None:
        try:
            self.joblog = JobLog(self.scan_id, self.job_id, self.tool)
            await self._claim()
            self._heartbeat = asyncio.create_task(self._heartbeat_loop())
            self._check_cancel()
            await self._build_context()
            await self._acquire_source()
            self._check_cancel()
            await self._prepare()
            spec = self._build_spec()
            self._check_cancel()
            await self._mark_running()
            result = await self._run_container(spec)
            await self._after_run(result)
        except _Finish as fin:
            return await self._conclude(fin.state, fin.reason, fin.outputs, skipped=fin.skipped)
        except _Stop:
            return None
        except SourceError as exc:
            return await self._conclude(JobState.FAILED, str(exc))
        except ToolPreparationError as exc:
            return await self._conclude(JobState.FAILED, str(exc))
        except CatalogueError as exc:
            return await self._conclude(JobState.FAILED, f"Scanner catalogue problem: {exc}")
        except LauncherConfigError as exc:
            return await self._conclude(JobState.FAILED, f"Docker cannot run this tool: {exc}")
        except LauncherError as exc:
            log.warning("launcher_error", error=scrub(str(exc))[:300], last_attempt=self.last_attempt)
            if self.last_attempt:
                return await self._conclude(
                    JobState.FAILED, f"Docker could not run the tool after retrying: {scrub(str(exc))[:300]}"
                )
            await self._reset_queued("Docker was unavailable; the job will be retried.")
            raise
        except asyncio.CancelledError:
            await asyncio.shield(self._reset_queued("The worker stopped; the job will be queued again."))
            raise
        except Exception as exc:
            log.exception("job_internal_error", error=type(exc).__name__)
            return await self._conclude(
                JobState.FAILED, f"Internal error ({type(exc).__name__}). The details are in the worker log."
            )
        finally:
            await self._cleanup()

    def _check_cancel(self) -> None:
        if self.cancel.is_set():
            raise _Finish(JobState.CANCELLED, "Cancelled by a user.")

    # ------------------------------------------------------------------ stages
    async def _claim(self) -> None:
        """preparing: take the job (a second worker cannot) and start the scan if it is the first job."""
        async with session_scope() as db:
            await lock_scan(db, self.scan_id)
            job = await db.scalar(select(ScanJob).where(ScanJob.id == self.job_id).with_for_update())
            scan = await db.get(Scan, self.scan_id)
            assert job is not None and scan is not None  # noqa: S101 - loaded a moment ago
            if job.state in TERMINAL:
                raise _Stop()
            now = utcnow()
            if job.state in (JobState.PREPARING, JobState.RUNNING):
                fresh = (
                    job.heartbeat_at is not None
                    and (now - job.heartbeat_at).total_seconds() < self.settings.job_stale_after_seconds
                )
                if fresh and job.procrastinate_job_id not in (None, self.procrastinate_job_id):
                    log.warning("job_claimed_elsewhere", procrastinate_job_id=self.procrastinate_job_id)
                    raise _Stop()
            if scan.cancel_requested_at is not None:
                raise _Finish(JobState.CANCELLED, "Cancelled before it started.")
            first = scan.state == ScanState.QUEUED
            job.state = JobState.PREPARING
            job.attempts = (job.attempts or 0) + 1
            job.started_at = job.started_at or now
            job.worker_name = self.worker_name
            job.heartbeat_at = now
            job.procrastinate_job_id = self.procrastinate_job_id or job.procrastinate_job_id
            job.container_id = None
            job.exit_code = None
            job.updated_at = now
            await db.flush()
            await finalize_scan(db, self.scan_id)
            if first:
                await record_audit(
                    db, SYSTEM_ACTOR, "scan.start", "scan", self.scan_id, {"tool": self.tool}
                )
            scan_state = scan.state.value
        bind_job_context(scan_id=self.scan_id, job_id=self.job_id, tool=self.tool)
        assert self.joblog is not None  # noqa: S101
        await self.joblog.system(f"attempt {self.loaded.job.attempts + 1}: preparing {self.tool}")
        await state_event(self.scan_id, self.job_id, self.tool, JobState.PREPARING.value, scan_state)

    async def _build_context(self) -> None:
        self.entry = get_entry(self.tool)
        try:
            self.builder = get_builder(self.tool)
        except KeyError as exc:
            raise ToolPreparationError(
                f"There is no command builder for {self.tool} in this version.", code="tool.no_builder"
            ) from exc
        async with session_scope() as db:
            # The job options carry a regression candidate's one-time token (image_candidates); without them a
            # regression scan of an image proposal would run the active image instead of the candidate.
            self.image = await resolve_image_with_override(
                db, self.entry, self.settings, dict(self.loaded.job.options or {})
            )
        self.workspace = await asyncio.to_thread(Workspace.create, self.job_id)
        job = self.loaded.job
        self.ctx = ToolContext(
            job=job,
            scan=self.loaded.scan,
            version=self.loaded.version,
            target=self.loaded.target,
            workspace=self.workspace,
            entry=self.entry,
            settings=self.settings,
            options=dict(job.options or {}),
            application=self.loaded.application,
            image=self.image,
            scanners_dir=find_scanners_dir(self.settings),
        )
        ok, note = self.builder.applicable(self.ctx)
        if not ok:
            raise _Finish(JobState.COMPLETED, note, skipped=True)

    async def _claim_commit(self, sha: str) -> str:
        """The scan's commit: the first job to clone decides, the others check out the same one."""
        async with session_scope() as db:
            result = await db.execute(
                update(Scan)
                .where(Scan.id == self.scan_id, Scan.commit_sha.is_(None))
                .values(commit_sha=sha, updated_at=utcnow())
                .returning(Scan.commit_sha)
            )
            if result.first() is not None:
                return sha
            current = await db.scalar(select(Scan.commit_sha).where(Scan.id == self.scan_id))
            return str(current or sha)

    async def _acquire_source(self) -> None:
        assert self.ctx is not None and self.workspace is not None and self.joblog is not None  # noqa: S101
        target = self.loaded.target
        if target is None:
            raise SourceError("This scan has no target.", code="scan.no_target")
        async with session_scope() as db:
            request = SourceRequest(
                session=db,
                scan=self.loaded.scan,
                version=self.loaded.version,
                application=self.loaded.application,
                target=target,
                workspace=self.workspace,
                settings=self.settings,
                log=self.joblog.system,
                claim_commit=self._claim_commit,
            )
            info: SourceInfo = await acquire_source(request)
        self.ctx.source = info
        await self.joblog.system(f"source ready: {info.description}")

    async def _prepare(self) -> None:
        assert self.ctx is not None and self.builder is not None  # noqa: S101
        async with session_scope() as db:
            self.ctx.session = db
            try:
                await self.builder.prepare(self.ctx)
            finally:
                self.ctx.session = None
        if self.joblog is not None:
            for note in self.ctx.coverage_notes:
                await self.joblog.system(note)

    def _build_spec(self) -> Any:
        assert self.ctx is not None and self.builder is not None  # noqa: S101
        return self.builder.container_spec(self.ctx)

    async def _mark_running(self) -> None:
        assert self.ctx is not None and self.image is not None  # noqa: S101
        ctx = self.ctx
        async with session_scope() as db:
            await lock_scan(db, self.scan_id)
            job = await db.get(ScanJob, self.job_id)
            assert job is not None  # noqa: S101
            now = utcnow()
            job.state = JobState.RUNNING
            job.image = f"{self.image.name}:{self.image.tag}" if self.image.tag else self.image.name
            job.image_digest = self.image.digest
            job.tool_version = ctx.tool_version or self.image.tag
            job.content_versions = dict(ctx.content_versions)
            job.applied_exclusions = list(ctx.applied_exclusions)
            job.log_path = job_log_key(self.scan_id, self.job_id)
            job.heartbeat_at = now
            job.updated_at = now
            scan_state = (await finalize_scan(db, self.scan_id) or self.loaded.scan).state.value
        await state_event(self.scan_id, self.job_id, self.tool, JobState.RUNNING.value, scan_state)

    async def _record_container(self, container_id: str) -> None:
        self.container_id = container_id
        async with session_scope() as db:
            await db.execute(
                update(ScanJob)
                .where(ScanJob.id == self.job_id)
                .values(container_id=container_id, updated_at=utcnow())
            )

    async def _run_container(self, spec: Any) -> Any:
        assert self.ctx is not None and self.builder is not None and self.entry is not None  # noqa: S101
        assert self.joblog is not None  # noqa: S101
        timeout_fn = getattr(self.builder, "timeout_seconds", None)
        self.timeout_s = float(timeout_fn(self.ctx)) if callable(timeout_fn) else self.entry.timeout_seconds
        await self.joblog.system(f"starting container {spec.name} from {spec.image}")
        return await self.launcher.run(
            spec,
            self.timeout_s,
            self.joblog.write,
            on_created=self._record_container,
            cancel=self.cancel,
        )

    async def _after_run(self, result: Any) -> NoReturn:
        assert self.ctx is not None and self.builder is not None and self.entry is not None  # noqa: S101
        assert self.workspace is not None  # noqa: S101
        self.exit_code = result.exit_code
        if result.cancelled:
            raise _Finish(JobState.CANCELLED, "Cancelled by a user.")
        if result.timed_out:
            minutes = int(self.timeout_s // 60)
            raise _Finish(
                JobState.TIMED_OUT,
                f"The tool did not finish within {minutes} minutes and was stopped.",
            )
        outcome = self.builder.classify_exit(self.ctx, result.exit_code)
        if outcome == "failed":
            raise _Finish(JobState.FAILED, describe_exit(result.exit_code, result.logs))
        validation = await asyncio.to_thread(validate_outputs, self.entry, self.workspace.out)
        if not validation.ok:
            raise _Finish(JobState.FAILED, validation.reason())
        async with session_scope() as db:
            self.ctx.session = db
            try:
                await self.builder.post_run(self.ctx, result)
            finally:
                self.ctx.session = None
        raise _Finish(JobState(outcome), None, outputs=validation.outputs)

    # ------------------------------------------------------------------ finishing
    async def _conclude(
        self,
        state: JobState,
        reason: str | None,
        outputs: list[ValidatedOutput] | None = None,
        *,
        skipped: bool = False,
    ) -> JobState | None:
        if self._concluded:
            return state
        self._concluded = True
        if self.joblog is not None:
            message = f"job {state.value}" + (f": {reason}" if reason else "")
            if self.exit_code is not None:
                message += f" (exit code {self.exit_code})"
            await self.joblog.system(message)
            await self.joblog.close()
        scan_state = ScanState.RUNNING.value
        final_state = state
        async with session_scope() as db:
            await lock_scan(db, self.scan_id)
            job = await db.scalar(select(ScanJob).where(ScanJob.id == self.job_id).with_for_update())
            assert job is not None  # noqa: S101
            if job.state in TERMINAL:
                return job.state
            now = utcnow()
            if outputs:
                for output in outputs:
                    await save_file(
                        db,
                        kind=ArtifactKind.RAW_REPORT,
                        source=output.path,
                        filename=output.spec.file.rsplit("/", 1)[-1],
                        content_type="application/json" if output.spec.format == "json" else "application/xml",
                        scan_id=self.scan_id,
                        job_id=self.job_id,
                    )
            if self.joblog is not None and self.joblog.path.is_file():
                await save_file(
                    db,
                    kind=ArtifactKind.LOG,
                    source=self.joblog.path,
                    filename="job.log",
                    content_type="text/plain",
                    key=job_log_key(self.scan_id, self.job_id),
                    scan_id=self.scan_id,
                    job_id=self.job_id,
                )
            ctx = self.ctx
            job.state = final_state
            job.finished_at = now
            job.updated_at = now
            job.exit_code = self.exit_code
            job.outcome_reason = (scrub(reason)[:MAX_REASON] if reason else None)
            job.partial = final_state == JobState.COMPLETED_PARTIAL
            job.container_id = self.container_id or job.container_id
            if ctx is not None:
                job.applied_exclusions = list(ctx.applied_exclusions)
                job.content_versions = dict(ctx.content_versions)
                notes = list(ctx.coverage_notes)
                if skipped and reason:
                    notes.append(reason)
                job.coverage_note = " ".join(notes)[:2000] or None
            elif skipped and reason:
                job.coverage_note = reason
            if skipped:
                job.outcome_reason = f"Skipped: {reason}" if reason else "Skipped"
            scan = await finalize_scan(db, self.scan_id)
            if scan is not None:
                scan_state = scan.state.value
        JOBS_TOTAL.labels(tool=self.tool, state=final_state.value).inc()
        JOB_DURATION.labels(tool=self.tool).observe(max(0.0, time.monotonic() - self._started))
        await state_event(
            self.scan_id,
            self.job_id,
            self.tool,
            final_state.value,
            scan_state,
            {"reason": scrub(reason)[:300] if reason else None, "skipped": skipped},
        )
        await self._hand_over(skipped, reason)
        return final_state

    async def _hand_over(self, skipped: bool, reason: str | None) -> None:
        """Queue the DefectDojo import (M4), or settle a job that has nothing to import."""
        try:
            if skipped:
                await settle_without_import(self.job_id, reason or "skipped")
            else:
                from securescan.jobs.import_job import enqueue_import

                async with session_scope() as db:
                    await enqueue_import(db, self.job_id)
        except Exception as exc:  # noqa: BLE001 - the import sweeper picks up what is left
            log.warning("import_handover_failed", error=type(exc).__name__)

    async def _reset_queued(self, note: str) -> None:
        """Put the job back to ``queued`` (retry or worker shutdown); the scan stays open."""
        try:
            async with session_scope() as db:
                await lock_scan(db, self.scan_id)
                job = await db.get(ScanJob, self.job_id)
                if job is None or job.state in TERMINAL:
                    return
                job.state = JobState.QUEUED
                job.heartbeat_at = None
                job.container_id = None
                job.outcome_reason = note
                job.updated_at = utcnow()
                await finalize_scan(db, self.scan_id)
            if self.joblog is not None:
                await self.joblog.system(note)
        except Exception as exc:  # noqa: BLE001
            log.warning("reset_queued_failed", error=type(exc).__name__)

    # ------------------------------------------------------------------ background and cleanup
    async def _heartbeat_loop(self) -> None:
        last_beat = time.monotonic()
        while True:
            await asyncio.sleep(CANCEL_POLL_SECONDS)
            try:
                async with session_scope() as db:
                    flag = await db.scalar(select(Scan.cancel_requested_at).where(Scan.id == self.scan_id))
                    if flag is not None:
                        self.cancel.set()
                    if time.monotonic() - last_beat >= self.settings.job_heartbeat_seconds:
                        await db.execute(
                            update(ScanJob).where(ScanJob.id == self.job_id).values(heartbeat_at=utcnow())
                        )
                        last_beat = time.monotonic()
            except Exception as exc:  # noqa: BLE001 - a database blip must not kill the scan
                log.warning("heartbeat_failed", error=type(exc).__name__)

    async def _cleanup(self) -> None:
        if self._heartbeat is not None:
            self._heartbeat.cancel()
            try:
                await self._heartbeat
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self.joblog is not None:
            try:
                await self.joblog.close()
            except Exception:  # noqa: BLE001
                pass
        if self.workspace is not None:
            try:
                await asyncio.to_thread(self.workspace.cleanup)
            except Exception as exc:  # noqa: BLE001
                log.warning("workspace_cleanup_failed", error=type(exc).__name__)


class _Stop(Exception):  # noqa: N818 - control flow
    """Nothing to do: the job is already finished or another worker has it."""


# --------------------------------------------------------------------------- public entry points
async def settle_without_import(job_id: uuid.UUID, reason: str) -> None:
    """A finished job with no report to import (skipped tool): mark it settled and, when it was the
    scan's last open job, let M4 evaluate the verdict (same steps as ``enqueue_import`` for no-result jobs)."""
    from securescan.jobs.import_job import enqueue_report, finalize_scan_if_ready, mark_import_skipped

    async with session_scope() as db:
        job = await db.get(ScanJob, job_id)
        if job is None:
            return
        await mark_import_skipped(db, job, reason)
        await db.flush()
        ready = await finalize_scan_if_ready(db, job.scan_id)
        scan_id = job.scan_id
    if ready:
        await enqueue_report(scan_id)


async def execute_job(
    job_id: uuid.UUID,
    *,
    last_attempt: bool = True,
    procrastinate_job_id: int | None = None,
    launcher: Launcher | None = None,
    worker_name: str = "securescan-worker",
) -> JobState | None:
    """Run the job to a final state. Returns it (None when there was nothing to do).

    Raises only ``LauncherError`` (Docker unreachable, not on the last attempt) so that Procrastinate
    retries; every other outcome is recorded on the job.
    """
    settings = get_settings()
    async with session_scope() as db:
        loaded = await _load(db, job_id)
    if loaded is None:
        log.warning("job_not_found", job_id=str(job_id))
        return None
    if loaded.job.state in TERMINAL:
        return loaded.job.state
    run = JobRun(
        loaded,
        settings=settings,
        launcher=launcher or get_launcher(),
        last_attempt=last_attempt,
        procrastinate_job_id=procrastinate_job_id,
        worker_name=worker_name,
    )
    return await run.execute()
