"""Scans: creating them, the state roll-up, cancelling, and putting their jobs on the queue.

Entry point for every caller (the API, the GitHub poller, schedules)::

    scan = await create_scan(session, version_id=..., profile_name="code-standard",
                             trigger=ScanTrigger.USER, requested_by=user, target_ids=[target.id],
                             options={"ref": "main"}, idempotency_key="<user id>:<Idempotency-Key>")
    await session.commit()          # the rows are durable now; the jobs are queued right after the commit

``create_scan`` writes the ``Scan`` and one ``ScanJob`` per tool of the profile (state ``queued``) and
registers a hook on the session: when the *outermost* transaction commits, ``enqueue_scan_jobs`` defers
one ``scan_job`` task per job (state first, queue second; see ``jobs/enqueue.py``). If that does not
happen (the process dies, the queue is down) the periodic ``stalled_jobs`` task re-defers queued jobs.

Rules enforced here (design: DAST safety controls): which target kinds a profile kind accepts, and that a
production URL target gets the unauthenticated ZAP baseline only. Later milestones add checks with
``register_scan_check``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import uuid
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.api.problems import BadRequest, Conflict, NotFound, UnprocessableEntity
from securescan.db.models.applications import Application
from securescan.db.models.enums import (
    JOB_TERMINAL_STATES,
    ArtifactKind,
    JobState,
    ScanKind,
    ScanState,
    ScanTrigger,
    TargetEnvironment,
    TargetKind,
)
from securescan.db.models.jobs import ScanJob
from securescan.db.models.profiles import ScanProfile
from securescan.db.models.scans import Scan
from securescan.db.models.targets import Target
from securescan.db.models.versions import ApplicationVersion
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.logging import get_logger
from securescan.runner.profiles import ProfileDoc, ProfileError
from securescan.util import new_id, utcnow

log = get_logger(__name__)

SAST_TARGET_KINDS = (
    TargetKind.GITHUB_REPO,
    TargetKind.VENDOR_REPO,
    TargetKind.ZIP,
    TargetKind.IMAGE,
)
PRODUCTION_DAST_TOOLS = frozenset({"zap"})
FORBIDDEN_REQUEST_TOOL_KEYS = ("limits", "timeout_minutes", "timeout_min")
MAX_REQUEST_EXCLUDES = 50
MAX_REQUEST_MINUTES = 480
MAX_OPTIONS_JSON_BYTES = 16 * 1024
_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$")
_KEY_OK = re.compile(r"^[A-Za-z0-9._:@+=-]{1,91}$")  # stored as "<user id>:<key>" in 128 characters

TERMINAL_JOB_STATES = frozenset(JOB_TERMINAL_STATES)
_BACKGROUND: set[asyncio.Task[Any]] = set()


# --------------------------------------------------------------------------- pure helpers
def job_lock_name(
    tool: str, job_id: uuid.UUID, max_parallel: int, fixed_lock: str | None = None
) -> str:
    """The Procrastinate ``lock`` of a job: ``tool:<name>:<slot>`` with ``slot = job id mod max_parallel``.

    Jobs with the same lock run one at a time, so a tool never runs more than ``max_parallel`` jobs at
    once. A catalogue entry can name a fixed lock instead (``dast``: one DAST job at a time).
    """
    if fixed_lock:
        return fixed_lock
    return f"tool:{tool}:{job_id.int % max(1, int(max_parallel))}"


def job_queueing_lock(
    application_id: uuid.UUID,
    version_id: uuid.UUID,
    target_id: uuid.UUID | None,
    tool: str,
    source_ref: str | None = None,
) -> str:
    """At most one waiting job per application, version, target, tool and source reference."""
    return f"scan:{application_id}:{version_id}:{target_id or '-'}:{tool}:{source_ref or '-'}"


def rollup_scan_state(states: Sequence[JobState], cancel_requested: bool = False) -> ScanState:
    """The state of a scan from the states of its jobs."""
    if not states:
        return ScanState.QUEUED
    if any(state not in TERMINAL_JOB_STATES for state in states):
        started = any(state != JobState.QUEUED for state in states)
        return ScanState.RUNNING if started else ScanState.QUEUED
    if cancel_requested or all(state == JobState.CANCELLED for state in states):
        return ScanState.CANCELLED
    good = [s for s in states if s == JobState.COMPLETED]
    partial = [s for s in states if s == JobState.COMPLETED_PARTIAL]
    if len(good) == len(states):
        return ScanState.COMPLETED
    if good or partial:
        return ScanState.COMPLETED_PARTIAL
    return ScanState.FAILED


def request_fingerprint(data: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def check_idempotency_key(key: str) -> str:
    if not _KEY_OK.match(key):
        raise BadRequest(
            "The Idempotency-Key must be 1 to 91 letters, digits or . _ : @ + = -",
            code="idempotency.invalid_key",
        )
    return key


def check_scan_allowed(
    *,
    profile_kind: str,
    mode: str | None,
    tools: Sequence[str],
    target_kind: TargetKind,
    environment: TargetEnvironment | None,
    login_profile_id: Any = None,
) -> None:
    """Refuse combinations the design forbids. Raises a problem with a stable ``code``."""
    if profile_kind == "sast":
        if target_kind not in SAST_TARGET_KINDS:
            raise UnprocessableEntity(
                "Code scan profiles run on repositories, zip uploads and images, not on web addresses.",
                code="scan.target_kind_mismatch",
            )
        return
    if target_kind != TargetKind.URL:
        raise UnprocessableEntity(
            "Web scan profiles run on web addresses (URL targets) only.",
            code="scan.target_kind_mismatch",
        )
    if environment is None:
        raise UnprocessableEntity(
            "This web address has no environment tag (production or uat).",
            code="target.environment_required",
        )
    if environment == TargetEnvironment.PRODUCTION:
        if mode != "baseline":
            raise UnprocessableEntity(
                "Production targets accept the unauthenticated ZAP baseline scan only. "
                "Full scans, API scans and Nuclei run on UAT targets.",
                code="dast.production_baseline_only",
            )
        if login_profile_id is not None:
            raise UnprocessableEntity(
                "Production targets cannot use a login profile.", code="dast.production_no_login"
            )
        extra = sorted(set(tools) - PRODUCTION_DAST_TOOLS)
        if extra:
            raise UnprocessableEntity(
                f"{', '.join(extra)} cannot run against a production target.",
                code="dast.production_baseline_only",
            )


@dataclass
class ScanCheckContext:
    application: Application
    version: ApplicationVersion
    target: Target
    profile: ScanProfile
    doc: ProfileDoc
    tools: list[str]
    trigger: ScanTrigger


ScanCheck = Callable[[ScanCheckContext], None]
_EXTRA_CHECKS: list[ScanCheck] = []


def register_scan_check(check: ScanCheck) -> None:
    """Add a rule run for every new scan (vendor authorization, host allowlist, blackout windows ...)."""
    if check not in _EXTRA_CHECKS:
        _EXTRA_CHECKS.append(check)


def resolve_source_reference(
    version: ApplicationVersion, target: Target, requested: str | None
) -> tuple[str | None, str | None]:
    """``(commit_sha, source_ref)`` for repository targets: a full commit id pins the commit."""
    if target.kind not in (TargetKind.GITHUB_REPO, TargetKind.VENDOR_REPO):
        return None, None
    candidate = (
        requested
        or version.commit_sha
        or (version.label if version.label_kind in ("branch", "tag", "release") else None)
        or target.default_branch
    )
    if not candidate:
        return None, None
    text = candidate.strip()
    if _FULL_SHA.match(text):
        return text.lower(), text.lower()
    return None, text


# --------------------------------------------------------------------------- profile access
async def get_profile(
    session: AsyncSession, name: str, version: int | None = None
) -> tuple[ScanProfile, ProfileDoc]:
    stmt = select(ScanProfile).where(ScanProfile.name == name, ScanProfile.active.is_(True))
    if version is not None:
        stmt = stmt.where(ScanProfile.version == version)
    row = await session.scalar(stmt.order_by(ScanProfile.version.desc()).limit(1))
    if row is None:
        raise NotFound(f"Scan profile {name!r} was not found or is switched off", code="profile.not_found")
    try:
        doc = ProfileDoc.model_validate(row.body)
    except Exception as exc:  # noqa: BLE001 - a damaged stored profile must not crash the request
        raise UnprocessableEntity(
            f"The stored scan profile {name!r} is damaged", code="profile.invalid"
        ) from exc
    return row, doc


# --------------------------------------------------------------------------- creating scans
@dataclass
class ScanCreation:
    scan: Scan
    jobs: list[ScanJob] = field(default_factory=list)
    created: bool = True
    replayed: bool = False  # the Idempotency-Key matched an earlier request
    collapsed: bool = False  # an identical scan was already waiting


def _user_id(requested_by: Any) -> uuid.UUID | None:
    if requested_by is None or requested_by == SYSTEM_ACTOR:
        return None
    if isinstance(requested_by, uuid.UUID):
        return requested_by
    value = getattr(requested_by, "id", None)
    return value if isinstance(value, uuid.UUID) else None


def _clean_options(options: dict[str, Any] | None) -> dict[str, Any]:
    clean = dict(options or {})
    if len(json.dumps(clean, default=str).encode("utf-8")) > MAX_OPTIONS_JSON_BYTES:
        raise UnprocessableEntity("The scan options are too large", code="scan.options_too_large")
    return clean


def _request_excludes(tool: str, key: str, value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_REQUEST_EXCLUDES
        or not all(isinstance(v, str) and 0 < len(v) <= 200 and "\x00" not in v for v in value)
    ):
        raise UnprocessableEntity(
            f"The option {key!r} of {tool} must be a list of at most {MAX_REQUEST_EXCLUDES} path patterns",
            code="scan.option_invalid",
        )
    return [str(v) for v in value]


def _request_minutes(tool: str, key: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_REQUEST_MINUTES:
        raise UnprocessableEntity(
            f"The option {key!r} of {tool} must be a whole number of minutes from 1 to {MAX_REQUEST_MINUTES}",
            code="scan.option_invalid",
        )
    return value


# Per tool, the job options a scan REQUEST may set, with the check each value must pass. Everything else is a policy
# switch (a regression candidate token, limits) that comes only
# from the scan profile or from SecureScan's own callers (the regression runner passes requested_by="system").
REQUEST_TOOL_OPTIONS: dict[str, dict[str, Any]] = {
    "semgrep": {"exclude": _request_excludes},
    "zap": {
        "spider_minutes": _request_minutes,
        "ajax_minutes": _request_minutes,
        "active_minutes": _request_minutes,
    },
}


def _job_options(
    doc: ProfileDoc, tool: str, request_options: dict[str, Any], trusted: bool = False
) -> dict[str, Any]:
    job = doc.job(tool)
    merged: dict[str, Any] = job.job_options() if job is not None else {}
    per_tool = request_options.get("tool_options")
    if isinstance(per_tool, dict) and isinstance(per_tool.get(tool), dict):
        allowed = REQUEST_TOOL_OPTIONS.get(tool, {})
        for key, value in per_tool[tool].items():
            if key in FORBIDDEN_REQUEST_TOOL_KEYS or (not trusted and key not in allowed):
                raise UnprocessableEntity(
                    f"The option {key!r} can only be set in a scan profile",
                    code="scan.option_not_allowed",
                )
            merged[key] = value if trusted or key not in allowed else allowed[key](tool, key, value)
    return merged


async def _inspect_upload(session: AsyncSession, target: Target) -> None:
    """Refuse a zip target whose archive is unsafe, now, so that the user sees the reason at once."""
    from securescan.db.models.artifacts import Artifact
    from securescan.config import get_settings
    from securescan.runner.sources.zip import ZipLimits, ZipRejected, inspect_zip
    from securescan.storage.artifacts import StorageError, artifact_path

    artifact = await session.get(Artifact, target.upload_artifact_id) if target.upload_artifact_id else None
    if artifact is None or artifact.deleted_at is not None or artifact.kind not in (
        ArtifactKind.UPLOAD,
        ArtifactKind.DOCUMENT,
    ):
        raise UnprocessableEntity("The uploaded archive of this target is missing", code="zip.upload_missing")
    try:
        path = artifact_path(artifact)
    except StorageError as exc:
        raise UnprocessableEntity("The uploaded archive of this target is missing", code="zip.upload_missing") from exc
    if not path.is_file():
        raise UnprocessableEntity("The uploaded archive of this target is missing", code="zip.upload_missing")
    try:
        await asyncio.to_thread(inspect_zip, path, ZipLimits.from_settings(get_settings()))
    except ZipRejected as exc:
        raise UnprocessableEntity(str(exc), code=exc.code) from exc


async def create_scan_result(
    session: AsyncSession,
    *,
    version_id: uuid.UUID,
    profile_name: str,
    trigger: ScanTrigger,
    requested_by: Any,
    target_ids: Sequence[uuid.UUID],
    options: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
    profile_version: int | None = None,
    tools: Sequence[str] | None = None,
    ref: str | None = None,
) -> ScanCreation:
    """Validate a scan request and write the Scan and its jobs. The caller commits."""
    if len(target_ids) != 1:
        raise UnprocessableEntity("A scan needs exactly one target", code="scan.one_target")
    opts = _clean_options(options)
    wanted_ref = ref or opts.get("ref") or opts.get("commit")
    fingerprint = request_fingerprint(
        {
            "version": str(version_id),
            "target": str(target_ids[0]),
            "profile": profile_name,
            "profile_version": profile_version,
            "tools": sorted(tools) if tools else None,
            "ref": wanted_ref,
            "options": {k: v for k, v in opts.items() if k not in ("trigger_detail", "schedule_id")},
        }
    )
    if idempotency_key:
        existing = await session.scalar(select(Scan).where(Scan.idempotency_key == idempotency_key))
        if existing is not None:
            return await _replay(session, existing, fingerprint)

    version = await session.get(ApplicationVersion, version_id)
    if version is None:
        raise NotFound("Version not found", code="version.not_found")
    application = await session.get(Application, version.application_id)
    if application is None or application.archived_at is not None:
        raise UnprocessableEntity("This application is archived", code="application.archived")
    if version.archived_at is not None:
        raise UnprocessableEntity("This version is archived", code="version.archived")
    target = await session.get(Target, target_ids[0])
    if target is None:
        raise NotFound("Target not found", code="target.not_found")
    if target.version_id != version.id:
        raise UnprocessableEntity("The target does not belong to this version", code="scan.target_not_in_version")
    if target.archived_at is not None:
        raise UnprocessableEntity("This target is archived", code="target.archived")

    profile, doc = await get_profile(session, profile_name, profile_version)
    chosen = list(tools) if tools else doc.tools
    unknown = [t for t in chosen if t not in doc.tools]
    if unknown:
        raise UnprocessableEntity(
            f"The profile {profile_name!r} has no tool {', '.join(unknown)}", code="scan.unknown_tool"
        )
    chosen = [t for t in doc.tools if t in chosen]  # profile order, no duplicates
    if doc.kind == "dast":  # M9: environment, vendor authorization, allowlist, blackout windows (403 problems)
        from securescan.domain.dast_rules import ProfileFacts, check_scan_allowed_async

        await check_scan_allowed_async(
            ProfileFacts(kind=doc.kind, mode=doc.mode, tools=tuple(chosen)), [target], application=application
        )
    check_scan_allowed(
        profile_kind=doc.kind,
        mode=doc.mode,
        tools=chosen,
        target_kind=target.kind,
        environment=target.environment,
        login_profile_id=target.login_profile_id,
    )
    if target.kind == TargetKind.ZIP:
        await _inspect_upload(session, target)
    check_context = ScanCheckContext(application, version, target, profile, doc, chosen, trigger)
    for check in list(_EXTRA_CHECKS):
        check(check_context)

    commit_sha, source_ref = resolve_source_reference(version, target, str(wanted_ref) if wanted_ref else None)
    queued = await _identical_queued(session, application.id, version.id, target.id, profile, chosen, source_ref, commit_sha)
    if queued is not None:
        jobs = await _jobs_of(session, queued.id)
        return ScanCreation(queued, jobs, created=False, collapsed=True)

    now = utcnow()
    scan = Scan(
        id=new_id(),
        application_id=application.id,
        version_id=version.id,
        target_id=target.id,
        profile_id=profile.id,
        profile_name=profile.name,
        profile_version=profile.version,
        kind=ScanKind(doc.kind),
        mode=doc.mode,
        trigger=trigger,
        trigger_detail=(str(opts.pop("trigger_detail"))[:255] if opts.get("trigger_detail") else None),
        state=ScanState.QUEUED,
        started_by_id=_user_id(requested_by),
        idempotency_key=idempotency_key,
        requested_tools=chosen,
        options={**opts, "fingerprint": fingerprint},
        commit_sha=commit_sha,
        source_ref=source_ref,
        created_at=now,
        updated_at=now,
    )
    try:
        async with session.begin_nested():  # a savepoint: a lost idempotency race must not undo the caller's work
            session.add(scan)
            await session.flush()
    except IntegrityError as exc:  # the same Idempotency-Key raced in from another request
        if idempotency_key:
            existing = await session.scalar(select(Scan).where(Scan.idempotency_key == idempotency_key))
            if existing is not None:
                return await _replay(session, existing, fingerprint)
        raise Conflict("The scan could not be created", code="scan.conflict") from exc
    jobs: list[ScanJob] = []
    for tool in chosen:
        job = ScanJob(
            id=new_id(),
            scan_id=scan.id,
            tool=tool,
            state=JobState.QUEUED,
            options=_job_options(doc, tool, opts, trusted=requested_by == SYSTEM_ACTOR),
            created_at=now,
            updated_at=now,
        )
        session.add(job)
        jobs.append(job)
    await session.flush()
    await record_audit(
        session,
        requested_by if requested_by is not None else SYSTEM_ACTOR,
        "scan.create",
        "scan",
        scan.id,
        {
            "application_id": str(application.id),
            "version_id": str(version.id),
            "target_id": str(target.id),
            "profile": f"{profile.name}@{profile.version}",
            "tools": chosen,
            "trigger": trigger.value,
        },
    )
    schedule_enqueue(session, scan.id)
    return ScanCreation(scan, jobs, created=True)


async def create_scan(session: AsyncSession, **kwargs: Any) -> Scan:
    """``create_scan_result(...)`` returning only the scan (the form the poller and schedules use)."""
    return (await create_scan_result(session, **kwargs)).scan


async def _replay(session: AsyncSession, existing: Scan, fingerprint: str) -> ScanCreation:
    stored = (existing.options or {}).get("fingerprint")
    if stored and stored != fingerprint and existing.started_by_id is not None:
        raise UnprocessableEntity(
            "This Idempotency-Key was already used for a different scan request",
            code="idempotency.key_reused",
        )
    return ScanCreation(existing, await _jobs_of(session, existing.id), created=False, replayed=True)


async def _jobs_of(session: AsyncSession, scan_id: uuid.UUID) -> list[ScanJob]:
    rows = await session.scalars(
        select(ScanJob).where(ScanJob.scan_id == scan_id).order_by(ScanJob.created_at, ScanJob.id)
    )
    return list(rows.all())


async def _identical_queued(
    session: AsyncSession,
    application_id: uuid.UUID,
    version_id: uuid.UUID,
    target_id: uuid.UUID,
    profile: ScanProfile,
    tools: list[str],
    source_ref: str | None,
    commit_sha: str | None,
) -> Scan | None:
    """A scan that is still waiting with the same inputs: a repeated trigger collapses into it."""
    rows = await session.scalars(
        select(Scan)
        .where(
            Scan.application_id == application_id,
            Scan.version_id == version_id,
            Scan.target_id == target_id,
            Scan.profile_id == profile.id,
            Scan.state == ScanState.QUEUED,
        )
        .order_by(Scan.created_at.desc())
        .limit(10)
    )
    for scan in rows.all():
        if (
            sorted(scan.requested_tools or []) == sorted(tools)
            and scan.source_ref == source_ref
            and scan.commit_sha == commit_sha
            and scan.cancel_requested_at is None
        ):
            return scan
    return None


# --------------------------------------------------------------------------- queueing
def schedule_enqueue(session: AsyncSession, scan_id: uuid.UUID) -> None:
    """Queue the scan's jobs right after the session's outermost transaction commits."""
    pending: list[uuid.UUID] = session.info.setdefault("scan_enqueue_pending", [])
    pending.append(scan_id)
    if session.info.get("scan_enqueue_hooked"):
        return
    session.info["scan_enqueue_hooked"] = True
    sync_session = session.sync_session
    event.listen(sync_session, "after_commit", _after_commit)
    event.listen(sync_session, "after_rollback", _after_rollback)


def _after_rollback(sync_session: Any) -> None:
    sync_session.info.pop("scan_enqueue_pending", None)


def _after_commit(sync_session: Any) -> None:
    ids: list[uuid.UUID] = sync_session.info.pop("scan_enqueue_pending", [])
    if not ids:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        log.warning("enqueue_without_loop", scans=len(ids))
        return
    task = loop.create_task(_enqueue_all(list(dict.fromkeys(ids))))
    _BACKGROUND.add(task)
    task.add_done_callback(_BACKGROUND.discard)


async def _enqueue_all(scan_ids: list[uuid.UUID]) -> None:
    for scan_id in scan_ids:
        try:
            await enqueue_scan_jobs(scan_id)
        except Exception as exc:  # noqa: BLE001 - stalled_jobs re-defers whatever is left
            log.warning("enqueue_failed", scan_id=str(scan_id), error=type(exc).__name__)


@dataclass(frozen=True)
class JobDeferral:
    scan_id: uuid.UUID
    job_id: uuid.UUID
    tool: str
    lock: str
    queueing_lock: str


def _max_parallel_and_lock(tool: str) -> tuple[int, str | None]:
    """Cap and fixed lock of a tool from the catalogue; 1 and None when the catalogue is not at hand."""
    from securescan.runner.catalogue import CatalogueError, load_catalogue

    try:
        entry = load_catalogue().get(tool)
    except CatalogueError:
        entry = None
    if entry is None:
        return 1, None
    return entry.max_parallel, entry.lock


def plan_deferrals(scan: Scan, jobs: Sequence[ScanJob], application_id: uuid.UUID) -> list[JobDeferral]:
    plans: list[JobDeferral] = []
    for job in jobs:
        max_parallel, fixed = _max_parallel_and_lock(job.tool)
        plans.append(
            JobDeferral(
                scan_id=scan.id,
                job_id=job.id,
                tool=job.tool,
                lock=job_lock_name(job.tool, job.id, max_parallel, fixed),
                queueing_lock=job_queueing_lock(
                    application_id,
                    scan.version_id,
                    scan.target_id,
                    job.tool,
                    scan.commit_sha or scan.source_ref,
                ),
            )
        )
    return plans


async def defer_job(plan: JobDeferral) -> int | None:
    """Put one job on the queue. Returns the Procrastinate job id, or None when it collapsed."""
    from securescan.jobs.enqueue import defer
    from securescan.jobs.scan_job import scan_job

    return await defer(
        scan_job, lock=plan.lock, queueing_lock=plan.queueing_lock, job_id=str(plan.job_id)
    )


async def enqueue_scan_jobs(
    scan_id: uuid.UUID, only_jobs: Collection[uuid.UUID] | None = None
) -> int:
    """Defer every still-queued job of the scan (or only ``only_jobs``). Returns how many were queued."""
    from securescan.db.session import session_scope

    async with session_scope() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            return 0
        application_id = scan.application_id
        jobs = [
            j
            for j in await _jobs_of(db, scan_id)
            if j.state == JobState.QUEUED and (only_jobs is None or j.id in only_jobs)
        ]
        plans = plan_deferrals(scan, jobs, application_id)
    queued = 0
    merged: list[uuid.UUID] = []
    for plan in plans:
        procrastinate_id = await defer_job(plan)
        async with session_scope() as db:
            await lock_scan(db, plan.scan_id)
            job = await db.get(ScanJob, plan.job_id)
            if job is None or job.state != JobState.QUEUED:
                continue
            if procrastinate_id is None:
                if await _has_live_queue_entry(db, plan.job_id):
                    continue  # this very job is already waiting (a re-defer after a lost commit)
                await mark_job_merged(db, job)
                merged.append(job.id)
                continue
            job.procrastinate_job_id = procrastinate_id
            job.updated_at = utcnow()
            queued += 1
    await settle_cancelled_jobs(merged)
    return queued


async def _has_live_queue_entry(db: AsyncSession, job_id: uuid.UUID) -> bool:
    from sqlalchemy import text

    found = await db.scalar(
        text(
            "SELECT 1 FROM procrastinate_jobs WHERE task_name = 'scan_job' "
            "AND status::text IN ('todo', 'doing') AND args ->> 'job_id' = :job_id LIMIT 1"
        ),
        {"job_id": str(job_id)},
    )
    return found is not None


async def mark_job_merged(db: AsyncSession, job: ScanJob) -> None:
    """The queue already holds an identical waiting job: this one is cancelled with that reason."""
    now = utcnow()
    job.state = JobState.CANCELLED
    job.finished_at = now
    job.updated_at = now
    job.outcome_reason = "An identical job was already waiting in the queue; this request was merged into it."
    await finalize_scan(db, job.scan_id)


# --------------------------------------------------------------------------- roll-up and cancel
async def lock_scan(session: AsyncSession, scan_id: uuid.UUID) -> Scan | None:
    """Take the scan's row lock and refresh the scan from the database. Every transaction that changes a
    scan and its jobs locks the scan first, then the jobs, so that two of them can never wait for each other."""
    return await session.scalar(
        select(Scan)
        .where(Scan.id == scan_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


async def finalize_scan(session: AsyncSession, scan_id: uuid.UUID) -> Scan | None:
    """Recompute the scan's state from its jobs (call after a job changed, in the same transaction).

    Locks the scan row so that two jobs finishing together cannot both compute from stale data. When
    every job is terminal the scan gets ``finished_at``, its final state and a ``scan.finish`` audit event.
    """
    scan = await lock_scan(session, scan_id)
    if scan is None:
        return None
    jobs = await _jobs_of(session, scan_id)
    states = [job.state for job in jobs]
    new_state = rollup_scan_state(states, scan.cancel_requested_at is not None)
    changed = new_state != scan.state
    now = utcnow()
    if new_state == ScanState.RUNNING and scan.started_at is None:
        scan.started_at = now
    scan.state = new_state
    final = new_state in (
        ScanState.COMPLETED,
        ScanState.COMPLETED_PARTIAL,
        ScanState.FAILED,
        ScanState.CANCELLED,
    )
    if final:
        if scan.finished_at is None:
            scan.finished_at = now
        notes = [
            {"tool": job.tool, "note": job.coverage_note} for job in jobs if job.coverage_note
        ]
        scan.coverage_notes = notes
        failed = [f"{j.tool}: {j.outcome_reason}" for j in jobs if j.state in (JobState.FAILED, JobState.TIMED_OUT) and j.outcome_reason]
        scan.error = "; ".join(failed)[:2000] if failed else None
    if changed:
        scan.updated_at = now
        if final:
            await record_audit(
                session,
                SYSTEM_ACTOR,
                "scan.finish",
                "scan",
                scan.id,
                {"state": new_state.value, "jobs": {j.tool: j.state.value for j in jobs}},
            )
    return scan


async def request_cancel(
    session: AsyncSession, scan: Scan, user: Any
) -> tuple[Scan, list[uuid.UUID]]:
    """Cancel a scan: queued jobs end at once; running jobs notice the flag and stop their container.

    Returns the scan and the ids of the jobs cancelled here. After the commit the caller passes those
    ids to ``settle_cancelled_jobs`` so that the import bookkeeping (M4) sees them as settled.
    """
    await lock_scan(session, scan.id)
    if scan.state in (
        ScanState.COMPLETED,
        ScanState.COMPLETED_PARTIAL,
        ScanState.FAILED,
        ScanState.CANCELLED,
    ):
        raise Conflict("This scan has already finished", code="scan.already_finished")
    now = utcnow()
    if scan.cancel_requested_at is None:
        scan.cancel_requested_at = now
        scan.cancelled_by_id = _user_id(user)
        scan.updated_at = now
    cancelled: list[uuid.UUID] = []
    for job in await _jobs_of(session, scan.id):
        if job.state == JobState.QUEUED:
            job.state = JobState.CANCELLED
            job.finished_at = now
            job.updated_at = now
            job.outcome_reason = "Cancelled before it started."
            cancelled.append(job.id)
    await session.flush()
    await finalize_scan(session, scan.id)
    return scan, cancelled


async def settle_cancelled_jobs(job_ids: Sequence[uuid.UUID]) -> None:
    """Tell the import bookkeeping (M4) that cancelled jobs have nothing to import. Never raises."""
    from securescan.db.session import session_scope

    for job_id in job_ids:
        try:
            from securescan.jobs.import_job import enqueue_import

            async with session_scope() as db:
                await enqueue_import(db, job_id)
        except Exception as exc:  # noqa: BLE001 - the recovery sweep repeats this
            log.warning("settle_cancelled_failed", job_id=str(job_id), error=type(exc).__name__)


def validate_profile_error(exc: ProfileError) -> UnprocessableEntity:
    """A problem response for an invalid profile (used by the profiles API)."""
    return UnprocessableEntity(
        str(exc),
        code="profile.invalid",
        errors=[{"detail": message} for message in exc.errors],
    )

