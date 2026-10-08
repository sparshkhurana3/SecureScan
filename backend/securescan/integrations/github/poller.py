"""Change polling: compare each automatic repository's default-branch head with the last scanned one.

``run_poll`` is the loop and the budget; persistence and scan creation sit behind ``PollStore`` so the
rules (head comparison, "one scan at a time per repository", request budget, rate-limit stop) can be
tested without a database. ``SqlPollStore`` is the SQLAlchemy implementation.

Rules:

* The budget per run is ``min(repositories, budget)`` head lookups, oldest-looked-at first, so every
  repository is reached even when the budget is smaller than the set. Requests are serial and paced
  over about 80% of the poll interval. Conditional requests are not relied on.
* A head that differs from ``last_scanned_sha`` enqueues one ``code-standard`` scan (trigger
  ``change``) unless a SAST scan of that application is queued or running; the repository is then
  looked at again on the next run. Pushes during a scan therefore never queue a second scan.
* At most ``max_scans`` scans are enqueued per run; the rest follow on later runs.
* A rate-limit stop ends the run early and is reported, not treated as a failure of every repository.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from sqlalchemy import ColumnElement, select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.db.models.applications import Application
from securescan.db.models.enums import ScanKind, ScanState, ScanTrigger
from securescan.db.models.github import RepositoryHead
from securescan.db.models.scans import Scan
from securescan.integrations.github.app import (
    GitHubAuthError,
    GitHubClient,
    GitHubError,
    GitHubRateLimited,
    GitHubUnreachable,
    explain_error,
)
from securescan.integrations.github.discovery import ensure_default_version
from securescan.logging import get_logger
from securescan.util import utcnow

log = get_logger(__name__)

CODE_PROFILE = "code-standard"
MAX_PACE_SECONDS = 2.0
PACE_FRACTION = 0.8  # of the poll interval


@dataclass
class PollCandidate:
    application_id: uuid.UUID
    full_name: str
    branch: str
    last_seen_sha: str | None = None
    last_scanned_sha: str | None = None
    last_seen_at: datetime | None = None

    @property
    def owner_and_repo(self) -> tuple[str, str]:
        owner, _, repo = self.full_name.partition("/")
        return owner, repo


@dataclass
class PollResult:
    considered: int = 0
    checked: int = 0
    changed: int = 0
    enqueued: int = 0
    busy: int = 0
    errors: int = 0
    deferred: int = 0  # changed but left for the next run (per-run scan cap)
    stopped_reason: str | None = None
    requests: int = 0
    rate_remaining: int | None = None
    rate_reset_at: datetime | None = None
    scan_ids: list[uuid.UUID] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.stopped_reason is None and (self.errors == 0 or self.checked > 0)

    def summary(self) -> str:
        text = "%d of %d repositories checked, %d changed, %d scans queued" % (
            self.checked,
            self.considered,
            self.changed,
            self.enqueued,
        )
        if self.busy:
            text += ", %d waiting for a running scan" % self.busy
        if self.deferred:
            text += ", %d left for the next run" % self.deferred
        if self.errors:
            text += ", %d errors" % self.errors
        if self.stopped_reason:
            text += ". Stopped early: %s" % self.stopped_reason
        return text


def automatic_conditions() -> list[ColumnElement[bool]]:
    """WHERE conditions of the automatic set: confirmed, switched on, still on GitHub, not archived."""
    return [
        Application.automatic.is_(True),
        Application.confirmed.is_(True),
        Application.archived_at.is_(None),
        Application.github_removed_at.is_(None),
        Application.github_repo_id.is_not(None),
        Application.github_full_name.is_not(None),
        Application.default_branch.is_not(None),
    ]


async def has_active_sast_scan(session: AsyncSession, application_id: uuid.UUID) -> bool:
    """True when a SAST scan of the application is queued or running."""
    found = await session.scalar(
        select(Scan.id)
        .where(
            Scan.application_id == application_id,
            Scan.kind == ScanKind.SAST,
            Scan.state.in_([ScanState.QUEUED, ScanState.RUNNING]),
        )
        .limit(1)
    )
    return found is not None


class ScanNotStartable(Exception):
    """A scan cannot be created for this repository (message is plain language)."""


def failure_reason(exc: BaseException) -> str:
    """A short plain-language reason: a problem's detail, our own message, or the error type."""
    if isinstance(exc, ScanNotStartable):
        return str(exc)
    detail = getattr(exc, "detail", None)
    if isinstance(detail, str) and detail:
        return detail
    return explain_error(exc)


class PollStore(Protocol):
    async def candidates(self) -> list[PollCandidate]: ...

    async def record_head(self, candidate: PollCandidate, sha: str, when: datetime) -> None: ...

    async def record_error(self, candidate: PollCandidate, message: str, when: datetime) -> None: ...

    async def has_active_scan(self, application_id: uuid.UUID) -> bool: ...

    async def enqueue_change_scan(
        self, candidate: PollCandidate, sha: str, when: datetime
    ) -> uuid.UUID | None: ...

    async def commit(self) -> None: ...


def is_changed(head: str, candidate: PollCandidate) -> bool:
    """True when the head is not the commit that was last sent to a scan."""
    return head != candidate.last_scanned_sha


def order_candidates(candidates: list[PollCandidate]) -> list[PollCandidate]:
    """Never-checked first, then the longest unchecked; ties by name for a stable order."""
    epoch = datetime.min.replace(tzinfo=None)

    def key(c: PollCandidate) -> tuple[int, datetime, str]:
        if c.last_seen_at is None:
            return (0, epoch, c.full_name)
        return (1, c.last_seen_at.replace(tzinfo=None), c.full_name)

    return sorted(candidates, key=key)


def pace_seconds(count: int, interval_seconds: float) -> float:
    """Minimum gap between two lookups so the run spreads over the poll interval."""
    if count <= 0:
        return 0.0
    return min(MAX_PACE_SECONDS, (interval_seconds * PACE_FRACTION) / count)


async def run_poll(
    client: GitHubClient,
    store: PollStore,
    *,
    budget: int,
    max_scans: int,
    interval_seconds: float = 600.0,
    low_water: int = 100,
    now: Callable[[], datetime] = utcnow,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> PollResult:
    result = PollResult()
    candidates = order_candidates(await store.candidates())
    result.considered = len(candidates)
    lookups = candidates[: max(0, min(len(candidates), budget))]
    gap = pace_seconds(len(lookups), interval_seconds)
    last_request: float | None = None
    for candidate in lookups:
        remaining = client.rate_remaining()
        if remaining is not None and remaining <= low_water:
            result.stopped_reason = "GitHub request limit nearly used up (%d left)" % remaining
            break
        if last_request is not None and gap > 0:
            wait = gap - (monotonic() - last_request)
            if wait > 0:
                await sleep(wait)
        last_request = monotonic()
        if result.checked and result.checked % 50 == 0:
            await store.commit()  # keep progress if the run is interrupted
        owner, repo = candidate.owner_and_repo
        try:
            head = await client.get_branch_head(owner, repo, candidate.branch)
        except GitHubRateLimited as exc:
            result.stopped_reason = explain_error(exc)
            break
        except (GitHubAuthError, GitHubUnreachable) as exc:
            result.errors += 1  # every further lookup would fail the same way
            result.stopped_reason = explain_error(exc)
            break
        except GitHubError as exc:
            result.errors += 1
            await store.record_error(candidate, explain_error(exc), now())
            continue
        when = now()
        if head is None:
            result.errors += 1
            await store.record_error(
                candidate,
                "The branch '%s' was not found or the repository is empty." % candidate.branch,
                when,
            )
            continue
        result.checked += 1
        await store.record_head(candidate, head, when)
        if not is_changed(head, candidate):
            continue
        result.changed += 1
        if result.enqueued >= max_scans:
            result.deferred += 1
            continue
        if await store.has_active_scan(candidate.application_id):
            result.busy += 1
            continue
        scan_id = await store.enqueue_change_scan(candidate, head, when)
        if scan_id is not None:
            result.enqueued += 1
            result.scan_ids.append(scan_id)
            candidate.last_scanned_sha = head
        await store.commit()
    await store.commit()
    result.requests = client.requests_made
    result.rate_remaining = client.rate_remaining()
    result.rate_reset_at = client.rate_reset_at()
    log.info(
        "github_poll_done",
        considered=result.considered,
        checked=result.checked,
        changed=result.changed,
        enqueued=result.enqueued,
        busy=result.busy,
        errors=result.errors,
        stopped=result.stopped_reason,
    )
    return result


# ------------------------------------------------------------------------------ SQL implementation


class SqlPollStore:
    """``PollStore`` on a SQLAlchemy session; it commits when ``commit`` is called."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._heads: dict[tuple[uuid.UUID, str], RepositoryHead] = {}
        self._apps: dict[uuid.UUID, Application] = {}

    async def candidates(self) -> list[PollCandidate]:
        apps = (
            await self._session.scalars(select(Application).where(*automatic_conditions()))
        ).all()
        heads = (await self._session.scalars(select(RepositoryHead))).all()
        self._heads = {(h.application_id, h.branch): h for h in heads}
        result: list[PollCandidate] = []
        for app in apps:
            self._apps[app.id] = app
            branch = app.default_branch or ""
            head = self._heads.get((app.id, branch))
            result.append(
                PollCandidate(
                    application_id=app.id,
                    full_name=app.github_full_name or "",
                    branch=branch,
                    last_seen_sha=head.last_seen_sha if head else None,
                    last_scanned_sha=head.last_scanned_sha if head else None,
                    last_seen_at=head.last_seen_at if head else None,
                )
            )
        return result

    def _head(self, candidate: PollCandidate) -> RepositoryHead:
        key = (candidate.application_id, candidate.branch)
        head = self._heads.get(key)
        if head is None:
            now = utcnow()
            head = RepositoryHead(
                application_id=candidate.application_id,
                repository=candidate.full_name,
                branch=candidate.branch,
                created_at=now,
                updated_at=now,
            )
            self._session.add(head)
            self._heads[key] = head
        return head

    async def record_head(self, candidate: PollCandidate, sha: str, when: datetime) -> None:
        head = self._head(candidate)
        head.repository = candidate.full_name
        head.last_seen_sha = sha
        head.last_seen_at = when
        head.last_poll_error = None
        head.updated_at = when
        candidate.last_seen_sha = sha

    async def record_error(self, candidate: PollCandidate, message: str, when: datetime) -> None:
        head = self._head(candidate)
        head.last_seen_at = when
        head.last_poll_error = message[:500]
        head.updated_at = when

    async def has_active_scan(self, application_id: uuid.UUID) -> bool:
        return await has_active_sast_scan(self._session, application_id)

    async def enqueue_change_scan(
        self, candidate: PollCandidate, sha: str, when: datetime
    ) -> uuid.UUID | None:
        # Imported here: the scan service belongs to M3 and imports a lot.
        from securescan.domain.scans import create_scan

        application = self._apps.get(candidate.application_id)
        if application is None:
            return None
        head = self._head(candidate)
        try:
            async with self._session.begin_nested():
                prepared = await ensure_default_version(self._session, application)
                if prepared is None:
                    raise ScanNotStartable(
                        "The default-branch version of this application is archived."
                    )
                version, target = prepared
                scan = await create_scan(
                    self._session,
                    version_id=version.id,
                    profile_name=CODE_PROFILE,
                    trigger=ScanTrigger.CHANGE,
                    requested_by=None,
                    target_ids=[target.id],
                    options={
                        "commit": sha,
                        "trigger_detail": "push to %s" % candidate.branch,
                    },
                    idempotency_key="system:change:%s:%s" % (application.id, sha),
                )
        except Exception as exc:  # noqa: BLE001 - one repository must not stop the whole run
            log.warning(
                "github_poll_enqueue_failed",
                application_id=str(application.id),
                error=type(exc).__name__,
            )
            head.last_poll_error = ("Could not start a scan: %s" % failure_reason(exc))[:500]
            return None
        head.last_scanned_sha = sha
        head.last_scanned_at = when
        head.last_scan_id = scan.id
        head.updated_at = when
        return uuid.UUID(str(scan.id))

    async def commit(self) -> None:
        await self._session.commit()
