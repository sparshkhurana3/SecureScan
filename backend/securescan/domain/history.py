"""Finding history: append after import, refresh "state now", query filters, per-scan reads.

History is append-only (design, "Historical data"): one ``FindingHistory`` row per finding per job,
written once with the state at scan time. The only column that changes afterwards is ``state_now``
(with ``flags_now`` and ``state_now_updated_at``), refreshed from DefectDojo by the nightly task and
on demand through ``refresh_scan_state``. Nothing here is ever deleted.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, cast

from sqlalchemy import ColumnElement, case, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.db.models.applications import Application
from securescan.db.models.enums import (
    AppType,
    ImportState,
    ScanKind,
    ScanState,
    Severity,
    Verdict,
)
from securescan.db.models.history import FindingHistory
from securescan.db.models.jobs import ScanJob
from securescan.db.models.scans import Scan
from securescan.db.repositories.common import escape_like
from securescan.integrations.defectdojo.client import DefectDojoClient
from securescan.integrations.defectdojo.findings import (
    SEVERITY_NAMES,
    STATE_DELETED,
    STATE_OPEN,
    empty_counts,
    finding_flags,
    history_values,
    state_from_flags,
)
from securescan.logging import get_logger
from securescan.util import new_id, utcnow

log = get_logger(__name__)

INSERT_BATCH = 500
UNIQUE_JOB_FINDING = "uq_finding_history_job_id_dd_finding_id"


# --- append ---------------------------------------------------------------------------------------


async def append_job_history(
    session: AsyncSession,
    *,
    job: ScanJob,
    scan: Scan,
    application: Application,
    target_kind: str | None,
    findings: Sequence[Mapping[str, Any]],
    scanned_at: datetime,
) -> int:
    """Append one history row per finding for this job. Safe to repeat: ``(job_id, dd_finding_id)``
    is unique and a second attempt inserts nothing. Returns the number of rows inserted. No commit."""
    now = utcnow()
    rows: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding.get("id"), int):
            continue
        rows.append(
            {
                "id": new_id(),
                "scan_id": scan.id,
                "job_id": job.id,
                "application_id": scan.application_id,
                "version_id": scan.version_id,
                "vendor_id": application.vendor_id,
                "started_by_id": scan.started_by_id,
                "source_kind": target_kind,
                "tool": job.tool,
                "dd_test_id": job.dd_test_id,
                "state_now_updated_at": now,
                "scanned_at": scanned_at,
                "created_at": now,
                **history_values(finding),
            }
        )
    inserted = 0
    for start in range(0, len(rows), INSERT_BATCH):
        stmt = (
            pg_insert(FindingHistory)
            .values(rows[start : start + INSERT_BATCH])
            .on_conflict_do_nothing(constraint=UNIQUE_JOB_FINDING)
        )
        result = cast("CursorResult[Any]", await session.execute(stmt))
        inserted += max(result.rowcount or 0, 0)
    return inserted


# --- reading one scan -------------------------------------------------------------------------------

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def severity_sort_key() -> ColumnElement[int]:
    """SQL expression ranking severities Critical first (for ``ORDER BY``)."""
    return case(SEVERITY_ORDER, value=FindingHistory.severity, else_=99)


async def scan_findings(
    session: AsyncSession, scan_id: uuid.UUID, include_inactive: bool = False
) -> list[FindingHistory]:
    """The history rows of a scan, Critical first. By default only findings that are still open
    (``state_now == "open"``, i.e. not triaged away or closed since); ``include_inactive=True`` returns
    every row of the scan."""
    stmt = select(FindingHistory).where(FindingHistory.scan_id == scan_id)
    if not include_inactive:
        stmt = stmt.where(FindingHistory.state_now == STATE_OPEN)
    stmt = stmt.order_by(
        severity_sort_key(),
        FindingHistory.tool,
        FindingHistory.title,
        FindingHistory.file_path,
        FindingHistory.line,
        FindingHistory.id,
    )
    return list((await session.scalars(stmt)).all())


# --- refresh "state now" -------------------------------------------------------------------------------


@dataclass
class RefreshStats:
    checked: int = 0
    missing: int = 0
    rows_updated: int = 0
    states: dict[str, int] = field(default_factory=dict)


def group_states(
    wanted: Sequence[int], found: Mapping[int, Mapping[str, Any]]
) -> dict[tuple[str, tuple[tuple[str, bool], ...]], list[int]]:
    """Group finding ids by (state, flags) so one UPDATE serves each group. A finding DefectDojo no
    longer has becomes ``deleted`` with empty flags."""
    groups: dict[tuple[str, tuple[tuple[str, bool], ...]], list[int]] = {}
    for finding_id in dict.fromkeys(wanted):
        finding = found.get(finding_id)
        if finding is None:
            key = (STATE_DELETED, ())
        else:
            flags = finding_flags(finding)
            key = (state_from_flags(flags), tuple(sorted(flags.items())))
        groups.setdefault(key, []).append(finding_id)
    return groups


async def refresh_finding_states(
    session: AsyncSession, client: DefectDojoClient, finding_ids: Sequence[int]
) -> RefreshStats:
    """Read the current state of these DefectDojo findings and update ``state_now`` on every history
    row that refers to them. No commit."""
    stats = RefreshStats()
    ids = list(dict.fromkeys(finding_ids))
    if not ids:
        return stats
    found = await client.get_findings_by_ids(ids)
    stats.checked = len(ids)
    now = utcnow()
    for (state, flag_items), group in group_states(ids, found).items():
        stmt = (
            update(FindingHistory)
            .where(FindingHistory.dd_finding_id.in_(group))
            .values(state_now=state, flags_now=dict(flag_items), state_now_updated_at=now)
        )
        result = cast("CursorResult[Any]", await session.execute(stmt))
        stats.rows_updated += max(result.rowcount or 0, 0)
        stats.states[state] = stats.states.get(state, 0) + len(group)
        if state == STATE_DELETED:
            stats.missing += len(group)
    return stats


async def refresh_scan_state(session: AsyncSession, scan_id: uuid.UUID) -> None:
    """Re-read DefectDojo's state of every finding of this scan and update ``state_now``, then refresh
    the application's cached open counts. No commit."""
    from securescan.integrations.defectdojo.factory import sync_client

    ids = list(
        (
            await session.scalars(
                select(FindingHistory.dd_finding_id)
                .where(FindingHistory.scan_id == scan_id)
                .distinct()
            )
        ).all()
    )
    if ids:
        client = await sync_client(session)
        try:
            stats = await refresh_finding_states(session, client, ids)
        finally:
            await client.aclose()
        log.info("scan_state_refreshed", scan_id=str(scan_id), checked=stats.checked)
    scan = await session.get(Scan, scan_id)
    if scan is not None:
        application = await session.get(Application, scan.application_id)
        if application is not None:
            await refresh_application_counts(session, application)


# --- application roll-up ---------------------------------------------------------------------------------


async def application_open_counts(
    session: AsyncSession, application_id: uuid.UUID, version_id: uuid.UUID
) -> dict[str, int]:
    """Open findings of one version: for every tool, the latest imported job of that version, counted
    by current triage state (``state_now == "open"``)."""
    latest = (
        select(ScanJob.id)
        .join(Scan, Scan.id == ScanJob.scan_id)
        .where(
            Scan.application_id == application_id,
            Scan.version_id == version_id,
            ScanJob.import_state == ImportState.IMPORTED,
            ScanJob.dd_test_id.is_not(None),
        )
        .distinct(ScanJob.tool)
        .order_by(ScanJob.tool, func.coalesce(ScanJob.dd_imported_at, ScanJob.created_at).desc())
        .subquery()
    )
    stmt = (
        select(FindingHistory.severity, func.count())
        .where(FindingHistory.job_id.in_(select(latest.c.id)), FindingHistory.state_now == STATE_OPEN)
        .group_by(FindingHistory.severity)
    )
    counts = empty_counts()
    for severity, number in (await session.execute(stmt)).all():
        counts[severity.value] = int(number)
    counts["total"] = sum(counts[name] for name in SEVERITY_NAMES)
    return counts


async def refresh_application_counts(session: AsyncSession, application: Application) -> None:
    """Recompute ``Application.cached_counts`` for the version of its latest scan."""
    version_id: uuid.UUID | None = None
    if application.last_scan_id is not None:
        last = await session.get(Scan, application.last_scan_id)
        version_id = last.version_id if last is not None else None
    if version_id is None:
        return
    application.cached_counts = await application_open_counts(session, application.id, version_id)
    application.cached_counts_at = utcnow()


async def rollup_application(session: AsyncSession, application: Application, scan: Scan) -> None:
    """After a scan's verdict is final: remember it as the application's latest scan when it is the
    newest, and refresh the cached open counts. No commit."""
    finished = scan.finished_at or utcnow()
    if application.last_scan_at is None or finished >= application.last_scan_at:
        application.last_scan_at = finished
        application.last_scan_id = scan.id
        application.last_verdict = scan.verdict if scan.verdict != Verdict.PENDING else None
    await refresh_application_counts(session, application)


# --- filters (history API) --------------------------------------------------------------------------------


@dataclass
class FindingFilters:
    """Filters of ``GET /history/findings`` and of the CSV export (same meaning in both)."""

    application_id: uuid.UUID | None = None
    version_id: uuid.UUID | None = None
    vendor_id: uuid.UUID | None = None
    app_type: AppType | None = None  # internal | vendor
    source: str | None = None  # target kind: github_repo, zip, image, url, ...
    tools: list[str] = field(default_factory=list)
    severities: list[Severity] = field(default_factory=list)
    cwe: int | None = None
    cve: str | None = None
    state_then: list[str] = field(default_factory=list)  # state at scan time
    state_now: list[str] = field(default_factory=list)
    scanned_from: datetime | None = None
    scanned_to: datetime | None = None
    started_by_id: uuid.UUID | None = None
    scan_id: uuid.UUID | None = None
    q: str | None = None  # title contains

    def as_detail(self) -> dict[str, Any]:
        """The non-empty filters as plain JSON (for the audit event of an export)."""
        out: dict[str, Any] = {}
        for key, value in self.__dict__.items():
            if value in (None, [], ""):
                continue
            if isinstance(value, list):
                out[key] = [getattr(v, "value", v) for v in value]
            elif isinstance(value, datetime):
                out[key] = value.isoformat()
            else:
                out[key] = getattr(value, "value", None) or str(value)
        return out


def finding_conditions(filters: FindingFilters) -> list[ColumnElement[bool]]:
    """WHERE conditions on ``FindingHistory`` for the filters (all are ANDed)."""
    c: list[ColumnElement[bool]] = []
    if filters.application_id is not None:
        c.append(FindingHistory.application_id == filters.application_id)
    if filters.version_id is not None:
        c.append(FindingHistory.version_id == filters.version_id)
    if filters.vendor_id is not None:
        c.append(FindingHistory.vendor_id == filters.vendor_id)
    if filters.app_type is not None:
        c.append(
            FindingHistory.application_id.in_(
                select(Application.id).where(Application.type == filters.app_type)
            )
        )
    if filters.source:
        c.append(FindingHistory.source_kind == filters.source)
    if filters.tools:
        c.append(FindingHistory.tool.in_(filters.tools))
    if filters.severities:
        c.append(FindingHistory.severity.in_(filters.severities))
    if filters.cwe is not None:
        c.append(FindingHistory.cwe == filters.cwe)
    if filters.cve:
        c.append(func.lower(FindingHistory.cve) == filters.cve.lower())
    if filters.state_then:
        c.append(FindingHistory.state_at_scan.in_(filters.state_then))
    if filters.state_now:
        c.append(FindingHistory.state_now.in_(filters.state_now))
    if filters.scanned_from is not None:
        c.append(FindingHistory.scanned_at >= filters.scanned_from)
    if filters.scanned_to is not None:
        c.append(FindingHistory.scanned_at <= filters.scanned_to)
    if filters.started_by_id is not None:
        c.append(FindingHistory.started_by_id == filters.started_by_id)
    if filters.scan_id is not None:
        c.append(FindingHistory.scan_id == filters.scan_id)
    if filters.q:
        c.append(FindingHistory.title.ilike(f"%{escape_like(filters.q)}%", escape="\\"))
    return c


@dataclass
class ScanFilters:
    """Filters of ``GET /history/scans``."""

    application_id: uuid.UUID | None = None
    version_id: uuid.UUID | None = None
    vendor_id: uuid.UUID | None = None
    app_type: AppType | None = None
    kind: ScanKind | None = None
    tools: list[str] = field(default_factory=list)
    states: list[ScanState] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)
    started_by_id: uuid.UUID | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None


def scan_conditions(filters: ScanFilters) -> list[ColumnElement[bool]]:
    """WHERE conditions on ``Scan`` for the filters."""
    c: list[ColumnElement[bool]] = []
    if filters.application_id is not None:
        c.append(Scan.application_id == filters.application_id)
    if filters.version_id is not None:
        c.append(Scan.version_id == filters.version_id)
    if filters.vendor_id is not None:
        c.append(
            Scan.application_id.in_(
                select(Application.id).where(Application.vendor_id == filters.vendor_id)
            )
        )
    if filters.app_type is not None:
        c.append(
            Scan.application_id.in_(select(Application.id).where(Application.type == filters.app_type))
        )
    if filters.kind is not None:
        c.append(Scan.kind == filters.kind)
    if filters.tools:
        c.append(Scan.id.in_(select(ScanJob.scan_id).where(ScanJob.tool.in_(filters.tools))))
    if filters.states:
        c.append(Scan.state.in_(filters.states))
    if filters.verdicts:
        c.append(Scan.verdict.in_(filters.verdicts))
    if filters.started_by_id is not None:
        c.append(Scan.started_by_id == filters.started_by_id)
    if filters.date_from is not None:
        c.append(Scan.created_at >= filters.date_from)
    if filters.date_to is not None:
        c.append(Scan.created_at <= filters.date_to)
    return c
