"""Historical data: scans and findings, filtered, cursor-paged, and the CSV export of the findings."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Sequence
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import BadRequest
from securescan.auth.roles import AnalystUser
from securescan.db.models.applications import Application
from securescan.db.models.enums import AppType, ScanKind, ScanState, Severity, Verdict
from securescan.db.models.history import FindingHistory
from securescan.db.models.jobs import ScanJob
from securescan.db.models.scans import Scan
from securescan.db.models.users import User
from securescan.db.models.vendors import Vendor
from securescan.db.models.versions import ApplicationVersion
from securescan.db.session import DbSession, session_scope
from securescan.domain.audit import record_audit
from securescan.domain.history import (
    FindingFilters,
    ScanFilters,
    finding_conditions,
    scan_conditions,
)
from securescan.integrations.defectdojo.findings import (
    STATE_CLOSED,
    STATE_DELETED,
    STATE_DUPLICATE,
    STATE_FALSE_POSITIVE,
    STATE_MITIGATED,
    STATE_OPEN,
    STATE_OUT_OF_SCOPE,
    STATE_RISK_ACCEPTED,
)
from securescan.integrations.defectdojo.mapping import defectdojo_link
from securescan.security.csv_safe import csv_line
from securescan.util import utcnow

router = APIRouter(tags=["history"])

KNOWN_STATES = frozenset(
    {
        STATE_OPEN,
        STATE_FALSE_POSITIVE,
        STATE_RISK_ACCEPTED,
        STATE_OUT_OF_SCOPE,
        STATE_DUPLICATE,
        STATE_MITIGATED,
        STATE_CLOSED,
        STATE_DELETED,
    }
)
CSV_BATCH = 2000

CSV_HEADER = [
    "scanned_at",
    "application",
    "application_type",
    "vendor",
    "version",
    "source",
    "tool",
    "severity",
    "title",
    "cwe",
    "cve",
    "cvss",
    "component",
    "component_version",
    "file",
    "line",
    "url",
    "state_at_scan",
    "state_now",
    "scan_id",
    "defectdojo_finding_id",
    "defectdojo_link",
]


# --- query parameters -------------------------------------------------------------------------------


def _severities(values: list[str] | None) -> list[Severity]:
    out: list[Severity] = []
    for value in values or []:
        try:
            out.append(Severity(value.strip().lower()))
        except ValueError as exc:
            raise BadRequest(
                f"Unknown severity {value!r}. Use critical, high, medium, low or info.",
                code="history.invalid_severity",
            ) from exc
    return out


def _states(values: list[str] | None) -> list[str]:
    out = [v.strip().lower() for v in values or []]
    bad = [v for v in out if v not in KNOWN_STATES]
    if bad:
        raise BadRequest(
            f"Unknown triage state {bad[0]!r}. Use one of: {', '.join(sorted(KNOWN_STATES))}.",
            code="history.invalid_state",
        )
    return out


def finding_filters(
    application_id: uuid.UUID | None = None,
    version_id: uuid.UUID | None = None,
    vendor_id: uuid.UUID | None = None,
    app_type: Annotated[AppType | None, Query(alias="type", description="internal or vendor")] = None,
    source: Annotated[str | None, Query(description="Target kind: github_repo, zip, image, url ...")] = None,
    tool: Annotated[list[str] | None, Query(description="Repeat for several tools")] = None,
    severity: Annotated[list[str] | None, Query(description="critical, high, medium, low, info")] = None,
    cwe: Annotated[int | None, Query(ge=1)] = None,
    cve: str | None = None,
    state_then: Annotated[list[str] | None, Query(description="Triage state at scan time")] = None,
    state_now: Annotated[list[str] | None, Query(description="Triage state today")] = None,
    date_from: Annotated[datetime | None, Query(description="Scanned at or after")] = None,
    date_to: Annotated[datetime | None, Query(description="Scanned at or before")] = None,
    started_by: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    q: Annotated[str | None, Query(max_length=200, description="Title contains")] = None,
) -> FindingFilters:
    return FindingFilters(
        application_id=application_id,
        version_id=version_id,
        vendor_id=vendor_id,
        app_type=app_type,
        source=source,
        tools=list(tool or []),
        severities=_severities(severity),
        cwe=cwe,
        cve=cve,
        state_then=_states(state_then),
        state_now=_states(state_now),
        scanned_from=date_from,
        scanned_to=date_to,
        started_by_id=started_by,
        scan_id=scan_id,
        q=q,
    )


def scan_filters(
    application_id: uuid.UUID | None = None,
    version_id: uuid.UUID | None = None,
    vendor_id: uuid.UUID | None = None,
    app_type: Annotated[AppType | None, Query(alias="type", description="internal or vendor")] = None,
    kind: ScanKind | None = None,
    tool: Annotated[list[str] | None, Query()] = None,
    state: Annotated[list[ScanState] | None, Query()] = None,
    verdict: Annotated[list[Verdict] | None, Query()] = None,
    started_by: uuid.UUID | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> ScanFilters:
    return ScanFilters(
        application_id=application_id,
        version_id=version_id,
        vendor_id=vendor_id,
        app_type=app_type,
        kind=kind,
        tools=list(tool or []),
        states=list(state or []),
        verdicts=list(verdict or []),
        started_by_id=started_by,
        date_from=date_from,
        date_to=date_to,
    )


FindingFilterDep = Annotated[FindingFilters, Depends(finding_filters)]
ScanFilterDep = Annotated[ScanFilters, Depends(scan_filters)]


# --- response models -------------------------------------------------------------------------------------


class HistoryScanOut(BaseModel):
    id: uuid.UUID
    application_id: uuid.UUID
    application_name: str
    application_type: AppType | None
    vendor_id: uuid.UUID | None
    vendor_name: str | None
    version_id: uuid.UUID
    version_label: str
    kind: ScanKind
    mode: str | None
    profile_name: str
    trigger: str
    state: ScanState
    verdict: Verdict
    counts: dict[str, Any]
    tools: list[str]
    commit_sha: str | None
    started_by_id: uuid.UUID | None
    started_by_name: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class HistoryFindingOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    job_id: uuid.UUID
    application_id: uuid.UUID
    application_name: str
    version_id: uuid.UUID
    version_label: str
    vendor_id: uuid.UUID | None
    source_kind: str | None
    tool: str
    severity: Severity
    title: str
    cwe: int | None
    cve: str | None
    cvss: float | None
    component: str | None
    component_version: str | None
    file_path: str | None
    line: int | None
    url: str | None
    state_at_scan: str
    state_now: str
    state_now_updated_at: datetime | None
    scanned_at: datetime
    dd_finding_id: int
    defectdojo_url: str


# --- name lookups ----------------------------------------------------------------------------------------------------


class Names:
    """Application, version, vendor and user names for a page of rows (one query each)."""

    def __init__(self) -> None:
        self.applications: dict[uuid.UUID, tuple[str, AppType]] = {}
        self.versions: dict[uuid.UUID, str] = {}
        self.vendors: dict[uuid.UUID, str] = {}
        self.users: dict[uuid.UUID, str] = {}

    @classmethod
    async def load(
        cls,
        db: AsyncSession,
        *,
        application_ids: set[uuid.UUID],
        version_ids: set[uuid.UUID],
        vendor_ids: set[uuid.UUID],
        user_ids: set[uuid.UUID] | None = None,
    ) -> Names:
        names = cls()
        if application_ids:
            for app_id, name, app_type in (
                await db.execute(
                    select(Application.id, Application.name, Application.type).where(
                        Application.id.in_(application_ids)
                    )
                )
            ).all():
                names.applications[app_id] = (name, app_type)
        if version_ids:
            names.versions = dict(
                (
                    await db.execute(
                        select(ApplicationVersion.id, ApplicationVersion.label).where(
                            ApplicationVersion.id.in_(version_ids)
                        )
                    )
                ).all()
            )
        if vendor_ids:
            names.vendors = dict(
                (await db.execute(select(Vendor.id, Vendor.name).where(Vendor.id.in_(vendor_ids)))).all()
            )
        if user_ids:
            for user_id, name, email in (
                await db.execute(select(User.id, User.name, User.email).where(User.id.in_(user_ids)))
            ).all():
                names.users[user_id] = name or email or str(user_id)
        return names


async def _finding_names(db: AsyncSession, rows: Sequence[FindingHistory]) -> Names:
    return await Names.load(
        db,
        application_ids={r.application_id for r in rows},
        version_ids={r.version_id for r in rows},
        vendor_ids={r.vendor_id for r in rows if r.vendor_id},
    )


def finding_out(row: FindingHistory, names: Names) -> HistoryFindingOut:
    return HistoryFindingOut(
        id=row.id,
        scan_id=row.scan_id,
        job_id=row.job_id,
        application_id=row.application_id,
        application_name=names.applications.get(row.application_id, ("?", AppType.INTERNAL))[0],
        version_id=row.version_id,
        version_label=names.versions.get(row.version_id, "?"),
        vendor_id=row.vendor_id,
        source_kind=row.source_kind,
        tool=row.tool,
        severity=row.severity,
        title=row.title,
        cwe=row.cwe,
        cve=row.cve,
        cvss=row.cvss,
        component=row.component,
        component_version=row.component_version,
        file_path=row.file_path,
        line=row.line,
        url=row.url,
        state_at_scan=row.state_at_scan,
        state_now=row.state_now,
        state_now_updated_at=row.state_now_updated_at,
        scanned_at=row.scanned_at,
        dd_finding_id=row.dd_finding_id,
        defectdojo_url=defectdojo_link(f"finding/{row.dd_finding_id}"),
    )


def finding_csv_row(row: FindingHistory, names: Names) -> list[Any]:
    """One CSV row (``csv_line`` escapes formula starters in every cell)."""
    application, app_type = names.applications.get(row.application_id, ("", None))
    return [
        row.scanned_at.isoformat(),
        application,
        app_type.value if app_type else "",
        names.vendors.get(row.vendor_id, "") if row.vendor_id else "",
        names.versions.get(row.version_id, ""),
        row.source_kind or "",
        row.tool,
        row.severity.value,
        row.title,
        row.cwe if row.cwe is not None else "",
        row.cve or "",
        row.cvss if row.cvss is not None else "",
        row.component or "",
        row.component_version or "",
        row.file_path or "",
        row.line if row.line is not None else "",
        row.url or "",
        row.state_at_scan,
        row.state_now,
        str(row.scan_id),
        row.dd_finding_id,
        defectdojo_link(f"finding/{row.dd_finding_id}"),
    ]


# --- endpoints ------------------------------------------------------------------------------------------------------------


@router.get("/history/scans", response_model=CursorPage[HistoryScanOut], summary="Scans, newest first")
async def history_scans(
    db: DbSession, user: AnalystUser, page: PageDep, filters: ScanFilterDep
) -> CursorPage[HistoryScanOut]:
    stmt = select(Scan).where(*scan_conditions(filters))
    result = await paginate(db, stmt, key=[Scan.created_at, Scan.id], params=page)
    scans: list[Scan] = result.items
    application_ids = {s.application_id for s in scans}
    vendor_by_application: dict[uuid.UUID, uuid.UUID] = {}
    if application_ids:
        for app_id, vendor_id in (
            await db.execute(
                select(Application.id, Application.vendor_id).where(
                    Application.id.in_(application_ids), Application.vendor_id.is_not(None)
                )
            )
        ).all():
            vendor_by_application[app_id] = vendor_id
    names = await Names.load(
        db,
        application_ids=application_ids,
        version_ids={s.version_id for s in scans},
        vendor_ids=set(vendor_by_application.values()),
        user_ids={s.started_by_id for s in scans if s.started_by_id},
    )
    tools: dict[uuid.UUID, list[str]] = {}
    if scans:
        for scan_id, tool in (
            await db.execute(select(ScanJob.scan_id, ScanJob.tool).where(ScanJob.scan_id.in_([s.id for s in scans])))
        ).all():
            tools.setdefault(scan_id, []).append(tool)
    items = []
    for s in scans:
        vendor_id = vendor_by_application.get(s.application_id)
        app_name, app_type = names.applications.get(s.application_id, ("?", None))
        items.append(
            HistoryScanOut(
                id=s.id,
                application_id=s.application_id,
                application_name=app_name,
                application_type=app_type,
                vendor_id=vendor_id,
                vendor_name=names.vendors.get(vendor_id) if vendor_id else None,
                version_id=s.version_id,
                version_label=names.versions.get(s.version_id, "?"),
                kind=s.kind,
                mode=s.mode,
                profile_name=s.profile_name,
                trigger=s.trigger.value,
                state=s.state,
                verdict=s.verdict,
                counts=s.counts or {},
                tools=sorted(tools.get(s.id, [])),
                commit_sha=s.commit_sha,
                started_by_id=s.started_by_id,
                started_by_name=names.users.get(s.started_by_id) if s.started_by_id else None,
                created_at=s.created_at,
                started_at=s.started_at,
                finished_at=s.finished_at,
            )
        )
    return CursorPage(items=items, next_cursor=result.next_cursor)


@router.get(
    "/history/findings",
    response_model=CursorPage[HistoryFindingOut],
    summary="Findings of every scan, newest first",
)
async def history_findings(
    db: DbSession, user: AnalystUser, page: PageDep, filters: FindingFilterDep
) -> CursorPage[HistoryFindingOut]:
    stmt = select(FindingHistory).where(*finding_conditions(filters))
    result = await paginate(db, stmt, key=[FindingHistory.scanned_at, FindingHistory.id], params=page)
    rows: list[FindingHistory] = result.items
    names = await _finding_names(db, rows)
    return CursorPage(
        items=[finding_out(r, names) for r in rows], next_cursor=result.next_cursor
    )


async def stream_findings_csv(filters: FindingFilters) -> AsyncIterator[str]:
    """The whole filtered result as CSV, newest first, read in keyset batches so memory stays flat
    however many rows match. Every cell goes through ``csv_safe``."""
    yield "\ufeff" + csv_line(CSV_HEADER)  # BOM so spreadsheet programs read UTF-8
    conditions = finding_conditions(filters)
    last: tuple[datetime, uuid.UUID] | None = None
    while True:
        async with session_scope() as db:
            stmt = select(FindingHistory).where(*conditions)
            if last is not None:
                stmt = stmt.where(tuple_(FindingHistory.scanned_at, FindingHistory.id) < tuple_(*last))
            stmt = stmt.order_by(FindingHistory.scanned_at.desc(), FindingHistory.id.desc()).limit(CSV_BATCH)
            rows = list((await db.scalars(stmt)).all())
            names = await _finding_names(db, rows) if rows else Names()
        if not rows:
            return
        for row in rows:
            yield csv_line(finding_csv_row(row, names))
        if len(rows) < CSV_BATCH:
            return
        last = (rows[-1].scanned_at, rows[-1].id)


@router.get(
    "/history/findings.csv",
    summary="Findings of every scan as CSV (the whole filtered result)",
    response_class=StreamingResponse,
)
async def history_findings_csv(
    request: Request, db: DbSession, user: AnalystUser, filters: FindingFilterDep
) -> StreamingResponse:
    await record_audit(
        db,
        user,
        "export.history_csv",
        "history",
        None,
        {"filters": filters.as_detail()},
        request,
    )
    await db.commit()
    filename = f"securescan-findings-{utcnow():%Y%m%d-%H%M%S}.csv"
    return StreamingResponse(
        stream_findings_csv(filters),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
