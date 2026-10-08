"""Vendor assessments (M10): hosting rule, delta between versions, conditions, vendor copy, intake.

A vendor assessment is a scan of a vendor application followed by an analyst-reviewed report
with a verdict (design, "Vendor assessment and reports"). The report itself is built by
``domain/reports.py`` and ``reports/snapshot.py`` (M5); this module adds what is vendor specific:

* **Hosting rule** (``vendor_hosting_decision``, ``check_vendor_dast``): a deployable product is
  installed by the company in UAT; a SaaS product stays vendor-hosted and counts as production
  unless the vendor provides and authorizes a UAT instance. DAST on a SaaS vendor target always
  needs the authorization record on the target (written authorization, scan window and contact).
  The check is registered with ``register_scan_check`` so every scan creation (API, schedules,
  poller) runs it.
* **Delta** (``compute_delta``): fixed, remaining, new (plus reopened and triaged) between two
  scans of the same product, compared by DefectDojo's ``hash_code`` from ``FindingHistory``. The
  pure function takes plain rows; ``compute_scan_delta`` reads them from the database.
* **Conditions** (``validate_vendor_conditions``): remediation deadlines belong to a conditional
  pass, only for open High findings, and must lie in the future.
* **Vendor copy** (``vendor_copy_snapshot``, ``render_vendor_copy``): the report without internal
  notes.
* **Intake** (``get_or_create_vendor_product``): the vendor fields of a scan form (vendor,
  product, version, deployable or SaaS) resolved to rows.

Nothing here commits; callers own the transaction. Nothing here parses scanner output: every
finding read here is a ``FindingHistory`` row that came from DefectDojo.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.api.problems import Conflict, NotFound, UnprocessableEntity
from securescan.db.models.applications import Application
from securescan.db.models.artifacts import Artifact
from securescan.db.models.enums import (
    AppType,
    ArtifactKind,
    ReportKind,
    ReviewState,
    ScanState,
    TargetEnvironment,
)
from securescan.db.models.jobs import ScanJob
from securescan.db.models.reports import Report
from securescan.db.models.scans import Scan
from securescan.db.models.targets import Target
from securescan.db.models.templates import ReportTemplate
from securescan.db.models.vendors import Vendor
from securescan.db.models.versions import ApplicationVersion
from securescan.domain import mappings
from securescan.domain.scans import ScanCheckContext, register_scan_check
from securescan.logging import get_logger
from securescan.reports import renderer
from securescan.reports import snapshot as snap
from securescan.storage.artifacts import save_bytes
from securescan.util import ensure_utc, new_id, sha256_hex, utcnow

log = get_logger(__name__)

# --------------------------------------------------------------------------- constants

HOSTING_DEPLOYABLE = "deployable"
HOSTING_SAAS = "saas"
HOSTING_LABELS = {
    HOSTING_DEPLOYABLE: "Deployable product, installed and tested by the company",
    HOSTING_SAAS: "SaaS, hosted by the vendor",
}

AUTH_MISSING = "missing"
AUTH_INCOMPLETE = "incomplete"
AUTH_NOT_STARTED = "not_started"
AUTH_EXPIRED = "expired"
AUTH_VALID = "valid"
AUTH_NOT_REQUIRED = "not_required"
AUTH_LABELS = {
    AUTH_MISSING: "No authorization record",
    AUTH_INCOMPLETE: "Authorization record incomplete",
    AUTH_NOT_STARTED: "Authorized window has not started",
    AUTH_EXPIRED: "Authorized window has ended",
    AUTH_VALID: "Authorized",
    AUTH_NOT_REQUIRED: "Not required",
}

CONDITION_SEVERITY = "high"
MAX_DEADLINE_DAYS = 365
CONDITIONS_RULE = (
    "Conditions apply to open High findings of a conditional pass only. Each needs a remediation "
    "deadline after the report date, agreed with the vendor."
)

TRIAGE_STATES = frozenset({"false_positive", "risk_accepted", "out_of_scope", "duplicate"})
USABLE_JOB_STATES = frozenset({"completed", "completed_partial"})
FINISHED_SCAN_STATES = (ScanState.COMPLETED, ScanState.COMPLETED_PARTIAL)

TARGET_KIND_LABELS = {
    "github_repo": "Source repository",
    "vendor_repo": "Source repository",
    "zip": "Uploaded source archive",
    "image": "Container image",
    "url": "Web application",
}


# --------------------------------------------------------------------------- hosting rule


def authorization_state(
    *,
    artifact_id: Any,
    authorized_from: datetime | None,
    authorized_until: datetime | None,
    contact: str | None,
    now: datetime,
) -> str:
    """State of the vendor authorization record of a target.

    The record is complete when it has the written authorization (an uploaded document), the scan
    window (from and until) and a contact. ``valid`` means complete and ``now`` inside the window
    (the end of the window is inclusive).
    """
    has_contact = bool((contact or "").strip())
    parts = (
        artifact_id is not None,
        authorized_from is not None,
        authorized_until is not None,
        has_contact,
    )
    if not any(parts):
        return AUTH_MISSING
    if not all(parts) or authorized_from is None or authorized_until is None:
        return AUTH_INCOMPLETE
    moment = ensure_utc(now)
    if moment < ensure_utc(authorized_from):
        return AUTH_NOT_STARTED
    if moment > ensure_utc(authorized_until):
        return AUTH_EXPIRED
    return AUTH_VALID


def target_authorization_state(target: Any, now: datetime) -> str:
    """``authorization_state`` of a ``Target`` row (or any object with the same attributes)."""
    return authorization_state(
        artifact_id=getattr(target, "vendor_authorization_artifact_id", None),
        authorized_from=getattr(target, "vendor_authorized_from", None),
        authorized_until=getattr(target, "vendor_authorized_until", None),
        contact=getattr(target, "vendor_contact", None),
        now=now,
    )


@dataclass(frozen=True)
class HostingDecision:
    """What the hosting rule says about one vendor target."""

    hosting: str
    environment: TargetEnvironment | None  # the environment the target counts as
    tagged_environment: TargetEnvironment | None
    authorization_required: bool
    authorization: str
    full_scans_allowed: bool
    rule: str


def normalise_hosting(hosting: str | None) -> str:
    """``deployable`` or ``saas``; an unset hosting is treated as SaaS, the stricter rule."""
    value = (hosting or "").strip().lower()
    return HOSTING_DEPLOYABLE if value == HOSTING_DEPLOYABLE else HOSTING_SAAS


def vendor_hosting_decision(
    *,
    hosting: str | None,
    tagged_environment: TargetEnvironment | None,
    authorization: str,
) -> HostingDecision:
    """The hosting rule of the design (DAST safety controls, vendor assessment workflow step 2).

    * Deployable product: the company installs it in its own environment, so the analyst's
      environment tag stands and no vendor authorization is needed.
    * SaaS product: vendor-hosted. It counts as production unless the vendor provides and authorizes
      a UAT instance, which means the target is tagged ``uat`` **and** carries a valid authorization
      record. DAST on it always needs that record.
    """
    kind = normalise_hosting(hosting)
    if kind == HOSTING_DEPLOYABLE:
        full = tagged_environment == TargetEnvironment.UAT
        return HostingDecision(
            hosting=kind,
            environment=tagged_environment,
            tagged_environment=tagged_environment,
            authorization_required=False,
            authorization=AUTH_NOT_REQUIRED,
            full_scans_allowed=full,
            rule=(
                "The company installs a deployable product in its own UAT environment, where full "
                "DAST is allowed. A target tagged production accepts the ZAP baseline only."
            ),
        )
    authorized_uat = tagged_environment == TargetEnvironment.UAT and authorization == AUTH_VALID
    environment = TargetEnvironment.UAT if authorized_uat else TargetEnvironment.PRODUCTION
    if authorized_uat:
        rule = (
            "The vendor provided a UAT instance and authorized it in writing, so full DAST is "
            "allowed inside the authorized scan window."
        )
    else:
        rule = (
            "A SaaS product stays vendor-hosted and counts as production: only the unauthenticated "
            "ZAP baseline runs, and only with the vendor's written authorization, scan window and "
            "contact on record."
        )
    return HostingDecision(
        hosting=kind,
        environment=environment,
        tagged_environment=tagged_environment,
        authorization_required=True,
        authorization=authorization,
        full_scans_allowed=authorized_uat,
        rule=rule,
    )


_AUTH_PROBLEMS: dict[str, tuple[str, str]] = {
    AUTH_MISSING: (
        "vendor.authorization_required",
        "This is a vendor-hosted SaaS target. Record the vendor's written authorization, scan "
        "window and contact on the target before a web scan can run.",
    ),
    AUTH_INCOMPLETE: (
        "vendor.authorization_incomplete",
        "The vendor authorization record of this target is incomplete. It needs the written "
        "authorization, the scan window (from and until) and a contact.",
    ),
    AUTH_NOT_STARTED: (
        "vendor.authorization_not_started",
        "The vendor's authorized scan window for this target has not started yet.",
    ),
    AUTH_EXPIRED: (
        "vendor.authorization_expired",
        "The vendor's authorized scan window for this target has ended. Record a new "
        "authorization.",
    ),
}


def check_vendor_dast(
    *,
    app_type: AppType | str | None,
    hosting: str | None,
    tagged_environment: TargetEnvironment | None,
    mode: str | None,
    authorization: str,
) -> HostingDecision | None:
    """Refuse a web scan of a vendor target that the hosting rule does not allow.

    Returns ``None`` for applications that are not vendor products (the general rules of
    ``domain/scans.check_scan_allowed`` apply to them). Raises ``UnprocessableEntity`` with a stable
    ``code``: ``vendor.authorization_required`` (and ``_incomplete``, ``_not_started``,
    ``_expired``) or ``dast.production_baseline_only``.
    """
    if str(getattr(app_type, "value", app_type)) != AppType.VENDOR.value:
        return None
    decision = vendor_hosting_decision(
        hosting=hosting, tagged_environment=tagged_environment, authorization=authorization
    )
    if decision.authorization_required and decision.authorization != AUTH_VALID:
        code, message = _AUTH_PROBLEMS.get(
            decision.authorization, _AUTH_PROBLEMS[AUTH_MISSING]
        )
        raise UnprocessableEntity(message, code=code)
    if decision.environment == TargetEnvironment.PRODUCTION and mode != "baseline":
        raise UnprocessableEntity(
            "This vendor target counts as production, so only the unauthenticated ZAP baseline "
            "scan may run. Full scans need a deployable product in UAT, or a UAT instance the "
            "vendor has authorized.",
            code="dast.production_baseline_only",
        )
    return decision


def vendor_scan_check(context: ScanCheckContext) -> None:
    """The scan-creation check (see ``domain.scans.register_scan_check``) for vendor web scans."""
    if context.doc.kind != "dast" or context.application.type != AppType.VENDOR:
        return
    check_vendor_dast(
        app_type=context.application.type,
        hosting=context.application.hosting,
        tagged_environment=context.target.environment,
        mode=context.doc.mode,
        authorization=target_authorization_state(context.target, utcnow()),
    )


register_scan_check(vendor_scan_check)


# --------------------------------------------------------------------------- delta


@dataclass
class DeltaFinding:
    """One finding of the delta, identified by its DefectDojo hash code."""

    key: str
    severity: str
    title: str
    tool: str
    location: str
    state: str = "open"  # state in the newer scan ("" when the finding is gone)
    previous_state: str = ""  # state in the older scan ("" when it was not there)
    hash_code: str | None = None
    rows: int = 1  # history rows that collapsed into this finding (duplicates)


@dataclass
class DeltaResult:
    """Fixed, remaining, new, reopened and triaged findings between an older and a newer scan."""

    fixed: list[DeltaFinding] = field(default_factory=list)
    remaining: list[DeltaFinding] = field(default_factory=list)
    new: list[DeltaFinding] = field(default_factory=list)
    reopened: list[DeltaFinding] = field(default_factory=list)
    triaged: list[DeltaFinding] = field(default_factory=list)
    compared_tools: list[str] = field(default_factory=list)
    skipped_tools: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    duplicate_rows_previous: int = 0
    duplicate_rows_current: int = 0

    def counts(self) -> dict[str, int]:
        return {
            "fixed": len(self.fixed),
            "remaining": len(self.remaining),
            "new": len(self.new),
            "reopened": len(self.reopened),
            "triaged": len(self.triaged),
        }

    def open_now(self) -> int:
        """Distinct open findings of the newer scan inside the comparison."""
        return len(self.remaining) + len(self.new) + len(self.reopened)


def _row(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def row_key(row: Any) -> str:
    """The identity of a history row across scans: the same key the report snapshot uses.

    DefectDojo's ``hash_code`` when the row has one, otherwise a digest of tool, CWE, title, file,
    component and CVE (``snapshot.finding_key``).
    """
    tool = str(_row(row, "tool", "") or "")
    title = snap.clip(_row(row, "title", ""), 500) or "(no title)"
    return snap.finding_key(
        _row(row, "hash_code") or None,
        tool,
        mappings.parse_cwe(_row(row, "cwe")),
        title,
        _row(row, "file_path"),
        _row(row, "component"),
        _row(row, "cve"),
    )


def row_state(row: Any) -> str:
    return snap.enum_value(_row(row, "state_now") or _row(row, "state_at_scan"), "open")


@dataclass
class _Group:
    key: str
    severity: str
    title: str
    tool: str
    location: str
    hash_code: str | None
    state: str
    rows: int = 1

    @property
    def is_open(self) -> bool:
        return self.state == "open"


def _group_of(row: Any) -> _Group:
    file_path = _row(row, "file_path")
    line = _row(row, "line")
    return _Group(
        key=row_key(row),
        severity=snap.severity_key(_row(row, "severity")),
        title=snap.clip(_row(row, "title", ""), 500) or "(no title)",
        tool=str(_row(row, "tool", "") or ""),
        location=snap.finding_location(
            file_path,
            int(line) if line else None,
            _row(row, "url"),
            _row(row, "component"),
            _row(row, "component_version"),
        ),
        hash_code=_row(row, "hash_code") or None,
        state=row_state(row),
    )


def _severity_rank(severity: str) -> int:
    return snap.SEVERITIES.index(severity) if severity in snap.SEVERITIES else len(snap.SEVERITIES)


def collapse_rows(
    rows: Iterable[Any], tools: Collection[str] | None = None
) -> tuple[dict[str, _Group], int]:
    """Group history rows by finding key. Returns ``(groups, duplicate_rows)``.

    Rows with the same key are one finding (the same hash code can come back several times, for
    example from two jobs or after a repeated import). A finding is open when any of its rows is
    open; among open rows the most severe represents it. ``tools`` limits the rows to those tools.
    """
    wanted = {snap.tool_key(t) for t in tools} if tools is not None else None
    groups: dict[str, _Group] = {}
    duplicates = 0
    for row in rows:
        if wanted is not None and snap.tool_key(str(_row(row, "tool", "") or "")) not in wanted:
            continue
        candidate = _group_of(row)
        current = groups.get(candidate.key)
        if current is None:
            groups[candidate.key] = candidate
            continue
        duplicates += 1
        rows_seen = current.rows + 1
        if candidate.is_open and not current.is_open:
            groups[candidate.key] = candidate
        elif candidate.is_open and current.is_open:
            if _severity_rank(candidate.severity) < _severity_rank(current.severity):
                groups[candidate.key] = candidate
        groups[candidate.key].rows = rows_seen
    return groups, duplicates


def _sorted(items: Iterable[DeltaFinding]) -> list[DeltaFinding]:
    return sorted(items, key=lambda f: (_severity_rank(f.severity), f.title, f.location, f.key))


def compute_delta(
    previous_rows: Iterable[Any],
    current_rows: Iterable[Any],
    *,
    compared_tools: Collection[str] | None = None,
) -> DeltaResult:
    """Compare the findings of an older and a newer scan by DefectDojo hash code.

    Definitions (one finding is one key; duplicates collapse):

    * **fixed**: open in the older scan; in the newer scan it is gone, or DefectDojo closed it
      (mitigated, closed, deleted);
    * **remaining**: open in both;
    * **new**: open in the newer scan and not in the older scan at all;
    * **reopened**: open in the newer scan and in the older scan only in a state other than open
      (it had been closed or triaged out there);
    * **triaged**: open in the older scan; in the newer scan an analyst triaged it away (false
      positive, risk accepted, out of scope, duplicate). It is not counted as fixed.

    ``compared_tools`` restricts both sides to tools that ran in both scans, so a tool that only ran
    once cannot make findings look fixed or new.
    """
    previous, previous_dupes = collapse_rows(previous_rows, compared_tools)
    current, current_dupes = collapse_rows(current_rows, compared_tools)
    result = DeltaResult(
        compared_tools=sorted(compared_tools) if compared_tools is not None else [],
        duplicate_rows_previous=previous_dupes,
        duplicate_rows_current=current_dupes,
    )

    def finding(group: _Group, state: str, previous_state: str) -> DeltaFinding:
        return DeltaFinding(
            key=group.key,
            severity=group.severity,
            title=group.title,
            tool=group.tool,
            location=group.location,
            state=state,
            previous_state=previous_state,
            hash_code=group.hash_code,
            rows=group.rows,
        )

    fixed: list[DeltaFinding] = []
    remaining: list[DeltaFinding] = []
    triaged: list[DeltaFinding] = []
    for key, old in previous.items():
        if not old.is_open:
            continue
        now = current.get(key)
        if now is not None and now.is_open:
            remaining.append(finding(now, "open", "open"))
        elif now is not None and now.state in TRIAGE_STATES:
            triaged.append(finding(old, now.state, "open"))
        else:
            fixed.append(finding(old, now.state if now is not None else "", "open"))

    new: list[DeltaFinding] = []
    reopened: list[DeltaFinding] = []
    for key, now in current.items():
        if not now.is_open:
            continue
        old = previous.get(key)
        if old is None:
            new.append(finding(now, "open", ""))
        elif not old.is_open:
            reopened.append(finding(now, "open", old.state))

    result.fixed = _sorted(fixed)
    result.remaining = _sorted(remaining)
    result.new = _sorted(new)
    result.reopened = _sorted(reopened)
    result.triaged = _sorted(triaged)
    return result


@dataclass
class ToolComparison:
    compared: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    partial: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _usable_jobs(jobs: Iterable[Any]) -> dict[str, Any]:
    """Jobs that produced findings in the history: finished and imported (the best one per tool)."""
    usable: dict[str, Any] = {}
    seen: set[str] = set()
    for job in jobs:
        tool = snap.tool_key(str(_row(job, "tool", "") or ""))
        if not tool:
            continue
        seen.add(tool)
        state = snap.enum_value(_row(job, "state"))
        imported = snap.enum_value(_row(job, "import_state"), "imported") == "imported"
        if state in USABLE_JOB_STATES and imported:
            previous = usable.get(tool)
            if previous is None or snap.enum_value(_row(previous, "state")) != "completed":
                usable[tool] = job
    return usable


def compare_tools(previous_jobs: Iterable[Any], current_jobs: Iterable[Any]) -> ToolComparison:
    """The tools whose findings can be compared: finished and imported in both scans."""
    older = list(previous_jobs)
    newer = list(current_jobs)
    usable_old = _usable_jobs(older)
    usable_new = _usable_jobs(newer)
    ran_old = {snap.tool_key(str(_row(j, "tool", "") or "")) for j in older} - {""}
    ran_new = {snap.tool_key(str(_row(j, "tool", "") or "")) for j in newer} - {""}
    comparison = ToolComparison()
    for tool in sorted(ran_old | ran_new):
        label = snap.tool_label(tool)
        if tool in usable_old and tool in usable_new:
            comparison.compared.append(tool)
            states = (usable_old[tool], usable_new[tool])
            if any(
                snap.enum_value(_row(j, "state")) == "completed_partial"
                or bool(_row(j, "partial", False))
                for j in states
            ):
                comparison.partial.append(tool)
                comparison.notes.append(
                    f"{label} was partial in one of the two scans, so its fixed and new counts "
                    "may be incomplete."
                )
            continue
        comparison.skipped.append(tool)
        if tool not in ran_old:
            comparison.notes.append(f"{label} ran only in this assessment and is not compared.")
        elif tool not in ran_new:
            comparison.notes.append(
                f"{label} ran in the previous assessment only and is not compared."
            )
        else:
            comparison.notes.append(
                f"{label} did not finish or was not imported in one of the two scans and is "
                "not compared."
            )
    return comparison


def _brief(item: DeltaFinding, note: str = "") -> snap.BriefFinding:
    return snap.BriefFinding(
        key=item.key,
        severity=item.severity,
        severity_label=snap.SEVERITY_LABELS.get(item.severity, item.severity.title()),
        title=item.title,
        tool=snap.tool_label(item.tool),
        location=item.location,
        note=note,
    )


def _state_text(state: str) -> str:
    return snap.STATE_LABELS.get(state, state.replace("_", " ").capitalize()) if state else ""


def to_snapshot_delta(
    result: DeltaResult,
    *,
    previous_ref: str,
    previous_scan_date: str,
    previous_version_label: str,
) -> snap.Delta:
    """The delta block of a report snapshot (counts are exact; the lists are capped)."""
    cap = snap.MAX_DELTA_ROWS
    notes = list(result.notes)
    if result.duplicate_rows_current or result.duplicate_rows_previous:
        notes.append(
            "Findings with the same DefectDojo hash code were counted once "
            f"({result.duplicate_rows_previous} repeated in the previous scan, "
            f"{result.duplicate_rows_current} in this one)."
        )
    return snap.Delta(
        previous_ref=previous_ref,
        previous_scan_date=previous_scan_date,
        previous_version_label=previous_version_label,
        fixed=len(result.fixed),
        remaining=len(result.remaining),
        new=len(result.new),
        reopened=len(result.reopened),
        triaged=len(result.triaged),
        fixed_findings=[_brief(f) for f in result.fixed[:cap]],
        new_findings=[_brief(f) for f in result.new[:cap]],
        remaining_findings=[_brief(f) for f in result.remaining[:cap]],
        reopened_findings=[
            _brief(f, f"Was {_state_text(f.previous_state).lower()} in the previous assessment")
            for f in result.reopened[:cap]
        ],
        triaged_findings=[
            _brief(f, f"Now {_state_text(f.state).lower()}") for f in result.triaged[:cap]
        ],
        compared_tools=[snap.tool_label(t) for t in result.compared_tools],
        skipped_tools=[snap.tool_label(t) for t in result.skipped_tools],
        notes=notes,
    )


def mark_findings_against(snapshot: snap.Snapshot, result: DeltaResult) -> None:
    """Set ``vs_previous`` on the findings of a snapshot from a delta (new, remaining, reopened)."""
    marks: dict[str, str] = {}
    for item in result.remaining:
        marks[item.key] = "remaining"
    for item in result.reopened:
        marks[item.key] = "reopened"
    for item in result.new:
        marks[item.key] = "new"
    for finding in snapshot.findings:
        finding.vs_previous = marks.get(finding.key, "")


# ------------------------------------------------------------------------ delta from the database


@dataclass
class ScanDelta:
    result: DeltaResult
    current: Scan
    previous: Scan


async def find_previous_scan(session: AsyncSession, scan: Scan) -> Scan | None:
    """The scan a new assessment is compared with.

    The latest earlier finished scan of the same application and kind **on another version** (the
    last assessment of the previous release). A first version that is scanned again is compared with
    its own earlier scan instead.
    """
    base = (
        Scan.application_id == scan.application_id,
        Scan.kind == scan.kind,
        Scan.id != scan.id,
        Scan.created_at < scan.created_at,
        Scan.state.in_(FINISHED_SCAN_STATES),
    )
    order = (Scan.created_at.desc(), Scan.id.desc())
    other_version = await session.scalar(
        select(Scan).where(*base, Scan.version_id != scan.version_id).order_by(*order).limit(1)
    )
    if other_version is not None:
        return other_version
    return await session.scalar(
        select(Scan).where(*base, Scan.version_id == scan.version_id).order_by(*order).limit(1)
    )


async def _jobs_of_scan(session: AsyncSession, scan_id: uuid.UUID) -> list[ScanJob]:
    rows = await session.scalars(
        select(ScanJob).where(ScanJob.scan_id == scan_id).order_by(ScanJob.created_at, ScanJob.id)
    )
    return list(rows.all())


async def compute_scan_delta(
    session: AsyncSession, scan: Scan, previous: Scan | None = None
) -> ScanDelta | None:
    """The delta of ``scan`` against ``previous`` (default: ``find_previous_scan``).

    Findings come from ``FindingHistory`` with their ``state_now`` (refreshed from DefectDojo), so
    findings triaged away since the scan do not count as open on either side. Returns ``None`` when
    there is no earlier scan to compare with.
    """
    from securescan.domain.history import scan_findings

    older = previous if previous is not None else await find_previous_scan(session, scan)
    if older is None:
        return None
    comparison = compare_tools(
        await _jobs_of_scan(session, older.id), await _jobs_of_scan(session, scan.id)
    )
    previous_rows = await scan_findings(session, older.id, include_inactive=True)
    current_rows = await scan_findings(session, scan.id, include_inactive=True)
    result = compute_delta(previous_rows, current_rows, compared_tools=comparison.compared)
    result.skipped_tools = list(comparison.skipped)
    result.notes = list(comparison.notes)
    if not comparison.compared:
        result.notes.append(
            "No tool finished and was imported in both scans, so nothing is compared."
        )
    return ScanDelta(result=result, current=scan, previous=older)


# --------------------------------------------------------------------------- the vendor scope


def build_vendor_scope(
    *, application: Any, target: Any | None, now: datetime
) -> snap.VendorScope:
    """What was assessed and under which hosting and authorization rules (pure)."""
    hosting = normalise_hosting(getattr(application, "hosting", None))
    recorded = getattr(application, "hosting", None)
    kind = snap.enum_value(getattr(target, "kind", None)) if target is not None else ""
    artefacts: list[str] = []
    if target is not None:
        locator = str(getattr(target, "locator", "") or "")
        name = str(getattr(target, "name", "") or "")
        label = TARGET_KIND_LABELS.get(kind, kind or "Target")
        if kind == "zip":
            artefacts.append(f"{label}{': ' + name if name else ''}")
        else:
            artefacts.append(f"{label}: {snap.clip(locator, 300)}" if locator else label)

    tagged = getattr(target, "environment", None) if target is not None else None
    if isinstance(tagged, str):
        tagged = TargetEnvironment(tagged)
    state = AUTH_MISSING
    if target is not None and kind == "url":
        state = target_authorization_state(target, now)
    decision = vendor_hosting_decision(
        hosting=recorded, tagged_environment=tagged, authorization=state
    )

    is_web = kind == "url"
    scope = snap.VendorScope(
        hosting=hosting if recorded else "",
        hosting_label=HOSTING_LABELS[hosting] if recorded else "Not recorded (treated as SaaS)",
        target_kind=kind,
        artefacts=artefacts,
        rule=decision.rule,
        conditions_rule=CONDITIONS_RULE,
    )
    if is_web and decision.environment is not None:
        scope.environment = decision.environment.value
        scope.environment_label = (
            "UAT" if decision.environment == TargetEnvironment.UAT else "Production"
        )
    if is_web and decision.authorization_required:
        scope.authorization_required = True
        scope.authorization_state = AUTH_LABELS.get(state, state)
        scope.authorized_from = snap.iso(getattr(target, "vendor_authorized_from", None))
        scope.authorized_until = snap.iso(getattr(target, "vendor_authorized_until", None))
        scope.authorization_contact = snap.clip(getattr(target, "vendor_contact", None), 300)
    return scope


async def apply_vendor_context(
    session: AsyncSession, snapshot: snap.Snapshot, scan: Scan, application: Application
) -> ScanDelta | None:
    """Add the vendor parts to a freshly built snapshot (``generate_report`` calls it).

    Sets ``vendor_scope`` and replaces the delta with the one computed from the finding history
    (including remaining, reopened and triaged findings). When there is nothing to compare, the
    delta of the report builder stays and a coverage note says why.
    """
    if getattr(application, "type", None) == AppType.VENDOR:
        target = await session.get(Target, scan.target_id) if scan.target_id else None
        snapshot.vendor_scope = build_vendor_scope(
            application=application, target=target, now=utcnow()
        )
    delta = await compute_scan_delta(session, scan)
    if delta is None:
        return None
    if not delta.result.compared_tools:
        snapshot.coverage.notes.extend(delta.result.notes)
        return delta
    previous_version = await session.get(ApplicationVersion, delta.previous.version_id)
    previous_ref = await session.scalar(
        select(Report.ref)
        .where(
            Report.scan_id == delta.previous.id,
            Report.kind == ReportKind.VENDOR,
            Report.status == "ready",
        )
        .order_by(Report.created_at.desc())
        .limit(1)
    )
    snapshot.summary.delta = to_snapshot_delta(
        delta.result,
        previous_ref=previous_ref or "an earlier scan",
        previous_scan_date=snap.iso(
            delta.previous.finished_at or delta.previous.started_at or delta.previous.created_at
        ),
        previous_version_label=previous_version.label if previous_version is not None else "",
    )
    mark_findings_against(snapshot, delta.result)
    return delta


# --------------------------------------------------------------------------- conditions


def _parse_deadline(raw: Any) -> date | None:
    if isinstance(raw, datetime):
        return raw.date()
    if isinstance(raw, date):
        return raw
    if raw:
        try:
            return date.fromisoformat(str(raw)[:10])
        except ValueError:
            return None
    return None


def validate_vendor_conditions(
    conditions: Sequence[Mapping[str, Any]],
    findings: Iterable[Any],
    verdict: str,
    today: date,
) -> list[dict[str, str]]:
    """Check the remediation conditions of a vendor review; returns ``{finding_hash, deadline}``.

    Rules (design: "Conditional pass: 1 to 5 open High findings, each with a remediation date agreed
    with the vendor"):

    * a condition names an open **High** finding of the report (``findings`` are the open findings
      of the snapshot: objects with ``key`` and ``severity``), listed once;
    * its deadline is a date **after** ``today`` and at most ``MAX_DEADLINE_DAYS`` days away;
    * conditions exist only with a **conditional** verdict.

    Problems with single conditions come first (``report.invalid_conditions`` with one entry per
    field); then ``vendor.conditions_need_conditional_verdict``.
    """
    by_key = {str(_row(f, "key")): f for f in findings}
    latest = today + timedelta(days=MAX_DEADLINE_DAYS)
    cleaned: list[dict[str, str]] = []
    errors: list[dict[str, Any]] = []
    seen: set[str] = set()
    for position, cond in enumerate(conditions):
        key = str(_row(cond, "finding_hash") or "").strip()
        deadline = _parse_deadline(_row(cond, "deadline"))
        prefix = f"conditions.{position}"
        finding = by_key.get(key)
        if finding is None:
            errors.append(
                {"field": f"{prefix}.finding_hash", "message": "not an open finding of this report"}
            )
        elif snap.severity_key(_row(finding, "severity")) != CONDITION_SEVERITY:
            errors.append(
                {
                    "field": f"{prefix}.finding_hash",
                    "message": "only open High findings can carry a condition",
                }
            )
        elif key in seen:
            errors.append({"field": f"{prefix}.finding_hash", "message": "listed twice"})
        if deadline is None:
            errors.append({"field": f"{prefix}.deadline", "message": "a date is required"})
        elif deadline <= today:
            errors.append(
                {"field": f"{prefix}.deadline", "message": "the deadline must be after today"}
            )
        elif deadline > latest:
            errors.append(
                {
                    "field": f"{prefix}.deadline",
                    "message": f"the deadline is more than {MAX_DEADLINE_DAYS} days away",
                }
            )
        seen.add(key)
        if deadline is not None:
            cleaned.append({"finding_hash": key, "deadline": deadline.isoformat()})
    if errors:
        raise UnprocessableEntity(
            "The conditions are not valid", code="report.invalid_conditions", errors=errors
        )
    if cleaned and verdict != "conditional":
        raise UnprocessableEntity(
            "Conditions belong to a conditional pass. Change the verdict to conditional, or "
            "remove the conditions.",
            code="vendor.conditions_need_conditional_verdict",
        )
    return cleaned


def findings_without_condition(
    findings: Iterable[Any], conditions: Iterable[Mapping[str, Any]]
) -> list[Any]:
    """Open High findings that have no condition yet (a conditional pass should cover each one)."""
    covered = {str(_row(c, "finding_hash") or "") for c in conditions}
    return [
        f
        for f in findings
        if snap.severity_key(_row(f, "severity")) == CONDITION_SEVERITY
        and str(_row(f, "key")) not in covered
    ]


# --------------------------------------------------------------------------- vendor copy


def vendor_copy_snapshot(snapshot: snap.Snapshot) -> snap.Snapshot:
    """The version of a reviewed report that may go to the vendor.

    Internal notes are removed (the review table omits the row too). The company's own rating of the
    product (criticality) and of the vendor (risk tier) are internal and are removed as well. The
    verdict, the override reason, the conditions and all findings stay.
    """
    data = snapshot.model_copy(deep=True)
    data.vendor_copy = True
    data.review.internal_notes = ""
    data.header.criticality = None
    if data.vendor is not None:
        data.vendor.risk_tier = None
    return data


@dataclass
class VendorCopyFiles:
    html: Artifact
    pdf: Artifact
    sha256: str
    created: bool


def vendor_copy_filenames(report: Report, digest: str) -> tuple[str, str]:
    base = f"{report.ref or report.id}-vendor-copy-{digest[:12]}"
    return f"{base}.html", f"{base}.pdf"


async def _stored_copy(
    session: AsyncSession, report: Report, filename: str
) -> Artifact | None:
    return await session.scalar(
        select(Artifact)
        .where(
            Artifact.owner_type == "report",
            Artifact.owner_id == report.id,
            Artifact.filename == filename,
            Artifact.deleted_at.is_(None),
        )
        .order_by(Artifact.created_at.desc())
        .limit(1)
    )


def require_copy_ready(report: Report) -> None:
    """A vendor copy exists only for a finished, analyst-reviewed vendor report."""
    if report.kind != ReportKind.VENDOR:
        raise UnprocessableEntity(
            "Only vendor assessment reports have a vendor copy", code="vendor.copy_not_available"
        )
    if report.status != "ready":
        raise Conflict("The report is not ready yet", code="report.not_ready")
    if report.review_state != ReviewState.REVIEWED:
        raise Conflict(
            "The report must be reviewed by an analyst before a copy is made for the vendor",
            code="vendor.copy_needs_review",
        )


async def render_vendor_copy(session: AsyncSession, report: Report) -> VendorCopyFiles:
    """The vendor copy of a reviewed report as stored HTML and PDF artifacts.

    The copy is rendered from the report's frozen snapshot with the internal notes removed and
    stored next to the report's own files, named after the copy's own hash, so what was sent to a
    vendor can always be found again. The same snapshot gives the same artifacts (no second
    render). Does not commit.
    """
    from securescan.domain import reports as report_service

    require_copy_ready(report)
    snapshot = await report_service.read_snapshot(session, report)
    copy = vendor_copy_snapshot(snapshot)
    raw = snap.canonical_json(copy)
    digest = sha256_hex(raw)
    html_name, pdf_name = vendor_copy_filenames(report, digest)
    html_artifact = await _stored_copy(session, report, html_name)
    pdf_artifact = await _stored_copy(session, report, pdf_name)
    if html_artifact is not None and pdf_artifact is not None:
        return VendorCopyFiles(html_artifact, pdf_artifact, digest, created=False)

    template = await session.get(ReportTemplate, report.template_id) if report.template_id else None
    if template is None:
        template = await report_service.get_default_template(session, report.kind)
    directory = report_service.template_directory(template)
    try:
        rendered = await asyncio.to_thread(
            renderer.render_report, directory, template.entry_file, copy, digest
        )
    except renderer.RenderError as exc:
        raise report_service.ReportError(str(exc)) from exc
    common: dict[str, Any] = {
        "scan_id": report.scan_id,
        "owner_type": "report",
        "owner_id": report.id,
    }
    if html_artifact is None:
        html_artifact = await save_bytes(
            session,
            kind=ArtifactKind.REPORT_FILE,
            data=rendered.html.encode("utf-8"),
            filename=html_name,
            content_type="text/html; charset=utf-8",
            **common,
        )
    if pdf_artifact is None:
        pdf_artifact = await save_bytes(
            session,
            kind=ArtifactKind.REPORT_FILE,
            data=rendered.pdf,
            filename=pdf_name,
            content_type="application/pdf",
            **common,
        )
    return VendorCopyFiles(html_artifact, pdf_artifact, digest, created=True)


# --------------------------------------------------------------------------- intake


@dataclass
class VendorIntake:
    vendor: Vendor
    application: Application
    version: ApplicationVersion
    vendor_created: bool
    application_created: bool
    version_created: bool


async def get_or_create_vendor_product(
    session: AsyncSession,
    *,
    user: Any,
    vendor_id: uuid.UUID | None,
    vendor_name: str | None,
    product: str,
    version_label: str,
    version_kind: str,
    hosting: str,
    contact_name: str | None = None,
    contact_email: str | None = None,
    risk_tier: str | None = None,
    criticality: str | None = None,
    data_classification: str | None = None,
    description: str | None = None,
) -> VendorIntake:
    """Resolve the vendor fields of a scan form to a vendor, a vendor application and a version.

    The vendor is found by id or by name (case-insensitive) or created. The application is the
    vendor's product (its name is the product name); an existing one is reused only when it is a
    vendor application of the same vendor and its recorded hosting agrees (a product's hosting
    decides the DAST rules, so it is changed on the application, not through an intake). The version
    is found by label or created. Flushes; does not commit or audit.
    """
    from securescan.db.repositories.applications import (
        find_application_by_name,
        find_version_by_label,
        find_vendor_by_name,
    )

    if hosting not in (HOSTING_DEPLOYABLE, HOSTING_SAAS):
        raise UnprocessableEntity(
            "Say whether the product is deployable or SaaS", code="vendor.hosting_required"
        )
    now = utcnow()
    user_id = getattr(user, "id", None)

    vendor: Vendor | None = None
    vendor_created = False
    if vendor_id is not None:
        vendor = await session.get(Vendor, vendor_id)
        if vendor is None:
            raise NotFound("Vendor not found", code="vendor.not_found")
    elif vendor_name and vendor_name.strip():
        vendor = await find_vendor_by_name(session, vendor_name.strip())
    else:
        raise UnprocessableEntity(
            "Name the vendor or choose an existing one", code="vendor.vendor_required"
        )
    if vendor is not None and vendor.archived_at is not None:
        raise UnprocessableEntity("This vendor is archived", code="vendor.archived")
    if vendor is None:
        vendor = Vendor(
            id=new_id(),
            name=str(vendor_name).strip(),
            contact_name=contact_name,
            contact_email=contact_email,
            risk_tier=risk_tier,
            created_by_id=user_id,
            created_at=now,
            updated_at=now,
        )
        session.add(vendor)
        await session.flush()
        vendor_created = True

    product_name = product.strip()
    application = await find_application_by_name(session, product_name)
    application_created = False
    if application is not None:
        if application.type != AppType.VENDOR or application.vendor_id != vendor.id:
            raise Conflict(
                "An application with this name exists and is not a product of this vendor. "
                "Use another product name.",
                code="application.duplicate_name",
            )
        if application.archived_at is not None:
            raise UnprocessableEntity("This product is archived", code="application.archived")
        if application.hosting and application.hosting != hosting:
            raise Conflict(
                f"This product is recorded as {application.hosting}. Change the hosting on the "
                "application itself if that is wrong.",
                code="vendor.hosting_mismatch",
            )
        if not application.hosting:
            application.hosting = hosting
            application.updated_at = now
    else:
        application = Application(
            id=new_id(),
            name=product_name,
            type=AppType.VENDOR,
            vendor_id=vendor.id,
            vendor_product=product_name,
            hosting=hosting,
            description=description,
            criticality=criticality,
            data_classification=data_classification,
            tags=[],
            confirmed=True,
            automatic=False,
            cached_counts={},
            created_by_id=user_id,
            created_at=now,
            updated_at=now,
        )
        session.add(application)
        await session.flush()
        application_created = True

    label = version_label.strip()
    version = await find_version_by_label(session, application.id, label)
    version_created = False
    if version is not None and version.archived_at is not None:
        raise UnprocessableEntity("This version is archived", code="version.archived")
    if version is None:
        version = ApplicationVersion(
            id=new_id(),
            application_id=application.id,
            label=label,
            label_kind=version_kind,
            created_by_id=user_id,
            created_at=now,
            updated_at=now,
        )
        session.add(version)
        await session.flush()
        version_created = True
    return VendorIntake(
        vendor=vendor,
        application=application,
        version=version,
        vendor_created=vendor_created,
        application_created=application_created,
        version_created=version_created,
    )
