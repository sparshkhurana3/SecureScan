"""Report services: templates, snapshot building from the database, rendering, review, CSV.

The pure parts (snapshot building, rendering, the template package) live in ``securescan/reports/``;
this module is the glue that reads the rows, calls them and stores the results as artifacts. Nothing
here commits: callers (the report job, the API) own the transaction.

Flow of one report (``generate_report``):

1. read the scan, its jobs and the finding history (``scan_findings``), after asking DefectDojo for
   the current triage state (``refresh_scan_state``), so a regenerated report drops false positives;
2. read the description and remediation text of the open findings from DefectDojo (the history table
   does not keep them), best effort;
3. build the ``Snapshot`` (frozen data), store it as a JSON artifact and hash it;
4. render HTML and PDF from the snapshot with the report's template and store both as artifacts.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import uuid
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.api.problems import Conflict, NotFound, UnprocessableEntity
from securescan.config import get_settings
from securescan.db.models.applications import Application
from securescan.db.models.artifacts import Artifact
from securescan.db.models.enums import (
    AppType,
    ArtifactKind,
    ReportKind,
    ReviewState,
    ScanState,
    Verdict,
)
from securescan.db.models.jobs import ScanJob
from securescan.db.models.reports import Report
from securescan.db.models.scans import Scan
from securescan.db.models.templates import ReportTemplate
from securescan.db.models.vendors import Vendor
from securescan.db.models.versions import ApplicationVersion
from securescan.domain import mappings, vendors  # vendors also registers the vendor DAST scan check
from securescan.logging import get_logger
from securescan.reports import renderer
from securescan.reports import snapshot as snap
from securescan.reports import template_package as package
from securescan.security.csv_safe import iter_csv
from securescan.storage.artifacts import StorageError, read_bytes, resolve_key, save_bytes
from securescan.util import new_id, sha256_hex, utcnow

log = get_logger(__name__)

BUILTIN_LOCK_KEY = 770501
MAX_TEXT_LOOKUPS = 2000
MAX_SBOM_BYTES = 64 * 1024 * 1024
DUPLICATE_GUARD_SECONDS = 300
RESUME_WINDOW_SECONDS = 3600
UNFINISHED_SCAN_STATES = (ScanState.QUEUED, ScanState.RUNNING)

CSV_HEADER = (
    "Report",
    "Severity",
    "Status",
    "Tool",
    "Title",
    "CWE",
    "OWASP Top 10",
    "CWE Top 25 rank",
    "CVE",
    "CVSS",
    "Component",
    "Component version",
    "File",
    "Line",
    "URL",
    "Versus previous report",
    "Finding hash",
)


class ReportError(Exception):
    """A report could not be built or rendered (the text is stored on the report row)."""


# --------------------------------------------------------------------------- small helpers


def report_ref(report_id: uuid.UUID, created: datetime) -> str:
    """Human readable report id, e.g. ``SSR-20261007-3F9A1C``."""
    return f"SSR-{created:%Y%m%d}-{report_id.hex[-6:].upper()}"


def report_kind_for(application: Application) -> ReportKind:
    return ReportKind.VENDOR if application.type == AppType.VENDOR else ReportKind.APPLICATION


def verdict_of(value: str | None) -> Verdict:
    try:
        return Verdict(value or "pending")
    except ValueError:
        return Verdict.PENDING


def sbom_component_count(data: bytes) -> int | None:
    """Number of components in a CycloneDX or Syft JSON SBOM; None when it cannot be told."""
    try:
        document = json.loads(data)
    except ValueError:
        return None
    if isinstance(document, dict):
        for key in ("components", "artifacts", "packages"):
            items = document.get(key)
            if isinstance(items, list):
                return len(items)
    return None


def reviewer_name(user: Any) -> str:
    for attribute in ("name", "email", "oid"):
        value = getattr(user, attribute, None)
        if value:
            return str(value)
    return "unknown"


# --------------------------------------------------------------------------- templates


def template_directory(template: ReportTemplate) -> Path:
    """The directory of a template's files on the artifacts volume."""
    if not template.directory:
        raise ReportError(f"template {template.name!r} has no files")
    return resolve_key(template.directory)


async def _advisory_lock(session: AsyncSession, key: int) -> None:
    await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})


async def ensure_builtin_template(session: AsyncSession) -> ReportTemplate:
    """The built-in SonaComstar template row; a new version is made when the shipped files change.

    The shipped files are copied to the artifacts volume for every version, so an old report can be
    re-rendered with the exact template it used even after an upgrade changes the shipped one.
    """
    await _advisory_lock(session, BUILTIN_LOCK_KEY)
    files = await asyncio.to_thread(package.directory_files, renderer.DEFAULT_TEMPLATE_DIR)
    digest = package.files_sha256(files)
    current = await session.scalar(
        select(ReportTemplate)
        .where(
            ReportTemplate.builtin.is_(True),
            ReportTemplate.name == renderer.DEFAULT_TEMPLATE_NAME,
        )
        .order_by(ReportTemplate.version.desc())
        .limit(1)
    )
    if current is not None and current.sha256 == digest:
        if current.directory:
            target = resolve_key(current.directory)
            if not (target / renderer.ENTRY_FILE).is_file():  # volume restored without templates
                await asyncio.to_thread(package.write_files, files, target)
        return current

    template_id = new_id()
    directory_key = f"templates/{template_id}/files"
    await asyncio.to_thread(package.write_files, files, resolve_key(directory_key))
    zipped = await asyncio.to_thread(package.zip_directory, renderer.DEFAULT_TEMPLATE_DIR)
    archive = await save_bytes(
        session,
        kind=ArtifactKind.TEMPLATE,
        data=zipped,
        filename="default-sonacomstar.zip",
        content_type="application/zip",
        key=f"templates/{template_id}/template.zip",
        owner_type="report_template",
        owner_id=template_id,
    )
    now = utcnow()
    row = ReportTemplate(
        id=template_id,
        name=renderer.DEFAULT_TEMPLATE_NAME,
        version=(current.version + 1) if current is not None else 1,
        builtin=True,
        default_for_application=current.default_for_application if current is not None else True,
        default_for_vendor=current.default_for_vendor if current is not None else True,
        zip_artifact_id=archive.id,
        directory=directory_key,
        entry_file=renderer.ENTRY_FILE,
        sha256=digest,
        validated_at=now,
        active=True,
        created_at=now,
    )
    if current is not None:
        current.default_for_application = False
        current.default_for_vendor = False
    session.add(row)
    await session.flush()
    return row


async def get_default_template(session: AsyncSession, kind: ReportKind) -> ReportTemplate:
    """The default template of a report kind (the built-in one until an Admin chooses another)."""
    builtin = await ensure_builtin_template(session)
    column = (
        ReportTemplate.default_for_vendor
        if kind == ReportKind.VENDOR
        else ReportTemplate.default_for_application
    )
    chosen = await session.scalar(
        select(ReportTemplate)
        .where(column.is_(True), ReportTemplate.active.is_(True))
        .order_by(ReportTemplate.created_at.desc())
        .limit(1)
    )
    return chosen or builtin


async def usable_template(session: AsyncSession, template_id: uuid.UUID) -> ReportTemplate:
    """A template a report may be generated with: it exists, is active and was test-rendered."""
    template = await session.get(ReportTemplate, template_id)
    if template is None:
        raise NotFound("Template not found", code="template.not_found")
    if not template.active or template.validated_at is None:
        raise UnprocessableEntity("This template cannot be used", code="template.unusable")
    return template


async def install_template(
    session: AsyncSession, *, name: str, data: bytes, created_by_id: uuid.UUID | None
) -> ReportTemplate:
    """Validate an uploaded template zip, test-render it in a sandbox and store it as a new version.

    Raises ``UnprocessableEntity`` (code ``template.invalid``) with the problems found when the zip
    or the template is not acceptable.
    """
    settings = get_settings()
    if len(data) > min(settings.report_template_max_bytes, package.MAX_ZIP_BYTES):
        raise UnprocessableEntity(
            "The template zip is larger than 20 MB", code="template.too_large"
        )
    try:
        files = await asyncio.to_thread(package.read_zip, data)
    except package.PackageError as exc:
        raise UnprocessableEntity(
            f"The zip cannot be used as a template: {exc}",
            code="template.invalid",
            errors=[{"field": "file", "message": str(exc)}],
        ) from exc

    with tempfile.TemporaryDirectory(prefix="ss-template-") as scratch:
        await asyncio.to_thread(package.write_files, files, Path(scratch))
        problems = await asyncio.to_thread(
            renderer.check_template_isolated,
            Path(scratch),
            renderer.ENTRY_FILE,
            timeout=settings.report_template_check_seconds,
        )
    if problems:
        raise UnprocessableEntity(
            "The template did not pass its test render: " + "; ".join(problems[:3]),
            code="template.invalid",
            errors=[{"field": "file", "message": p} for p in problems[:20]],
        )

    await _advisory_lock(session, BUILTIN_LOCK_KEY + 1)
    latest = await session.scalar(
        select(ReportTemplate.version)
        .where(ReportTemplate.name == name)
        .order_by(ReportTemplate.version.desc())
        .limit(1)
    )
    template_id = new_id()
    directory_key = f"templates/{template_id}/files"
    await asyncio.to_thread(package.write_files, files, resolve_key(directory_key))
    archive = await save_bytes(
        session,
        kind=ArtifactKind.TEMPLATE,
        data=data,
        filename=f"{name}.zip",
        content_type="application/zip",
        key=f"templates/{template_id}/template.zip",
        owner_type="report_template",
        owner_id=template_id,
        created_by_id=created_by_id,
    )
    now = utcnow()
    row = ReportTemplate(
        id=template_id,
        name=name,
        version=(latest or 0) + 1,
        builtin=False,
        zip_artifact_id=archive.id,
        directory=directory_key,
        entry_file=renderer.ENTRY_FILE,
        sha256=package.files_sha256(files),
        validated_at=now,
        active=True,
        created_by_id=created_by_id,
        created_at=now,
    )
    session.add(row)
    await session.flush()
    return row


async def set_default_template(
    session: AsyncSession, template: ReportTemplate, kind: ReportKind
) -> None:
    """Make ``template`` the default of ``kind`` (and no other template)."""
    if not template.active or template.validated_at is None:
        raise UnprocessableEntity("This template cannot be used", code="template.unusable")
    if kind == ReportKind.VENDOR:
        await session.execute(
            update(ReportTemplate)
            .where(ReportTemplate.default_for_vendor.is_(True))
            .values(default_for_vendor=False)
        )
        template.default_for_vendor = True
    else:
        await session.execute(
            update(ReportTemplate)
            .where(ReportTemplate.default_for_application.is_(True))
            .values(default_for_application=False)
        )
        template.default_for_application = True
    await session.flush()


async def preview_html(template: ReportTemplate, kind: ReportKind) -> str:
    """HTML of the template rendered with the sample snapshot (blocking work runs in a thread)."""
    from securescan.reports.sample import sample_snapshot

    directory = template_directory(template)
    sample = sample_snapshot("vendor" if kind == ReportKind.VENDOR else "application")
    return await asyncio.to_thread(
        renderer.render_html, directory, template.entry_file, sample, "0" * 64
    )


# --------------------------------------------------------------------------- reading the facts


async def read_snapshot(session: AsyncSession, report: Report) -> snap.Snapshot:
    """The frozen snapshot of a report, read from its artifact."""
    if report.snapshot_artifact_id is None:
        raise Conflict("The report has no snapshot yet", code="report.not_ready")
    artifact = await session.get(Artifact, report.snapshot_artifact_id)
    if artifact is None:
        raise ReportError("the snapshot artifact row is missing")
    try:
        return snap.load_snapshot(await read_bytes(artifact))
    except (StorageError, ValueError) as exc:
        raise ReportError(f"the snapshot cannot be read: {exc}") from exc


async def fetch_finding_texts(
    session: AsyncSession, rows: Sequence[Any]
) -> dict[int, dict[str, str]]:
    """Description and remediation of the open findings, read from DefectDojo (best effort)."""
    ids = [int(r.dd_finding_id) for r in rows if getattr(r, "state_now", "open") == "open"]
    ids = list(dict.fromkeys(ids))[:MAX_TEXT_LOOKUPS]
    if not ids:
        return {}
    try:
        from securescan.integrations.defectdojo.factory import sync_client

        client = await sync_client(session)
        try:
            found = await client.get_findings_by_ids(ids)
        finally:
            await client.aclose()
    except Exception as exc:  # noqa: BLE001 - the report is still useful without the long texts
        log.warning("report_finding_texts_unavailable", error_type=type(exc).__name__)
        return {}
    texts: dict[int, dict[str, str]] = {}
    for finding_id, finding in found.items():
        texts[int(finding_id)] = {
            "description": str(finding.get("description") or ""),
            "mitigation": str(finding.get("mitigation") or ""),
        }
    return texts


async def sbom_info(session: AsyncSession, scan_id: uuid.UUID) -> tuple[list[Artifact], int | None]:
    """SBOM artifacts of the scan and the component count of the first readable one."""
    artifacts = list(
        (
            await session.scalars(
                select(Artifact)
                .where(
                    Artifact.scan_id == scan_id,
                    Artifact.kind == ArtifactKind.SBOM,
                    Artifact.deleted_at.is_(None),
                )
                .order_by(Artifact.created_at)
            )
        ).all()
    )
    count: int | None = None
    for artifact in artifacts:
        if artifact.size_bytes > MAX_SBOM_BYTES:
            continue
        try:
            count = sbom_component_count(await read_bytes(artifact))
        except StorageError:
            continue
        if count is not None:
            break
    return artifacts, count


async def previous_report_data(
    session: AsyncSession, report: Report, scan: Scan, kind: ReportKind
) -> snap.PreviousReport | None:
    """The newest ready report of an earlier scan, preferring the same version, for the delta."""
    base = (
        Report.application_id == scan.application_id,
        Report.kind == kind,
        Report.status == "ready",
        Report.id != report.id,
        Report.snapshot_artifact_id.is_not(None),
        Scan.created_at < scan.created_at,
    )
    order = (Scan.created_at.desc(), Report.created_at.desc())
    previous = await session.scalar(
        select(Report)
        .join(Scan, Scan.id == Report.scan_id)
        .where(*base, Report.version_id == scan.version_id)
        .order_by(*order)
        .limit(1)
    )
    if previous is None:
        previous = await session.scalar(
            select(Report)
            .join(Scan, Scan.id == Report.scan_id)
            .where(*base)
            .order_by(*order)
            .limit(1)
        )
    if previous is None:
        return None
    try:
        return snap.previous_from_snapshot(await read_snapshot(session, previous))
    except (ReportError, Conflict) as exc:
        log.warning("report_previous_unreadable", report_id=str(previous.id), error=str(exc))
        return None


# --------------------------------------------------------------------------- generating


async def create_report_row(
    session: AsyncSession,
    *,
    scan: Scan,
    application: Application,
    template: ReportTemplate,
    created_by_id: uuid.UUID | None,
    kind: ReportKind | None = None,
    vendor_copy: bool = False,
) -> Report:
    """A pending ``Report`` for a scan; ``generate_report`` fills it. Flushes, does not commit."""
    report_id = new_id()
    now = utcnow()
    report = Report(
        id=report_id,
        application_id=scan.application_id,
        version_id=scan.version_id,
        scan_id=scan.id,
        kind=kind or report_kind_for(application),
        ref=report_ref(report_id, now),
        template_id=template.id,
        template_version=template.version,
        status="pending",
        review_state=ReviewState.AUTOMATIC,
        verdict=Verdict.PENDING,
        verdict_overridden=False,
        conditions=[],
        vendor_copy=vendor_copy,
        mapping_versions=mappings.mapping_versions(),
        generated_by_id=created_by_id,
        created_at=now,
        updated_at=now,
    )
    session.add(report)
    await session.flush()
    return report


async def recent_system_report(session: AsyncSession, scan_id: uuid.UUID) -> Report | None:
    """A report the system made for this scan that the report task should not repeat.

    A ``ready`` one made in the last five minutes means the task ran twice (return it: skip). A
    ``pending`` or ``failed`` one made in the last hour is an interrupted run (return it: resume).
    """
    newest = await session.scalar(
        select(Report)
        .where(Report.scan_id == scan_id, Report.generated_by_id.is_(None))
        .order_by(Report.created_at.desc())
        .limit(1)
    )
    if newest is None:
        return None
    age = (utcnow() - newest.created_at).total_seconds()
    if newest.status == "ready":
        return newest if age < DUPLICATE_GUARD_SECONDS else None
    return newest if age < RESUME_WINDOW_SECONDS else None


async def render_and_store(
    session: AsyncSession, report: Report, snapshot: snap.Snapshot, template: ReportTemplate
) -> None:
    """Freeze ``snapshot``, render HTML and PDF with ``template`` and store the three artifacts.

    The new artifacts are added next to the old ones (nothing is deleted); the report row then
    points at them. Raises ``ReportError`` when rendering fails.
    """
    directory = template_directory(template)
    raw = snap.canonical_json(snapshot)
    digest = sha256_hex(raw)
    try:
        rendered = await asyncio.to_thread(
            renderer.render_report, directory, template.entry_file, snapshot, digest
        )
    except renderer.RenderError as exc:
        raise ReportError(str(exc)) from exc
    base = report.ref or str(report.id)
    stamp = f"{utcnow():%Y%m%dT%H%M%S}-{digest[:8]}"
    common: dict[str, Any] = {
        "scan_id": report.scan_id,
        "owner_type": "report",
        "owner_id": report.id,
    }
    snapshot_artifact = await save_bytes(
        session,
        kind=ArtifactKind.SNAPSHOT,
        data=raw,
        filename=f"{base}-{stamp}.json",
        content_type="application/json",
        **common,
    )
    html_artifact = await save_bytes(
        session,
        kind=ArtifactKind.REPORT_FILE,
        data=rendered.html.encode("utf-8"),
        filename=f"{base}-{stamp}.html",
        content_type="text/html; charset=utf-8",
        **common,
    )
    pdf_artifact = await save_bytes(
        session,
        kind=ArtifactKind.REPORT_FILE,
        data=rendered.pdf,
        filename=f"{base}-{stamp}.pdf",
        content_type="application/pdf",
        **common,
    )
    report.snapshot_artifact_id = snapshot_artifact.id
    report.snapshot_sha256 = digest
    report.html_artifact_id = html_artifact.id
    report.pdf_artifact_id = pdf_artifact.id
    report.title = snapshot.header.title
    report.status = "ready"
    report.error = None
    report.updated_at = utcnow()


async def generate_report(session: AsyncSession, report: Report) -> snap.Snapshot:
    """Build the snapshot of ``report.scan_id`` and render it. Does not commit."""
    from securescan.domain.history import refresh_scan_state, scan_findings

    if report.scan_id is None:
        raise ReportError("the report has no scan")
    scan = await session.get(Scan, report.scan_id)
    if scan is None:
        raise ReportError("the scan of this report no longer exists")
    application = await session.get(Application, scan.application_id)
    version = await session.get(ApplicationVersion, scan.version_id)
    if application is None or version is None:
        raise ReportError("the application or version of this scan no longer exists")
    vendor = await session.get(Vendor, application.vendor_id) if application.vendor_id else None
    template = (
        await session.get(ReportTemplate, report.template_id) if report.template_id else None
    ) or await get_default_template(session, report.kind)

    refresh_failed = False
    try:
        await refresh_scan_state(session, scan.id)
    except Exception as exc:  # noqa: BLE001 - DefectDojo may be down; use the last known state
        refresh_failed = True
        log.warning(
            "report_state_refresh_failed", scan_id=str(scan.id), error_type=type(exc).__name__
        )

    jobs = list(
        (
            await session.scalars(
                select(ScanJob).where(ScanJob.scan_id == scan.id).order_by(ScanJob.created_at)
            )
        ).all()
    )
    findings = await scan_findings(session, scan.id, include_inactive=True)
    texts = await fetch_finding_texts(session, findings)
    sboms, component_count = await sbom_info(session, scan.id)
    previous = await previous_report_data(session, report, scan, report.kind)

    snapshot = snap.build_snapshot(
        kind=report.kind.value,
        application=application,
        version=version,
        scan=scan,
        jobs=jobs,
        findings=findings,
        vendor=vendor,
        template_name=template.name,
        template_version=template.version,
        report_ref=report.ref or "",
        previous=previous,
        sbom_artifacts=sboms,
        sbom_component_count=component_count,
        vendor_copy=report.vendor_copy,
        detail_limit=get_settings().report_detail_limit,
        finding_texts=texts,
    )
    if refresh_failed:
        snapshot.coverage.notes.append(
            "The triage state could not be refreshed from DefectDojo; "
            "this report uses the last known state."
        )
        snapshot.coverage.complete = False

    if report.kind == ReportKind.VENDOR:
        # M10: hosting and authorization scope, and the delta from the finding history by hash code.
        await vendors.apply_vendor_context(session, snapshot, scan, application)

    await render_and_store(session, report, snapshot, template)
    report.template_id = template.id
    report.template_version = template.version
    report.proposed_verdict = verdict_of(snapshot.summary.verdict)
    report.verdict = verdict_of(snapshot.summary.verdict)
    report.mapping_versions = dict(snapshot.header.mapping_versions)
    return snapshot


# --------------------------------------------------------------------------- review


@dataclass
class ReviewRequest:
    decision: str  # "confirm" or "override"
    verdict: str | None = None
    reason: str | None = None
    conditions: list[dict[str, Any]] = field(default_factory=list)
    internal_notes: str | None = None
    vendor_copy: bool | None = None


def validate_conditions(
    conditions: Sequence[Mapping[str, Any]], open_keys: set[str], today: date
) -> list[dict[str, str]]:
    """Check the conditions of a review and return them as ``{finding_hash, deadline}``."""
    cleaned: list[dict[str, str]] = []
    errors: list[dict[str, Any]] = []
    seen: set[str] = set()
    for position, cond in enumerate(conditions):
        key = str(cond.get("finding_hash") or "").strip()
        raw_deadline = cond.get("deadline")
        deadline = raw_deadline if isinstance(raw_deadline, date) else None
        if deadline is None and raw_deadline:
            try:
                deadline = date.fromisoformat(str(raw_deadline)[:10])
            except ValueError:
                deadline = None
        field_name = f"conditions.{position}"
        if key not in open_keys:
            errors.append(
                {
                    "field": f"{field_name}.finding_hash",
                    "message": "not an open finding of this report",
                }
            )
        elif key in seen:
            errors.append({"field": f"{field_name}.finding_hash", "message": "listed twice"})
        if deadline is None:
            errors.append({"field": f"{field_name}.deadline", "message": "a date is required"})
        elif deadline < today:
            errors.append(
                {"field": f"{field_name}.deadline", "message": "the deadline is in the past"}
            )
        seen.add(key)
        if deadline is not None:
            cleaned.append({"finding_hash": key, "deadline": deadline.isoformat()})
    if errors:
        raise UnprocessableEntity(
            "The conditions are not valid", code="report.invalid_conditions", errors=errors
        )
    return cleaned


async def apply_review(
    session: AsyncSession, report: Report, user: Any, request: ReviewRequest
) -> snap.Snapshot:
    """Record an analyst's review on the row and return the reviewed snapshot (not yet rendered).

    Confirms the policy's proposed verdict or overrides it with a reason, attaches conditions and
    sets ``review_state=reviewed``. The caller audits, commits and then calls ``render_and_store``.
    """
    if report.status != "ready":
        raise Conflict("The report is not ready yet", code="report.not_ready")
    snapshot = await read_snapshot(session, report)
    proposed = (
        report.proposed_verdict.value
        if report.proposed_verdict is not None
        else snapshot.review.proposed_verdict
    )
    if request.decision == "confirm":
        if proposed == Verdict.PENDING.value:
            raise UnprocessableEntity(
                "There is no proposed verdict to confirm; choose a verdict and give a reason",
                code="report.nothing_to_confirm",
            )
        verdict = proposed
        overridden = False
        reason = None
    else:
        verdict = request.verdict or ""
        if verdict not in (Verdict.PASS.value, Verdict.CONDITIONAL.value, Verdict.FAIL.value):
            raise UnprocessableEntity(
                "Choose pass, conditional or fail", code="report.invalid_verdict"
            )
        if verdict == proposed:
            raise UnprocessableEntity(
                "That is the proposed verdict; confirm it instead of overriding it",
                code="report.not_an_override",
            )
        reason = (request.reason or "").strip()
        if len(reason) < 5:
            raise UnprocessableEntity(
                "Overriding the verdict needs a reason", code="report.override_reason_required"
            )
        overridden = True
    if request.conditions and verdict == Verdict.PASS.value:
        raise UnprocessableEntity(
            "A passing verdict has no conditions", code="report.conditions_not_allowed"
        )
    if report.kind == ReportKind.VENDOR:
        # M10: conditions are for open High findings of a conditional pass, with a future deadline.
        conditions = vendors.validate_vendor_conditions(
            request.conditions, snapshot.findings, verdict, utcnow().date()
        )
    else:
        conditions = validate_conditions(
            request.conditions, {item.key for item in snapshot.findings}, utcnow().date()
        )

    now = utcnow()
    vendor_copy = report.vendor_copy if request.vendor_copy is None else request.vendor_copy
    notes = report.internal_notes
    if request.internal_notes is not None:
        notes = request.internal_notes.strip() or None
    review = snap.ReviewInput(
        state="reviewed",
        reviewer=reviewer_name(user),
        reviewed_at=now,
        proposed_verdict=proposed,
        verdict=verdict,
        overridden=overridden,
        override_reason=reason or "",
        conditions=conditions,
        internal_notes=notes or "",
    )
    reviewed = snap.with_review(snapshot, review, vendor_copy)

    report.review_state = ReviewState.REVIEWED
    report.proposed_verdict = verdict_of(proposed)
    report.verdict = verdict_of(verdict)
    report.verdict_overridden = overridden
    report.override_reason = reason
    report.reviewer_id = getattr(user, "id", None)
    report.reviewed_at = now
    report.conditions = conditions
    report.vendor_copy = vendor_copy
    report.internal_notes = notes
    report.updated_at = now

    if report.scan_id is not None:
        application = await session.get(Application, report.application_id)
        if application is not None and application.last_scan_id == report.scan_id:
            application.last_verdict = report.verdict
    return reviewed


async def rerender(session: AsyncSession, report: Report, snapshot: snap.Snapshot) -> None:
    """Render ``snapshot`` again with the report's own template (after a review)."""
    template = await session.get(ReportTemplate, report.template_id) if report.template_id else None
    if template is None:
        template = await get_default_template(session, report.kind)
    await render_and_store(session, report, snapshot, template)


# --------------------------------------------------------------------------- CSV


def finding_csv_rows(snapshot: snap.Snapshot) -> Iterator[list[Any]]:
    """Rows of the finding list: every open finding of the report, then the triaged-out ones."""
    ref = snapshot.header.report_ref
    for f in snapshot.findings:
        yield [
            ref,
            f.severity_label,
            f.state_label,
            f.tool_label,
            f.title,
            f.cwe_label,
            f"{f.owasp_id} {f.owasp_name}".strip(),
            f.top25_rank if f.top25_rank else "",
            f.cve or "",
            f.cvss if f.cvss is not None else "",
            f.component or "",
            f.component_version or "",
            f.file_path or "",
            f.line or "",
            f.url or "",
            f.vs_previous,
            f.hash_code or "",
        ]
    for t in snapshot.triaged:
        yield [
            ref,
            t.severity_label,
            t.state_label,
            t.tool_label,
            t.title,
            f"CWE-{t.cwe}" if t.cwe else "",
            "",
            "",
            "",
            "",
            "",
            "",
            t.location,
            "",
            "",
            "",
            t.hash_code or "",
        ]


def findings_csv(snapshot: snap.Snapshot) -> Iterator[str]:
    """CSV text of the finding list, every cell made safe for spreadsheets."""
    return iter_csv(CSV_HEADER, finding_csv_rows(snapshot))
