"""Vendor assessments: intake, list, create, detail, delta, hosting rule and the vendor copy.

A vendor assessment is a scan of a vendor application followed by an analyst-reviewed ``vendor``
report (design, "Vendor assessment and reports"). The report itself, its HTML, PDF and CSV and the
review (``POST /reports/{id}/review``: confirm or override the verdict, add conditions) are the
report endpoints of ``api/reports.py``; this module adds what is vendor specific:

* ``POST /vendor-assessments/intake``: the vendor fields of a scan form (vendor, product, version,
  deployable or SaaS) become a vendor, a vendor application and a version. The target and the scan
  are then created with ``POST /versions/{id}/targets`` and ``POST /scans`` as usual; the hosting
  rule and the vendor authorization record are checked when the scan is created.
* ``GET|POST /vendor-assessments``, ``GET /vendor-assessments/{id}``: list, create (a ``vendor``
  report for a finished scan) and read an assessment with its delta and the conditions still to set.
* ``GET /vendor-assessments/delta``: fixed, remaining and new findings between two scans or
  versions.
* ``GET /vendor-assessments/targets/{id}/hosting``: what the hosting rule says about a target.
* ``GET /vendor-assessments/{id}/html?copy=vendor`` and ``/pdf?copy=vendor``: the reviewed report
  without internal notes, for the vendor.

Both roles may use all of it; every state change and every vendor copy view is audited.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Sequence
from datetime import date, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from securescan.api.applications import ApplicationOut
from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import (
    Conflict,
    NotFound,
    ServiceUnavailable,
    UnprocessableEntity,
)
from securescan.api.reports import DOWNLOAD_HEADERS, HTML_HEADERS, ReportOut, to_out
from securescan.api.schemas import Criticality, DataClassification, Hosting, LabelKind, RiskTier
from securescan.api.vendors import VendorOut
from securescan.api.versions_targets import VersionOut
from securescan.auth.roles import AnalystUser
from securescan.db.models.applications import Application
from securescan.db.models.enums import AppType, ReportKind, ReviewState, ScanKind, Verdict
from securescan.db.models.reports import Report
from securescan.db.models.scans import Scan
from securescan.db.models.targets import Target
from securescan.db.models.vendors import Vendor
from securescan.db.models.versions import ApplicationVersion
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain import reports as report_service
from securescan.domain import vendors as vendor_service
from securescan.domain.audit import record_audit
from securescan.jobs.enqueue import defer
from securescan.jobs.report_job import render_report_job
from securescan.logging import get_logger
from securescan.reports import snapshot as snap
from securescan.reports.watermark import stamp_pdf
from securescan.storage.artifacts import StorageError, read_bytes
from securescan.util import utcnow

log = get_logger(__name__)

router = APIRouter(tags=["vendor assessments"])

MAX_DELTA_ROWS_API = 1000


# --------------------------------------------------------------------------- schemas


class AssessmentOut(ReportOut):
    """A vendor report with the names an analyst looks for."""

    vendor_id: uuid.UUID | None = None
    vendor_name: str | None = None
    product: str | None = None
    hosting: str | None = None
    version_label: str | None = None


class FindingRefOut(BaseModel):
    key: str
    severity: str
    severity_label: str
    title: str
    location: str = ""


class ConditionRules(BaseModel):
    """What a review may attach as conditions (the rules of ``validate_vendor_conditions``)."""

    severity: str = vendor_service.CONDITION_SEVERITY
    verdict: str = "conditional"
    earliest_deadline: date
    latest_deadline: date
    text: str = vendor_service.CONDITIONS_RULE


class AssessmentDetail(AssessmentOut):
    counts: snap.SeverityCounts | None = None
    delta: snap.Delta | None = None
    scope: snap.VendorScope | None = None
    review: snap.Review | None = None
    condition_rules: ConditionRules
    condition_candidates: list[FindingRefOut] = Field(default_factory=list)
    missing_conditions: list[FindingRefOut] = Field(default_factory=list)


class AssessmentCreate(BaseModel):
    """Make the vendor report of a finished scan, or of the newest finished scan of a version."""

    scan_id: uuid.UUID | None = None
    version_id: uuid.UUID | None = None
    kind: ScanKind = Field(default=ScanKind.SAST, description="With version_id: which scans")
    template_id: uuid.UUID | None = Field(
        default=None, description="Default vendor template when empty"
    )
    vendor_copy: bool = Field(
        default=False, description="Render the report itself without internal notes"
    )

    @model_validator(mode="after")
    def _one_target(self) -> AssessmentCreate:
        if (self.scan_id is None) == (self.version_id is None):
            raise ValueError("give either scan_id or version_id")
        return self


class IntakeIn(BaseModel):
    vendor_id: uuid.UUID | None = Field(default=None, description="An existing vendor")
    vendor_name: str | None = Field(
        default=None, min_length=1, max_length=200, description="A new or existing vendor, by name"
    )
    contact_name: str | None = Field(default=None, max_length=200)
    contact_email: str | None = Field(default=None, max_length=320)
    risk_tier: RiskTier | None = None
    product: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=255, description="The vendor's version label")
    version_kind: LabelKind = "release"
    hosting: Hosting
    criticality: Criticality | None = None
    data_classification: DataClassification | None = None
    description: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def _vendor_named(self) -> IntakeIn:
        if self.vendor_id is None and not (self.vendor_name or "").strip():
            raise ValueError("give vendor_id or vendor_name")
        return self


class IntakeOut(BaseModel):
    vendor: VendorOut
    application: ApplicationOut
    version: VersionOut
    vendor_created: bool
    application_created: bool
    version_created: bool
    next_steps: list[str]


class DeltaFindingOut(BaseModel):
    key: str
    severity: str
    title: str
    tool: str
    location: str
    state: str
    previous_state: str
    hash_code: str | None
    occurrences: int


class DeltaOut(BaseModel):
    application_id: uuid.UUID
    scan_id: uuid.UUID
    previous_scan_id: uuid.UUID
    version_id: uuid.UUID
    previous_version_id: uuid.UUID
    counts: dict[str, int]
    fixed: list[DeltaFindingOut]
    remaining: list[DeltaFindingOut]
    new: list[DeltaFindingOut]
    reopened: list[DeltaFindingOut]
    triaged: list[DeltaFindingOut]
    compared_tools: list[str]
    skipped_tools: list[str]
    notes: list[str]
    duplicate_rows_previous: int
    duplicate_rows_current: int
    truncated: bool


class HostingOut(BaseModel):
    target_id: uuid.UUID
    application_id: uuid.UUID
    hosting: str
    hosting_recorded: bool
    tagged_environment: str | None
    effective_environment: str | None
    authorization_required: bool
    authorization: str
    authorization_label: str
    full_scans_allowed: bool
    rule: str


# --------------------------------------------------------------------------- helpers


def _finding_ref(item: Any) -> FindingRefOut:
    return FindingRefOut(
        key=str(item.key),
        severity=str(item.severity),
        severity_label=str(item.severity_label),
        title=str(item.title),
        location=str(item.location or ""),
    )


async def _vendor_application(db: DbSession, application_id: uuid.UUID) -> Application:
    application = await get_or_404(db, Application, application_id, "Application")
    if application.type != AppType.VENDOR:
        raise UnprocessableEntity(
            "This is not a vendor application. Vendor assessments are for vendor products.",
            code="vendor.not_a_vendor_application",
        )
    return application


async def _enrich(db: DbSession, reports: Sequence[Report]) -> list[AssessmentOut]:
    """``AssessmentOut`` for each report, with the vendor, product and version names."""
    if not reports:
        return []
    application_ids = {r.application_id for r in reports}
    version_ids = {r.version_id for r in reports}
    applications = {
        row.id: row
        for row in (
            await db.scalars(select(Application).where(Application.id.in_(application_ids)))
        ).all()
    }
    vendor_ids = {a.vendor_id for a in applications.values() if a.vendor_id is not None}
    vendors_by_id: dict[uuid.UUID, Vendor] = {}
    if vendor_ids:
        found = await db.scalars(select(Vendor).where(Vendor.id.in_(vendor_ids)))
        vendors_by_id = {row.id: row for row in found.all()}
    versions = {
        row.id: row
        for row in (
            await db.scalars(
                select(ApplicationVersion).where(ApplicationVersion.id.in_(version_ids))
            )
        ).all()
    }
    items: list[AssessmentOut] = []
    for report in reports:
        application = applications.get(report.application_id)
        vendor = vendors_by_id.get(application.vendor_id) if application is not None else None
        version = versions.get(report.version_id)
        base = to_out(report).model_dump()
        items.append(
            AssessmentOut(
                **base,
                vendor_id=application.vendor_id if application is not None else None,
                vendor_name=vendor.name if vendor is not None else None,
                product=(
                    (application.vendor_product or application.name)
                    if application is not None
                    else None
                ),
                hosting=application.hosting if application is not None else None,
                version_label=version.label if version is not None else None,
            )
        )
    return items


async def _vendor_report(db: DbSession, report_id: uuid.UUID) -> Report:
    report = await get_or_404(db, Report, report_id, "Report")
    if report.kind != ReportKind.VENDOR:
        raise NotFound("This report is not a vendor assessment", code="vendor.not_an_assessment")
    return report


async def _latest_finished_scan(
    db: DbSession, version_id: uuid.UUID, kind: ScanKind
) -> Scan | None:
    return await db.scalar(
        select(Scan)
        .where(
            Scan.version_id == version_id,
            Scan.kind == kind,
            Scan.state.in_(vendor_service.FINISHED_SCAN_STATES),
        )
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    )


def _delta_findings(items: Sequence[vendor_service.DeltaFinding]) -> list[DeltaFindingOut]:
    return [
        DeltaFindingOut(
            key=f.key,
            severity=f.severity,
            title=f.title,
            tool=f.tool,
            location=f.location,
            state=f.state,
            previous_state=f.previous_state,
            hash_code=f.hash_code,
            occurrences=f.rows,
        )
        for f in items[:MAX_DELTA_ROWS_API]
    ]


# --------------------------------------------------------------------------- intake


@router.post(
    "/vendor-assessments/intake",
    response_model=IntakeOut,
    status_code=201,
    summary="Name the vendor, product and version of a vendor scan",
)
async def vendor_intake(
    body: IntakeIn, request: Request, db: DbSession, user: AnalystUser
) -> IntakeOut:
    """Find or create the vendor, the vendor application and the version for a scan form.

    The product's hosting (deployable or SaaS) decides the DAST rules and is fixed once recorded:
    asking for the other value for an existing product is refused.
    """
    try:
        intake = await vendor_service.get_or_create_vendor_product(
            db,
            user=user,
            vendor_id=body.vendor_id,
            vendor_name=body.vendor_name,
            product=body.product,
            version_label=body.version,
            version_kind=body.version_kind,
            hosting=body.hosting,
            contact_name=body.contact_name,
            contact_email=body.contact_email,
            risk_tier=body.risk_tier,
            criticality=body.criticality,
            data_classification=body.data_classification,
            description=body.description,
        )
    except IntegrityError as exc:
        await db.rollback()
        raise Conflict(
            "The vendor, product or version was created by someone else at the same moment. "
            "Try again.",
            code="vendor.intake_conflict",
        ) from exc
    if intake.vendor_created:
        await record_audit(
            db,
            user,
            "vendor.create",
            "vendor",
            intake.vendor.id,
            {"name": intake.vendor.name},
            request,
        )
    if intake.application_created:
        await record_audit(
            db,
            user,
            "application.create",
            "application",
            intake.application.id,
            {"name": intake.application.name, "type": AppType.VENDOR.value},
            request,
        )
    if intake.version_created:
        await record_audit(
            db,
            user,
            "version.create",
            "version",
            intake.version.id,
            {"application_id": str(intake.application.id), "label": intake.version.label},
            request,
        )
    await record_audit(
        db,
        user,
        "vendor.intake",
        "application",
        intake.application.id,
        {
            "vendor": intake.vendor.name,
            "product": intake.application.name,
            "version": intake.version.label,
            "hosting": intake.application.hosting,
            "created": {
                "vendor": intake.vendor_created,
                "application": intake.application_created,
                "version": intake.version_created,
            },
        },
        request,
    )
    await db.commit()
    steps = [
        "Add the target the vendor supplied (repository, zip, image or web address) to the "
        "version.",
    ]
    if intake.application.hosting == vendor_service.HOSTING_SAAS:
        steps.append(
            "For a web scan of the SaaS product, record the vendor's written authorization, scan "
            "window and contact on the target. Without them the scan is refused."
        )
    else:
        steps.append(
            "Install the deployable product in UAT and register that address as a UAT target for "
            "full web scans."
        )
    steps.append("Start the scan, triage in DefectDojo, then create and review the assessment.")
    return IntakeOut(
        vendor=VendorOut.model_validate(intake.vendor),
        application=ApplicationOut.model_validate(intake.application),
        version=VersionOut.model_validate(intake.version),
        vendor_created=intake.vendor_created,
        application_created=intake.application_created,
        version_created=intake.version_created,
        next_steps=steps,
    )


# --------------------------------------------------------------------------- delta and hosting rule


@router.get(
    "/vendor-assessments/delta",
    response_model=DeltaOut,
    summary="Fixed, remaining and new findings between two scans or versions",
)
async def assessment_delta(
    db: DbSession,
    user: AnalystUser,
    scan_id: uuid.UUID | None = None,
    previous_scan_id: uuid.UUID | None = None,
    version_id: uuid.UUID | None = None,
    against_version_id: uuid.UUID | None = None,
    kind: ScanKind = ScanKind.SAST,
) -> DeltaOut:
    """Compare by DefectDojo hash code, from the finding history.

    Either give ``scan_id`` (the newer scan; ``previous_scan_id`` optional, default: the last scan
    of an earlier version) or ``version_id`` and ``against_version_id`` (the newest finished scan
    of each, of the given ``kind``).
    """
    if (scan_id is None) == (version_id is None):
        raise UnprocessableEntity(
            "Give either scan_id, or version_id with against_version_id", code="vendor.delta_input"
        )
    older: Scan | None = None
    if scan_id is not None:
        newer = await get_or_404(db, Scan, scan_id, "Scan")
        if previous_scan_id is not None:
            older = await get_or_404(db, Scan, previous_scan_id, "Scan")
    else:
        if against_version_id is None:
            raise UnprocessableEntity(
                "Give against_version_id, the version to compare with", code="vendor.delta_input"
            )
        assert version_id is not None  # noqa: S101 - checked above
        newer_scan = await _latest_finished_scan(db, version_id, kind)
        older = await _latest_finished_scan(db, against_version_id, kind)
        if newer_scan is None or older is None:
            raise NotFound(
                "Both versions need a finished scan of that kind to be compared",
                code="vendor.no_scan_to_compare",
            )
        newer = newer_scan
    if older is not None and older.application_id != newer.application_id:
        raise UnprocessableEntity(
            "The two scans belong to different applications", code="vendor.delta_applications"
        )
    delta = await vendor_service.compute_scan_delta(db, newer, older)
    if delta is None:
        raise NotFound(
            "There is no earlier scan of this product to compare with",
            code="vendor.no_previous_scan",
        )
    result = delta.result
    sizes = [len(result.fixed), len(result.remaining), len(result.new), len(result.reopened)]
    return DeltaOut(
        application_id=newer.application_id,
        scan_id=newer.id,
        previous_scan_id=delta.previous.id,
        version_id=newer.version_id,
        previous_version_id=delta.previous.version_id,
        counts=result.counts(),
        fixed=_delta_findings(result.fixed),
        remaining=_delta_findings(result.remaining),
        new=_delta_findings(result.new),
        reopened=_delta_findings(result.reopened),
        triaged=_delta_findings(result.triaged),
        compared_tools=[snap.tool_label(t) for t in result.compared_tools],
        skipped_tools=[snap.tool_label(t) for t in result.skipped_tools],
        notes=result.notes,
        duplicate_rows_previous=result.duplicate_rows_previous,
        duplicate_rows_current=result.duplicate_rows_current,
        truncated=max(sizes + [len(result.triaged)]) > MAX_DELTA_ROWS_API,
    )


@router.get(
    "/vendor-assessments/targets/{target_id}/hosting",
    response_model=HostingOut,
    summary="What the hosting rule says about a vendor target",
)
async def target_hosting(target_id: uuid.UUID, db: DbSession, user: AnalystUser) -> HostingOut:
    target = await get_or_404(db, Target, target_id, "Target")
    version = await get_or_404(db, ApplicationVersion, target.version_id, "Version")
    application = await _vendor_application(db, version.application_id)
    state = vendor_service.target_authorization_state(target, utcnow())
    decision = vendor_service.vendor_hosting_decision(
        hosting=application.hosting, tagged_environment=target.environment, authorization=state
    )
    return HostingOut(
        target_id=target.id,
        application_id=application.id,
        hosting=decision.hosting,
        hosting_recorded=bool(application.hosting),
        tagged_environment=target.environment.value if target.environment else None,
        effective_environment=decision.environment.value if decision.environment else None,
        authorization_required=decision.authorization_required,
        authorization=decision.authorization,
        authorization_label=vendor_service.AUTH_LABELS.get(
            decision.authorization, decision.authorization
        ),
        full_scans_allowed=decision.full_scans_allowed,
        rule=decision.rule,
    )


# --------------------------------------------------------------------------- list, create, detail


@router.get(
    "/vendor-assessments",
    response_model=CursorPage[AssessmentOut],
    summary="List vendor assessments",
)
async def list_assessments(
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    vendor_id: uuid.UUID | None = None,
    application_id: uuid.UUID | None = None,
    version_id: uuid.UUID | None = None,
    verdict: Verdict | None = None,
    review_state: ReviewState | None = None,
    status: Literal["pending", "ready", "failed"] | None = None,
) -> CursorPage[AssessmentOut]:
    stmt = select(Report).where(Report.kind == ReportKind.VENDOR)
    if vendor_id:
        stmt = stmt.where(
            Report.application_id.in_(
                select(Application.id).where(Application.vendor_id == vendor_id)
            )
        )
    if application_id:
        stmt = stmt.where(Report.application_id == application_id)
    if version_id:
        stmt = stmt.where(Report.version_id == version_id)
    if verdict:
        stmt = stmt.where(Report.verdict == verdict)
    if review_state:
        stmt = stmt.where(Report.review_state == review_state)
    if status:
        stmt = stmt.where(Report.status == status)
    result = await paginate(db, stmt, key=[Report.created_at, Report.id], params=page)
    return CursorPage(items=await _enrich(db, result.items), next_cursor=result.next_cursor)


@router.post(
    "/vendor-assessments",
    response_model=AssessmentOut,
    status_code=202,
    summary="Create the vendor assessment report of a finished scan",
)
async def create_assessment(
    body: AssessmentCreate, request: Request, db: DbSession, user: AnalystUser
) -> AssessmentOut:
    """Freeze the current findings of the scan into a ``vendor`` report; the worker renders it.

    Poll the assessment until ``status`` is ``ready``, then review it with
    ``POST /reports/{id}/review`` (confirm or override the verdict, conditions with deadlines).
    """
    if body.scan_id is not None:
        scan = await db.get(Scan, body.scan_id)
    else:
        assert body.version_id is not None  # noqa: S101 - the validator guarantees it
        scan = await _latest_finished_scan(db, body.version_id, body.kind)
    if scan is None:
        raise NotFound("No finished scan found to assess", code="scan.not_found")
    if scan.state in report_service.UNFINISHED_SCAN_STATES:
        raise Conflict("The scan has not finished yet", code="report.scan_not_finished")
    application = await _vendor_application(db, scan.application_id)
    if body.template_id is not None:
        template = await report_service.usable_template(db, body.template_id)
    else:
        template = await report_service.get_default_template(db, ReportKind.VENDOR)
    report = await report_service.create_report_row(
        db,
        scan=scan,
        application=application,
        template=template,
        created_by_id=user.id,
        kind=ReportKind.VENDOR,
        vendor_copy=body.vendor_copy,
    )
    await record_audit(
        db,
        user,
        "vendor_assessment.create",
        "report",
        report.id,
        {
            "ref": report.ref,
            "scan_id": str(scan.id),
            "application_id": str(application.id),
            "template": template.name,
        },
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
            "The assessment could not be queued; try again in a moment",
            code="report.enqueue_failed",
        ) from exc
    return (await _enrich(db, [report]))[0]


@router.get(
    "/vendor-assessments/{report_id}",
    response_model=AssessmentDetail,
    summary="A vendor assessment with its delta and the conditions still to set",
)
async def get_assessment(
    report_id: uuid.UUID, db: DbSession, user: AnalystUser
) -> AssessmentDetail:
    report = await _vendor_report(db, report_id)
    base = (await _enrich(db, [report]))[0]
    today = utcnow().date()
    rules = ConditionRules(
        earliest_deadline=today + timedelta(days=1),
        latest_deadline=today + timedelta(days=vendor_service.MAX_DEADLINE_DAYS),
    )
    detail = AssessmentDetail(**base.model_dump(), condition_rules=rules)
    if report.status != "ready" or report.snapshot_artifact_id is None:
        return detail
    try:
        snapshot = await report_service.read_snapshot(db, report)
    except report_service.ReportError as exc:
        log.warning("vendor_snapshot_unreadable", report_id=str(report.id), error=str(exc))
        return detail
    detail.counts = snapshot.summary.counts
    detail.delta = snapshot.summary.delta
    detail.scope = snapshot.vendor_scope
    detail.review = snapshot.review
    detail.condition_candidates = [
        _finding_ref(f)
        for f in snapshot.findings
        if f.severity == vendor_service.CONDITION_SEVERITY
    ]
    detail.missing_conditions = [
        _finding_ref(f)
        for f in vendor_service.findings_without_condition(snapshot.findings, report.conditions)
    ]
    return detail


# --------------------------------------------------------------------------- the vendor copy


async def _vendor_copy(
    db: DbSession, report_id: uuid.UUID
) -> tuple[Report, vendor_service.VendorCopyFiles]:
    report = await _vendor_report(db, report_id)
    try:
        files = await vendor_service.render_vendor_copy(db, report)
    except report_service.ReportError as exc:
        log.error("vendor_copy_failed", report_id=str(report.id), error=str(exc)[:300])
        raise ServiceUnavailable(
            "The vendor copy could not be prepared", code="vendor.copy_failed"
        ) from exc
    return report, files


async def _read_copy(artifact: Any) -> bytes:
    try:
        return await read_bytes(artifact)
    except StorageError as exc:
        raise NotFound(
            "The vendor copy file is missing from storage", code="report.file_missing"
        ) from exc


@router.get(
    "/vendor-assessments/{report_id}/html",
    summary="The reviewed report for the vendor, without internal notes (HTML)",
)
async def vendor_copy_html(
    report_id: uuid.UUID,
    request: Request,
    db: DbSession,
    user: AnalystUser,
    copy: Literal["vendor"],
) -> Response:
    """``?copy=vendor`` is required: the internal version is ``GET /reports/{id}/html``."""
    report, files = await _vendor_copy(db, report_id)
    data = await _read_copy(files.html)
    await record_audit(
        db,
        user,
        "report.vendor_copy_view",
        "report",
        report.id,
        {"ref": report.ref, "format": "html", "copy_sha256": files.sha256},
        request,
    )
    await db.commit()
    return Response(content=data, media_type="text/html; charset=utf-8", headers=dict(HTML_HEADERS))


@router.get(
    "/vendor-assessments/{report_id}/pdf",
    summary="The reviewed report for the vendor, without internal notes (PDF)",
)
async def vendor_copy_pdf(
    report_id: uuid.UUID,
    request: Request,
    db: DbSession,
    user: AnalystUser,
    copy: Literal["vendor"],
) -> Response:
    """The PDF is stamped with the downloader's name and the time, like every report PDF."""
    report, files = await _vendor_copy(db, report_id)
    data = await _read_copy(files.pdf)
    who = user.name or user.email or user.oid
    if user.name and user.email:
        who = f"{user.name} ({user.email})"
    try:
        stamped = await asyncio.to_thread(stamp_pdf, data, who, utcnow())
    except Exception as exc:  # noqa: BLE001 - a damaged stored PDF must not be handed out unstamped
        log.error("report_stamp_failed", report_id=str(report.id), error_type=type(exc).__name__)
        raise ServiceUnavailable(
            "The PDF could not be prepared for download", code="report.stamp_failed"
        ) from exc
    await record_audit(
        db,
        user,
        "report.vendor_copy_download",
        "report",
        report.id,
        {
            "ref": report.ref,
            "format": "pdf",
            "copy_sha256": files.sha256,
            "artifact_sha256": files.pdf.sha256,
        },
        request,
    )
    await db.commit()
    filename = f"{report.ref or report.id}-vendor-copy.pdf"
    headers = {**DOWNLOAD_HEADERS, "Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=stamped, media_type="application/pdf", headers=headers)
