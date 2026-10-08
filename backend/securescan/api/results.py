"""Results of a scan and of an application: counts, import state, verdict, links into DefectDojo."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import select

from securescan.auth.roles import AnalystUser
from securescan.db.models.applications import Application
from securescan.db.models.enums import AppType, ScanState, Verdict
from securescan.db.models.jobs import ScanJob
from securescan.db.models.reports import Report
from securescan.db.models.scans import Scan
from securescan.db.models.versions import ApplicationVersion
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain.history import application_open_counts
from securescan.domain.policy import job_import_status, scan_import_status
from securescan.integrations.defectdojo.findings import empty_counts
from securescan.integrations.defectdojo.mapping import (
    engagement_link,
    link_to_test,
    product_link,
)

router = APIRouter(tags=["results"])


class JobResultOut(BaseModel):
    job_id: uuid.UUID
    tool: str
    state: str
    import_status: str
    counts: dict[str, Any]
    dd_test_id: int | None
    defectdojo_url: str | None
    coverage_note: str | None
    outcome_reason: str | None
    imported_at: datetime | None


class ScanResultsOut(BaseModel):
    scan_id: uuid.UUID
    application_id: uuid.UUID
    application_name: str
    version_id: uuid.UUID
    version_label: str
    state: ScanState
    verdict: Verdict
    verdict_detail: dict[str, Any]
    counts: dict[str, Any]
    import_state: str
    jobs: list[JobResultOut]
    report_id: uuid.UUID | None
    defectdojo_engagement_url: str | None
    defectdojo_product_url: str | None


class VersionResultOut(BaseModel):
    version_id: uuid.UUID
    label: str
    latest_scan_id: uuid.UUID | None
    latest_scan_at: datetime | None
    latest_verdict: Verdict | None
    scan_counts: dict[str, Any]
    open_counts: dict[str, Any]
    defectdojo_engagement_url: str | None


class ApplicationResultsOut(BaseModel):
    application_id: uuid.UUID
    name: str
    type: AppType
    cached_counts: dict[str, Any]
    cached_counts_at: datetime | None
    last_scan_id: uuid.UUID | None
    last_scan_at: datetime | None
    last_verdict: Verdict | None
    defectdojo_product_url: str | None
    versions: list[VersionResultOut]


def job_result(job: ScanJob) -> JobResultOut:
    return JobResultOut(
        job_id=job.id,
        tool=job.tool,
        state=job.state.value,
        import_status=job_import_status(job),
        counts=job.counts or {},
        dd_test_id=job.dd_test_id,
        defectdojo_url=link_to_test(job.dd_test_id),
        coverage_note=job.coverage_note,
        outcome_reason=job.outcome_reason,
        imported_at=job.dd_imported_at,
    )


@router.get(
    "/scans/{scan_id}/results",
    response_model=ScanResultsOut,
    summary="Counts, import state, verdict and DefectDojo links of a scan",
)
async def scan_results(scan_id: uuid.UUID, db: DbSession, user: AnalystUser) -> ScanResultsOut:
    scan = await get_or_404(db, Scan, scan_id, "Scan")
    application = await get_or_404(db, Application, scan.application_id, "Application")
    version = await get_or_404(db, ApplicationVersion, scan.version_id, "Version")
    jobs = list(
        (
            await db.scalars(
                select(ScanJob).where(ScanJob.scan_id == scan.id).order_by(ScanJob.created_at, ScanJob.id)
            )
        ).all()
    )
    report_id = await db.scalar(
        select(Report.id).where(Report.scan_id == scan.id).order_by(Report.created_at.desc()).limit(1)
    )
    return ScanResultsOut(
        scan_id=scan.id,
        application_id=application.id,
        application_name=application.name,
        version_id=version.id,
        version_label=version.label,
        state=scan.state,
        verdict=scan.verdict,
        verdict_detail=scan.verdict_detail or {},
        counts=scan.counts or empty_counts(),
        import_state=scan_import_status(jobs),
        jobs=[job_result(j) for j in jobs],
        report_id=report_id,
        defectdojo_engagement_url=engagement_link(version.dd_engagement_id),
        defectdojo_product_url=product_link(application.dd_product_id),
    )


@router.get(
    "/applications/{application_id}/results",
    response_model=ApplicationResultsOut,
    summary="Latest results of an application, per version",
)
async def application_results(
    application_id: uuid.UUID, db: DbSession, user: AnalystUser
) -> ApplicationResultsOut:
    application = await get_or_404(db, Application, application_id, "Application")
    versions = list(
        (
            await db.scalars(
                select(ApplicationVersion)
                .where(
                    ApplicationVersion.application_id == application.id,
                    ApplicationVersion.archived_at.is_(None),
                )
                .order_by(ApplicationVersion.created_at.desc(), ApplicationVersion.id)
                .limit(50)
            )
        ).all()
    )
    latest_rows = (
        await db.scalars(
            select(Scan)
            .where(Scan.application_id == application.id)
            .distinct(Scan.version_id)
            .order_by(Scan.version_id, Scan.created_at.desc())
        )
    ).all()
    latest = {s.version_id: s for s in latest_rows}
    out: list[VersionResultOut] = []
    for version in versions:
        scan = latest.get(version.id)
        out.append(
            VersionResultOut(
                version_id=version.id,
                label=version.label,
                latest_scan_id=scan.id if scan else None,
                latest_scan_at=(scan.finished_at or scan.created_at) if scan else None,
                latest_verdict=scan.verdict if scan else None,
                scan_counts=(scan.counts if scan else None) or empty_counts(),
                open_counts=await application_open_counts(db, application.id, version.id),
                defectdojo_engagement_url=engagement_link(version.dd_engagement_id),
            )
        )
    return ApplicationResultsOut(
        application_id=application.id,
        name=application.name,
        type=application.type,
        cached_counts=application.cached_counts or empty_counts(),
        cached_counts_at=application.cached_counts_at,
        last_scan_id=application.last_scan_id,
        last_scan_at=application.last_scan_at,
        last_verdict=application.last_verdict,
        defectdojo_product_url=product_link(application.dd_product_id),
        versions=out,
    )
