"""Verdict policy: pass, conditional or fail from the open findings of a scan.

Default policy (design, "Default verdict policy"): Fail on any open Critical or more than 5 open
High; Conditional with 1 to 5 High; Pass otherwise. A policy stores its rule as thresholds::

    {"fail": {"critical": 1, "high": 6}, "conditional": {"high": 1}}

meaning *fail* when any listed severity reaches its number, else *conditional* when any severity in the
second map does, else *pass*. Policies are chosen by application, then by the application's data
classification, then the default policy, then the built-in default. The verdict stays ``pending``
until every job of the scan has been imported into DefectDojo (a scan never fails because DefectDojo
is down).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.db.models.applications import Application
from securescan.db.models.enums import (
    ImportState,
    JobState,
    Verdict,
)
from securescan.db.models.jobs import ScanJob
from securescan.db.models.policies import Policy
from securescan.db.models.scans import Scan
from securescan.domain.history import rollup_application
from securescan.integrations.defectdojo.findings import SEVERITY_NAMES, add_counts, empty_counts
from securescan.logging import get_logger
from securescan.util import utcnow

log = get_logger(__name__)

DEFAULT_THRESHOLDS: dict[str, dict[str, int]] = {
    "fail": {"critical": 1, "high": 6},
    "conditional": {"high": 1},
}

# Jobs in these states never produce a report to import.
_NO_RESULT_STATES = frozenset({JobState.FAILED, JobState.CANCELLED, JobState.TIMED_OUT})
_RESULT_STATES = frozenset({JobState.COMPLETED, JobState.COMPLETED_PARTIAL})


class Thresholds(BaseModel):
    """The rule of a policy. Severities are ``critical`` ... ``info``; numbers are at least 1."""

    fail: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_THRESHOLDS["fail"]))
    conditional: dict[str, int] = Field(
        default_factory=lambda: dict(DEFAULT_THRESHOLDS["conditional"])
    )

    @field_validator("fail", "conditional")
    @classmethod
    def _valid_levels(cls, value: dict[str, int]) -> dict[str, int]:
        for severity, number in value.items():
            if severity not in SEVERITY_NAMES:
                raise ValueError(f"unknown severity {severity!r}; use one of {', '.join(SEVERITY_NAMES)}")
            if number < 1:
                raise ValueError("a threshold must be at least 1")
        return value

    def as_dict(self) -> dict[str, dict[str, int]]:
        return {"fail": dict(self.fail), "conditional": dict(self.conditional)}


def parse_thresholds(raw: Mapping[str, Any] | None) -> Thresholds:
    """Thresholds from a stored JSON value; an empty or missing value means the default rule."""
    if not raw:
        return Thresholds()
    return Thresholds.model_validate(raw)


def verdict_for(counts: Mapping[str, Any], thresholds: Thresholds) -> tuple[Verdict, list[str]]:
    """The verdict for open counts by severity, and the reasons in words."""
    reasons: list[str] = []
    for severity in SEVERITY_NAMES:
        limit = thresholds.fail.get(severity)
        number = int(counts.get(severity, 0) or 0)
        if limit is not None and number >= limit:
            reasons.append(f"{number} open {severity} (fails from {limit})")
    if reasons:
        return Verdict.FAIL, reasons
    for severity in SEVERITY_NAMES:
        limit = thresholds.conditional.get(severity)
        number = int(counts.get(severity, 0) or 0)
        if limit is not None and number >= limit:
            reasons.append(f"{number} open {severity} (conditional from {limit})")
    if reasons:
        return Verdict.CONDITIONAL, reasons
    return Verdict.PASS, ["no open finding reaches a threshold"]


@dataclass(frozen=True)
class JobSettlement:
    """Where the scan's jobs stand, for the verdict."""

    settled: bool
    waiting: list[str]  # tools that are still running or whose import is outstanding
    without_results: list[str]  # failed, cancelled or timed out: nothing to import
    partial: list[str]  # completed_partial: imported, but the tool says coverage is partial
    imported: list[str]  # imported into DefectDojo: their findings count
    stored_only: list[str]  # finished, output kept, nothing imported (an SBOM, a skipped tool)


def job_settlement(jobs: Iterable[ScanJob]) -> JobSettlement:
    """A scan is settled when no job is still running and every job that produced a report has
    been imported. Failed, cancelled and timed-out jobs do not hold a scan back."""
    waiting: list[str] = []
    without_results: list[str] = []
    partial: list[str] = []
    imported: list[str] = []
    stored_only: list[str] = []
    for job in jobs:
        if job.state in _NO_RESULT_STATES:
            without_results.append(job.tool)
        elif job.state in _RESULT_STATES:
            if job.import_state == ImportState.IMPORTED:
                if (job.dd_import_stats or {}).get("skipped"):
                    stored_only.append(job.tool)
                    continue
                imported.append(job.tool)
                if job.state == JobState.COMPLETED_PARTIAL:
                    partial.append(job.tool)
            else:
                waiting.append(job.tool)
        else:
            waiting.append(job.tool)
    return JobSettlement(
        settled=not waiting,
        waiting=waiting,
        without_results=without_results,
        partial=partial,
        imported=imported,
        stored_only=stored_only,
    )


def job_import_status(job: ScanJob) -> str:
    """One word for the portal: ``waiting`` (job still running), ``pending`` (import outstanding),
    ``imported``, ``skipped`` (output stored, not imported), ``failed`` (dead letter) or
    ``not_applicable`` (the job produced no report)."""
    if job.state in _NO_RESULT_STATES:
        return "not_applicable"
    if job.state not in _RESULT_STATES:
        return "waiting"
    if job.import_state == ImportState.IMPORTED:
        return "skipped" if (job.dd_import_stats or {}).get("skipped") else "imported"
    if job.import_state == ImportState.FAILED:
        return "failed"
    return "pending"


def scan_import_status(jobs: Iterable[ScanJob]) -> str:
    """The scan's import state: the worst of its jobs (failed, pending, waiting), else ``imported``,
    else ``not_applicable`` when no job has anything to import."""
    statuses = {job_import_status(j) for j in jobs}
    for worst in ("failed", "pending", "waiting"):
        if worst in statuses:
            return worst
    if statuses & {"imported", "skipped"}:
        return "imported"
    return "not_applicable"


@dataclass(frozen=True)
class ChosenPolicy:
    policy_id: uuid.UUID | None
    name: str
    version: int
    source: str  # application | classification | default | builtin
    thresholds: Thresholds


BUILTIN_POLICY = ChosenPolicy(None, "Built-in default", 1, "builtin", Thresholds())


async def select_policy(session: AsyncSession, application: Application) -> ChosenPolicy:
    """Most specific active policy: this application, its data classification, the default one."""
    candidates: list[tuple[str, Any]] = [
        (
            "application",
            select(Policy)
            .where(Policy.active.is_(True), Policy.application_id == application.id)
            .order_by(Policy.created_at.desc())
            .limit(1),
        )
    ]
    if application.data_classification:
        candidates.append(
            (
                "classification",
                select(Policy)
                .where(
                    Policy.active.is_(True),
                    Policy.application_id.is_(None),
                    Policy.data_classification == application.data_classification,
                )
                .order_by(Policy.created_at.desc())
                .limit(1),
            )
        )
    candidates.append(
        (
            "default",
            select(Policy)
            .where(
                Policy.active.is_(True),
                Policy.is_default.is_(True),
                Policy.application_id.is_(None),
            )
            .order_by(Policy.created_at.desc())
            .limit(1),
        )
    )
    for source, stmt in candidates:
        policy = await session.scalar(stmt)
        if policy is not None:
            try:
                thresholds = parse_thresholds(policy.thresholds)
            except ValueError as exc:
                log.warning("policy_invalid", policy_id=str(policy.id), error=str(exc)[:200])
                continue
            return ChosenPolicy(policy.id, policy.name, policy.version, source, thresholds)
    return BUILTIN_POLICY


async def evaluate_scan(session: AsyncSession, scan_id: uuid.UUID) -> str:
    """Compute and store ``Scan.verdict`` (and counts, policy, detail). Returns ``"pass"``,
    ``"conditional"``, ``"fail"`` or ``"pending"``.

    ``pending`` while a job is unfinished or its import is outstanding, and when no tool produced
    results at all. Does not commit.
    """
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise LookupError(f"scan {scan_id} does not exist")
    jobs = list((await session.scalars(select(ScanJob).where(ScanJob.scan_id == scan_id))).all())
    settlement = job_settlement(jobs)
    counts = add_counts(*[j.counts or empty_counts() for j in jobs if j.tool in settlement.imported])
    scan.counts = counts
    detail: dict[str, Any] = {
        "evaluated_at": utcnow().isoformat(),
        "counts": counts,
        "waiting_tools": settlement.waiting,
        "incomplete_tools": settlement.without_results,
        "partial_tools": settlement.partial,
        "stored_only_tools": settlement.stored_only,
    }
    if not settlement.settled or not settlement.imported:
        detail["reason"] = (
            "waiting for " + ", ".join(settlement.waiting)
            if settlement.waiting
            else "no tool produced findings to judge"
        )
        scan.verdict = Verdict.PENDING
        scan.verdict_detail = detail
        return Verdict.PENDING.value

    application = await session.get(Application, scan.application_id)
    chosen = await select_policy(session, application) if application else BUILTIN_POLICY
    verdict, reasons = verdict_for(counts, chosen.thresholds)
    detail["reasons"] = reasons
    detail["thresholds"] = chosen.thresholds.as_dict()
    detail["policy"] = {
        "id": str(chosen.policy_id) if chosen.policy_id else None,
        "name": chosen.name,
        "version": chosen.version,
        "source": chosen.source,
    }
    scan.verdict = verdict
    scan.verdict_detail = detail
    scan.policy_id = chosen.policy_id
    if application is not None:
        await rollup_application(session, application, scan)
    return verdict.value
