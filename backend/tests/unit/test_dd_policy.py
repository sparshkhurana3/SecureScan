"""Verdict policy: thresholds, policy choice, job settlement, scan evaluation (no database)."""

from __future__ import annotations

import types
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from securescan.db.models.applications import Application
from securescan.db.models.enums import AppType, ImportState, JobState, Verdict
from securescan.db.models.jobs import ScanJob
from securescan.db.models.policies import Policy
from securescan.db.models.scans import Scan
from securescan.domain.policy import (
    BUILTIN_POLICY,
    DEFAULT_THRESHOLDS,
    Thresholds,
    evaluate_scan,
    job_import_status,
    job_settlement,
    parse_thresholds,
    scan_import_status,
    select_policy,
    verdict_for,
)


def counts(**kwargs: int) -> dict[str, int]:
    base = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    base.update(kwargs)
    return base


# --- thresholds ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (counts(), Verdict.PASS),
        (counts(medium=50, low=200, info=999), Verdict.PASS),
        (counts(high=1), Verdict.CONDITIONAL),
        (counts(high=5), Verdict.CONDITIONAL),
        (counts(high=6), Verdict.FAIL),
        (counts(critical=1), Verdict.FAIL),
        (counts(critical=1, high=1), Verdict.FAIL),
        (counts(critical=3, high=40), Verdict.FAIL),
    ],
)
def test_default_policy_thresholds(given: dict[str, int], expected: Verdict) -> None:
    verdict, reasons = verdict_for(given, Thresholds())
    assert verdict == expected
    assert reasons


def test_default_thresholds_are_the_design_rule() -> None:
    assert DEFAULT_THRESHOLDS == {"fail": {"critical": 1, "high": 6}, "conditional": {"high": 1}}
    assert Thresholds().as_dict() == DEFAULT_THRESHOLDS


def test_custom_thresholds_for_a_stricter_classification() -> None:
    strict = Thresholds(fail={"critical": 1, "high": 1}, conditional={"medium": 1})
    assert verdict_for(counts(high=1), strict)[0] == Verdict.FAIL
    assert verdict_for(counts(medium=1), strict)[0] == Verdict.CONDITIONAL
    assert verdict_for(counts(low=9), strict)[0] == Verdict.PASS


def test_reasons_name_the_severity_and_the_limit() -> None:
    _, reasons = verdict_for(counts(high=7, critical=1), Thresholds())
    assert any("critical" in r for r in reasons)
    assert any("high" in r and "6" in r for r in reasons)


def test_invalid_thresholds_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Thresholds(fail={"urgent": 1})
    with pytest.raises(ValidationError):
        Thresholds(fail={"high": 0})
    with pytest.raises(ValidationError):
        parse_thresholds({"fail": {"high": "many"}})


def test_empty_stored_thresholds_mean_the_default_rule() -> None:
    assert parse_thresholds({}) == Thresholds()
    assert parse_thresholds(None) == Thresholds()
    assert parse_thresholds({"fail": {"critical": 2}, "conditional": {}}).fail == {"critical": 2}


# --- settlement ------------------------------------------------------------------------------------------------


def job(tool: str, state: JobState, import_state: ImportState = ImportState.PENDING, **kw: Any) -> ScanJob:
    return ScanJob(id=uuid.uuid4(), scan_id=uuid.uuid4(), tool=tool, state=state, import_state=import_state, **kw)


def test_a_scan_waits_for_running_jobs_and_outstanding_imports() -> None:
    running = job("semgrep", JobState.RUNNING)
    awaiting = job("gitleaks", JobState.COMPLETED, ImportState.PENDING)
    done = job("syft", JobState.COMPLETED, ImportState.IMPORTED)
    s = job_settlement([running, awaiting, done])
    assert not s.settled
    assert sorted(s.waiting) == ["gitleaks", "semgrep"]
    assert s.imported == ["syft"]


def test_failed_jobs_do_not_hold_a_scan_back() -> None:
    s = job_settlement(
        [
            job("semgrep", JobState.COMPLETED, ImportState.IMPORTED),
            job("gitleaks", JobState.FAILED),
            job("grype", JobState.TIMED_OUT),
            job("sonarqube", JobState.CANCELLED),
        ]
    )
    assert s.settled
    assert sorted(s.without_results) == ["gitleaks", "grype", "sonarqube"]


def test_a_dead_letter_keeps_the_scan_pending() -> None:
    s = job_settlement([job("semgrep", JobState.COMPLETED, ImportState.FAILED)])
    assert not s.settled


def test_a_job_whose_output_is_only_stored_does_not_count_as_findings() -> None:
    skipped = job("syft", JobState.COMPLETED, ImportState.IMPORTED, dd_import_stats={"skipped": "no parser"})
    s = job_settlement([skipped, job("semgrep", JobState.COMPLETED, ImportState.IMPORTED)])
    assert s.settled
    assert s.stored_only == ["syft"]
    assert s.imported == ["semgrep"]


def test_partial_jobs_are_listed() -> None:
    s = job_settlement([job("semgrep", JobState.COMPLETED_PARTIAL, ImportState.IMPORTED)])
    assert s.settled
    assert s.partial == ["semgrep"]


def test_job_and_scan_import_status_words() -> None:
    assert job_import_status(job("a", JobState.FAILED)) == "not_applicable"
    assert job_import_status(job("a", JobState.RUNNING)) == "waiting"
    assert job_import_status(job("a", JobState.COMPLETED)) == "pending"
    assert job_import_status(job("a", JobState.COMPLETED, ImportState.FAILED)) == "failed"
    assert job_import_status(job("a", JobState.COMPLETED, ImportState.IMPORTED)) == "imported"
    skipped = job("a", JobState.COMPLETED, ImportState.IMPORTED, dd_import_stats={"skipped": "no parser"})
    assert job_import_status(skipped) == "skipped"
    assert scan_import_status([skipped, job("b", JobState.COMPLETED, ImportState.IMPORTED)]) == "imported"
    assert scan_import_status([job("b", JobState.COMPLETED), job("c", JobState.COMPLETED, ImportState.FAILED)]) == "failed"
    assert scan_import_status([job("b", JobState.COMPLETED)]) == "pending"
    assert scan_import_status([job("b", JobState.RUNNING)]) == "waiting"
    assert scan_import_status([job("b", JobState.FAILED)]) == "not_applicable"


# --- evaluate_scan with a stub session -----------------------------------------------------------------------------------


class Rows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)


class EvalDb:
    """Just enough of AsyncSession for ``evaluate_scan``."""

    def __init__(self, scan: Scan, application: Application, jobs: list[ScanJob], policy: Policy | None = None) -> None:
        self.scan = scan
        self.application = application
        self.jobs = jobs
        self.policy = policy
        self.added: list[Any] = []

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def get(self, model: Any, ident: Any) -> Any:
        if model is Scan:
            return self.scan
        if model is Application:
            return self.application
        return None

    async def scalars(self, stmt: Any) -> Rows:
        return Rows(self.jobs)

    async def scalar(self, stmt: Any) -> Any:
        return self.policy

    async def execute(self, stmt: Any) -> Any:
        return types.SimpleNamespace(all=lambda: [])


def make_scan_and_app(classification: str | None = None) -> tuple[Scan, Application]:
    app_id, scan_id = uuid.uuid4(), uuid.uuid4()
    application = Application(
        id=app_id,
        name="js-planted",
        type=AppType.INTERNAL,
        data_classification=classification,
        cached_counts={},
        last_scan_at=None,
        last_scan_id=None,
    )
    scan = Scan(
        id=scan_id,
        application_id=app_id,
        version_id=uuid.uuid4(),
        verdict=Verdict.PENDING,
        verdict_detail={},
        counts={},
        finished_at=datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc),
    )
    return scan, application


async def test_evaluate_scan_is_pending_until_every_job_is_imported() -> None:
    scan, application = make_scan_and_app()
    jobs = [
        job("semgrep", JobState.COMPLETED, ImportState.IMPORTED, counts=counts(high=1)),
        job("gitleaks", JobState.COMPLETED, ImportState.PENDING),
    ]
    db = EvalDb(scan, application, jobs)
    assert await evaluate_scan(db, scan.id) == "pending"  # type: ignore[arg-type]
    assert scan.verdict == Verdict.PENDING
    assert scan.verdict_detail["waiting_tools"] == ["gitleaks"]
    assert application.last_scan_id is None


async def test_evaluate_scan_stores_verdict_counts_and_rolls_up() -> None:
    scan, application = make_scan_and_app()
    jobs = [
        job("semgrep", JobState.COMPLETED, ImportState.IMPORTED, counts=counts(high=3, medium=2)),
        job("gitleaks", JobState.COMPLETED, ImportState.IMPORTED, counts=counts(high=3)),
        job("grype", JobState.FAILED),
    ]
    db = EvalDb(scan, application, jobs)
    verdict = await evaluate_scan(db, scan.id)  # type: ignore[arg-type]
    assert verdict == "fail"  # 6 High in total
    assert scan.verdict == Verdict.FAIL
    assert scan.counts["high"] == 6
    assert scan.counts["medium"] == 2
    assert scan.counts["total"] == 8
    assert scan.verdict_detail["incomplete_tools"] == ["grype"]
    assert scan.verdict_detail["policy"]["source"] == "builtin"
    assert application.last_scan_id == scan.id
    assert application.last_verdict == Verdict.FAIL


async def test_evaluate_scan_pass_and_conditional() -> None:
    scan, application = make_scan_and_app()
    db = EvalDb(scan, application, [job("semgrep", JobState.COMPLETED, ImportState.IMPORTED, counts=counts(low=9))])
    assert await evaluate_scan(db, scan.id) == "pass"  # type: ignore[arg-type]
    db = EvalDb(scan, application, [job("semgrep", JobState.COMPLETED, ImportState.IMPORTED, counts=counts(high=2))])
    assert await evaluate_scan(db, scan.id) == "conditional"  # type: ignore[arg-type]


async def test_evaluate_scan_with_no_results_stays_pending() -> None:
    scan, application = make_scan_and_app()
    db = EvalDb(scan, application, [job("semgrep", JobState.FAILED)])
    assert await evaluate_scan(db, scan.id) == "pending"  # type: ignore[arg-type]
    assert scan.verdict_detail["reason"] == "no tool produced findings to judge"


async def test_evaluate_scan_uses_the_chosen_policy() -> None:
    scan, application = make_scan_and_app("restricted")
    policy = Policy(
        id=uuid.uuid4(),
        name="Restricted data",
        data_classification="restricted",
        is_default=False,
        active=True,
        version=3,
        thresholds={"fail": {"high": 1}, "conditional": {}},
    )
    db = EvalDb(scan, application, [job("semgrep", JobState.COMPLETED, ImportState.IMPORTED, counts=counts(high=1))], policy)
    assert await evaluate_scan(db, scan.id) == "fail"  # type: ignore[arg-type]
    assert scan.policy_id == policy.id
    assert scan.verdict_detail["policy"]["version"] == 3
    assert scan.verdict_detail["policy"]["source"] == "application"  # first candidate that matched in the stub


async def test_select_policy_falls_back_to_the_builtin_one() -> None:
    scan, application = make_scan_and_app()
    db = EvalDb(scan, application, [], None)
    assert await select_policy(db, application) is BUILTIN_POLICY  # type: ignore[arg-type]


async def test_an_invalid_stored_policy_is_skipped() -> None:
    scan, application = make_scan_and_app()
    broken = Policy(
        id=uuid.uuid4(), name="broken", is_default=True, active=True, version=1,
        thresholds={"fail": {"nonsense": 1}},
    )
    db = EvalDb(scan, application, [], broken)
    assert await select_policy(db, application) is BUILTIN_POLICY  # type: ignore[arg-type]
