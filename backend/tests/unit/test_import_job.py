"""Import outbox: backoff schedule, retry decisions, the reimport call built for a job, enqueue."""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from securescan.db.models.applications import Application
from securescan.db.models.enums import AppType, ImportState, JobState, OutboxState
from securescan.db.models.jobs import ScanJob
from securescan.db.models.outbox import SyncOutbox
from securescan.db.models.scans import Scan
from securescan.db.models.versions import ApplicationVersion
from securescan.integrations.defectdojo.client import DefectDojoRejected, DefectDojoUnavailable
from securescan.jobs import import_job as ij
from securescan.util import new_id

UTC = timezone.utc
T0 = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)


# --- backoff ------------------------------------------------------------------------------------------------


def test_backoff_schedule_is_1_5_15_60_minutes_then_every_six_hours() -> None:
    minutes = [ij.backoff_delay(n) for n in range(1, 8)]
    assert minutes[:4] == [timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=15), timedelta(minutes=60)]
    assert minutes[4:] == [timedelta(hours=6)] * 3
    assert ij.backoff_delay(0) == timedelta(0)


def test_retry_is_scheduled_after_the_backoff() -> None:
    due = ij.decide_retry(failures=2, created_at=T0, now=T0 + timedelta(minutes=3))
    assert due == T0 + timedelta(minutes=8)


def test_a_row_older_than_seven_days_becomes_a_dead_letter() -> None:
    assert ij.decide_retry(failures=9, created_at=T0, now=T0 + timedelta(days=6, hours=12)) is not None
    assert ij.decide_retry(failures=9, created_at=T0, now=T0 + timedelta(days=6, hours=20)) is None
    assert ij.decide_retry(failures=30, created_at=T0, now=T0 + timedelta(days=8)) is None


def test_total_schedule_over_seven_days_is_31_attempts() -> None:
    now = T0
    attempts = 0
    failures = 1
    while True:
        due = ij.decide_retry(failures=failures, created_at=T0, now=now)
        if due is None:
            break
        now = due
        attempts += 1
        failures += 1
    # 1 + 5 + 15 + 60 minutes (4 attempts), then one every 6 hours while the row is under 7 days old (27)
    assert attempts == 31


def test_rejected_requests_get_three_attempts() -> None:
    assert ij.decide_retry(failures=1, created_at=T0, now=T0, rejected=True) is not None
    assert ij.decide_retry(failures=2, created_at=T0, now=T0, rejected=True) is not None
    assert ij.decide_retry(failures=3, created_at=T0, now=T0, rejected=True) is None


def test_imports_into_one_test_share_a_lock() -> None:
    version = uuid.uuid4()
    assert ij.import_lock(version, "semgrep") == f"dd-import:{version}:semgrep"
    assert ij.import_lock(version, "semgrep") != ij.import_lock(version, "gitleaks")


# --- the reimport call for a job -------------------------------------------------------------------------------------


def make_objects(app_type: AppType = AppType.INTERNAL) -> tuple[Application, ApplicationVersion, Scan, ScanJob]:
    application = Application(id=new_id(), name="js-planted", type=app_type)
    version = ApplicationVersion(
        id=new_id(), application_id=application.id, label="main", label_kind="branch", commit_sha="v-sha"
    )
    scan = Scan(id=new_id(), application_id=application.id, version_id=version.id, commit_sha="s-sha")
    job = ScanJob(id=new_id(), scan_id=scan.id, tool="semgrep")
    return application, version, scan, job


def test_reimport_request_names_follow_the_mapping(tmp_path: Path) -> None:
    application, version, scan, job = make_objects()
    path = tmp_path / "semgrep.json"
    path.write_text("{}")
    request = ij.build_reimport_request(
        application=application,
        version=version,
        scan=scan,
        job=job,
        scan_type="Semgrep JSON Report",
        file_path=path,
        file_name="semgrep.json",
        scan_date=date(2026, 10, 7),
    )
    fields = request.form_fields()
    assert fields["product_type_name"] == "Internal Applications"
    assert fields["product_name"] == "js-planted"
    assert fields["engagement_name"] == "main"
    assert fields["test_title"] == "semgrep:main"
    assert fields["scan_type"] == "Semgrep JSON Report"
    assert fields["version"] == "main"
    assert fields["commit_hash"] == "s-sha"  # the scan's commit wins over the version's
    assert fields["branch_tag"] == "main"
    assert fields["tags"] == [f"securescan-scan:{scan.id}", "tool:semgrep"]
    assert fields["scan_date"] == "2026-10-07"
    assert request.content_type == "application/json"
    # the parameters of plan M4 task 3
    assert fields["auto_create_context"] == "true"
    assert fields["deduplication_on_engagement"] == "true"
    assert fields["close_old_findings"] == "true"
    assert fields["deduplication_execution_mode"] == "async_wait"
    assert fields["minimum_severity"] == "Info"


def test_vendor_applications_go_to_the_vendor_product_type(tmp_path: Path) -> None:
    application, version, scan, job = make_objects(AppType.VENDOR)
    version.label_kind = "upload"
    version.label = "upload-2026-10"
    scan.commit_sha = None
    request = ij.build_reimport_request(
        application=application,
        version=version,
        scan=scan,
        job=job,
        scan_type="Gitleaks Scan",
        file_path=tmp_path / "gitleaks.json",
        file_name="gitleaks.json",
        scan_date=date(2026, 10, 7),
    )
    fields = request.form_fields()
    assert fields["product_type_name"] == "Vendor Applications"
    assert fields["commit_hash"] == "v-sha"  # falls back to the version's commit
    assert "branch_tag" not in fields  # an upload is not a branch or tag
    assert fields["test_title"] == "semgrep:upload-2026-10"


# --- failure recording ---------------------------------------------------------------------------------------------------


class AddOnly:
    def __init__(self) -> None:
        self.added: list[Any] = []

    def add(self, obj: Any) -> None:
        self.added.append(obj)


def outbox_row(attempts: int = 0, age: timedelta = timedelta(0)) -> SyncOutbox:
    return SyncOutbox(
        id=new_id(),
        job_id=new_id(),
        state=OutboxState.PROCESSING,
        attempts=attempts,
        payload={},
        created_at=datetime.now(UTC) - age,
    )


async def test_a_failure_schedules_the_next_attempt() -> None:
    db = AddOnly()
    row = outbox_row()
    job = ScanJob(id=row.job_id, scan_id=new_id(), tool="semgrep", import_state=ImportState.PENDING)
    outcome = await ij._record_failure(
        db,  # type: ignore[arg-type]
        row,
        job,
        DefectDojoUnavailable("DefectDojo did not answer"),
        rejected=False,
    )
    assert outcome == "retry"
    assert row.state == OutboxState.PENDING
    assert row.attempts == 1
    assert "did not answer" in (row.last_error or "")
    assert timedelta(seconds=30) < row.next_attempt_at - datetime.now(UTC) <= timedelta(minutes=1, seconds=5)
    assert job.import_state == ImportState.PENDING
    assert db.added == []  # nothing audited for a plain retry


async def test_the_last_error_never_holds_a_token() -> None:
    db = AddOnly()
    row = outbox_row()
    token = "0123456789abcdef0123456789abcdef01234567"  # noqa: S105
    await ij._record_failure(
        db,  # type: ignore[arg-type]
        row,
        None,
        DefectDojoRejected(f"refused: Token {token}"),
        rejected=True,
    )
    assert token not in (row.last_error or "")


async def test_the_third_rejection_is_a_dead_letter_and_fails_the_job() -> None:
    db = AddOnly()
    row = outbox_row(attempts=2)
    job = ScanJob(id=row.job_id, scan_id=new_id(), tool="semgrep", import_state=ImportState.PENDING)
    outcome = await ij._record_failure(
        db,  # type: ignore[arg-type]
        row,
        job,
        DefectDojoRejected("HTTP 400"),
        rejected=True,
    )
    assert outcome == "dead_letter"
    assert row.state == OutboxState.DEAD_LETTER
    assert job.import_state == ImportState.FAILED
    assert [e.action for e in db.added] == ["import.dead_letter"]


async def test_an_old_row_dies_even_without_rejection() -> None:
    db = AddOnly()
    row = outbox_row(attempts=12, age=timedelta(days=8))
    outcome = await ij._record_failure(
        db,  # type: ignore[arg-type]
        row,
        None,
        DefectDojoUnavailable("down"),
        rejected=False,
    )
    assert outcome == "dead_letter"


# --- enqueue_import ----------------------------------------------------------------------------------------------------------


class EnqueueDb:
    def __init__(self, job: ScanJob, scan: Scan, existing: SyncOutbox | None = None) -> None:
        self.job = job
        self.scan = scan
        self.existing = existing
        self.added: list[Any] = []
        self.events: list[str] = []

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def get(self, model: Any, ident: Any) -> Any:
        if model is ScanJob:
            return self.job
        if model is Scan:
            return self.scan
        return None

    async def scalar(self, stmt: Any) -> Any:
        return self.existing

    async def flush(self) -> None:
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                obj.id = new_id()

    async def commit(self) -> None:
        self.events.append("commit")


@pytest.fixture
def deferred(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def fake_defer(task: Any, **kwargs: Any) -> int:
        calls.append({"task": task, **kwargs})
        return 1

    monkeypatch.setattr(ij, "defer", fake_defer)
    return calls


async def test_enqueue_import_writes_the_outbox_row_commits_then_defers(
    monkeypatch: pytest.MonkeyPatch, deferred: list[dict[str, Any]]
) -> None:
    _, version, scan, job = make_objects()
    job.state = JobState.COMPLETED
    scan.version_id = version.id
    db = EnqueueDb(job, scan)
    monkeypatch.setattr(ij, "import_applicability", lambda j: (True, ""))

    async def fake_defer_recording(task: Any, **kwargs: Any) -> int:
        db.events.append("defer")
        deferred.append({"task": task, **kwargs})
        return 1

    monkeypatch.setattr(ij, "defer", fake_defer_recording)
    outbox_id = await ij.enqueue_import(db, job.id)  # type: ignore[arg-type]
    rows = [o for o in db.added if isinstance(o, SyncOutbox)]
    assert len(rows) == 1
    assert rows[0].job_id == job.id
    assert rows[0].state == OutboxState.PENDING
    assert outbox_id == rows[0].id
    assert job.import_state == ImportState.PENDING
    assert db.events == ["commit", "defer"]  # state first, queue second
    call = deferred[-1]
    assert call["task"] is ij.import_job
    assert call["outbox_id"] == str(outbox_id)
    assert call["queueing_lock"] == f"import:{outbox_id}"
    assert call["lock"] == ij.import_lock(scan.version_id, "semgrep")


async def test_enqueue_import_reuses_an_open_outbox_row(
    monkeypatch: pytest.MonkeyPatch, deferred: list[dict[str, Any]]
) -> None:
    _, _, scan, job = make_objects()
    job.state = JobState.COMPLETED
    existing = SyncOutbox(id=new_id(), job_id=job.id, state=OutboxState.PENDING)
    db = EnqueueDb(job, scan, existing)
    monkeypatch.setattr(ij, "import_applicability", lambda j: (True, ""))
    outbox_id = await ij.enqueue_import(db, job.id)  # type: ignore[arg-type]
    assert outbox_id == existing.id
    assert not [o for o in db.added if isinstance(o, SyncOutbox)]


async def test_a_job_without_a_parser_is_settled_at_once(
    monkeypatch: pytest.MonkeyPatch, deferred: list[dict[str, Any]]
) -> None:
    _, _, scan, job = make_objects()
    job.tool = "syft"
    job.state = JobState.COMPLETED
    db = EnqueueDb(job, scan)
    reports: list[uuid.UUID] = []

    async def fake_finalize(session: Any, scan_id: uuid.UUID) -> bool:
        return True

    async def fake_report(scan_id: uuid.UUID) -> None:
        reports.append(scan_id)

    monkeypatch.setattr(ij, "import_applicability", lambda j: (False, "syft has no DefectDojo parser"))
    monkeypatch.setattr(ij, "finalize_scan_if_ready", fake_finalize)
    monkeypatch.setattr(ij, "enqueue_report", fake_report)
    assert await ij.enqueue_import(db, job.id) is None  # type: ignore[arg-type]
    assert job.import_state == ImportState.IMPORTED
    assert job.dd_import_stats == {"skipped": "syft has no DefectDojo parser"}
    assert deferred == []  # no import task
    assert reports == [job.scan_id]
    assert db.events == ["commit"]


async def test_enqueue_import_refuses_a_job_that_is_still_running(deferred: list[dict[str, Any]]) -> None:
    _, _, scan, job = make_objects()
    job.state = JobState.RUNNING
    with pytest.raises(ValueError):
        await ij.enqueue_import(EnqueueDb(job, scan), job.id)  # type: ignore[arg-type]
    assert deferred == []


def test_a_failed_job_is_not_applicable() -> None:
    job = ScanJob(id=new_id(), scan_id=new_id(), tool="semgrep", state=JobState.FAILED)
    applicable, reason = ij.import_applicability(job)
    assert not applicable
    assert "failed" in reason


def test_report_task_name_is_the_one_m5_registers() -> None:
    assert ij.REPORT_TASK_NAME == "securescan.jobs.report_job.build_report"
    assert ij.IMPORT_TASK_NAME == "import_job"
