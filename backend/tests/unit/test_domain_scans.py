"""Scan creation rules, roll-up, locks, idempotency, cancel, and the after-commit queueing hook."""

from __future__ import annotations

import asyncio
import types
import uuid
from typing import Any

import pytest
from sqlalchemy.orm import Session

from securescan.api.problems import Conflict, UnprocessableEntity
from securescan.db.models.enums import (
    JobState,
    ScanKind,
    ScanState,
    ScanTrigger,
    TargetEnvironment,
    TargetKind,
)
from securescan.db.models.jobs import ScanJob
from securescan.db.models.scans import Scan
from securescan.domain import scans as scans_module
from securescan.domain.scans import (
    ScanCheckContext,
    check_idempotency_key,
    check_scan_allowed,
    create_scan,
    create_scan_result,
    finalize_scan,
    job_lock_name,
    job_queueing_lock,
    register_scan_check,
    request_cancel,
    request_fingerprint,
    resolve_source_reference,
    rollup_scan_state,
)
from securescan.runner.profiles import ProfileDoc
from securescan.util import new_id, utcnow
from tests.unit.conftest import FakeScalars, FakeSession

FULL_SHA = "0123456789abcdef0123456789abcdef01234567"
S, J = ScanState, JobState


# --------------------------------------------------------------------------- locks
def test_lock_name_is_tool_and_slot() -> None:
    assert job_lock_name("semgrep", uuid.UUID(int=5), 3) == "tool:semgrep:2"
    assert job_lock_name("semgrep", uuid.UUID(int=6), 3) == "tool:semgrep:0"
    assert job_lock_name("gitleaks", uuid.UUID(int=12345), 1) == "tool:gitleaks:0"
    assert job_lock_name("anything", uuid.UUID(int=12345), 0) == "tool:anything:0"  # never divides by zero
    assert job_lock_name("zap", uuid.UUID(int=7), 4, fixed_lock="dast") == "dast"


def test_slots_never_exceed_the_tool_cap() -> None:
    for cap in (1, 2, 3, 5):
        locks = {job_lock_name("t", new_id(), cap) for _ in range(300)}
        assert len(locks) <= cap
        assert all(lock.startswith("tool:t:") for lock in locks)
    assert {job_lock_name("t", new_id(), 1) for _ in range(50)} == {"tool:t:0"}  # max_parallel 1 = one at a time


def test_queueing_lock_collapses_per_application_version_target_tool_and_ref() -> None:
    app, ver, tgt = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    a = job_queueing_lock(app, ver, tgt, "semgrep", "main")
    assert a == job_queueing_lock(app, ver, tgt, "semgrep", "main")
    assert a != job_queueing_lock(app, ver, tgt, "gitleaks", "main")
    assert a != job_queueing_lock(app, ver, tgt, "semgrep", "dev")
    assert a != job_queueing_lock(app, uuid.uuid4(), tgt, "semgrep", "main")
    assert a != job_queueing_lock(app, ver, uuid.uuid4(), "semgrep", "main")
    assert "-" in job_queueing_lock(app, ver, None, "semgrep", None)


def test_plan_deferrals_use_catalogue_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.runner.catalogue import clear_catalogue_cache
    from tests.unit.runner_helpers import REPO_SCANNERS

    monkeypatch.setenv("SECURESCAN_SCANNERS_DIR", str(REPO_SCANNERS))
    from securescan.config import get_settings

    get_settings.cache_clear()
    clear_catalogue_cache()
    scan = types.SimpleNamespace(
        id=uuid.uuid4(), version_id=uuid.uuid4(), target_id=uuid.uuid4(), commit_sha=None, source_ref="main"
    )
    jobs = [types.SimpleNamespace(id=new_id(), tool=tool) for tool in ("semgrep", "gitleaks", "semgrep")]
    plans = scans_module.plan_deferrals(scan, jobs, uuid.uuid4())  # type: ignore[arg-type]
    assert [p.tool for p in plans] == ["semgrep", "gitleaks", "semgrep"]
    for plan in plans:
        assert plan.lock == "scanner"  # every scan tool shares one lock: one scanner container at a time
        assert plan.queueing_lock.startswith("scan:")
    assert plans[0].queueing_lock == plans[2].queueing_lock  # the same tool collapses
    assert plans[0].queueing_lock != plans[1].queueing_lock
    clear_catalogue_cache()


# --------------------------------------------------------------------------- roll-up
@pytest.mark.parametrize(
    ("states", "cancel", "expected"),
    [
        ([], False, S.QUEUED),
        ([J.QUEUED, J.QUEUED], False, S.QUEUED),
        ([J.PREPARING, J.QUEUED], False, S.RUNNING),
        ([J.RUNNING, J.COMPLETED], False, S.RUNNING),
        ([J.COMPLETED, J.QUEUED], False, S.RUNNING),
        ([J.COMPLETED, J.COMPLETED], False, S.COMPLETED),
        ([J.COMPLETED, J.COMPLETED_PARTIAL], False, S.COMPLETED_PARTIAL),
        ([J.COMPLETED, J.FAILED], False, S.COMPLETED_PARTIAL),
        ([J.COMPLETED, J.TIMED_OUT], False, S.COMPLETED_PARTIAL),
        ([J.COMPLETED_PARTIAL, J.FAILED], False, S.COMPLETED_PARTIAL),
        ([J.FAILED, J.FAILED], False, S.FAILED),
        ([J.FAILED, J.TIMED_OUT], False, S.FAILED),
        ([J.FAILED, J.CANCELLED], False, S.FAILED),
        ([J.CANCELLED, J.CANCELLED], False, S.CANCELLED),
        ([J.COMPLETED, J.CANCELLED], True, S.CANCELLED),
        ([J.COMPLETED], True, S.CANCELLED),
        ([J.RUNNING], True, S.RUNNING),  # cancelling: the scan ends when the container is gone
    ],
)
def test_rollup(states: list[JobState], cancel: bool, expected: ScanState) -> None:
    assert rollup_scan_state(states, cancel) == expected


class ScanSession(FakeSession):
    """FakeSession whose ``scalar`` is the scan and whose ``scalars`` are its jobs."""

    def __init__(self, scan: Scan, jobs: list[ScanJob]) -> None:
        super().__init__()
        self.scan = scan
        self.jobs = jobs

    async def scalar(self, stmt: Any) -> Any:
        return self.scan

    async def scalars(self, stmt: Any) -> FakeScalars:
        return FakeScalars(self.jobs)


def new_scan(state: ScanState = ScanState.QUEUED) -> Scan:
    return Scan(
        id=new_id(), state=state, cancel_requested_at=None, started_at=None, finished_at=None,
        coverage_notes=[], error=None, requested_tools=["semgrep", "gitleaks"], options={},
    )  # fmt: skip


def new_job(scan: Scan, tool: str, state: JobState, **fields: Any) -> ScanJob:
    return ScanJob(id=new_id(), scan_id=scan.id, tool=tool, state=state, coverage_note=None, outcome_reason=None, **fields)


async def test_finalize_marks_the_scan_running_then_final() -> None:
    scan = new_scan()
    jobs = [new_job(scan, "semgrep", J.PREPARING), new_job(scan, "gitleaks", J.QUEUED)]
    session = ScanSession(scan, jobs)
    await finalize_scan(session, scan.id)  # type: ignore[arg-type]
    assert scan.state == S.RUNNING and scan.started_at is not None and scan.finished_at is None
    assert session.added == []  # no audit event while it is still running

    jobs[0].state = J.COMPLETED
    jobs[0].coverage_note = "Semgrep rules 0123"
    jobs[1].state = J.FAILED
    jobs[1].outcome_reason = "exit code 1"
    await finalize_scan(session, scan.id)  # type: ignore[arg-type]
    assert scan.state == S.COMPLETED_PARTIAL and scan.finished_at is not None
    assert scan.coverage_notes == [{"tool": "semgrep", "note": "Semgrep rules 0123"}]
    assert scan.error == "gitleaks: exit code 1"
    audit = [row for row in session.added if getattr(row, "action", "") == "scan.finish"]
    assert len(audit) == 1 and audit[0].detail["state"] == "completed_partial"


async def test_finalize_without_a_scan_is_a_noop() -> None:
    class Empty(FakeSession):
        async def scalar(self, stmt: Any) -> Any:
            return None

    assert await finalize_scan(Empty(), uuid.uuid4()) is None  # type: ignore[arg-type]


async def test_cancel_ends_queued_jobs_and_leaves_running_ones() -> None:
    scan = new_scan(S.RUNNING)
    jobs = [new_job(scan, "semgrep", J.RUNNING), new_job(scan, "gitleaks", J.QUEUED)]
    user = types.SimpleNamespace(id=uuid.uuid4())
    session = ScanSession(scan, jobs)
    result, cancelled = await request_cancel(session, scan, user)  # type: ignore[arg-type]
    assert result is scan and cancelled == [jobs[1].id]
    assert jobs[1].state == J.CANCELLED and jobs[1].finished_at is not None
    assert jobs[0].state == J.RUNNING  # the worker stops it
    assert scan.cancel_requested_at is not None and scan.cancelled_by_id == user.id
    assert scan.state == S.RUNNING


async def test_cancel_of_an_entirely_queued_scan_finishes_it() -> None:
    scan = new_scan()
    jobs = [new_job(scan, "semgrep", J.QUEUED), new_job(scan, "gitleaks", J.QUEUED)]
    session = ScanSession(scan, jobs)
    _, cancelled = await request_cancel(session, scan, types.SimpleNamespace(id=uuid.uuid4()))  # type: ignore[arg-type]
    assert len(cancelled) == 2 and scan.state == S.CANCELLED and scan.finished_at is not None


async def test_finished_scans_cannot_be_cancelled() -> None:
    scan = new_scan(S.COMPLETED)
    with pytest.raises(Conflict) as caught:
        await request_cancel(ScanSession(scan, []), scan, None)  # type: ignore[arg-type]
    assert caught.value.code == "scan.already_finished"


# --------------------------------------------------------------------------- rules
def allowed(**kw: Any) -> None:
    values: dict[str, Any] = {
        "profile_kind": "sast",
        "mode": None,
        "tools": ["semgrep"],
        "target_kind": TargetKind.ZIP,
        "environment": None,
        "login_profile_id": None,
    }
    values.update(kw)
    check_scan_allowed(**values)


def refused(code: str, **kw: Any) -> None:
    with pytest.raises(UnprocessableEntity) as caught:
        allowed(**kw)
    assert caught.value.code == code


def test_code_profiles_run_on_code_targets_only() -> None:
    for kind in (TargetKind.ZIP, TargetKind.GITHUB_REPO, TargetKind.VENDOR_REPO, TargetKind.IMAGE):
        allowed(target_kind=kind)
    refused("scan.target_kind_mismatch", target_kind=TargetKind.URL)


def test_web_profiles_run_on_urls_only() -> None:
    allowed(profile_kind="dast", mode="full", tools=["zap"], target_kind=TargetKind.URL, environment=TargetEnvironment.UAT)
    refused("scan.target_kind_mismatch", profile_kind="dast", mode="baseline", target_kind=TargetKind.ZIP)
    refused("target.environment_required", profile_kind="dast", mode="baseline", target_kind=TargetKind.URL)


def test_production_gets_the_unauthenticated_baseline_only() -> None:
    prod = {"profile_kind": "dast", "target_kind": TargetKind.URL, "environment": TargetEnvironment.PRODUCTION}
    allowed(mode="baseline", tools=["zap"], **prod)
    for mode in ("full", "api", "nuclei"):
        refused("dast.production_baseline_only", mode=mode, tools=["zap"], **prod)
    refused("dast.production_baseline_only", mode="baseline", tools=["zap", "nuclei"], **prod)
    refused("dast.production_no_login", mode="baseline", tools=["zap"], login_profile_id=uuid.uuid4(), **prod)


def test_uat_may_use_every_mode_and_a_login_profile() -> None:
    uat = {"profile_kind": "dast", "target_kind": TargetKind.URL, "environment": TargetEnvironment.UAT}
    for mode, tools in (("baseline", ["zap"]), ("full", ["zap"]), ("api", ["zap"]), ("nuclei", ["nuclei"])):
        allowed(mode=mode, tools=tools, login_profile_id=uuid.uuid4(), **uat)


def test_source_reference_resolution() -> None:
    version = types.SimpleNamespace(commit_sha=None, label="release-1", label_kind="branch")
    repo = types.SimpleNamespace(kind=TargetKind.GITHUB_REPO, default_branch="main")
    zipped = types.SimpleNamespace(kind=TargetKind.ZIP, default_branch=None)
    assert resolve_source_reference(version, repo, None) == (None, "release-1")  # type: ignore[arg-type]
    assert resolve_source_reference(version, repo, "dev") == (None, "dev")  # type: ignore[arg-type]
    assert resolve_source_reference(version, repo, FULL_SHA.upper()) == (FULL_SHA, FULL_SHA)  # type: ignore[arg-type]
    assert resolve_source_reference(version, zipped, "dev") == (None, None)  # type: ignore[arg-type]
    upload = types.SimpleNamespace(commit_sha=None, label="v1.zip", label_kind="upload")
    assert resolve_source_reference(upload, repo, None) == (None, "main")  # type: ignore[arg-type]
    pinned = types.SimpleNamespace(commit_sha=FULL_SHA, label="x", label_kind="tag")
    assert resolve_source_reference(pinned, repo, None) == (FULL_SHA, FULL_SHA)  # type: ignore[arg-type]
    bare = types.SimpleNamespace(kind=TargetKind.VENDOR_REPO, default_branch=None)
    assert resolve_source_reference(upload, bare, None) == (None, None)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- idempotency
def test_idempotency_key_format() -> None:
    assert check_idempotency_key("abc-123_x:y.z@1") == "abc-123_x:y.z@1"
    for bad in ("", "has space", "a" * 92, "semi;colon", "new\nline"):
        with pytest.raises(Exception) as caught:
            check_idempotency_key(bad)
        assert getattr(caught.value, "code", "") == "idempotency.invalid_key"


def test_fingerprint_is_stable_and_sensitive() -> None:
    base = {"a": 1, "b": [1, 2], "c": {"x": "y"}}
    assert request_fingerprint(base) == request_fingerprint({"c": {"x": "y"}, "b": [1, 2], "a": 1})
    assert request_fingerprint(base) != request_fingerprint({**base, "a": 2})


# --------------------------------------------------------------------------- create_scan
PROFILE_DOC = ProfileDoc.model_validate(
    {
        "profile": "code-standard",
        "version": 1,
        "kind": "sast",
        "jobs": [
            {"tool": "semgrep", "timeout_min": 60, "limits": {"cpus": 2, "memory": "2g"}},
            {"tool": "gitleaks"},
        ],
    }
)


class _Nested:
    async def __aenter__(self) -> _Nested:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


class CreateSession(FakeSession):
    """Just enough of AsyncSession for ``create_scan_result``."""

    def __init__(self) -> None:
        super().__init__()
        self.info: dict[str, Any] = {}
        self.sync_session = Session()
        self.objects: dict[Any, Any] = {}
        self.existing_by_key: Scan | None = None
        self.queued: list[Scan] = []
        self.jobs_of_existing: list[ScanJob] = []

    def begin_nested(self) -> _Nested:
        return _Nested()

    async def get(self, model: Any, ident: Any) -> Any:
        return self.objects.get((model, ident))

    async def scalar(self, stmt: Any) -> Any:
        return self.existing_by_key

    async def scalars(self, stmt: Any) -> FakeScalars:
        if "FROM scan_jobs" in str(stmt):
            return FakeScalars(self.jobs_of_existing)
        return FakeScalars(self.queued)


def build_world(monkeypatch: pytest.MonkeyPatch, *, kind: TargetKind = TargetKind.GITHUB_REPO, doc: ProfileDoc = PROFILE_DOC) -> tuple[CreateSession, Any, Any]:
    from securescan.db.models.applications import Application
    from securescan.db.models.targets import Target
    from securescan.db.models.versions import ApplicationVersion

    session = CreateSession()
    application = types.SimpleNamespace(id=uuid.uuid4(), archived_at=None)
    version = types.SimpleNamespace(
        id=uuid.uuid4(), application_id=application.id, archived_at=None, label="main", label_kind="branch", commit_sha=None
    )
    target = types.SimpleNamespace(
        id=uuid.uuid4(), version_id=version.id, archived_at=None, kind=kind, environment=None,
        login_profile_id=None, default_branch="main", upload_artifact_id=None,
    )  # fmt: skip
    session.objects[(Application, application.id)] = application
    session.objects[(ApplicationVersion, version.id)] = version
    session.objects[(Target, target.id)] = target
    profile = types.SimpleNamespace(id=uuid.uuid4(), name=doc.profile, version=doc.version or 1)

    async def fake_profile(_session: Any, name: str, version_number: int | None = None) -> tuple[Any, ProfileDoc]:
        return profile, doc

    monkeypatch.setattr(scans_module, "get_profile", fake_profile)

    async def no_inspection(_session: Any, _target: Any) -> None:
        return None

    monkeypatch.setattr(scans_module, "_inspect_upload", no_inspection)
    return session, version, target


async def test_create_scan_writes_one_job_per_profile_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    session, version, target = build_world(monkeypatch)
    user = types.SimpleNamespace(id=uuid.uuid4(), label="analyst@example.com")
    result = await create_scan_result(
        session,  # type: ignore[arg-type]
        version_id=version.id,
        profile_name="code-standard",
        trigger=ScanTrigger.USER,
        requested_by=user,
        target_ids=[target.id],
        options={"trigger_detail": "manual", "tool_options": {"semgrep": {"exclude": ["*.gen.js"]}}},
        idempotency_key=f"{user.id}:k1",
    )
    scan = result.scan
    assert result.created and not result.replayed and not result.collapsed
    assert scan.state == S.QUEUED and scan.kind == ScanKind.SAST and scan.profile_name == "code-standard"
    assert scan.requested_tools == ["semgrep", "gitleaks"]
    assert scan.started_by_id == user.id and scan.idempotency_key == f"{user.id}:k1"
    assert scan.source_ref == "main" and scan.commit_sha is None
    assert scan.trigger_detail == "manual" and "trigger_detail" not in scan.options
    assert scan.options["fingerprint"]
    assert [j.tool for j in result.jobs] == ["semgrep", "gitleaks"]
    assert all(j.state == J.QUEUED for j in result.jobs)
    assert result.jobs[0].options == {"timeout_minutes": 60, "limits": {"cpus": 2.0, "memory": "2g"}, "exclude": ["*.gen.js"]}
    assert result.jobs[1].options == {}
    actions = [getattr(row, "action", None) for row in session.added]
    assert "scan.create" in actions
    assert session.info["scan_enqueue_pending"] == [scan.id]  # queued right after the commit


async def test_a_full_commit_id_pins_the_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    session, version, target = build_world(monkeypatch)
    scan = await create_scan(
        session,  # type: ignore[arg-type]
        version_id=version.id,
        profile_name="code-standard",
        trigger=ScanTrigger.CHANGE,
        requested_by=None,
        target_ids=[target.id],
        options={"commit": FULL_SHA, "trigger_detail": "push to main"},
        idempotency_key="system:change:app:sha",
    )
    assert scan.commit_sha == FULL_SHA and scan.source_ref == FULL_SHA
    assert scan.started_by_id is None and scan.trigger == ScanTrigger.CHANGE and scan.trigger_detail == "push to main"


async def test_a_subset_of_tools_keeps_profile_order(monkeypatch: pytest.MonkeyPatch) -> None:
    session, version, target = build_world(monkeypatch)
    result = await create_scan_result(
        session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
        requested_by=None, target_ids=[target.id], tools=["gitleaks"],
    )  # fmt: skip
    assert [j.tool for j in result.jobs] == ["gitleaks"]
    with pytest.raises(UnprocessableEntity) as caught:
        await create_scan_result(
            session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
            requested_by=None, target_ids=[target.id], tools=["sonarqube"],
        )  # fmt: skip
    assert caught.value.code == "scan.unknown_tool"


async def test_request_level_limits_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    session, version, target = build_world(monkeypatch)
    with pytest.raises(UnprocessableEntity) as caught:
        await create_scan_result(
            session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
            requested_by=None, target_ids=[target.id],
            options={"tool_options": {"semgrep": {"limits": {"memory": "64g"}}}},
        )  # fmt: skip
    assert caught.value.code == "scan.option_not_allowed"


async def test_rules_are_enforced_at_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    session, version, target = build_world(monkeypatch)
    target.kind = TargetKind.URL
    target.environment = TargetEnvironment.UAT
    with pytest.raises(UnprocessableEntity) as caught:
        await create_scan_result(
            session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
            requested_by=None, target_ids=[target.id],
        )  # fmt: skip
    assert caught.value.code == "scan.target_kind_mismatch"
    target.kind = TargetKind.GITHUB_REPO
    target.archived_at = utcnow()
    with pytest.raises(UnprocessableEntity) as archived:
        await create_scan_result(
            session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
            requested_by=None, target_ids=[target.id],
        )  # fmt: skip
    assert archived.value.code == "target.archived"
    target.archived_at = None
    target.version_id = uuid.uuid4()
    with pytest.raises(UnprocessableEntity) as foreign:
        await create_scan_result(
            session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
            requested_by=None, target_ids=[target.id],
        )  # fmt: skip
    assert foreign.value.code == "scan.target_not_in_version"
    with pytest.raises(UnprocessableEntity) as two:
        await create_scan_result(
            session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
            requested_by=None, target_ids=[target.id, uuid.uuid4()],
        )  # fmt: skip
    assert two.value.code == "scan.one_target"


async def test_extra_checks_can_be_registered(monkeypatch: pytest.MonkeyPatch) -> None:
    session, version, target = build_world(monkeypatch)
    seen: list[ScanCheckContext] = []

    def check(context: ScanCheckContext) -> None:
        seen.append(context)
        raise UnprocessableEntity("host not approved", code="dast.host_not_approved")

    monkeypatch.setattr(scans_module, "_EXTRA_CHECKS", [])
    register_scan_check(check)
    register_scan_check(check)  # once
    with pytest.raises(UnprocessableEntity) as caught:
        await create_scan_result(
            session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
            requested_by=None, target_ids=[target.id],
        )  # fmt: skip
    assert caught.value.code == "dast.host_not_approved" and len(seen) == 1
    assert seen[0].tools == ["semgrep", "gitleaks"]


async def test_same_idempotency_key_returns_the_first_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    session, version, target = build_world(monkeypatch)
    user = types.SimpleNamespace(id=uuid.uuid4())
    kwargs: dict[str, Any] = {
        "version_id": version.id, "profile_name": "code-standard", "trigger": ScanTrigger.USER,
        "requested_by": user, "target_ids": [target.id], "idempotency_key": f"{user.id}:same",
    }  # fmt: skip
    first = await create_scan_result(session, **kwargs)  # type: ignore[arg-type]
    session.existing_by_key = first.scan
    session.jobs_of_existing = first.jobs
    added_before = len(session.added)
    second = await create_scan_result(session, **kwargs)  # type: ignore[arg-type]
    assert second.replayed and not second.created and second.scan is first.scan
    assert [j.id for j in second.jobs] == [j.id for j in first.jobs]
    assert len(session.added) == added_before  # nothing new was written
    # the same key with a different request is refused
    with pytest.raises(UnprocessableEntity) as caught:
        await create_scan_result(session, **{**kwargs, "tools": ["gitleaks"]})  # type: ignore[arg-type]
    assert caught.value.code == "idempotency.key_reused"


async def test_a_waiting_identical_scan_absorbs_the_repeat(monkeypatch: pytest.MonkeyPatch) -> None:
    session, version, target = build_world(monkeypatch)
    first = await create_scan_result(
        session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
        requested_by=None, target_ids=[target.id],
    )  # fmt: skip
    session.queued = [first.scan]
    session.jobs_of_existing = first.jobs
    again = await create_scan_result(
        session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
        requested_by=None, target_ids=[target.id],
    )  # fmt: skip
    assert again.collapsed and not again.created and again.scan is first.scan
    # a different ref is a different scan
    other = await create_scan_result(
        session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
        requested_by=None, target_ids=[target.id], ref="dev",
    )  # fmt: skip
    assert other.created and other.scan is not first.scan


# --------------------------------------------------------------------------- queueing after commit
async def test_pending_scans_are_queued_after_the_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    sync = Session()
    session = types.SimpleNamespace(info=sync.info, sync_session=sync)  # AsyncSession.info is the sync session's
    queued: list[list[uuid.UUID]] = []

    async def fake_enqueue_all(ids: list[uuid.UUID]) -> None:
        queued.append(ids)

    monkeypatch.setattr(scans_module, "_enqueue_all", fake_enqueue_all)
    first, second = uuid.uuid4(), uuid.uuid4()
    scans_module.schedule_enqueue(session, first)  # type: ignore[arg-type]
    scans_module.schedule_enqueue(session, second)  # type: ignore[arg-type]
    scans_module.schedule_enqueue(session, first)  # type: ignore[arg-type]
    assert session.info["scan_enqueue_pending"] == [first, second, first]
    from sqlalchemy import event

    assert event.contains(session.sync_session, "after_commit", scans_module._after_commit)
    assert event.contains(session.sync_session, "after_rollback", scans_module._after_rollback)

    scans_module._after_commit(session.sync_session)
    await asyncio.sleep(0.01)
    assert queued == [[first, second]]  # de-duplicated, in order
    assert "scan_enqueue_pending" not in session.sync_session.info
    scans_module._after_commit(session.sync_session)  # nothing pending: nothing happens
    await asyncio.sleep(0.01)
    assert len(queued) == 1


def test_a_rollback_forgets_pending_scans() -> None:
    sync = Session()
    sync.info["scan_enqueue_pending"] = [uuid.uuid4()]
    scans_module._after_rollback(sync)
    assert "scan_enqueue_pending" not in sync.info


async def test_policy_switches_cannot_be_set_by_a_scan_request(monkeypatch: pytest.MonkeyPatch) -> None:
    session, version, target = build_world(monkeypatch)
    for tool, key, value in (
        ("semgrep", "no_disclosure", False),
        ("semgrep", "image_candidates", {"semgrep": {"id": "x", "token": "y"}}),
        ("gitleaks", "sonar_binaries", ["build"]),
        ("gitleaks", "exclude", ["src/**"]),  # exclusions are allowed for Semgrep only
    ):
        with pytest.raises(UnprocessableEntity) as caught:
            await create_scan_result(
                session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
                requested_by=None, target_ids=[target.id],
                options={"tool_options": {tool: {key: value}}},
            )  # fmt: skip
        assert caught.value.code == "scan.option_not_allowed", (tool, key)


async def test_a_request_may_set_the_allow_listed_options_within_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    session, version, target = build_world(monkeypatch)
    result = await create_scan_result(
        session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
        requested_by=None, target_ids=[target.id],
        options={"tool_options": {"semgrep": {"exclude": ["vendor/**"]}}},
    )  # fmt: skip
    semgrep = next(j for j in result.jobs if j.tool == "semgrep")
    assert semgrep.options["exclude"] == ["vendor/**"]
    for bad in ("vendor/**", [""], ["x"] * 51, [1]):
        with pytest.raises(UnprocessableEntity) as caught:
            await create_scan_result(
                session, version_id=version.id, profile_name="code-standard", trigger=ScanTrigger.USER,  # type: ignore[arg-type]
                requested_by=None, target_ids=[target.id],
                options={"tool_options": {"semgrep": {"exclude": bad}}},
            )  # fmt: skip
        assert caught.value.code == "scan.option_invalid"


def test_the_zap_minutes_are_bounded() -> None:
    check = scans_module.REQUEST_TOOL_OPTIONS["zap"]["active_minutes"]
    assert check("zap", "active_minutes", 30) == 30
    for bad in (0, -1, 10_000, True, "30", 1.5):
        with pytest.raises(UnprocessableEntity):
            check("zap", "active_minutes", bad)


def test_our_own_callers_may_set_any_job_option_except_the_limits() -> None:
    from securescan.runner.profiles import ProfileDoc

    doc = ProfileDoc.model_validate(
        {"profile": "x", "version": 1, "kind": "sast", "mode": "source", "jobs": [{"tool": "semgrep"}]}
    )
    options = {"tool_options": {"semgrep": {"image_candidates": {"semgrep": {"id": "i", "token": "t"}}}}}
    merged = scans_module._job_options(doc, "semgrep", options, trusted=True)
    assert merged["image_candidates"]["semgrep"]["token"] == "t"
    with pytest.raises(UnprocessableEntity):
        scans_module._job_options(doc, "semgrep", {"tool_options": {"semgrep": {"limits": {}}}}, trusted=True)
    with pytest.raises(UnprocessableEntity):
        scans_module._job_options(doc, "semgrep", options, trusted=False)
