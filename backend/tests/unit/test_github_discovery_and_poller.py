"""Discovery rules, the poller loop and the SQL stores' calls (no database, no network)."""

from __future__ import annotations

import sys
import types
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from securescan.db.models.applications import Application
from securescan.db.models.enums import AppType, ScanTrigger, TargetKind
from securescan.db.models.targets import Target
from securescan.db.models.versions import ApplicationVersion
from securescan.integrations.github.app import (
    GitHubAuthError,
    GitHubError,
    GitHubRateLimited,
    GitHubUnreachable,
    RepositoryInfo,
)
from securescan.integrations.github.discovery import (
    KnownApplication,
    SqlDiscoveryStore,
    run_discovery,
)
from securescan.integrations.github.poller import (
    PollCandidate,
    SqlPollStore,
    is_changed,
    order_candidates,
    pace_seconds,
    run_poll,
)

UTC = timezone.utc
NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)


def repo(repo_id: int, name: str, branch: str | None = "main", **kw: Any) -> RepositoryInfo:
    return RepositoryInfo(
        id=repo_id,
        name=name,
        full_name="sona/" + name,
        owner="sona",
        default_branch=branch,
        **kw,
    )


# --------------------------------------------------------------------------- discovery rules
class MemoryDiscoveryStore:
    def __init__(self, known: list[KnownApplication] | None = None) -> None:
        self.known = known or []
        self.created: list[RepositoryInfo] = []
        self.updated: list[tuple[uuid.UUID, RepositoryInfo, bool]] = []
        self.removed: list[uuid.UUID] = []
        self.audits: list[tuple[str, dict[str, object]]] = []

    async def known_applications(self) -> list[KnownApplication]:
        return list(self.known)

    async def create_application(self, repository: RepositoryInfo) -> uuid.UUID:
        self.created.append(repository)
        return uuid.uuid4()

    async def update_application(
        self, application_id: uuid.UUID, repository: RepositoryInfo, *, restored: bool
    ) -> None:
        self.updated.append((application_id, repository, restored))

    async def mark_removed(self, application_id: uuid.UUID, when: datetime) -> None:
        self.removed.append(application_id)

    async def audit(self, action: str, object_id: uuid.UUID, detail: dict[str, object]) -> None:
        self.audits.append((action, detail))


async def test_new_repositories_are_created() -> None:
    store = MemoryDiscoveryStore()
    result = await run_discovery([repo(1, "a"), repo(2, "b")], store, now=NOW)
    assert [r.full_name for r in store.created] == ["sona/a", "sona/b"]
    assert (result.seen, result.created, result.updated, result.removed) == (2, 2, 0, 0)
    assert result.created_names == ["sona/a", "sona/b"]
    assert [a for a, _ in store.audits] == ["application.discovered"] * 2


async def test_disabled_repositories_are_not_added() -> None:
    store = MemoryDiscoveryStore()
    result = await run_discovery([repo(1, "a", disabled=True), repo(2, "b")], store, now=NOW)
    assert [r.id for r in store.created] == [2]
    assert result.seen == 2


async def test_unchanged_repositories_cause_no_writes() -> None:
    known = [KnownApplication(uuid.uuid4(), 1, "sona/a", "main", None)]
    store = MemoryDiscoveryStore(known)
    result = await run_discovery([repo(1, "a")], store, now=NOW)
    assert not store.created and not store.updated and not store.removed
    assert result.updated == 0


async def test_rename_and_branch_change_update_the_application() -> None:
    known = KnownApplication(uuid.uuid4(), 1, "sona/old-name", "master", None)
    store = MemoryDiscoveryStore([known])
    result = await run_discovery([repo(1, "new-name", "main")], store, now=NOW)
    assert result.updated == 1 and result.restored == 0
    application_id, repository, restored = store.updated[0]
    assert application_id == known.id
    assert (repository.full_name, repository.default_branch, restored) == (
        "sona/new-name",
        "main",
        False,
    )


async def test_repositories_that_disappear_are_flagged_once_and_never_deleted() -> None:
    gone = KnownApplication(uuid.uuid4(), 2, "sona/b", "main", None)
    already = KnownApplication(uuid.uuid4(), 3, "sona/c", "main", NOW - timedelta(days=3))
    store = MemoryDiscoveryStore([gone, already])
    result = await run_discovery([repo(1, "a")], store, now=NOW)
    assert store.removed == [gone.id]
    assert result.removed == 1


async def test_a_returning_repository_is_restored() -> None:
    back = KnownApplication(uuid.uuid4(), 2, "sona/b", "main", NOW - timedelta(days=3))
    store = MemoryDiscoveryStore([back])
    result = await run_discovery([repo(2, "b")], store, now=NOW)
    assert result.restored == 1
    assert store.updated[0][2] is True


class NoRowsSession:
    """An AsyncSession stand-in whose queries find nothing; records what gets added."""

    def __init__(self, scalar_results: list[Any] | None = None) -> None:
        self.added: list[Any] = []
        self.scalar_results = scalar_results
        self.flushes = 0

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushes += 1

    async def scalar(self, _stmt: Any) -> Any:
        if self.scalar_results:
            return self.scalar_results.pop(0)
        return None

    async def get(self, _model: Any, _ident: Any) -> Any:
        return None


async def test_discovery_creates_unconfirmed_internal_applications_with_a_repo_target() -> None:
    session = NoRowsSession()
    store = SqlDiscoveryStore(session)  # type: ignore[arg-type]
    await store.create_application(repo(77, "payroll", "main"))
    applications = [o for o in session.added if isinstance(o, Application)]
    versions = [o for o in session.added if isinstance(o, ApplicationVersion)]
    targets = [o for o in session.added if isinstance(o, Target)]
    assert len(applications) == len(versions) == len(targets) == 1
    application = applications[0]
    assert application.confirmed is False
    assert application.automatic is False
    assert application.type == AppType.INTERNAL
    assert application.name == "sona/payroll"
    assert application.github_repo_id == 77
    assert application.github_full_name == "sona/payroll"
    assert application.default_branch == "main"
    assert application.created_by_id is None
    assert versions[0].label == "main" and versions[0].label_kind == "branch"
    assert targets[0].kind == TargetKind.GITHUB_REPO
    assert targets[0].locator == "sona/payroll"
    assert targets[0].default_branch == "main"


async def test_a_name_clash_gets_the_repository_id_appended() -> None:
    session = NoRowsSession(scalar_results=[1])  # the name-count query finds one existing row
    store = SqlDiscoveryStore(session)  # type: ignore[arg-type]
    await store.create_application(repo(77, "payroll"))
    application = next(o for o in session.added if isinstance(o, Application))
    assert application.name == "sona/payroll (77)"


# --------------------------------------------------------------------------- poller loop
class FakeGitHub:
    """What ``run_poll`` needs from the client: heads, rate-limit state and a request counter."""

    def __init__(self, heads: dict[str, Any], remaining: int | None = None) -> None:
        self.heads = heads
        self.looked_up: list[str] = []
        self.requests_made = 0
        self._remaining = remaining

    def rate_remaining(self) -> int | None:
        return self._remaining

    def rate_reset_at(self) -> datetime | None:
        return NOW + timedelta(minutes=30) if self._remaining is not None else None

    async def get_branch_head(self, owner: str, repo_name: str, branch: str) -> str | None:
        name = "%s/%s" % (owner, repo_name)
        self.looked_up.append(name)
        self.requests_made += 1
        value = self.heads[name]
        if isinstance(value, BaseException):
            raise value
        if self._remaining is not None:
            self._remaining -= 1
        return value  # type: ignore[no-any-return]


class MemoryPollStore:
    def __init__(self, candidates: list[PollCandidate]) -> None:
        self._candidates = candidates
        self.heads: dict[uuid.UUID, str] = {}
        self.errors: dict[uuid.UUID, str] = {}
        self.active: set[uuid.UUID] = set()
        self.enqueued: list[tuple[uuid.UUID, str]] = []
        self.commits = 0

    async def candidates(self) -> list[PollCandidate]:
        return list(self._candidates)

    async def record_head(self, candidate: PollCandidate, sha: str, when: datetime) -> None:
        self.heads[candidate.application_id] = sha

    async def record_error(self, candidate: PollCandidate, message: str, when: datetime) -> None:
        self.errors[candidate.application_id] = message

    async def has_active_scan(self, application_id: uuid.UUID) -> bool:
        return application_id in self.active

    async def enqueue_change_scan(
        self, candidate: PollCandidate, sha: str, when: datetime
    ) -> uuid.UUID | None:
        self.enqueued.append((candidate.application_id, sha))
        self.active.add(candidate.application_id)  # a queued scan counts as active
        return uuid.uuid4()

    async def commit(self) -> None:
        self.commits += 1


def candidate(name: str, scanned: str | None = None, seen_at: datetime | None = None) -> PollCandidate:
    return PollCandidate(
        application_id=uuid.uuid4(),
        full_name="sona/" + name,
        branch="main",
        last_scanned_sha=scanned,
        last_seen_at=seen_at,
    )


async def no_sleep(_seconds: float) -> None:
    return None


def poll(client: FakeGitHub, store: MemoryPollStore, **kw: Any) -> Any:
    options: dict[str, Any] = {
        "budget": 1200,
        "max_scans": 25,
        "now": lambda: NOW,
        "sleep": no_sleep,
        "monotonic": lambda: 0.0,
    }
    options.update(kw)
    return run_poll(client, store, **options)  # type: ignore[arg-type]


async def test_a_new_head_enqueues_one_scan_and_is_remembered() -> None:
    cand = candidate("a", scanned="old")
    store = MemoryPollStore([cand])
    result = await poll(FakeGitHub({"sona/a": "new" * 13}), store)
    assert store.enqueued == [(cand.application_id, "new" * 13)]
    assert store.heads[cand.application_id] == "new" * 13
    assert (result.checked, result.changed, result.enqueued) == (1, 1, 1)
    assert result.ok


async def test_an_unchanged_head_enqueues_nothing() -> None:
    cand = candidate("a", scanned="same")
    store = MemoryPollStore([cand])
    result = await poll(FakeGitHub({"sona/a": "same"}), store)
    assert store.enqueued == []
    assert store.heads[cand.application_id] == "same"
    assert result.changed == 0


async def test_a_never_scanned_repository_is_scanned_once() -> None:
    cand = candidate("a", scanned=None)
    store = MemoryPollStore([cand])
    await poll(FakeGitHub({"sona/a": "head1"}), store)
    assert len(store.enqueued) == 1


async def test_a_second_push_during_a_scan_does_not_queue_a_second_scan() -> None:
    cand = candidate("a", scanned="v0")
    store = MemoryPollStore([cand])
    first = await poll(FakeGitHub({"sona/a": "v1"}), store)
    assert first.enqueued == 1
    # the scan of v1 is still queued or running when the next push lands
    second = await poll(FakeGitHub({"sona/a": "v2"}), store)
    assert second.enqueued == 0
    assert second.busy == 1
    assert len(store.enqueued) == 1
    # once the scan is over the newer head is picked up on the next run
    store.active.clear()
    third = await poll(FakeGitHub({"sona/a": "v2"}), store)
    assert third.enqueued == 1
    assert store.enqueued[-1][1] == "v2"


async def test_the_scan_cap_leaves_the_rest_for_the_next_run() -> None:
    cands = [candidate("r%d" % i, scanned="old") for i in range(5)]
    store = MemoryPollStore(cands)
    client = FakeGitHub({c.full_name: "new-" + c.full_name for c in cands})
    result = await poll(client, store, max_scans=2)
    assert result.enqueued == 2
    assert result.deferred == 3
    assert result.changed == 5


async def test_budget_limits_lookups_and_unchecked_repositories_go_first() -> None:
    old = candidate("old", scanned="x", seen_at=NOW - timedelta(hours=5))
    recent = candidate("recent", scanned="x", seen_at=NOW - timedelta(minutes=5))
    never = candidate("never", scanned="x", seen_at=None)
    store = MemoryPollStore([recent, old, never])
    client = FakeGitHub({"sona/old": "x", "sona/recent": "x", "sona/never": "x"})
    result = await poll(client, store, budget=2)
    assert client.looked_up == ["sona/never", "sona/old"]
    assert result.considered == 3
    assert result.checked == 2


async def test_rate_limit_ends_the_run_early_without_counting_it_as_repository_errors() -> None:
    cands = [candidate("a", scanned="x"), candidate("b", scanned="x")]
    store = MemoryPollStore(cands)
    limited = GitHubRateLimited("GitHub is limiting requests.", retry_after=900.0)
    client = FakeGitHub({"sona/a": limited, "sona/b": "x"})
    result = await poll(client, store)
    assert client.looked_up == ["sona/a"]
    assert result.stopped_reason is not None and "limiting" in result.stopped_reason
    assert result.errors == 0
    assert not result.ok


async def test_run_stops_when_the_remaining_budget_is_nearly_used_up() -> None:
    cands = [candidate("r%d" % i, scanned="x") for i in range(4)]
    store = MemoryPollStore(cands)
    client = FakeGitHub({c.full_name: "x" for c in cands}, remaining=102)
    result = await poll(client, store, low_water=100)
    assert len(client.looked_up) == 2  # 102 -> 101 -> 100; at 100 the run stops before the third
    assert result.stopped_reason is not None and "nearly used up" in result.stopped_reason
    assert result.rate_remaining is not None


async def test_one_failing_repository_does_not_stop_the_others() -> None:
    cands = [candidate("a", scanned="x"), candidate("b", scanned="x")]
    store = MemoryPollStore(cands)
    client = FakeGitHub({"sona/a": GitHubError("GitHub answered with an unexpected error (500)."), "sona/b": "y"})
    result = await poll(client, store)
    assert result.errors == 1
    assert store.errors[cands[0].application_id].startswith("GitHub answered")
    assert [e[0] for e in store.enqueued] == [cands[1].application_id]
    assert result.ok  # one failure out of two is not a failed run


@pytest.mark.parametrize(
    "failure",
    [GitHubAuthError("GitHub rejected the App's credentials."), GitHubUnreachable("GitHub could not be reached.")],
)
async def test_credential_and_network_failures_abort_the_run(failure: BaseException) -> None:
    cands = [candidate("a", scanned="x"), candidate("b", scanned="x")]
    client = FakeGitHub({"sona/a": failure, "sona/b": "x"})
    result = await poll(client, MemoryPollStore(cands))
    assert client.looked_up == ["sona/a"]
    assert result.stopped_reason is not None
    assert not result.ok


async def test_an_empty_branch_is_recorded_as_a_problem() -> None:
    cand = candidate("a", scanned="x")
    store = MemoryPollStore([cand])
    await poll(FakeGitHub({"sona/a": None}), store)
    assert "not found" in store.errors[cand.application_id]
    assert store.enqueued == []


async def test_requests_are_paced_over_the_interval() -> None:
    cands = [candidate("r%d" % i, scanned="x") for i in range(3)]
    sleeps: list[float] = []

    async def record_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    client = FakeGitHub({c.full_name: "x" for c in cands})
    await poll(client, MemoryPollStore(cands), sleep=record_sleep, interval_seconds=6.0)
    assert sleeps == [pytest.approx(1.6), pytest.approx(1.6)]  # 6 s * 0.8 / 3 lookups


def test_pace_is_capped_and_zero_without_work() -> None:
    assert pace_seconds(0, 600.0) == 0.0
    assert pace_seconds(1, 600.0) == 2.0
    assert pace_seconds(1200, 600.0) == pytest.approx(0.4)


def test_head_comparison_and_ordering_helpers() -> None:
    assert is_changed("abc", candidate("a", scanned="old"))
    assert not is_changed("abc", candidate("a", scanned="abc"))
    assert is_changed("abc", candidate("a", scanned=None))
    ordered = order_candidates(
        [candidate("b", seen_at=NOW), candidate("a", seen_at=None), candidate("c", seen_at=NOW - timedelta(days=1))]
    )
    assert [c.full_name for c in ordered] == ["sona/a", "sona/c", "sona/b"]


# --------------------------------------------------------------------------- the SQL poll store
class NestedContext:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc: object) -> bool:
        return False


class ScanSession(NoRowsSession):
    def begin_nested(self) -> NestedContext:
        return NestedContext()


def install_fake_scan_service(
    monkeypatch: pytest.MonkeyPatch, create_scan: Callable[..., Any]
) -> None:
    module = types.ModuleType("securescan.domain.scans")
    module.create_scan = create_scan  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "securescan.domain.scans", module)


def sql_candidate_and_application() -> tuple[PollCandidate, Application]:
    application = Application(
        id=uuid.uuid4(),
        name="sona/payroll",
        type=AppType.INTERNAL,
        github_repo_id=5,
        github_full_name="sona/payroll",
        default_branch="main",
    )
    cand = PollCandidate(application_id=application.id, full_name="sona/payroll", branch="main")
    return cand, application


async def test_the_change_scan_is_created_with_the_planned_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    async def fake_create_scan(session: Any, **kwargs: Any) -> Any:
        calls.append(kwargs)
        return types.SimpleNamespace(id=uuid.uuid4())

    install_fake_scan_service(monkeypatch, fake_create_scan)
    cand, application = sql_candidate_and_application()
    version = ApplicationVersion(id=uuid.uuid4(), application_id=application.id, label="main")
    target = Target(id=uuid.uuid4(), version_id=version.id, kind=TargetKind.GITHUB_REPO, locator="sona/payroll")
    session = ScanSession(scalar_results=[version, target])
    store = SqlPollStore(session)  # type: ignore[arg-type]
    store._apps[application.id] = application
    scan_id = await store.enqueue_change_scan(cand, "f" * 40, NOW)
    assert scan_id is not None
    (call,) = calls
    assert call["version_id"] == version.id
    assert call["profile_name"] == "code-standard"
    assert call["trigger"] == ScanTrigger.CHANGE
    assert call["requested_by"] is None
    assert call["target_ids"] == [target.id]
    assert call["idempotency_key"] == "system:change:%s:%s" % (application.id, "f" * 40)
    assert call["options"]["commit"] == "f" * 40
    head = store._heads[(application.id, "main")]
    assert head.last_scanned_sha == "f" * 40
    assert head.last_scan_id == scan_id


async def test_a_scan_that_cannot_be_created_is_recorded_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failing_create_scan(session: Any, **kwargs: Any) -> Any:
        raise RuntimeError("profile code-standard is not seeded")

    install_fake_scan_service(monkeypatch, failing_create_scan)
    cand, application = sql_candidate_and_application()
    version = ApplicationVersion(id=uuid.uuid4(), application_id=application.id, label="main")
    target = Target(id=uuid.uuid4(), version_id=version.id, kind=TargetKind.GITHUB_REPO, locator="sona/payroll")
    session = ScanSession(scalar_results=[version, target])
    store = SqlPollStore(session)  # type: ignore[arg-type]
    store._apps[application.id] = application
    assert await store.enqueue_change_scan(cand, "f" * 40, NOW) is None
    head = store._heads[(application.id, "main")]
    assert head.last_scanned_sha is None  # tried again on the next run
    assert head.last_poll_error is not None and "Could not start a scan" in head.last_poll_error
