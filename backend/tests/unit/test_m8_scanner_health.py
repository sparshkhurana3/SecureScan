"""Feed ages and limits, the alert metrics, update exclusion, and the scanner-health and content endpoints."""

from __future__ import annotations

import time
import types
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from securescan.api import content as content_api
from securescan.api import scanner_health as health_api
from securescan.api.problems import install_problem_handlers
from securescan.auth.roles import CurrentUser, current_user
from securescan.config import Settings, get_settings
from securescan.db.models.content import ContentVersion
from securescan.db.models.enums import ContentFeed, UserRole
from securescan.db.session import get_session
from securescan.jobs import scanner_health as health
from securescan.jobs.scanner_health import (
    age_seconds,
    feed_status,
    is_stale,
    limit_days,
    record_feed_clock,
    record_update_result,
    reference_time,
)
from securescan.observability import metrics
from securescan.runner.catalogue import clear_catalogue_cache
from securescan.util import utcnow
from tests.unit.conftest import FakeSession
from tests.unit.m8_helpers import set_pin
from tests.unit.runner_helpers import REPO_SCANNERS

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def clean_health_state() -> None:
    """The feed clocks and failure flags are process-wide: start every test without them."""
    health._failed.clear()
    health._reference_times.clear()


def row(**values: Any) -> Any:
    defaults: dict[str, Any] = {"version": "v1", "path": None, "source_commit": None, "built_at": None, "fetched_at": None,
                                "activated_at": None, "regression_result": "passed"}  # fmt: skip
    defaults.update(values)
    return types.SimpleNamespace(**defaults)


# --------------------------------------------------------------------------- limits and ages
def test_limits_follow_the_design() -> None:
    assert limit_days(ContentFeed.GRYPE_DB) == 7
    assert limit_days(ContentFeed.SEMGREP_RULES) == 30 and limit_days("nuclei_templates") == 30
    assert limit_days("grype_db", Settings(feed_max_age_days_database=3)) == 3  # type: ignore[call-arg]


def test_databases_age_from_their_build_and_rules_from_their_last_check() -> None:
    built = NOW - timedelta(days=2)
    fetched = NOW - timedelta(hours=1)
    assert reference_time(ContentFeed.GRYPE_DB, row(built_at=built, fetched_at=fetched)) == built
    assert reference_time(ContentFeed.SEMGREP_RULES, row(built_at=built, fetched_at=fetched)) == fetched
    assert reference_time(ContentFeed.GRYPE_DB, row(fetched_at=fetched)) == fetched, "no build date: the fetch time"
    assert reference_time(ContentFeed.GRYPE_DB, row()) is None
    assert age_seconds(None) is None and age_seconds(built, NOW) == 2 * 86400.0
    assert age_seconds(NOW + timedelta(days=1), NOW) == 0.0, "never negative"


def test_staleness() -> None:
    assert is_stale(ContentFeed.GRYPE_DB, None), "no version at all"
    assert not is_stale(ContentFeed.GRYPE_DB, 6 * 86400.0) and is_stale(ContentFeed.GRYPE_DB, 7 * 86400.0 + 1)
    assert not is_stale(ContentFeed.SEMGREP_RULES, 29 * 86400.0) and is_stale(ContentFeed.SEMGREP_RULES, 31 * 86400.0)


def test_feed_status_summarises_a_feed() -> None:
    status = feed_status(ContentFeed.GRYPE_DB, row(version="v6-x", built_at=NOW - timedelta(days=8)), now=NOW)
    assert (status.feed, status.version, status.tool, status.limit_days, status.stale) == ("grype_db", "v6-x", "syft-grype", 7, True)
    assert status.age_seconds == 8 * 86400.0 and status.label == "Grype vulnerability database"
    empty = feed_status(ContentFeed.NUCLEI_TEMPLATES, None, now=NOW)
    assert empty.version is None and empty.age_seconds is None and empty.stale is True and empty.tool == "nuclei"


# --------------------------------------------------------------------------- metrics
def sample(name: str, feed: str) -> float | None:
    for family in metrics.REGISTRY.collect():
        for item in family.samples:
            if item.name == name and item.labels.get("feed") == feed:
                return float(item.value)
    return None


def test_the_feed_age_gauge_keeps_counting_between_updates() -> None:
    record_feed_clock(ContentFeed.GRYPE_DB, utcnow() - timedelta(days=3))
    age = sample("securescan_feed_age_seconds", "grype_db")
    assert age is not None and 3 * 86400 <= age < 3 * 86400 + 60
    assert sample("securescan_feed_stale", "grype_db") == 0.0
    record_feed_clock(ContentFeed.GRYPE_DB, utcnow() - timedelta(days=9))
    assert sample("securescan_feed_stale", "grype_db") == 1.0
    record_feed_clock(ContentFeed.SEMGREP_RULES, utcnow() - timedelta(days=9))
    assert sample("securescan_feed_stale", "semgrep_rules") == 0.0, "30 days for rules"
    record_feed_clock(ContentFeed.GRYPE_DB, None)  # forgotten: stale until a version exists
    assert sample("securescan_feed_stale", "grype_db") == 1.0


def test_the_update_alert_metric_is_set_on_failure_and_cleared_on_success() -> None:
    record_update_result(ContentFeed.GRYPE_DB, False)
    assert sample("securescan_content_update_failed", "grype_db") == 1.0
    assert feed_status(ContentFeed.GRYPE_DB, row(), now=NOW).update_failed is True
    before = time.time()
    record_update_result("grype_db", True)
    assert sample("securescan_content_update_failed", "grype_db") == 0.0
    assert (sample("securescan_content_update_last_success_timestamp", "grype_db") or 0) >= before - 1
    assert feed_status(ContentFeed.GRYPE_DB, row(), now=NOW).update_failed is False


# --------------------------------------------------------------------------- the endpoints
def user(role: UserRole) -> CurrentUser:
    return CurrentUser(
        id=uuid.uuid4(), oid="oid", name="T", email="t@example.com", role=role, session_id=uuid.uuid4(), csrf_token="c",
    )  # fmt: skip


def build_client(role: UserRole = UserRole.ADMIN, session: FakeSession | None = None) -> tuple[TestClient, FakeSession]:
    app = FastAPI()
    install_problem_handlers(app)
    app.include_router(health_api.router, prefix="/api/v1")
    app.include_router(content_api.router, prefix="/api/v1")
    fake = session or FakeSession()

    async def db() -> AsyncIterator[FakeSession]:
        yield fake

    app.dependency_overrides[get_session] = db
    app.dependency_overrides[current_user] = lambda: user(role)
    return TestClient(app), fake


@pytest.fixture
def catalogue_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_SCANNERS_DIR", str(REPO_SCANNERS))
    get_settings.cache_clear()
    clear_catalogue_cache()
    set_pin(monkeypatch, "SEMGREP", "semgrep/semgrep")
    set_pin(monkeypatch, "GRYPE", "anchore/grype")


def patch_health_data(monkeypatch: pytest.MonkeyPatch, *, runs: dict[str, Any] | None = None, approved: dict[str, Any] | None = None,
                      feeds: dict[str, Any] | None = None, digests: dict[str, str] | None = None) -> None:  # fmt: skip
    async def last_runs(_db: Any) -> dict[str, Any]:
        return runs or {}

    async def last_digests(_db: Any) -> dict[str, str]:
        return digests or {}

    async def approved_images(_db: Any) -> dict[str, Any]:
        return approved or {}

    async def refresh(_db: Any) -> dict[str, Any]:
        active = feeds or {}
        return {f.value: feed_status(f, active.get(f.value), now=utcnow()) for f in health.ALL_FEEDS}

    monkeypatch.setattr(health_api, "last_runs_by_tool", last_runs)
    monkeypatch.setattr(health_api, "last_job_digests", last_digests)
    monkeypatch.setattr(health_api, "approved_images", approved_images)
    monkeypatch.setattr(health_api, "refresh_feed_clocks", refresh)


def test_scanner_health_lists_tools_digests_and_feed_ages(monkeypatch: pytest.MonkeyPatch, catalogue_env: None) -> None:
    fresh = utcnow() - timedelta(hours=5)
    patch_health_data(
        monkeypatch,
        runs={"semgrep": {"success": fresh, "failure": None}, "syft-grype": {"success": None, "failure": fresh}},
        digests={"semgrep": "sha256:" + "9" * 64},
        approved={"semgrep": types.SimpleNamespace(image="semgrep/semgrep", tag="1.180.0-nonroot", digest="sha256:" + "c" * 64, approved_at=fresh)},
        feeds={"grype_db": row(version="v6-x", built_at=utcnow() - timedelta(days=9)), "semgrep_rules": row(version="rules-abc", fetched_at=fresh)},
    )
    client, _db = build_client()
    response = client.get("/api/v1/scanner-health")
    assert response.status_code == 200, response.text
    body = response.json()
    tools = {t["tool"]: t for t in body["tools"]}
    assert {"semgrep", "gitleaks", "syft-grype", "spotbugs"} <= set(tools)
    assert not {"dependency-check", "sonarqube", "sonarqube-server"} & set(tools)
    semgrep = tools["semgrep"]
    assert semgrep["role"] == "scanner" and semgrep["feed"] == "semgrep_rules"
    assert semgrep["digest"] == "sha256:" + "c" * 64 and semgrep["digest_source"] == "override", "an approved image wins"
    assert semgrep["approved_image"]["tag"] == "1.180.0-nonroot" and semgrep["last_job_digest"] == "sha256:" + "9" * 64
    assert semgrep["last_success_at"] is not None and semgrep["last_failure_at"] is None
    grype = tools["syft-grype"]
    assert grype["digest"] == "sha256:" + "a" * 64 and grype["digest_source"] == "env" and grype["last_failure_at"] is not None
    assert tools["gitleaks"]["digest_source"] == "unresolved" and tools["gitleaks"]["digest"] is None
    assert tools["skopeo"]["role"] == "support" and tools["grype-db-update"]["role"] == "support"
    assert [t["role"] for t in body["tools"]] == sorted((t["role"] for t in body["tools"]), key=lambda r: r != "scanner")
    feeds = {f["feed"]: f for f in body["feeds"]}
    assert set(feeds) == {"grype_db", "semgrep_rules", "nuclei_templates"}
    assert feeds["grype_db"]["stale"] is True and feeds["grype_db"]["limit_days"] == 7
    assert feeds["semgrep_rules"]["stale"] is False and feeds["semgrep_rules"]["limit_days"] == 30
    assert feeds["nuclei_templates"]["version"] is None and feeds["nuclei_templates"]["stale"] is True
    assert body["status"] == "attention" and any("Needs attention" in n for n in body["notes"])


def test_scanner_health_is_ok_when_everything_is_fresh(monkeypatch: pytest.MonkeyPatch, catalogue_env: None) -> None:
    fresh = row(version="v", built_at=utcnow() - timedelta(hours=3), fetched_at=utcnow() - timedelta(hours=3))
    patch_health_data(monkeypatch, feeds={f.value: fresh for f in health.ALL_FEEDS})
    body = build_client()[0].get("/api/v1/scanner-health").json()
    assert body["status"] == "ok" and body["notes"] == []


def test_scanner_health_without_a_catalogue_falls_back_to_the_jobs_that_ran(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(health_api, "load_catalogue", lambda: (_ for _ in ()).throw(health_api.CatalogueError("not found")))
    patch_health_data(monkeypatch, runs={"semgrep": {"success": utcnow(), "failure": None}}, digests={"semgrep": "sha256:" + "9" * 64})
    body = build_client()[0].get("/api/v1/scanner-health").json()
    assert [t["tool"] for t in body["tools"]] == ["semgrep"] and body["tools"][0]["digest"] is None
    assert body["tools"][0]["last_job_digest"] == "sha256:" + "9" * 64
    assert any("catalogue is not available" in n for n in body["notes"])


def test_scanner_health_is_for_admins_only(monkeypatch: pytest.MonkeyPatch, catalogue_env: None) -> None:
    patch_health_data(monkeypatch)
    response = build_client(UserRole.ANALYST)[0].get("/api/v1/scanner-health")
    assert response.status_code == 403 and response.headers["content-type"].startswith("application/problem+json")


# --------------------------------------------------------------------------- content versions
def version_row(feed: ContentFeed = ContentFeed.GRYPE_DB, **changes: Any) -> Any:
    values: dict[str, Any] = {
        "id": uuid.uuid4(), "feed": feed, "version": "v6-20261007", "path": "grype-db", "source_commit": None,
        "built_at": NOW, "fetched_at": NOW, "regression_result": "skipped", "regression_detail": {}, "active": True,
        "activated_at": NOW, "created_at": NOW,
    }  # fmt: skip
    values.update(changes)
    return ContentVersion(**values)


def test_content_versions_are_listed_for_analysts(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    async def paginate(_db: Any, statement: Any, *, key: Any, params: Any, descending: bool) -> Any:
        captured["sql"] = str(statement)
        captured["descending"] = descending
        return types.SimpleNamespace(items=[version_row(), version_row(ContentFeed.SEMGREP_RULES, version="rules-abc", active=False)], next_cursor="next")

    monkeypatch.setattr(content_api, "paginate", paginate)
    client, _db = build_client(UserRole.ANALYST)
    response = client.get("/api/v1/content-versions", params={"feed": "grype_db", "active": "true"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert [i["version"] for i in body["items"]] == ["v6-20261007", "rules-abc"] and body["next_cursor"] == "next"
    assert body["items"][0]["feed"] == "grype_db" and body["items"][0]["active"] is True
    assert "content_versions.feed" in captured["sql"] and "active" in captured["sql"] and captured["descending"] is True
    assert client.get("/api/v1/content-versions", params={"feed": "bogus"}).status_code == 422


def test_an_update_can_be_started_by_an_admin_only(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.jobs import enqueue

    queued: list[dict[str, Any]] = []

    async def defer(task: Any, **kwargs: Any) -> int | None:
        queued.append({"task": task.name, **kwargs})
        return None if len(queued) > 1 else 7

    monkeypatch.setattr(enqueue, "defer", defer)
    client, db = build_client(UserRole.ADMIN)
    first = client.post("/api/v1/content-versions/updates", json={"feed": "grype_db"})
    assert first.status_code == 202 and first.json() == {"feed": "grype_db", "queued": True, "message": "The update was queued; the worker starts it shortly."}
    assert queued[0] == {"task": "content_update", "queueing_lock": "content_update:grype_db", "feed": "grype_db"}
    second = client.post("/api/v1/content-versions/updates", json={"feed": "grype_db"})
    assert second.status_code == 202 and second.json()["queued"] is False
    assert db.commits == 2 and any(getattr(a, "action", "") == "content.update_requested" for a in db.added)
    assert client.post("/api/v1/content-versions/updates", json={"feed": "bogus"}).status_code == 422
    assert client.post("/api/v1/content-versions/updates", json={"feed": "nvd_data"}).status_code == 422, "retired feed"
    denied = build_client(UserRole.ANALYST)[0].post("/api/v1/content-versions/updates", json={"feed": "grype_db"})
    assert denied.status_code == 403


def test_an_unreachable_queue_is_a_503(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.jobs import enqueue

    async def defer(*_a: Any, **_k: Any) -> int:
        raise ConnectionError("no database")

    monkeypatch.setattr(enqueue, "defer", defer)
    response = build_client()[0].post("/api/v1/content-versions/updates", json={"feed": "grype_db"})
    assert response.status_code == 503 and response.json()["code"] == "content.queue_unavailable"
