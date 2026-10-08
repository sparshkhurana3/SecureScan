"""The scans and profiles endpoints (routers, roles, Idempotency-Key, problems) without a database."""

from __future__ import annotations

import types
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from securescan.api import profiles as profiles_api
from securescan.api import scans as scans_api
from securescan.api.problems import install_problem_handlers
from securescan.auth.roles import CurrentUser, current_user
from securescan.db.models.enums import ScanKind, ScanState, ScanTrigger, UserRole, Verdict
from securescan.db.models.profiles import ScanProfile
from securescan.db.session import get_session
from securescan.domain.scans import ScanCreation
from securescan.runner.catalogue import clear_catalogue_cache
from securescan.util import utcnow
from tests.unit.conftest import FakeSession
from tests.unit.runner_helpers import REPO_SCANNERS

VERSION_ID, TARGET_ID = uuid.uuid4(), uuid.uuid4()


def make_user(role: UserRole = UserRole.ANALYST) -> CurrentUser:
    return CurrentUser(
        id=uuid.uuid4(), oid="oid", name="Tester", email="tester@example.com", role=role,
        session_id=uuid.uuid4(), csrf_token="csrf",
    )  # fmt: skip


def build_app(role: UserRole = UserRole.ANALYST, session: FakeSession | None = None) -> tuple[TestClient, FakeSession, CurrentUser]:
    app = FastAPI()
    install_problem_handlers(app)
    app.include_router(scans_api.router, prefix="/api/v1")
    app.include_router(profiles_api.router, prefix="/api/v1")
    fake = session or FakeSession()
    user = make_user(role)

    async def db() -> AsyncIterator[FakeSession]:
        yield fake

    app.dependency_overrides[get_session] = db
    app.dependency_overrides[current_user] = lambda: user
    return TestClient(app), fake, user


def make_detail(scan_id: uuid.UUID | None = None, **changes: Any) -> scans_api.ScanDetail:
    values: dict[str, Any] = {
        "id": scan_id or uuid.uuid4(), "application_id": uuid.uuid4(), "version_id": VERSION_ID, "target_id": TARGET_ID,
        "profile_name": "code-standard", "profile_version": 1, "kind": ScanKind.SAST, "mode": None,
        "trigger": ScanTrigger.USER, "trigger_detail": None, "state": ScanState.QUEUED, "verdict": Verdict.PENDING,
        "started_by_id": None, "requested_tools": ["semgrep", "gitleaks"], "commit_sha": None, "source_ref": "main",
        "counts": {}, "coverage_notes": [], "error": None, "created_at": utcnow(), "started_at": None,
        "finished_at": None, "cancel_requested_at": None,
    }  # fmt: skip
    values.update(changes)
    return scans_api.ScanDetail(**values)


# --------------------------------------------------------------------------- POST /scans
def test_start_scan_passes_the_namespaced_idempotency_key(monkeypatch: pytest.MonkeyPatch) -> None:
    client, fake, user = build_app()
    captured: dict[str, Any] = {}
    detail = make_detail()

    async def fake_create(db: Any, **kwargs: Any) -> ScanCreation:
        captured.update(kwargs)
        return ScanCreation(scan=types.SimpleNamespace(id=detail.id), jobs=[], created=False, replayed=True)  # type: ignore[arg-type]

    async def fake_detail(db: Any, scan: Any, replayed: bool = False, collapsed: bool = False) -> scans_api.ScanDetail:
        return make_detail(detail.id, replayed=replayed, collapsed=collapsed)

    monkeypatch.setattr(scans_api, "create_scan_result", fake_create)
    monkeypatch.setattr(scans_api, "load_detail", fake_detail)
    response = client.post(
        "/api/v1/scans",
        json={"version_id": str(VERSION_ID), "target_id": str(TARGET_ID), "ref": "main", "options": {"a": 1}},
        headers={"Idempotency-Key": "abc-123"},
    )
    assert response.status_code == 202, response.text
    assert response.headers["idempotent-replayed"] == "true"
    body = response.json()
    assert body["id"] == str(detail.id) and body["replayed"] is True and body["state"] == "queued"
    assert captured["idempotency_key"] == f"{user.id}:abc-123"  # per user: two users cannot collide
    assert captured["trigger"] == ScanTrigger.USER and captured["requested_by"] is user
    assert captured["target_ids"] == [TARGET_ID] and captured["version_id"] == VERSION_ID
    assert captured["profile_name"] == "code-standard" and captured["ref"] == "main" and captured["options"] == {"a": 1}
    assert fake.commits == 1


def test_without_a_key_the_scan_is_not_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    client, _fake, _user = build_app()
    captured: dict[str, Any] = {}

    async def fake_create(db: Any, **kwargs: Any) -> ScanCreation:
        captured.update(kwargs)
        return ScanCreation(scan=types.SimpleNamespace(id=uuid.uuid4()), jobs=[], collapsed=True, created=False)  # type: ignore[arg-type]

    async def fake_detail(db: Any, scan: Any, replayed: bool = False, collapsed: bool = False) -> scans_api.ScanDetail:
        return make_detail(collapsed=collapsed)

    monkeypatch.setattr(scans_api, "create_scan_result", fake_create)
    monkeypatch.setattr(scans_api, "load_detail", fake_detail)
    response = client.post("/api/v1/scans", json={"version_id": str(VERSION_ID), "target_id": str(TARGET_ID)})
    assert response.status_code == 202
    assert captured["idempotency_key"] is None
    assert "idempotent-replayed" not in response.headers and response.headers["x-scan-collapsed"] == "true"


@pytest.mark.parametrize("key", ["has space", "x" * 92, "semi;colon"])
def test_a_malformed_idempotency_key_is_a_problem(key: str) -> None:
    client, _fake, _user = build_app()
    response = client.post(
        "/api/v1/scans",
        json={"version_id": str(VERSION_ID), "target_id": str(TARGET_ID)},
        headers={"Idempotency-Key": key},
    )
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "idempotency.invalid_key"


def test_start_scan_validates_the_body() -> None:
    client, _fake, _user = build_app()
    assert client.post("/api/v1/scans", json={"version_id": str(VERSION_ID)}).status_code == 422
    assert client.post("/api/v1/scans", json={"version_id": "nope", "target_id": str(TARGET_ID)}).status_code == 422
    too_long = {"version_id": str(VERSION_ID), "target_id": str(TARGET_ID), "ref": "r" * 300}
    assert client.post("/api/v1/scans", json=too_long).status_code == 422


# --------------------------------------------------------------------------- cancel
def test_cancel_settles_the_jobs_cancelled_before_they_started(monkeypatch: pytest.MonkeyPatch) -> None:
    scan = types.SimpleNamespace(id=uuid.uuid4())
    client, fake, user = build_app(session=FakeSession(rows=[scan]))
    job_ids = [uuid.uuid4(), uuid.uuid4()]
    calls: dict[str, Any] = {}

    async def fake_cancel(db: Any, row: Any, who: Any) -> tuple[Any, list[uuid.UUID]]:
        calls["cancel"] = (row, who)
        return row, job_ids

    async def fake_settle(ids: list[uuid.UUID]) -> None:
        calls["settled"] = ids

    async def fake_event(*args: Any, **kwargs: Any) -> None:
        calls["event"] = args

    async def fake_detail(db: Any, row: Any, **kwargs: Any) -> scans_api.ScanDetail:
        return make_detail(scan.id, state=ScanState.CANCELLED)

    monkeypatch.setattr(scans_api, "request_cancel", fake_cancel)
    monkeypatch.setattr(scans_api, "settle_cancelled_jobs", fake_settle)
    monkeypatch.setattr(scans_api, "state_event", fake_event)
    monkeypatch.setattr(scans_api, "load_detail", fake_detail)
    response = client.post(f"/api/v1/scans/{scan.id}/cancel")
    assert response.status_code == 202, response.text
    assert response.json()["state"] == "cancelled"
    assert calls["cancel"][1] is user and calls["settled"] == job_ids
    assert calls["event"][0] == scan.id and calls["event"][3] == "cancel_requested"
    assert any(getattr(row, "action", "") == "scan.cancel" for row in fake.added)  # audited
    assert fake.commits == 1


def test_unknown_scans_are_404_problems() -> None:
    client, _fake, _user = build_app()
    response = client.post(f"/api/v1/scans/{uuid.uuid4()}/cancel")
    assert response.status_code == 404 and response.json()["code"] == "scan.not_found"
    assert client.get(f"/api/v1/scans/{uuid.uuid4()}").status_code == 404
    assert client.get(f"/api/v1/scans/{uuid.uuid4()}/events").status_code == 404
    assert client.get(f"/api/v1/scans/{uuid.uuid4()}/jobs/{uuid.uuid4()}/log").status_code == 404


def test_server_sent_event_format() -> None:
    text = scans_api.sse("log", {"lines": ["a", "b"], "n": 1})
    assert text == 'event: log\ndata: {"lines":["a","b"],"n":1}\n\n'
    assert scans_api.sse("done", {}).endswith("\n\n")


def test_the_fingerprint_changes_with_state_or_jobs() -> None:
    base = {"state": "running", "jobs": [{"id": "1", "state": "running", "import_state": "pending"}]}
    same = {"state": "running", "jobs": [{"id": "1", "state": "running", "import_state": "pending"}]}
    done = {"state": "running", "jobs": [{"id": "1", "state": "completed", "import_state": "pending"}]}
    assert scans_api._fingerprint(base) == scans_api._fingerprint(same)
    assert scans_api._fingerprint(base) != scans_api._fingerprint(done)


# --------------------------------------------------------------------------- profiles
@pytest.fixture
def catalogue_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.config import get_settings

    monkeypatch.setenv("SECURESCAN_SCANNERS_DIR", str(REPO_SCANNERS))
    get_settings.cache_clear()
    clear_catalogue_cache()


def profile_yaml(**changes: Any) -> str:
    base: dict[str, Any] = {"profile": "team-profile", "kind": "sast", "jobs": [{"tool": "semgrep"}, {"tool": "gitleaks"}]}
    base.update(changes)
    return yaml.safe_dump(base)


def stored_profile(**changes: Any) -> ScanProfile:
    values: dict[str, Any] = {
        "id": uuid.uuid4(), "name": "code-standard", "version": 1, "kind": "sast", "description": "d",
        "body_yaml": "profile: code-standard", "body": {"jobs": [{"tool": "semgrep"}, {"tool": "gitleaks"}]},
        "sha256": "a" * 64, "active": True, "created_at": utcnow(),
    }  # fmt: skip
    values.update(changes)
    return ScanProfile(**values)


def test_profiles_are_listed_with_their_tools() -> None:
    client, _fake, _user = build_app(session=FakeSession(rows=[stored_profile()]))
    response = client.get("/api/v1/profiles")
    assert response.status_code == 200, response.text
    item = response.json()["items"][0]
    assert item["name"] == "code-standard" and item["tools"] == ["semgrep", "gitleaks"] and item["version"] == 1
    assert "body_yaml" not in item


def test_profile_detail_includes_the_yaml() -> None:
    row = stored_profile()
    client, _fake, _user = build_app(session=FakeSession(rows=[row]))
    detail = client.get(f"/api/v1/profiles/{row.id}").json()
    assert detail["body_yaml"] == "profile: code-standard" and detail["body"]["jobs"][0]["tool"] == "semgrep"


def test_only_admins_add_profiles() -> None:
    client, _fake, _user = build_app(UserRole.ANALYST)
    response = client.post("/api/v1/profiles", json={"yaml": profile_yaml()})
    assert response.status_code == 403 and response.json()["code"] == "auth.insufficient_role"


def test_an_admin_adds_the_first_version(catalogue_env: None) -> None:
    client, fake, admin = build_app(UserRole.ADMIN)
    response = client.post("/api/v1/profiles", json={"yaml": profile_yaml()})
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["name"] == "team-profile" and body["version"] == 1 and body["tools"] == ["semgrep", "gitleaks"]
    rows = [r for r in fake.added if isinstance(r, ScanProfile)]
    assert len(rows) == 1 and rows[0].created_by_id == admin.id and rows[0].body["version"] == 1
    assert any(getattr(r, "action", "") == "profile.create" for r in fake.added)
    assert fake.commits == 1


class LatestVersion(FakeSession):
    async def scalar(self, stmt: Any) -> Any:
        return 2


def test_a_new_profile_version_follows_the_latest(catalogue_env: None) -> None:
    client, fake, _admin = build_app(UserRole.ADMIN, session=LatestVersion())
    assert client.post("/api/v1/profiles", json={"yaml": profile_yaml()}).json()["version"] == 3
    mismatch = client.post("/api/v1/profiles", json={"yaml": profile_yaml(version=7)})
    assert mismatch.status_code == 422 and mismatch.json()["code"] == "profile.version_mismatch"
    assert client.post("/api/v1/profiles", json={"yaml": profile_yaml(version=3)}).status_code == 201


@pytest.mark.parametrize(
    "text",
    [
        "just: text, not a profile\n" * 2,
        yaml.safe_dump({"profile": "x", "kind": "sast", "jobs": []}),
        yaml.safe_dump({"profile": "team-profile", "kind": "sast", "jobs": [{"tool": "codeql"}]}),
        yaml.safe_dump({"profile": "team-profile", "kind": "sast", "jobs": [{"tool": "semgrep", "limits": {"memory": "999g"}}]}),
    ],
)
def test_invalid_profiles_are_422_problems_with_details(text: str, catalogue_env: None) -> None:
    client, fake, _admin = build_app(UserRole.ADMIN)
    response = client.post("/api/v1/profiles", json={"yaml": text})
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "profile.invalid" and body["errors"]
    assert not [r for r in fake.added if isinstance(r, ScanProfile)]


def test_profiles_can_be_switched_off_by_an_admin() -> None:
    row = stored_profile()
    client, fake, _admin = build_app(UserRole.ADMIN, session=FakeSession(rows=[row]))
    response = client.patch(f"/api/v1/profiles/{row.id}", json={"active": False})
    assert response.status_code == 200 and response.json()["active"] is False and row.active is False
    assert any(getattr(r, "action", "") == "profile.update" for r in fake.added)
    analyst, _f, _u = build_app(UserRole.ANALYST, session=FakeSession(rows=[stored_profile()]))
    assert analyst.patch(f"/api/v1/profiles/{row.id}", json={"active": True}).status_code == 403
