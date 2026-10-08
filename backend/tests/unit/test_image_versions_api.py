"""The image-versions endpoints: roles, the approval rules, audit events, secrets kept out of the output."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from securescan.api import image_versions as api
from securescan.api.problems import install_problem_handlers
from securescan.auth.roles import CurrentUser, current_user
from securescan.db.models.enums import UserRole
from securescan.db.session import get_session
from tests.unit.conftest import FakeSession
from tests.unit.test_image_updates import D1, D2, make_row


def build(role: UserRole = UserRole.ADMIN, session: FakeSession | None = None) -> tuple[TestClient, FakeSession, CurrentUser]:
    app = FastAPI()
    install_problem_handlers(app)
    app.include_router(api.router, prefix="/api/v1")
    fake = session or FakeSession()
    user = CurrentUser(
        id=uuid.uuid4(), oid="oid", name="Admin", email="admin@example.com", role=role,
        session_id=uuid.uuid4(), csrf_token="csrf",
    )  # fmt: skip

    async def db() -> AsyncIterator[FakeSession]:
        yield fake

    app.dependency_overrides[get_session] = db
    app.dependency_overrides[current_user] = lambda: user
    return TestClient(app), fake, user


def actions(session: FakeSession) -> list[str]:
    return [o.action for o in session.added if hasattr(o, "action")]


def test_every_endpoint_is_admin_only() -> None:
    client, _, _ = build(UserRole.ANALYST)
    row = uuid.uuid4()
    for method, path in (
        ("get", "/api/v1/image-versions"),
        ("get", "/api/v1/image-versions/%s" % row),
        ("post", "/api/v1/image-versions/check"),
        ("post", "/api/v1/image-versions/%s/approve" % row),
        ("post", "/api/v1/image-versions/%s/reject" % row),
        ("post", "/api/v1/image-versions/%s/deactivate" % row),
        ("post", "/api/v1/image-versions/%s/regression" % row),
    ):
        response = getattr(client, method)(path, **({"json": {}} if method == "post" else {}))
        assert response.status_code == 403, (method, path, response.text)


def test_get_shows_the_row_without_the_candidate_token() -> None:
    row = make_row(regression_result="testing")
    client, _, _ = build(session=FakeSession(rows=[row]))
    body = client.get("/api/v1/image-versions/%s" % row.id).json()
    assert body["state"] == "pending" and body["regression_result"] == "testing"
    assert body["scope"] == "runtime" and body["previous_tag"] == "1.179.0-nonroot"
    assert "candidate_token" not in str(body) and "secret" not in str(body)
    assert body["lock_line"].endswith("digest: %s }" % D2)


def test_approve_makes_the_image_active_and_audits() -> None:
    old = make_row(active=True, approved=True, digest=D1)
    row = make_row()
    client, fake, user = build(session=FakeSession(rows=[old, row]))
    response = client.post("/api/v1/image-versions/%s/approve" % row.id, json={})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "active" and body["active"] is True and body["approved_by_id"] == str(user.id)
    assert old.active is False
    assert actions(fake) == ["image.approve"] and fake.commits == 1


def test_approve_refuses_a_failed_regression() -> None:
    row = make_row(regression_result="failed")
    client, fake, _ = build(session=FakeSession(rows=[row]))
    response = client.post("/api/v1/image-versions/%s/approve" % row.id, json={})
    assert response.status_code == 409 and response.json()["code"] == "image.regression_not_passed"
    assert row.active is False and fake.commits == 0


def test_approve_of_an_untested_image_needs_the_acknowledgement() -> None:
    row = make_row(regression_result="skipped")
    client, _, _ = build(session=FakeSession(rows=[row]))
    refused = client.post("/api/v1/image-versions/%s/approve" % row.id, json={})
    assert refused.status_code == 422 and refused.json()["code"] == "image.ack_required"
    accepted = client.post("/api/v1/image-versions/%s/approve" % row.id, json={"acknowledge_skipped": True})
    assert accepted.status_code == 200 and accepted.json()["state"] == "active"


def test_a_platform_image_cannot_be_approved_here() -> None:
    row = make_row(regression_result="skipped", regression_detail={"scope": "release", "lock_name": "POSTGRES"})
    client, _, _ = build(session=FakeSession(rows=[row]))
    response = client.post("/api/v1/image-versions/%s/approve" % row.id, json={"acknowledge_skipped": True})
    assert response.status_code == 409 and response.json()["code"] == "image.release_scope"


def test_reject_and_deactivate() -> None:
    pending = make_row()
    active = make_row(active=True, approved=True, tag="1.179.0-nonroot", digest=D1)
    client, fake, _ = build(session=FakeSession(rows=[pending, active]))
    rejected = client.post("/api/v1/image-versions/%s/reject" % pending.id, json={"note": "breaks our rules"})
    assert rejected.status_code == 200 and rejected.json()["state"] == "rejected"
    assert pending.notes == "breaks our rules"
    deactivated = client.post("/api/v1/image-versions/%s/deactivate" % active.id)
    assert deactivated.status_code == 200 and deactivated.json()["state"] == "retired"
    assert actions(fake) == ["image.reject", "image.deactivate"]
    again = client.post("/api/v1/image-versions/%s/deactivate" % active.id)
    assert again.status_code == 409 and again.json()["code"] == "image.not_active"


def test_unknown_ids_are_404() -> None:
    client, _, _ = build()
    assert client.get("/api/v1/image-versions/%s" % uuid.uuid4()).status_code == 404
    assert client.post("/api/v1/image-versions/%s/approve" % uuid.uuid4(), json={}).status_code == 404


def test_check_now_queues_a_run(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.jobs import image_updates

    queued: list[int] = []

    async def fake_queue() -> int | None:
        queued.append(1)
        return 7 if len(queued) == 1 else None

    monkeypatch.setattr(image_updates, "queue_check_now", fake_queue)
    client, fake, _ = build()
    first = client.post("/api/v1/image-versions/check")
    assert first.status_code == 202 and first.json()["queued"] is True
    second = client.post("/api/v1/image-versions/check")
    assert second.json()["queued"] is False
    assert actions(fake) == ["image.check", "image.check"]


def test_regression_rerun_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.jobs import image_updates

    async def fake_queue(image_version_id: str) -> int | None:
        return 3

    monkeypatch.setattr(image_updates, "queue_regression", fake_queue)
    failed = make_row(regression_result="failed")
    running = make_row(regression_result="testing")
    release = make_row(regression_detail={"scope": "release"}, regression_result="skipped")
    decided = make_row(active=True, approved=True)
    client, _, _ = build(session=FakeSession(rows=[failed, running, release, decided]))
    ok = client.post("/api/v1/image-versions/%s/regression" % failed.id)
    assert ok.status_code == 202 and failed.regression_result == "pending"
    assert client.post("/api/v1/image-versions/%s/regression" % running.id).json()["code"] == "image.regression_running"
    assert client.post("/api/v1/image-versions/%s/regression" % release.id).json()["code"] == "image.release_scope"
    assert client.post("/api/v1/image-versions/%s/regression" % decided.id).json()["code"] == "image.not_pending"


def test_state_of_covers_every_row_kind() -> None:
    assert api.state_of(make_row()) == "pending"
    assert api.state_of(make_row(active=True, approved=True)) == "active"
    assert api.state_of(make_row(approved=True)) == "retired"
    assert api.state_of(make_row(source="rejected")) == "rejected"


def test_the_module_exposes_the_router_the_api_includes_automatically() -> None:
    paths: Any = {route.path for route in api.router.routes}  # type: ignore[attr-defined]
    assert "/image-versions" in paths and "/image-versions/{image_version_id}/approve" in paths
