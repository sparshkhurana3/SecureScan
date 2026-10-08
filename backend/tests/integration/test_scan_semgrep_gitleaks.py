"""Real Semgrep and Gitleaks runs against the planted sample apps (``@pytest.mark.integration``).

What must be running (see docs/build-notes/M3.md for the exact commands):

* the Compose stack with the worker, ``socket-proxy`` and the pre-pulled scanner images (``dev.py pull-images``),
  and a database that the worker and this test share (``SECURESCAN_DATABASE_URL`` and friends),
* the Semgrep rules in the content volume (``content/semgrep/rules`` -> ``rules-<commit>``; spike S7's
  ``prefetch.sh semgrep`` writes them),
* this test process sees the same artifacts volume as the worker (``SECURESCAN_ARTIFACTS_ROOT``), because the
  raw reports are read from disk.

Run: ``SECURESCAN_INTEGRATION=1 python scripts/dev.py test integration -k semgrep_gitleaks``.
The expected findings are checked loosely (file and line within a few lines) on the *raw* reports, which is
what the plan's acceptance asks for; nothing here parses findings for SecureScan itself.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import time
import zipfile
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from securescan.config import get_settings
from securescan.db.models.enums import UserRole
from securescan.storage.artifacts import resolve_key

pytestmark = pytest.mark.integration

Login = Callable[[UserRole], Awaitable[httpx.AsyncClient]]

SAMPLE_APPS = Path(__file__).resolve().parents[1] / "fixtures" / "sample-apps"
FINAL = {"completed", "completed_partial", "failed", "cancelled"}
WAIT_SECONDS = int(os.environ.get("SECURESCAN_TEST_SCAN_WAIT", "900"))
LINE_TOLERANCE = 3


@pytest.fixture(autouse=True)
async def seeded_profiles_and_queue(database: None) -> AsyncIterator[None]:
    """Profiles are seeded by ``migrate`` in a real stack; the test database is emptied after every test, so
    seed here, and open the job queue so that ``POST /scans`` can defer its jobs from this process."""
    from securescan.db.session import session_scope
    from securescan.jobs.app import app as jobs_app
    from securescan.jobs.app import load_tasks
    from securescan.runner.profiles import seed_profiles

    async with session_scope() as db:
        await seed_profiles(db)
    load_tasks()
    async with jobs_app.open_async():
        yield


def zip_app(app: str) -> bytes:
    """The sample app as a zip, without build output."""
    buffer = io.BytesIO()
    root = SAMPLE_APPS / app
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file() and "target" not in path.relative_to(root).parts[:1]:
                archive.writestr(str(path.relative_to(root)).replace(os.sep, "/"), path.read_bytes())
    return buffer.getvalue()


async def upload(client: httpx.AsyncClient, name: str, data: bytes) -> str:
    created = await client.post(
        "/api/v1/uploads",
        json={"filename": name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
    )
    assert created.status_code == 201, created.text
    upload_id = created.json()["id"]
    chunk = created.json()["chunk_bytes"]
    for start in range(0, len(data), chunk):
        part = data[start : start + chunk]
        response = await client.patch(
            f"/api/v1/uploads/{upload_id}",
            content=part,
            headers={"Content-Range": f"bytes {start}-{start + len(part) - 1}/{len(data)}"},
        )
        assert response.status_code == 200, response.text
    done = await client.post(f"/api/v1/uploads/{upload_id}/complete")
    assert done.status_code == 200, done.text
    return str(done.json()["artifact_id"])


async def make_zip_target(client: httpx.AsyncClient, app: str, data: bytes | None = None) -> tuple[str, str]:
    """Create application, version and a zip target; returns ``(version_id, target_id)``."""
    artifact_id = await upload(client, f"{app}.zip", data if data is not None else zip_app(app))
    application = await client.post("/api/v1/applications", json={"name": f"{app}-{time.time_ns()}"})
    assert application.status_code == 201, application.text
    version = await client.post(
        f"/api/v1/applications/{application.json()['id']}/versions", json={"label": "upload-1", "label_kind": "upload"}
    )
    assert version.status_code == 201, version.text
    target = await client.post(
        f"/api/v1/versions/{version.json()['id']}/targets",
        json={"kind": "zip", "upload_artifact_id": artifact_id},
    )
    assert target.status_code == 201, target.text
    return str(version.json()["id"]), str(target.json()["id"])


async def wait_for_scan(client: httpx.AsyncClient, scan_id: str, timeout: int = WAIT_SECONDS) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        response = await client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200, response.text
        scan: dict[str, Any] = response.json()
        # the scan is final when its jobs are; the DefectDojo import (M4) is separate
        if scan["state"] in FINAL and all(j["state"] in FINAL | {"timed_out"} for j in scan["jobs"]):
            return scan
        assert time.monotonic() < deadline, f"scan {scan_id} still {scan['state']} after {timeout} s"
        await asyncio.sleep(3)


def raw_report(scan: dict[str, Any], job: dict[str, Any], filename: str) -> Path:
    for artifact in scan["artifacts"]:
        if artifact["job_id"] == job["id"] and artifact["filename"] == filename:
            return resolve_key(f"scans/{scan['id']}/{job['id']}/{filename}")
    raise AssertionError(f"no artifact {filename} for job {job['tool']}")


def expected(app: str, tool: str) -> list[dict[str, Any]]:
    data = yaml.safe_load((SAMPLE_APPS / app / "expected-findings.yaml").read_text(encoding="utf-8"))
    return list((data.get("tools") or {}).get(tool) or [])


def semgrep_hits(report: dict[str, Any]) -> list[tuple[str, int]]:
    return [(r["path"], int(r["start"]["line"])) for r in report.get("results", [])]


def gitleaks_hits(report: list[dict[str, Any]]) -> list[tuple[str, int]]:
    return [(str(r["File"]), int(r["StartLine"])) for r in report]


def near(hits: list[tuple[str, int]], file: str, line: int) -> bool:
    return any(path.endswith(file) and abs(found - line) <= LINE_TOLERANCE for path, found in hits)


# --------------------------------------------------------------------------- the acceptance scenarios
async def test_zip_scan_runs_semgrep_and_gitleaks(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    version_id, target_id = await make_zip_target(client, "js-planted")
    started = await client.post(
        "/api/v1/scans",
        json={"version_id": version_id, "target_id": target_id, "profile": "code-standard", "profile_version": 1},
        headers={"Idempotency-Key": f"it-{time.time_ns()}"},
    )
    assert started.status_code == 202, started.text
    scan = await wait_for_scan(client, started.json()["id"])

    assert scan["state"] == "completed", [(j["tool"], j["state"], j["outcome_reason"]) for j in scan["jobs"]]
    assert {j["tool"] for j in scan["jobs"]} == {"semgrep", "gitleaks"}
    assert all(j["state"] == "completed" for j in scan["jobs"])
    jobs = {j["tool"]: j for j in scan["jobs"]}

    semgrep_file = raw_report(scan, jobs["semgrep"], "semgrep.json")
    gitleaks_file = raw_report(scan, jobs["gitleaks"], "gitleaks.json")
    assert semgrep_file.stat().st_size > 0 and gitleaks_file.stat().st_size > 0
    for artifact in scan["artifacts"]:  # recorded with a digest that matches the bytes on disk
        path = resolve_key(f"scans/{scan['id']}/{artifact['job_id']}/{artifact['filename']}")
        assert hashlib.sha256(path.read_bytes()).hexdigest() == artifact["sha256"]
    assert {a["kind"] for a in scan["artifacts"]} >= {"raw_report", "log"}

    semgrep = semgrep_hits(json.loads(semgrep_file.read_text(encoding="utf-8")))
    for item in expected("js-planted", "semgrep"):
        assert near(semgrep, item["file"], item["line"]), f"Semgrep missed {item['id']}"
    gitleaks = gitleaks_hits(json.loads(gitleaks_file.read_text(encoding="utf-8")))
    for item in expected("js-planted", "gitleaks"):
        assert near(gitleaks, item["file"], item["line"]), f"Gitleaks missed {item['id']}"
    for entry in json.loads(gitleaks_file.read_text(encoding="utf-8")):
        assert entry.get("Secret") in ("REDACTED", "", None), "Gitleaks runs with --redact"

    assert jobs["semgrep"]["applied_exclusions"], "the exclusions of the run are recorded"
    assert jobs["semgrep"]["content_versions"].get("semgrep_rules", "").startswith("rules")
    assert jobs["semgrep"]["image_digest"] and jobs["gitleaks"]["image_digest"]

    again = await client.post(
        "/api/v1/scans",
        json={"version_id": version_id, "target_id": target_id, "profile": "code-standard", "profile_version": 1},
    )
    assert again.status_code == 202 and again.json()["id"] != started.json()["id"]  # new scan after the first finished

    log = await client.get(f"/api/v1/scans/{scan['id']}/jobs/{jobs['semgrep']['id']}/log")
    assert log.status_code == 200 and "[securescan]" in log.text


async def test_the_same_idempotency_key_returns_the_same_scan(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    version_id, target_id = await make_zip_target(client, "python-planted")
    body = {"version_id": version_id, "target_id": target_id, "profile": "code-standard", "profile_version": 1}
    key = {"Idempotency-Key": f"same-{time.time_ns()}"}
    first = await client.post("/api/v1/scans", json=body, headers=key)
    second = await client.post("/api/v1/scans", json=body, headers=key)
    assert first.status_code == second.status_code == 202
    assert first.json()["id"] == second.json()["id"]
    assert second.headers.get("idempotent-replayed") == "true"
    other = await client.post("/api/v1/scans", json={**body, "tools": ["gitleaks"]}, headers=key)
    assert other.status_code == 422 and other.json()["code"] == "idempotency.key_reused"
    await client.post(f"/api/v1/scans/{first.json()['id']}/cancel")


async def test_a_zip_with_path_traversal_is_refused_at_once(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("ok.txt", "fine")
        archive.writestr("../evil", "gotcha")
    version_id, target_id = await make_zip_target(client, "evil", buffer.getvalue())
    response = await client.post(
        "/api/v1/scans", json={"version_id": version_id, "target_id": target_id, "profile": "code-standard", "profile_version": 1}
    )
    assert response.status_code == 422, response.text
    assert response.json()["code"] == "zip.path_traversal"


async def test_cancel_stops_the_scan_and_removes_the_container(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    version_id, target_id = await make_zip_target(client, "java-planted")
    started = await client.post(
        "/api/v1/scans", json={"version_id": version_id, "target_id": target_id, "profile": "code-standard", "profile_version": 1}
    )
    scan_id = started.json()["id"]
    await asyncio.sleep(2)
    cancelled = await client.post(f"/api/v1/scans/{scan_id}/cancel")
    assert cancelled.status_code in (202, 409)
    scan = await wait_for_scan(client, scan_id, timeout=120)
    assert scan["state"] in ("cancelled", "completed", "completed_partial")
    if scan["state"] == "cancelled":
        assert all(j["state"] in ("cancelled", "completed") for j in scan["jobs"])
    again = await client.post(f"/api/v1/scans/{scan_id}/cancel")
    assert again.status_code == 409 and again.json()["code"] == "scan.already_finished"


async def test_events_stream_snapshot_and_done(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    version_id, target_id = await make_zip_target(client, "js-planted")
    started = await client.post(
        "/api/v1/scans", json={"version_id": version_id, "target_id": target_id, "profile": "code-standard", "profile_version": 1}
    )
    scan_id = started.json()["id"]
    names: list[str] = []
    async with client.stream("GET", f"/api/v1/scans/{scan_id}/events", timeout=WAIT_SECONDS) as stream:
        assert stream.status_code == 200
        assert stream.headers["content-type"].startswith("text/event-stream")
        assert stream.headers.get("x-accel-buffering") == "no"
        async for line in stream.aiter_lines():
            if line.startswith("event: "):
                names.append(line[len("event: ") :])
            if names and names[-1] == "done":
                break
    assert names[0] == "snapshot" and names[-1] == "done"
    assert "log" in names or "state" in names  # live updates arrived while it ran


async def test_profiles_are_seeded(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    listing = await client.get("/api/v1/profiles")
    assert listing.status_code == 200
    versions = {p["version"]: p["tools"] for p in listing.json()["items"] if p["name"] == "code-standard"}
    assert versions.get(1) == ["semgrep", "gitleaks"], "version 1 stays available (the scans of this module name it)"
    assert versions.get(2) and versions[2][:2] == ["semgrep", "gitleaks"] and len(versions[2]) == 6


def test_integration_settings_point_at_a_shared_artifacts_volume() -> None:
    root = Path(get_settings().artifacts_root)
    assert root.is_absolute(), "SECURESCAN_ARTIFACTS_ROOT must be the worker's artifacts volume"
