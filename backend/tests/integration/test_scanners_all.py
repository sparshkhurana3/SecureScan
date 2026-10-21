"""M8 against the real stack: every code tool on ``java-planted``, an image scan, the stale Grype database
and the content updaters (``@pytest.mark.integration``).

What must be running: the Compose stack (worker, socket-proxy, database, DefectDojo), the pre-pulled scanner images
(``dev.py pull-images``) including the self-built SpotBugs image, rules and databases installed (the worker queues
their first update at start-up; wait for ``GET /api/v1/scanner-health`` to show every feed with a version). The
committed jar of ``java-planted`` must exist (``sh scripts/build_planted_jar.sh``).

Optional scenarios, each skipped unless its variable is set (they need things only the operator can provide):

* ``SECURESCAN_TEST_IMAGE``: a registry reference of a Java application image, for the image scan;
* ``SECURESCAN_TEST_GRYPE_STALE=1``: the worker was started with ``SECURESCAN_GRYPE_DB_MAX_AGE=1h`` (stale-database check);
* ``SECURESCAN_TEST_UPDATERS=1``: start the Semgrep rules update and expect an active version afterwards (needs egress to GitHub).

Run: ``SECURESCAN_INTEGRATION=1 python scripts/dev.py test integration -k scanners_all``.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from securescan.db.models.enums import UserRole
from securescan.storage.artifacts import resolve_key
from tests.integration.test_scan_semgrep_gitleaks import (
    FINAL,
    SAMPLE_APPS,
    WAIT_SECONDS,
    Login,
    make_zip_target,
    wait_for_scan,
)

pytestmark = pytest.mark.integration

CODE_TOOLS = ["semgrep", "gitleaks", "syft-grype", "spotbugs"]
JAVA_PLANTED = SAMPLE_APPS / "java-planted"


@pytest.fixture(autouse=True)
async def seeded_profiles_and_queue(database: None) -> Any:
    """Profiles are seeded by ``migrate`` in a real stack; the test database is emptied after every test."""
    from securescan.db.session import session_scope
    from securescan.jobs.app import app as jobs_app
    from securescan.jobs.app import load_tasks
    from securescan.runner.profiles import seed_profiles

    async with session_scope() as db:
        await seed_profiles(db)
    load_tasks()
    async with jobs_app.open_async():
        yield


def zip_with_jar(app: str) -> bytes:
    """The sample app as a zip **including** its committed ``target/*.jar`` (the M3 helper leaves ``target`` out)."""
    buffer = io.BytesIO()
    root = SAMPLE_APPS / app
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                archive.writestr(str(path.relative_to(root)).replace(os.sep, "/"), path.read_bytes())
    return buffer.getvalue()


def expected(app: str, tool: str) -> list[dict[str, Any]]:
    data = yaml.safe_load((SAMPLE_APPS / app / "expected-findings.yaml").read_text(encoding="utf-8"))
    return list((data.get("tools") or {}).get(tool) or [])


def artifact_path(scan: dict[str, Any], job: dict[str, Any], filename: str) -> Path:
    for artifact in scan["artifacts"]:
        if artifact["job_id"] == job["id"] and artifact["filename"] == filename:
            return resolve_key(f"scans/{scan['id']}/{job['id']}/{filename}")
    raise AssertionError(f"no artifact {filename} for job {job['tool']}: {[a['filename'] for a in scan['artifacts']]}")


async def run_scan(client: httpx.AsyncClient, version_id: str, target_id: str, **body: Any) -> dict[str, Any]:
    started = await client.post(
        "/api/v1/scans",
        json={"version_id": version_id, "target_id": target_id, "profile": "code-standard", **body},
        headers={"Idempotency-Key": f"m8-{time.time_ns()}"},
    )
    assert started.status_code == 202, started.text
    return await wait_for_scan(client, started.json()["id"], timeout=max(WAIT_SECONDS, 3600))


def jobs_by_tool(scan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {j["tool"]: j for j in scan["jobs"]}


def explain(scan: dict[str, Any]) -> list[tuple[str, str, str | None]]:
    return [(j["tool"], j["state"], j["outcome_reason"]) for j in scan["jobs"]]


# --------------------------------------------------------------------------- the acceptance scenario
async def test_every_code_tool_runs_on_the_planted_java_app(api_as: Login) -> None:
    if not list((JAVA_PLANTED / "target").glob("*.jar")):
        pytest.skip("build the planted jar first: sh scripts/build_planted_jar.sh")
    client = await api_as(UserRole.ANALYST)
    version_id, target_id = await make_zip_target(client, "java-planted", zip_with_jar("java-planted"))
    scan = await run_scan(client, version_id, target_id)
    jobs = jobs_by_tool(scan)
    assert set(jobs) == set(CODE_TOOLS), explain(scan)
    for tool, job in jobs.items():
        assert job["state"] in ("completed", "completed_partial"), (tool, explain(scan))
        assert job["image_digest"], f"{tool}: the image digest is recorded"
    assert not any((job["outcome_reason"] or "").startswith("Skipped") for job in jobs.values()), explain(scan)

    # raw reports, the SBOMs and the content versions that were used
    for tool, filename in (("syft-grype", "grype.json"), ("spotbugs", "spotbugs.xml")):
        assert artifact_path(scan, jobs[tool], filename).stat().st_size > 0, tool
    sboms = [a for a in scan["artifacts"] if a["kind"] == "sbom"]
    assert {a["filename"] for a in sboms} == {"sbom.syft.json", "sbom.cdx.json"}
    cyclonedx = json.loads(artifact_path(scan, jobs["syft-grype"], "sbom.cdx.json").read_text(encoding="utf-8"))
    assert len(cyclonedx.get("components", [])) > 0, "the SBOM lists the declared dependencies"
    assert jobs["syft-grype"]["content_versions"].get("grype_db")

    # SpotBugs analysed the committed jar, with Find Security Bugs
    spotbugs = artifact_path(scan, jobs["spotbugs"], "spotbugs.xml").read_text(encoding="utf-8")
    assert "<BugCollection" in spotbugs
    assert all(item["id"] for item in expected("java-planted", "spotbugs")), "the expectation files stay readable"

    # each report was handed to DefectDojo (M4); the import itself is checked by the DefectDojo tests
    for _ in range(60):
        refreshed = (await client.get(f"/api/v1/scans/{scan['id']}")).json()
        if all(j["import_state"] in ("imported", "failed") for j in refreshed["jobs"]):
            break
        await asyncio.sleep(5)
    assert all(j["import_state"] == "imported" for j in refreshed["jobs"]), [(j["tool"], j["import_state"]) for j in refreshed["jobs"]]


async def test_a_c_sharp_only_source_skips_spotbugs_with_a_coverage_note(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    version_id, target_id = await make_zip_target(client, "csharp-planted")
    scan = await run_scan(client, version_id, target_id, tools=["spotbugs"])
    jobs = jobs_by_tool(scan)
    assert scan["state"] in FINAL
    assert jobs["spotbugs"]["state"] == "completed" and "no compiled classes found" in (jobs["spotbugs"]["coverage_note"] or "")
    assert all((j["outcome_reason"] or "").startswith("Skipped") for j in jobs.values())


async def test_one_scanner_runs_at_a_time_for_three_queued_scans(api_as: Login) -> None:
    """Every scan tool shares the catalogue lock ``scanner``: at no moment do two scan jobs run (4 vCPU / 8 GB sizing)."""
    client = await api_as(UserRole.ANALYST)
    scan_ids = []
    for app in ("js-planted", "python-planted", "java-planted"):
        version_id, target_id = await make_zip_target(client, app)
        started = await client.post(
            "/api/v1/scans", json={"version_id": version_id, "target_id": target_id, "profile": "code-standard", "tools": ["semgrep", "gitleaks"]}
        )
        assert started.status_code == 202, started.text
        scan_ids.append(started.json()["id"])
    deadline = time.monotonic() + max(WAIT_SECONDS, 3600)
    while time.monotonic() < deadline:
        scans = [(await client.get(f"/api/v1/scans/{sid}")).json() for sid in scan_ids]
        running = [j for s in scans for j in s["jobs"] if j["state"] in ("preparing", "running")]
        assert len(running) <= 1, "two scan jobs run at once: %s" % [j["tool"] for j in running]
        if all(s["state"] in FINAL for s in scans):
            return
        await asyncio.sleep(2)
    raise AssertionError("the three scans did not finish")


# --------------------------------------------------------------------------- an image
async def test_an_image_reference_is_scanned_through_syft_spotbugs_and_the_file_tools(api_as: Login) -> None:
    reference = os.environ.get("SECURESCAN_TEST_IMAGE")
    if not reference:
        pytest.skip("set SECURESCAN_TEST_IMAGE to a Java application image reference")
    client = await api_as(UserRole.ANALYST)
    application = await client.post("/api/v1/applications", json={"name": f"image-{time.time_ns()}"})
    version = await client.post(
        f"/api/v1/applications/{application.json()['id']}/versions", json={"label": "image-1", "label_kind": "image"}
    )
    target = await client.post(f"/api/v1/versions/{version.json()['id']}/targets", json={"kind": "image", "locator": reference})
    assert target.status_code == 201, target.text
    scan = await run_scan(client, version.json()["id"], target.json()["id"])
    jobs = jobs_by_tool(scan)
    assert scan["state"] in ("completed", "completed_partial"), explain(scan)
    assert jobs["syft-grype"]["state"] in ("completed", "completed_partial")
    assert artifact_path(scan, jobs["syft-grype"], "sbom.syft.json").stat().st_size > 0
    assert jobs["spotbugs"]["state"] == "completed", explain(scan)
    for tool in ("semgrep", "gitleaks"):
        assert jobs[tool]["state"] in ("completed", "completed_partial"), (tool, explain(scan))


# --------------------------------------------------------------------------- the stale Grype database
async def test_a_stale_grype_database_fails_the_job_visibly(api_as: Login) -> None:
    if os.environ.get("SECURESCAN_TEST_GRYPE_STALE") != "1":
        pytest.skip("start the worker with SECURESCAN_GRYPE_DB_MAX_AGE=1h and set SECURESCAN_TEST_GRYPE_STALE=1")
    client = await api_as(UserRole.ANALYST)
    version_id, target_id = await make_zip_target(client, "python-planted")
    scan = await run_scan(client, version_id, target_id, tools=["syft-grype"])
    job = jobs_by_tool(scan)["syft-grype"]
    assert job["state"] == "failed"
    assert "older than the allowed" in (job["outcome_reason"] or ""), job["outcome_reason"]


# --------------------------------------------------------------------------- scanner health and the updaters
async def test_scanner_health_shows_digests_and_feed_ages(api_as: Login) -> None:
    client = await api_as(UserRole.ADMIN)
    response = await client.get("/api/v1/scanner-health")
    assert response.status_code == 200, response.text
    body = response.json()
    tools = {t["tool"]: t for t in body["tools"]}
    assert set(CODE_TOOLS) <= set(tools)
    assert all(tools[t]["digest"] and tools[t]["digest"].startswith("sha256:") for t in ("semgrep", "gitleaks")), "images are pinned by digest"
    assert {f["feed"] for f in body["feeds"]} == {"grype_db", "semgrep_rules", "nuclei_templates"}
    versions = await client.get("/api/v1/content-versions", params={"active": "true"})
    assert versions.status_code == 200 and isinstance(versions.json()["items"], list)
    analyst = await api_as(UserRole.ANALYST)
    assert (await analyst.get("/api/v1/scanner-health")).status_code == 403


async def test_the_rules_update_promotes_a_version_behind_the_gate(api_as: Login) -> None:
    if os.environ.get("SECURESCAN_TEST_UPDATERS") != "1":
        pytest.skip("set SECURESCAN_TEST_UPDATERS=1 (needs egress to GitHub and the planted apps)")
    client = await api_as(UserRole.ADMIN)
    started = await client.post("/api/v1/content-versions/updates", json={"feed": "semgrep_rules"})
    assert started.status_code == 202, started.text
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        health = (await client.get("/api/v1/scanner-health")).json()
        feed = next(f for f in health["feeds"] if f["feed"] == "semgrep_rules")
        if feed["version"] and not feed["update_failed"] and feed["age_seconds"] is not None and feed["age_seconds"] < 3600:
            assert feed["version"].startswith("rules-") and not feed["stale"]
            return
        if feed["update_failed"]:
            versions = (await client.get("/api/v1/content-versions", params={"feed": "semgrep_rules"})).json()["items"]
            raise AssertionError(f"the update failed; the previous version stays active: {versions[:2]}")
        await asyncio.sleep(15)
    raise AssertionError("the rules update did not finish in time")
