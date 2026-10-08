"""Web scans against OWASP Juice Shop (``@pytest.mark.integration``): the environment rule, the proxy, the lock.

What must be running (see docs/build-notes/M9.md for the exact commands):

* the Compose stack with the worker, ``socket-proxy``, DefectDojo, and the pinned images pulled
  (``dev.py pull-images``: ZAP, Nuclei and squid), the Nuclei templates in the content volume
  (``content/nuclei-templates`` -> ``nuclei-templates-<date>``), ``SECURESCAN_EGRESS_IMAGE`` set for the worker,
* the Docker CLI on this machine (the tests start Juice Shop on the ``dast`` network with it) and
  ``SECURESCAN_TEST_JUICE_SHOP_IMAGE`` set to a pinned Juice Shop image (digest or exact tag),
* this test process sees the same artifacts volume as the worker (``SECURESCAN_ARTIFACTS_ROOT``).

Optionally ``SECURESCAN_TEST_CURL_IMAGE`` (a curl image) enables the "nothing can leave the dast network" check.
Run: ``SECURESCAN_INTEGRATION=1 python scripts/dev.py test integration -k test_dast``.

Juice Shop sits on the internal ``dast`` network, which the worker and the API cannot resolve, so the
targets are registered with an Admin's explicit host approval (``host_approved``). The squid access log of
each job is stored as the artifact ``dast-proxy-access.log``; the assertions read it.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx
import pytest

from securescan.config import get_settings
from securescan.db.models.enums import UserRole
from securescan.storage.artifacts import resolve_key

pytestmark = pytest.mark.integration

Login = Callable[[UserRole], Awaitable[httpx.AsyncClient]]

FINAL = {"completed", "completed_partial", "failed", "cancelled", "timed_out"}
SCAN_FINAL = {"completed", "completed_partial", "failed", "cancelled"}
JUICE_NAME = "securescan-test-juice-shop"
JUICE_URL = f"http://{JUICE_NAME}:3000/"
WAIT_SECONDS = int(os.environ.get("SECURESCAN_TEST_SCAN_WAIT", "3600"))


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check, timeout=300)  # noqa: S603, S607


@pytest.fixture
def juice_shop() -> Any:
    image = os.environ.get("SECURESCAN_TEST_JUICE_SHOP_IMAGE", "")
    if not image or shutil.which("docker") is None:
        pytest.skip("set SECURESCAN_TEST_JUICE_SHOP_IMAGE and install the Docker CLI")
    network = get_settings().network_dast
    docker("rm", "-f", JUICE_NAME, check=False)
    docker("run", "-d", "--rm", "--name", JUICE_NAME, "--network", network, image)
    deadline = time.monotonic() + 120
    while "listening on port 3000" not in docker("logs", JUICE_NAME, check=False).stdout.lower():
        assert time.monotonic() < deadline, "Juice Shop did not start"
        time.sleep(2)
    yield JUICE_URL
    docker("rm", "-f", JUICE_NAME, check=False)


async def make_target(admin: httpx.AsyncClient, environment: str, locator: str = JUICE_URL, **extra: Any) -> tuple[str, str]:
    """Application, version and an approved web target; returns ``(version_id, target_id)``."""
    application = await admin.post("/api/v1/applications", json={"name": f"juice-{environment}-{uuid.uuid4().hex[:8]}"})
    assert application.status_code == 201, application.text
    version = await admin.post(
        f"/api/v1/applications/{application.json()['id']}/versions", json={"label": "v1", "label_kind": "release"}
    )
    assert version.status_code == 201, version.text
    target = await admin.post(
        f"/api/v1/versions/{version.json()['id']}/targets",
        json={"kind": "url", "locator": locator, "environment": environment, "host_approved": True, **extra},
    )
    assert target.status_code == 201, target.text
    return str(version.json()["id"]), str(target.json()["id"])


async def wait_for_scan(client: httpx.AsyncClient, scan_id: str, timeout: int = WAIT_SECONDS) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        response = await client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200, response.text
        scan: dict[str, Any] = response.json()
        if scan["state"] in SCAN_FINAL and all(j["state"] in FINAL for j in scan["jobs"]):
            return scan
        assert time.monotonic() < deadline, f"scan {scan_id} still {scan['state']} after {timeout} s"
        await asyncio.sleep(5)


def artifact_text(scan: dict[str, Any], job: dict[str, Any], filename: str) -> str:
    for artifact in scan["artifacts"]:
        if artifact["job_id"] == job["id"] and artifact["filename"] == filename:
            return resolve_key(f"scans/{scan['id']}/{job['id']}/{filename}").read_text(encoding="utf-8", errors="replace")
    raise AssertionError(f"no artifact {filename} for job {job['tool']}")


def proxy_hosts(log: str) -> set[str]:
    hosts: set[str] = set()
    for line in log.splitlines():
        fields = line.split()
        if len(fields) > 6 and "DENIED" not in fields[3]:
            url = fields[6].split("://", 1)[-1]
            hosts.add(url.split("/", 1)[0].split(":", 1)[0])
    return hosts


@pytest.fixture
async def clients(api_as: Login) -> AsyncIterator[tuple[httpx.AsyncClient, httpx.AsyncClient]]:
    yield await api_as(UserRole.ADMIN), await api_as(UserRole.ANALYST)


# --------------------------------------------------------------------------- the environment rule (no scan has to run)
async def test_a_production_target_accepts_only_the_baseline(clients: tuple[httpx.AsyncClient, httpx.AsyncClient]) -> None:
    admin, analyst = clients
    _version, target = await make_target(admin, "production", locator="http://10.255.255.1:3000/")
    for profile in ("dast-full", "dast-api"):
        refused = await analyst.post(f"/api/v1/dast/targets/{target}/scans", json={"profile": profile})
        assert refused.status_code == 403, refused.text
        assert refused.headers["content-type"].startswith("application/problem+json")
        assert refused.json()["code"] == "dast.production_baseline_only"
        assert "baseline" in refused.json()["detail"]
    version_id = (await admin.get(f"/api/v1/targets/{target}")).json()["version_id"]
    direct = await analyst.post("/api/v1/scans", json={"version_id": version_id, "target_id": target, "profile": "dast-full"})
    assert direct.status_code == 403 and direct.json()["code"] == "dast.production_baseline_only"
    options = (await analyst.get(f"/api/v1/dast/targets/{target}/options")).json()
    allowed = {o["profile"] for o in options["options"] if o["allowed"]}
    assert allowed == {"dast-baseline"}
    accepted = await analyst.post(f"/api/v1/dast/targets/{target}/scans", json={})
    assert accepted.status_code == 202, accepted.text  # the default for production is the baseline
    cancelled = await analyst.post(f"/api/v1/scans/{accepted.json()['id']}/cancel")
    assert cancelled.status_code == 202


async def test_a_login_profile_cannot_be_attached_to_a_production_target(clients: tuple[httpx.AsyncClient, httpx.AsyncClient]) -> None:
    admin, analyst = clients
    created = await analyst.post(
        "/api/v1/dast/login-profiles",
        json={
            "name": f"login-{uuid.uuid4().hex[:6]}",
            "settings": {
                "method": "form", "login_page_url": "http://10.255.255.1/login", "login_request_url": "http://10.255.255.1/login",
                "login_request_body": "u={%username%}&p={%password%}", "logged_in_regex": "Sign out",
            },
            "username": "analyst", "password": "not-a-real-password",
        },
    )  # fmt: skip
    assert created.status_code == 201, created.text
    assert "not-a-real-password" not in created.text
    _version, target = await make_target(admin, "production", locator="http://10.255.255.1/")
    attach = await admin.patch(f"/api/v1/targets/{target}", json={"login_profile_id": created.json()["id"]})
    assert attach.status_code in (403, 422), attach.text
    assert (await analyst.delete(f"/api/v1/dast/login-profiles/{created.json()['id']}")).status_code == 200


async def test_check_endpoint_reports_the_allowlist(clients: tuple[httpx.AsyncClient, httpx.AsyncClient]) -> None:
    _admin, analyst = clients
    blocked = await analyst.post("/api/v1/dast/targets/check", json={"locator": "http://169.254.169.254/", "environment": "uat"})
    assert blocked.status_code == 200 and blocked.json()["allowed"] is False
    assert blocked.json()["code"] in ("dast.host_blocked", "dast.host_not_allowlisted")


# --------------------------------------------------------------------------- real scans
async def test_baseline_against_juice_shop_posts_nothing(
    clients: tuple[httpx.AsyncClient, httpx.AsyncClient], juice_shop: str
) -> None:
    admin, analyst = clients
    _version, target = await make_target(admin, "production", locator=juice_shop)
    started = await analyst.post(f"/api/v1/dast/targets/{target}/scans", json={"profile": "dast-baseline"})
    assert started.status_code == 202, started.text
    scan = await wait_for_scan(analyst, started.json()["id"])
    assert scan["state"] in ("completed", "completed_partial"), [(j["tool"], j["state"], j["outcome_reason"]) for j in scan["jobs"]]
    job = scan["jobs"][0]
    assert job["tool"] == "zap" and job["exit_code"] in (0, 1, 2) and job["image_digest"]
    report = artifact_text(scan, job, "zap.xml")
    assert "<OWASPZAPReport" in report
    access = artifact_text(scan, job, "dast-proxy-access.log")
    assert access.strip(), "the proxy log shows what ZAP requested"
    assert " POST " not in access, "the production baseline never posts forms"
    assert proxy_hosts(access) <= {JUICE_NAME}
    plan = artifact_text(scan, job, "zap-plan.yaml")
    assert "activeScan" not in plan and "postForm: false" in plan
    for _ in range(60):  # the DefectDojo import runs after the job
        detail = (await analyst.get(f"/api/v1/scans/{scan['id']}")).json()
        if detail["jobs"][0]["import_state"] in ("imported", "failed"):
            break
        await asyncio.sleep(5)
    assert detail["jobs"][0]["import_state"] == "imported" and detail["jobs"][0]["dd_test_id"]


async def test_full_and_nuclei_on_uat_use_only_juice_shop_and_wait_for_each_other(
    clients: tuple[httpx.AsyncClient, httpx.AsyncClient], juice_shop: str
) -> None:
    admin, analyst = clients
    _version, target = await make_target(admin, "uat", locator=juice_shop, rate_limit_rps=20)
    first = await analyst.post(f"/api/v1/dast/targets/{target}/scans", json={"profile": "dast-full"})
    assert first.status_code == 202, first.text
    second = await analyst.post(f"/api/v1/dast/targets/{target}/scans", json={"profile": "dast-baseline"})
    assert second.status_code == 202, second.text
    assert second.json()["id"] != first.json()["id"]
    saw_wait = False
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        one = (await analyst.get(f"/api/v1/scans/{first.json()['id']}")).json()
        two = (await analyst.get(f"/api/v1/scans/{second.json()['id']}")).json()
        running_one = any(j["state"] in ("preparing", "running") for j in one["jobs"])
        if running_one:
            saw_wait = saw_wait or all(j["state"] == "queued" for j in two["jobs"])
            assert not any(j["state"] in ("preparing", "running") for j in two["jobs"]), "two web jobs ran together"
        if one["state"] in SCAN_FINAL and two["state"] in SCAN_FINAL:
            break
        await asyncio.sleep(3)
    assert saw_wait, "the second scan waited while the first one ran"
    full = await wait_for_scan(analyst, first.json()["id"])
    assert {j["tool"] for j in full["jobs"]} == {"zap", "nuclei"}
    assert all(j["state"] in ("completed", "completed_partial") for j in full["jobs"]), [
        (j["tool"], j["state"], j["outcome_reason"]) for j in full["jobs"]
    ]
    for job in full["jobs"]:
        assert proxy_hosts(artifact_text(full, job, "dast-proxy-access.log")) <= {JUICE_NAME}
    nuclei = next(j for j in full["jobs"] if j["tool"] == "nuclei")
    assert nuclei["content_versions"].get("nuclei_templates")
    assert artifact_text(full, nuclei, "nuclei.json").lstrip().startswith("[")
    zap = next(j for j in full["jobs"] if j["tool"] == "zap")
    assert "WARNING" not in (zap["coverage_note"] or "")


async def test_nothing_leaves_the_dast_network(juice_shop: str) -> None:
    image = os.environ.get("SECURESCAN_TEST_CURL_IMAGE", "")
    if not image:
        pytest.skip("set SECURESCAN_TEST_CURL_IMAGE (a curl image) to check the dast network")
    network = get_settings().network_dast
    direct = docker("run", "--rm", "--network", network, image, "-sS", "-m", "8", "https://example.com/", check=False)
    assert direct.returncode != 0, "a container on the dast network must not reach the internet"
    inside = docker("run", "--rm", "--network", network, image, "-sS", "-m", "8", "-o", "/dev/null", "-w", "%{http_code}", juice_shop, check=False)
    assert inside.stdout.strip() == "200"
