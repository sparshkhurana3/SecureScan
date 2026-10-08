"""The vendor assessment end to end (``@pytest.mark.integration``): intake, two versions, delta, report, vendor copy, hosting rule.

Follows the acceptance run of docs/build-notes/M10.md and plan M1.5/M10. What must be running is the same as for
``test_scan_semgrep_gitleaks.py`` (worker, socket-proxy, DefectDojo, pre-pulled Semgrep and Gitleaks images, the
Semgrep rules in the content volume, a shared artifacts volume); the DefectDojo import must work too, because the
delta is built from the finding history that the import fills.

Version 1 is the planted Java application. Version 2 is the same application without the servlet that holds the
planted SQL injection, so a correct delta lists that finding as fixed and the others as remaining.

Run: ``SECURESCAN_INTEGRATION=1 python scripts/dev.py test integration -k vendor_flow``.
Skipped without ``SECURESCAN_INTEGRATION=1`` (conftest) and when the sample application is missing.
"""

from __future__ import annotations

import asyncio
import io
import time
import zipfile
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest

from securescan.db.models.enums import UserRole

from .test_scan_semgrep_gitleaks import (  # noqa: F401  (the autouse fixture must be visible in this module)
    SAMPLE_APPS,
    WAIT_SECONDS,
    seeded_profiles_and_queue,
    upload,
    wait_for_scan,
    zip_app,
)

pytestmark = pytest.mark.integration

Login = Callable[[UserRole], Awaitable[httpx.AsyncClient]]

APP = "java-planted"
FIXED_FILE = "src/main/java/com/sonacomstar/planted/UserServlet.java"
TOOLS = ["semgrep", "gitleaks"]


def zip_without(app: str, drop: str) -> bytes:
    """The sample application as a zip with one file left out (version 2: the weakness is removed)."""
    source = io.BytesIO(zip_app(app))
    target = io.BytesIO()
    with zipfile.ZipFile(source) as read, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as write:
        for info in read.infolist():
            if info.filename != drop:
                write.writestr(info, read.read(info.filename))
    return target.getvalue()


async def intake(client: httpx.AsyncClient, version: str, hosting: str = "deployable") -> dict[str, Any]:
    response = await client.post(
        "/api/v1/vendor-assessments/intake",
        json={"vendor_name": "Acme Test Vendor", "product": f"Ledger {hosting}", "version": version, "hosting": hosting},
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


async def zip_target(client: httpx.AsyncClient, version_id: str, data: bytes, name: str) -> str:
    artifact_id = await upload(client, name, data)
    target = await client.post(
        f"/api/v1/versions/{version_id}/targets", json={"kind": "zip", "upload_artifact_id": artifact_id}
    )
    assert target.status_code == 201, target.text
    return str(target.json()["id"])


async def scan(client: httpx.AsyncClient, version_id: str, target_id: str) -> dict[str, Any]:
    created = await client.post(
        "/api/v1/scans",
        json={"version_id": version_id, "target_id": target_id, "profile": "code-standard", "tools": TOOLS},
    )
    assert created.status_code in (201, 202), created.text
    return await wait_for_scan(client, created.json()["id"])


async def wait_for(
    check: Callable[[], Awaitable[Any]], what: str, timeout: int = WAIT_SECONDS, step: float = 3.0
) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = await check()
        if value:
            return value
        assert time.monotonic() < deadline, f"timed out waiting for {what}"
        await asyncio.sleep(step)


@pytest.mark.skipif(not (SAMPLE_APPS / APP).is_dir(), reason="the sample application is not checked out")
async def test_two_versions_delta_report_and_vendor_copy(api_as: Login) -> None:
    analyst = await api_as(UserRole.ANALYST)

    first = await intake(analyst, "1.0")
    second = await intake(analyst, "2.0")
    assert second["vendor_created"] is False and second["application_created"] is False
    assert second["version_created"] is True

    v1, v2 = str(first["version"]["id"]), str(second["version"]["id"])
    t1 = await zip_target(analyst, v1, zip_app(APP), "v1.zip")
    t2 = await zip_target(analyst, v2, zip_without(APP, FIXED_FILE), "v2.zip")
    scan1 = await scan(analyst, v1, t1)
    scan2 = await scan(analyst, v2, t2)
    assert scan1["state"] in ("completed", "completed_partial"), scan1["state"]
    assert scan2["state"] in ("completed", "completed_partial"), scan2["state"]

    # The delta reads the finding history, which the DefectDojo import fills a little after the scan ends.
    async def delta_has_fixed() -> dict[str, Any] | None:
        response = await analyst.get(
            "/api/v1/vendor-assessments/delta", params={"scan_id": scan2["id"], "previous_scan_id": scan1["id"]}
        )
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body if body["fixed"] else None

    delta = await wait_for(delta_has_fixed, "the fixed findings of version 2 in the delta")
    assert any(FIXED_FILE.split("/")[-1] in row["location"] for row in delta["fixed"]), delta["fixed"]
    assert delta["remaining"], "the other planted weaknesses must still be reported as remaining"

    # The report of version 2, then the vendor copy: refused until an analyst reviewed it.
    created = await analyst.post("/api/v1/vendor-assessments", json={"scan_id": scan2["id"]})
    assert created.status_code == 202, created.text
    report_id = created.json()["id"]

    async def report_ready() -> dict[str, Any] | None:
        response = await analyst.get(f"/api/v1/vendor-assessments/{report_id}")
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        assert body["status"] != "failed", body
        return body if body["status"] == "ready" else None

    detail = await wait_for(report_ready, "the vendor report to render")
    before = await analyst.get(f"/api/v1/vendor-assessments/{report_id}/html", params={"copy": "vendor"})
    assert before.status_code == 409, before.text
    assert "needs_review" in before.text or "review" in before.text.lower()

    review: dict[str, Any] = {"decision": "confirm", "internal_notes": "internal only: do not send"}
    if detail["proposed_verdict"] == "conditional":
        # A conditional verdict needs a dated condition for every High finding (plan M10).
        review["conditions"] = [
            {"finding_hash": row["key"], "deadline": "2099-01-01"} for row in detail.get("missing_conditions", [])
        ]
    reviewed = await analyst.post(f"/api/v1/reports/{report_id}/review", json=review)
    assert reviewed.status_code == 200, reviewed.text

    copy = await analyst.get(f"/api/v1/vendor-assessments/{report_id}/html", params={"copy": "vendor"})
    assert copy.status_code == 200, copy.text
    assert "do not send" not in copy.text, "internal notes must not appear in the vendor copy"


async def test_saas_product_in_production_refuses_active_scans(api_as: Login) -> None:
    """The hosting rule: a SaaS product is production unless the vendor authorized UAT in writing; no full scan then."""
    analyst = await api_as(UserRole.ANALYST)
    created = await intake(analyst, "9.9", hosting="saas")
    version_id = str(created["version"]["id"])
    target = await analyst.post(
        f"/api/v1/versions/{version_id}/targets",
        json={"kind": "url", "locator": "https://vendor-saas.example.com/", "environment": "uat"},
    )
    assert target.status_code == 201, target.text
    target_id = str(target.json()["id"])

    hosting = await analyst.get(f"/api/v1/vendor-assessments/targets/{target_id}/hosting")
    assert hosting.status_code == 200, hosting.text
    assert hosting.json()["authorization_required"] is True
    assert hosting.json()["full_scans_allowed"] is False

    refused = await analyst.post(
        "/api/v1/scans",
        json={"version_id": version_id, "target_id": target_id, "profile": "dast-full"},
    )
    assert 400 <= refused.status_code < 500, refused.text
