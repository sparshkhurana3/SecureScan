"""GitHub App connection and a repository scan against the S6 test App (``@pytest.mark.integration``).

Needs a real GitHub App installed on a test organisation or account (spike S6, docs/spikes). Without these variables
every test here is skipped with the reason shown:

* ``SECURESCAN_TEST_GITHUB_APP_ID``, ``SECURESCAN_TEST_GITHUB_CLIENT_ID``, ``SECURESCAN_TEST_GITHUB_INSTALLATION_ID``
* ``SECURESCAN_TEST_GITHUB_PRIVATE_KEY_FILE``  path of the App's PEM (read here, sent once to the API, never logged)
* ``SECURESCAN_TEST_GITHUB_REPO``  optional ``owner/name`` of a small repository the App can read; enables the scan test

and the Compose stack with the worker, the egress proxy image (``SECURESCAN_EGRESS_IMAGE``) and the pinned scanner images.
Run: ``SECURESCAN_INTEGRATION=1 python scripts/dev.py test integration -k github_app``.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from securescan.db.models.enums import UserRole

from .test_scan_semgrep_gitleaks import (  # noqa: F401  (the autouse fixture must be visible in this module)
    seeded_profiles_and_queue,
    wait_for_scan,
)

pytestmark = pytest.mark.integration

Login = Callable[[UserRole], Awaitable[httpx.AsyncClient]]

APP_ID = os.environ.get("SECURESCAN_TEST_GITHUB_APP_ID", "")
CLIENT_ID = os.environ.get("SECURESCAN_TEST_GITHUB_CLIENT_ID", "")
INSTALLATION_ID = os.environ.get("SECURESCAN_TEST_GITHUB_INSTALLATION_ID", "")
KEY_FILE = os.environ.get("SECURESCAN_TEST_GITHUB_PRIVATE_KEY_FILE", "")
REPO = os.environ.get("SECURESCAN_TEST_GITHUB_REPO", "")

needs_app = pytest.mark.skipif(
    not (APP_ID and CLIENT_ID and INSTALLATION_ID and KEY_FILE and Path(KEY_FILE).is_file()),
    reason="set SECURESCAN_TEST_GITHUB_APP_ID, _CLIENT_ID, _INSTALLATION_ID and _PRIVATE_KEY_FILE (the S6 test App)",
)


async def connect(admin: httpx.AsyncClient) -> dict[str, Any]:
    response = await admin.put(
        "/api/v1/integrations/github",
        json={
            "name": "S6 test App",
            "app_id": APP_ID,
            "client_id": CLIENT_ID,
            "installation_id": INSTALLATION_ID,
            "private_key_1": Path(KEY_FILE).read_text(encoding="utf-8"),
        },
    )
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


@needs_app
async def test_connection_is_stored_without_the_key_and_the_test_passes(api_as: Login) -> None:
    admin = await api_as(UserRole.ADMIN)
    saved = await connect(admin)
    assert saved["configured"] is True
    assert "BEGIN" not in response_text(saved), "the private key must never come back from the API"

    tested = await admin.post("/api/v1/integrations/github/test", params={"wait": 90})
    assert tested.status_code == 200, tested.text
    assert tested.json()["status"] == "ok", tested.json()
    assert (tested.json().get("repositories") or 0) >= 1


@needs_app
async def test_an_analyst_cannot_read_or_change_the_connection(api_as: Login) -> None:
    analyst = await api_as(UserRole.ANALYST)
    assert (await analyst.get("/api/v1/integrations/github")).status_code == 403
    assert (await analyst.put("/api/v1/integrations/github", json={})).status_code in (403, 422)


@needs_app
@pytest.mark.skipif(not REPO, reason="set SECURESCAN_TEST_GITHUB_REPO to owner/name to scan a repository")
async def test_discovery_finds_the_repository_and_a_scan_of_it_finishes(api_as: Login) -> None:
    admin = await api_as(UserRole.ADMIN)
    await connect(admin)
    synced = await admin.post("/api/v1/integrations/github/sync")
    assert synced.status_code == 202, synced.text

    deadline = time.monotonic() + 180
    repository: dict[str, Any] | None = None
    while repository is None:
        listing = await admin.get("/api/v1/integrations/github/repositories", params={"q": REPO.split("/")[-1]})
        assert listing.status_code == 200, listing.text
        repository = next((r for r in listing.json()["items"] if r["full_name"] == REPO), None)
        assert time.monotonic() < deadline, f"{REPO} was not discovered; is it in the App's installation?"
        if repository is None:
            await asyncio.sleep(3)

    application_id = repository["application_id"]
    versions = await admin.get(f"/api/v1/applications/{application_id}/versions")
    assert versions.status_code == 200, versions.text
    version = versions.json()["items"][0]
    targets = await admin.get(f"/api/v1/versions/{version['id']}/targets")
    assert targets.status_code == 200, targets.text
    target = next(t for t in targets.json()["items"] if t["kind"] == "github_repo")

    created = await admin.post(
        "/api/v1/scans",
        json={"version_id": version["id"], "target_id": target["id"], "profile": "code-standard", "tools": ["gitleaks"]},
    )
    assert created.status_code in (201, 202), created.text
    scan = await wait_for_scan(admin, created.json()["id"])
    assert scan["state"] in ("completed", "completed_partial"), scan["state"]
    # The clone went through the egress proxy with a short-lived installation token: no secret in the job record.
    assert "ghs_" not in str(scan) and "BEGIN" not in str(scan)


def response_text(value: Any) -> str:
    return str(value)
