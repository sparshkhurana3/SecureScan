"""End-to-end checks of the M2 API against a real database (``@pytest.mark.integration``)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import httpx
import pytest

from securescan.db.models.enums import UserRole

pytestmark = pytest.mark.integration

Login = Callable[[UserRole], Awaitable[httpx.AsyncClient]]


async def test_anonymous_requests_are_refused(api: httpx.AsyncClient) -> None:
    response = await api.get("/api/v1/applications")
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")
    check = await api.get("/api/v1/auth/check")
    assert check.status_code == 401


async def test_session_check_and_me(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    assert (await client.get("/api/v1/auth/check")).status_code == 204
    me = (await client.get("/api/v1/me")).json()
    assert me["role"] == "Analyst"
    assert me["csrf_token"]


async def test_application_version_target_vendor_crud_and_audit(api_as: Login) -> None:
    client = await api_as(UserRole.ADMIN)

    vendor = await client.post("/api/v1/vendors", json={"name": "Acme Software", "risk_tier": "high"})
    assert vendor.status_code == 201, vendor.text
    vendor_id = vendor.json()["id"]

    duplicate = await client.post("/api/v1/vendors", json={"name": "acme software"})
    assert duplicate.status_code == 409

    app_response = await client.post(
        "/api/v1/applications",
        json={"name": "Billing", "criticality": "high", "tags": ["finance", "finance"]},
    )
    assert app_response.status_code == 201, app_response.text
    app_id = app_response.json()["id"]
    assert app_response.json()["tags"] == ["finance"]

    bad = await client.post("/api/v1/applications", json={"name": "X", "type": "vendor"})
    assert bad.status_code == 422
    assert bad.json()["code"] == "application.vendor_required"

    version = await client.post(
        f"/api/v1/applications/{app_id}/versions", json={"label": "main", "label_kind": "branch"}
    )
    assert version.status_code == 201, version.text
    version_id = version.json()["id"]

    target = await client.post(
        f"/api/v1/versions/{version_id}/targets",
        json={"kind": "url", "locator": "https://billing.example.com", "environment": "production"},
    )
    assert target.status_code == 201, target.text
    target_id = target.json()["id"]

    changed = await client.patch(f"/api/v1/targets/{target_id}", json={"environment": "uat"})
    assert changed.status_code == 200
    assert changed.json()["environment"] == "uat"

    listing = await client.get("/api/v1/applications", params={"limit": 1})
    assert listing.status_code == 200
    assert len(listing.json()["items"]) == 1

    events = await client.get("/api/v1/audit-events", params={"limit": 100})
    actions = {e["action"] for e in events.json()["items"]}
    assert {
        "vendor.create",
        "application.create",
        "version.create",
        "target.create",
        "target.environment_change",
    } <= actions

    archived = await client.delete(f"/api/v1/vendors/{vendor_id}")
    assert archived.status_code == 204


async def test_analyst_cannot_use_admin_endpoints(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    assert (await client.get("/api/v1/audit-events")).status_code == 403
    assert (await client.get("/api/v1/admin/health")).status_code == 403


async def test_post_without_csrf_header_is_refused(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    del client.headers["X-CSRF-Token"]
    response = await client.post("/api/v1/vendors", json={"name": "No Token Ltd"})
    assert response.status_code == 403
    assert response.json()["code"] == "csrf.invalid"


async def test_cursor_pagination_walks_all_rows(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    for index in range(5):
        created = await client.post("/api/v1/vendors", json={"name": f"Vendor {index}"})
        assert created.status_code == 201
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(10):
        params: dict[str, str | int] = {"limit": 2}
        if cursor:
            params["after"] = cursor
        page = (await client.get("/api/v1/vendors", params=params)).json()
        seen.extend(item["name"] for item in page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == [f"Vendor {i}" for i in range(5)]


async def test_chunked_upload_of_one_megabyte(api_as: Login) -> None:
    import hashlib

    client = await api_as(UserRole.ANALYST)
    payload = (bytes(range(256)) * 4096)[: 1024 * 1024]
    digest = hashlib.sha256(payload).hexdigest()
    created = await client.post(
        "/api/v1/uploads",
        json={"filename": "source.zip", "size_bytes": len(payload), "sha256": digest},
    )
    assert created.status_code == 201, created.text
    upload_id = created.json()["id"]
    chunk = 256 * 1024
    for start in range(0, len(payload), chunk):
        part = payload[start : start + chunk]
        sent = await client.patch(
            f"/api/v1/uploads/{upload_id}",
            content=part,
            headers={"Content-Range": f"bytes {start}-{start + len(part) - 1}/{len(payload)}"},
        )
        assert sent.status_code == 200, sent.text
    done = await client.post(f"/api/v1/uploads/{upload_id}/complete")
    assert done.status_code == 200, done.text
    assert done.json()["sha256"] == digest


async def test_openapi_document_is_served(api: httpx.AsyncClient) -> None:
    document = (await api.get("/api/v1/openapi.json")).json()
    assert document["openapi"].startswith("3.")
    assert "/api/v1/applications" in document["paths"]
