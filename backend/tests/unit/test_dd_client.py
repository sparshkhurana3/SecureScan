"""DefectDojo client: request shape, retries and backoff, error mapping, paging (httpx MockTransport)."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Any

import httpx
import pytest

from securescan.integrations.defectdojo.client import (
    ACTIVE_FILTER,
    DefectDojoAuthError,
    DefectDojoClient,
    DefectDojoError,
    DefectDojoNotFound,
    DefectDojoRejected,
    DefectDojoUnavailable,
    ReimportRequest,
    ReimportResult,
)

BASE = "http://dd.test"
TOKEN = "0123456789abcdef0123456789abcdef01234567"  # noqa: S105 - a made-up token


class Recorder:
    """Collects the sleeps the client asks for instead of waiting."""

    def __init__(self) -> None:
        self.sleeps: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.sleeps.append(seconds)


def make_client(handler: Any, sleeper: Recorder | None = None, **kwargs: Any) -> DefectDojoClient:
    return DefectDojoClient(
        BASE,
        kwargs.pop("token", TOKEN),
        transport=httpx.MockTransport(handler),
        sleep=sleeper or Recorder(),
        **kwargs,
    )


def parse_multipart(request: httpx.Request) -> tuple[dict[str, list[str]], dict[str, bytes]]:
    """Form fields (name -> values) and uploaded files (name -> bytes) of a multipart request."""
    content_type = request.headers["content-type"]
    boundary = content_type.split("boundary=", 1)[1].encode()
    fields: dict[str, list[str]] = {}
    files: dict[str, bytes] = {}
    for part in request.content.split(b"--" + boundary):
        if part in (b"", b"--\r\n", b"\r\n") or part.startswith(b"--"):
            continue
        head, _, body = part.partition(b"\r\n\r\n")
        body = body[:-2] if body.endswith(b"\r\n") else body
        name = re.search(rb'name="([^"]+)"', head)
        assert name is not None
        key = name.group(1).decode()
        if b"filename=" in head:
            files[key] = body
        else:
            fields.setdefault(key, []).append(body.decode())
    return fields, files


def ok_import_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "test_id": 11,
        "engagement_id": 7,
        "product_id": 5,
        "product_type_id": 2,
        "statistics": {"after": {"high": {"active": 2}, "total": {"active": 2}}},
        "deduplication_complete": True,
    }
    payload.update(overrides)
    return payload


def make_request(tmp_path: Path, **overrides: Any) -> ReimportRequest:
    report = tmp_path / "semgrep.json"
    report.write_bytes(b'{"results": []}')
    values: dict[str, Any] = {
        "file_path": report,
        "file_name": "semgrep.json",
        "scan_type": "Semgrep JSON Report",
        "product_type_name": "Internal Applications",
        "product_name": "js-planted",
        "engagement_name": "main",
        "test_title": "semgrep:main",
        "version": "main",
        "commit_hash": "abc123",
        "branch_tag": "main",
        "tags": ("securescan-scan:1", "tool:semgrep"),
        "scan_date": date(2026, 10, 7),
        "content_type": "application/json",
    }
    values.update(overrides)
    return ReimportRequest(**values)


# --- reimport request shape -------------------------------------------------------------------------------


async def test_reimport_sends_every_parameter_and_the_file(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json=ok_import_payload())

    async with make_client(handler) as client:
        result = await client.reimport_scan(make_request(tmp_path))

    request = seen[0]
    assert request.method == "POST"
    assert request.url.path == "/api/v2/reimport-scan/"
    assert request.headers["authorization"] == f"Token {TOKEN}"
    fields, files = parse_multipart(request)
    assert files == {"file": b'{"results": []}'}
    assert fields["scan_type"] == ["Semgrep JSON Report"]
    assert fields["product_type_name"] == ["Internal Applications"]
    assert fields["product_name"] == ["js-planted"]
    assert fields["engagement_name"] == ["main"]
    assert fields["test_title"] == ["semgrep:main"]
    assert fields["auto_create_context"] == ["true"]
    assert fields["deduplication_on_engagement"] == ["true"]
    assert fields["close_old_findings"] == ["true"]
    assert fields["deduplication_execution_mode"] == ["async_wait"]
    assert fields["minimum_severity"] == ["Info"]
    assert fields["version"] == ["main"]
    assert fields["commit_hash"] == ["abc123"]
    assert fields["branch_tag"] == ["main"]
    assert fields["tags"] == ["securescan-scan:1", "tool:semgrep"]
    assert fields["scan_date"] == ["2026-10-07"]
    assert result == ReimportResult(
        test_id=11,
        engagement_id=7,
        product_id=5,
        product_type_id=2,
        statistics=ok_import_payload()["statistics"],
        deduplication_complete=True,
    )


def test_form_fields_omit_what_is_not_given(tmp_path: Path) -> None:
    request = make_request(tmp_path, version=None, commit_hash=None, branch_tag=None, tags=())
    fields = request.form_fields()
    for name in ("version", "commit_hash", "branch_tag", "tags"):
        assert name not in fields
    assert fields["auto_create_context"] == "true"


async def test_deduplication_not_complete_is_reported(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=ok_import_payload(deduplication_complete=False))

    async with make_client(handler) as client:
        result = await client.reimport_scan(make_request(tmp_path))
    assert result.deduplication_complete is False


async def test_missing_deduplication_flag_counts_as_not_complete(tmp_path: Path) -> None:
    payload = ok_import_payload()
    del payload["deduplication_complete"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async with make_client(handler) as client:
        result = await client.reimport_scan(make_request(tmp_path))
    assert result.deduplication_complete is False


async def test_import_response_without_test_id_is_an_error(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"statistics": {}})

    async with make_client(handler) as client:
        with pytest.raises(DefectDojoError):
            await client.reimport_scan(make_request(tmp_path))


# --- retries and backoff ---------------------------------------------------------------------------------------


async def test_5xx_is_retried_with_exponential_backoff(tmp_path: Path) -> None:
    calls = {"n": 0}
    sleeper = Recorder()

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503, text="busy")
        return httpx.Response(200, json=ok_import_payload())

    async with make_client(handler, sleeper) as client:
        result = await client.reimport_scan(make_request(tmp_path))
    assert result.test_id == 11
    assert calls["n"] == 3
    assert sleeper.sleeps == [2.0, 4.0]


async def test_the_file_is_sent_again_on_every_attempt(tmp_path: Path) -> None:
    bodies: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        _, files = parse_multipart(request)
        bodies.append(files["file"])
        if len(bodies) == 1:
            return httpx.Response(502)
        return httpx.Response(200, json=ok_import_payload())

    async with make_client(handler) as client:
        await client.reimport_scan(make_request(tmp_path))
    assert bodies == [b'{"results": []}', b'{"results": []}']


async def test_retry_after_header_is_honoured() -> None:
    sleeper = Recorder()
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return httpx.Response(200, json={"count": 0, "results": []})

    async with make_client(handler, sleeper) as client:
        assert await client.count_findings({"test": 1}) == 0
    assert sleeper.sleeps == [7.0]


async def test_connection_errors_give_up_as_unavailable() -> None:
    sleeper = Recorder()

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    async with make_client(handler, sleeper, max_retries=2) as client:
        with pytest.raises(DefectDojoUnavailable) as caught:
            await client.get_finding(1)
    assert "ConnectError" in str(caught.value)
    assert sleeper.sleeps == [2.0, 4.0]


async def test_backoff_is_capped() -> None:
    sleeper = Recorder()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    async with make_client(handler, sleeper, max_retries=6, backoff_base=10.0) as client:
        with pytest.raises(DefectDojoUnavailable):
            await client.get_finding(1)
    assert sleeper.sleeps == [10.0, 20.0, 30.0, 30.0, 30.0, 30.0]


async def test_4xx_is_not_retried() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(400, json={"file": ["unsupported"]})

    async with make_client(handler) as client:
        with pytest.raises(DefectDojoRejected) as caught:
            await client.get_finding(1)
    assert calls["n"] == 1
    assert caught.value.status_code == 400


async def test_401_and_403_are_auth_errors_and_404_is_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        code = int(request.url.path.strip("/").split("/")[-1])
        return httpx.Response(code, json={"detail": "x"})

    async with make_client(handler) as client:
        with pytest.raises(DefectDojoAuthError):
            await client.get_finding(401)
        with pytest.raises(DefectDojoAuthError):
            await client.get_finding(403)
        with pytest.raises(DefectDojoNotFound):
            await client.get_finding(404)


async def test_error_messages_never_contain_a_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text=f"bad request, header was Token {TOKEN}")

    async with make_client(handler) as client:
        with pytest.raises(DefectDojoRejected) as caught:
            await client.get_finding(1)
    assert TOKEN not in str(caught.value)
    assert TOKEN not in (caught.value.body or "")


def test_token_is_not_in_repr() -> None:
    client = DefectDojoClient(BASE, TOKEN)
    assert TOKEN not in repr(client)


# --- tokens -------------------------------------------------------------------------------------------------------------


async def test_obtain_token_posts_the_credentials_once() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"token": "abc"})

    token = await DefectDojoClient.obtain_token(
        BASE, "securescan-sync", "pw", transport=httpx.MockTransport(handler)
    )
    assert token == "abc"  # noqa: S105
    assert seen[0].url.path == "/api/v2/api-token-auth/"
    assert "authorization" not in seen[0].headers
    assert b'"username":"securescan-sync"' in seen[0].content.replace(b" ", b"")


async def test_obtain_token_refused_does_not_leak_the_password() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"non_field_errors": ["Unable to log in"]})

    with pytest.raises(DefectDojoRejected) as caught:
        await DefectDojoClient.obtain_token(
            BASE, "u", "s3cret-pass-word", transport=httpx.MockTransport(handler)
        )
    assert "s3cret-pass-word" not in str(caught.value)


async def test_ping_reports_answer_without_raising() -> None:
    def up(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    def down(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502)

    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    async with make_client(up) as client:
        answers, status, _ = await client.ping()
        assert (answers, status) == (True, 401)
    async with make_client(down) as client:
        answers, status, _ = await client.ping()
        assert (answers, status) == (False, 502)
    async with make_client(broken) as client:
        answers, status, _ = await client.ping()
        assert (answers, status) == (False, None)


# --- findings -------------------------------------------------------------------------------------------------------------


async def test_iter_findings_pages_with_limit_200_and_the_open_filter() -> None:
    seen: list[dict[str, str]] = []
    total = 450

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        seen.append(params)
        offset = int(params["offset"])
        limit = int(params["limit"])
        results = [{"id": i} for i in range(offset, min(offset + limit, total))]
        more = offset + limit < total
        return httpx.Response(
            200, json={"count": total, "next": "http://x/next" if more else None, "results": results}
        )

    async with make_client(handler) as client:
        findings = await client.list_findings(42, include_inactive=False)
    assert [f["id"] for f in findings] == list(range(total))
    assert [p["offset"] for p in seen] == ["0", "200", "400"]
    assert all(p["limit"] == "200" and p["test"] == "42" for p in seen)
    for key, value in ACTIVE_FILTER.items():
        assert seen[0][key] == value


async def test_include_inactive_drops_the_filter() -> None:
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        return httpx.Response(200, json={"count": 1, "next": None, "results": [{"id": 1}]})

    async with make_client(handler) as client:
        await client.list_findings(42, include_inactive=True)
    assert "active" not in seen[0]
    assert "false_p" not in seen[0]
    assert seen[0]["test"] == "42"


async def test_get_findings_by_ids_uses_the_id_filter_when_honoured() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        ids = [int(i) for i in request.url.params["id"].split(",")]
        requested.append(request.url.params["id"])
        results = [{"id": i, "active": True} for i in ids if i != 3]  # 3 was deleted
        return httpx.Response(200, json={"count": len(results), "next": None, "results": results})

    async with make_client(handler) as client:
        found = await client.get_findings_by_ids([1, 2, 3, 2])
    assert requested == ["1,2,3"]
    assert sorted(found) == [1, 2]


async def test_get_findings_by_ids_falls_back_when_the_filter_is_ignored() -> None:
    singles: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/findings/"):
            everything = [{"id": i} for i in range(100, 150)]
            return httpx.Response(200, json={"count": 5000, "next": "x", "results": everything})
        singles.append(request.url.path)
        finding_id = int(request.url.path.strip("/").split("/")[-1])
        if finding_id == 2:
            return httpx.Response(404)
        return httpx.Response(200, json={"id": finding_id})

    async with make_client(handler) as client:
        found = await client.get_findings_by_ids([1, 2, 3])
        assert sorted(found) == [1, 3]
        # the second call does not probe the filter again
        singles.clear()
        await client.get_findings_by_ids([4])
    assert singles == ["/api/v2/findings/4/"]


# --- users, settings, product types ----------------------------------------------------------------------------------------


async def test_create_user_sends_the_required_fields() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"id": 9, "username": "jane"})

    async with make_client(handler) as client:
        created = await client.create_user(
            username="jane",
            password="Pw-1234-abcd-EFGH",  # noqa: S106
            email="jane@example.test",
            first_name="Jane",
            last_name="Doe",
            is_staff=True,
        )
    assert created["id"] == 9
    import json

    body = json.loads(seen[0].content)
    assert body["username"] == "jane"
    assert body["email"] == "jane@example.test"
    assert body["is_staff"] is True
    assert body["is_superuser"] is False
    assert body["is_active"] is True


async def test_find_user_matches_the_exact_name() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"count": 2, "results": [{"id": 1, "username": "jane2"}, {"id": 2, "username": "jane"}]},
        )

    async with make_client(handler) as client:
        user = await client.find_user("jane")
        assert user is not None and user["id"] == 2
        assert await client.find_user("nobody") is None


async def test_force_password_reset_patches_an_existing_row_or_creates_one() -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "GET":
            rows = [{"id": 4}] if request.url.params["user"] == "1" else []
            return httpx.Response(200, json={"results": rows})
        return httpx.Response(200 if request.method == "PATCH" else 201, json={})

    async with make_client(handler) as client:
        await client.set_force_password_reset(1)
        await client.set_force_password_reset(2)
    assert ("PATCH", "/api/v2/user_contact_infos/4/") in calls
    assert ("POST", "/api/v2/user_contact_infos/") in calls


async def test_set_user_password_refusal_is_a_rejection() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json=["Update of password though API is not allowed"])

    async with make_client(handler) as client:
        with pytest.raises(DefectDojoRejected):
            await client.set_user_password(3, "x")


async def test_system_settings_and_product_types() -> None:
    state: dict[str, Any] = {"dedupe": False, "types": []}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v2/system_settings/":
            return httpx.Response(
                200, json={"results": [{"id": 1, "enable_deduplication": state["dedupe"]}]}
            )
        if path == "/api/v2/system_settings/1/":
            state["dedupe"] = True
            return httpx.Response(200, json={"id": 1, "enable_deduplication": True})
        if path == "/api/v2/product_types/" and request.method == "GET":
            name = request.url.params.get("name")
            return httpx.Response(
                200, json={"results": [t for t in state["types"] if name in (None, t["name"])]}
            )
        if path == "/api/v2/product_types/" and request.method == "POST":
            import json

            created = {"id": len(state["types"]) + 1, "name": json.loads(request.content)["name"]}
            state["types"].append(created)
            return httpx.Response(201, json=created)
        return httpx.Response(404)

    async with make_client(handler) as client:
        current = await client.system_settings()
        assert current["enable_deduplication"] is False
        await client.patch_system_settings(1, {"enable_deduplication": True})
        assert (await client.system_settings())["enable_deduplication"] is True
        assert await client.product_types("Internal Applications") == []
        await client.create_product_type("Internal Applications")
        assert len(await client.product_types("Internal Applications")) == 1
