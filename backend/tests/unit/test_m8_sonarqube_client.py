"""The SonarQube client against ``httpx.MockTransport``: status wait, compute-engine polling, issue paging and zip."""

from __future__ import annotations

import base64
import json
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from securescan.integrations.sonarqube import client as client_module
from securescan.integrations.sonarqube.client import (
    SonarAuthError,
    SonarError,
    SonarNotReady,
    SonarQubeClient,
    issues_zip_summary,
    read_report_task,
    tomorrow,
)

BASE = "http://sonarqube:9000"


class Clock:
    """A monotonic clock that ``sleep`` advances, so waits cost no real time."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def make_client(handler: Callable[[httpx.Request], httpx.Response], clock: Clock | None = None, **kwargs: Any) -> SonarQubeClient:
    clock = clock or Clock()
    return SonarQubeClient(BASE, transport=httpx.MockTransport(handler), sleep=clock.sleep, clock=clock, **kwargs)


def form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def query(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.url.query.decode()).items()}


# --------------------------------------------------------------------------- status
async def test_wait_until_up_polls_the_status_until_up() -> None:
    clock = Clock()
    statuses = iter(["", "STARTING", "STARTING", "UP"])
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        status = next(statuses)
        if not status:
            return httpx.Response(503)
        return httpx.Response(200, json={"id": "x", "version": "26.9", "status": status})

    async with make_client(handler, clock) as sonar:
        waited = await sonar.wait_until_up(600, interval_s=3.0)
    assert seen == ["/api/system/status"] * 4 and clock.sleeps == [3.0, 3.0, 3.0] and waited == 9.0


async def test_wait_until_up_times_out_with_the_last_status() -> None:
    clock = Clock()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "STARTING"})

    async with make_client(handler, clock) as sonar:
        with pytest.raises(SonarNotReady) as info:
            await sonar.wait_until_up(30, interval_s=10.0)
    assert "within 30 seconds" in str(info.value) and "STARTING" in str(info.value)


async def test_a_server_that_is_not_reachable_is_status_empty_and_times_out() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    async with make_client(handler) as sonar:
        assert await sonar.system_status() == ""
        with pytest.raises(SonarNotReady) as info:
            await sonar.wait_until_up(5, interval_s=2.0)
    assert "no answer" in str(info.value)


async def test_a_pending_database_migration_is_started_once() -> None:
    statuses = iter(["DB_MIGRATION_NEEDED", "DB_MIGRATION_RUNNING", "UP"])
    posts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            posts.append(request.url.path)
            return httpx.Response(200, json={"state": "MIGRATION_RUNNING"})
        return httpx.Response(200, json={"status": next(statuses)})

    async with make_client(handler) as sonar:
        await sonar.wait_until_up(600)
    assert posts == ["/api/system/migrate_db"]


# --------------------------------------------------------------------------- authentication, users, tokens
async def test_a_token_is_sent_as_the_basic_auth_user_name() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization", ""))
        return httpx.Response(200, json={"valid": True})

    async with make_client(handler, token="squ_abc") as sonar:
        assert await sonar.validate_auth() is True
    assert seen == ["Basic " + base64.b64encode(b"squ_abc:").decode()]


async def test_wrong_credentials_are_not_valid_and_a_refusal_is_an_auth_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/authentication/validate":
            return httpx.Response(200, json={"valid": False})
        return httpx.Response(401, json={"errors": [{"msg": "Authentication is required"}]})

    async with make_client(handler, username="admin", password="nope") as sonar:
        assert await sonar.validate_auth() is False
        with pytest.raises(SonarAuthError) as info:
            await sonar.find_user("someone")
    assert "Authentication is required" in str(info.value) and info.value.status == 401


async def test_the_servers_own_error_text_is_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"errors": [{"msg": "Password is too short"}, {"msg": "second"}]})

    async with make_client(handler, username="admin", password="x") as sonar:
        with pytest.raises(SonarError) as info:
            await sonar.change_password("admin", "admin", "x")
    assert "Password is too short; second" in str(info.value) and info.value.status == 400


async def test_generate_token_sends_the_form_and_returns_the_token_once() -> None:
    captured: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(form(request))
        return httpx.Response(200, json={"login": "u", "name": "n", "token": "sqp_secret"})

    async with make_client(handler, username="admin", password="pw") as sonar:
        token = await sonar.generate_token(
            "ss-job", "PROJECT_ANALYSIS_TOKEN", project_key="proj", expiration_date="2026-10-08"
        )
    assert token == "sqp_secret"
    assert captured == [{"name": "ss-job", "type": "PROJECT_ANALYSIS_TOKEN", "projectKey": "proj", "expirationDate": "2026-10-08"}]


async def test_a_response_without_a_token_is_an_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"login": "u"})

    async with make_client(handler, username="admin", password="pw") as sonar:
        with pytest.raises(SonarError):
            await sonar.generate_token("n", "USER_TOKEN", login="u")


async def test_ensure_project_creates_only_what_is_missing() -> None:
    projects: set[str] = set()
    created: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/projects/search":
            key = query(request)["projects"]
            return httpx.Response(200, json={"components": [{"key": key}] if key in projects else []})
        if request.url.path == "/api/projects/create":
            body = form(request)
            created.append(body)
            projects.add(body["project"])
            return httpx.Response(200, json={"project": {"key": body["project"]}})
        return httpx.Response(404)

    async with make_client(handler, token="t") as sonar:
        assert await sonar.ensure_project("ss-app", "App / main") is True
        assert await sonar.ensure_project("ss-app", "App / main") is False
    assert created == [{"project": "ss-app", "name": "App / main"}]


async def test_settings_and_permissions() -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"settings": [{"key": "sonar.multi-quality-mode.enabled", "value": "true"}]})
        calls.append((request.url.path, form(request)))
        return httpx.Response(204)

    async with make_client(handler, username="admin", password="pw") as sonar:
        assert await sonar.get_setting("sonar.multi-quality-mode.enabled") == "true"
        assert await sonar.get_setting("sonar.other") is None
        await sonar.set_setting("sonar.multi-quality-mode.enabled", "false")
        await sonar.add_permission("svc", "provisioning")
        await sonar.revoke_token("old")
    assert calls[0] == ("/api/settings/set", {"key": "sonar.multi-quality-mode.enabled", "value": "false"})
    assert calls[1] == ("/api/permissions/add_user", {"login": "svc", "permission": "provisioning"})
    assert calls[2] == ("/api/user_tokens/revoke", {"name": "old"})


# --------------------------------------------------------------------------- compute engine, gate, measures
async def test_the_compute_engine_task_is_polled_until_it_ends() -> None:
    clock = Clock()
    states = iter(["PENDING", "IN_PROGRESS", "IN_PROGRESS", "SUCCESS"])

    def handler(request: httpx.Request) -> httpx.Response:
        assert query(request) == {"id": "AY1"}
        return httpx.Response(200, json={"task": {"id": "AY1", "status": next(states), "analysisId": "an-1"}})

    async with make_client(handler, clock) as sonar:
        task = await sonar.wait_for_ce_task("AY1", 600, interval_s=2.0)
    assert task["status"] == "SUCCESS" and task["analysisId"] == "an-1" and clock.sleeps == [2.0, 2.0, 2.0]


async def test_a_failed_task_is_returned_not_raised_and_a_slow_one_times_out() -> None:
    def failed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"task": {"id": "x", "status": "FAILED", "errorMessage": "boom"}})

    async with make_client(failed) as sonar:
        assert (await sonar.wait_for_ce_task("x", 60))["errorMessage"] == "boom"

    def slow(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"task": {"id": "x", "status": "IN_PROGRESS"}})

    async with make_client(slow) as sonar:
        with pytest.raises(SonarNotReady):
            await sonar.wait_for_ce_task("x", 10, interval_s=5.0)


async def test_quality_gate_and_measures_are_normalised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/qualitygates/project_status":
            assert query(request) == {"analysisId": "an-1"}
            return httpx.Response(200, json={"projectStatus": {"status": "ERROR", "conditions": [
                {"status": "ERROR", "metricKey": "new_vulnerabilities", "comparator": "GT", "errorThreshold": "0", "actualValue": "3"},
                {"status": "OK", "metricKey": "new_coverage", "comparator": "LT", "errorThreshold": "80"},
            ]}})  # fmt: skip
        assert query(request)["component"] == "proj" and "ncloc" in query(request)["metricKeys"]
        return httpx.Response(200, json={"component": {"key": "proj", "measures": [
            {"metric": "bugs", "value": "2"}, {"metric": "ncloc", "value": "1234"}, {"metric": "coverage", "period": {"value": "1"}},
        ]}})  # fmt: skip

    async with make_client(handler, token="t") as sonar:
        gate = await sonar.quality_gate("proj", "an-1")
        measures = await sonar.measures("proj")
    assert gate["status"] == "ERROR"
    assert gate["conditions"][0] == {
        "metric": "new_vulnerabilities", "status": "ERROR", "actual": "3", "threshold": "0", "comparator": "GT",
    }  # fmt: skip
    assert gate["conditions"][1]["actual"] == ""
    assert measures == {"bugs": "2", "ncloc": "1234", "coverage": None}


# --------------------------------------------------------------------------- the issues export
def issues_handler(totals: Callable[[dict[str, str]], int], seen: list[dict[str, str]] | None = None) -> Callable[[httpx.Request], httpx.Response]:
    """``/api/issues/search`` for a project whose total depends on the filters; pages carry dummy issues."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/issues/search"
        params = query(request)
        if seen is not None:
            seen.append(params)
        total = totals(params)
        size, page = int(params["ps"]), int(params["p"])
        assert size <= 500 and page * size - size < 10_000, "the API cannot page past 10000"
        first = (page - 1) * size
        count = max(0, min(size, total - first))
        issues = [{"key": f"I-{first + i}", "type": "BUG", "severity": "MAJOR", "rule": "x:y"} for i in range(count)]
        return httpx.Response(
            200, json={"total": total, "p": page, "ps": size, "paging": {"pageIndex": page, "pageSize": size, "total": total},
                       "issues": issues, "components": [], "rules": []},
        )  # fmt: skip

    return handler


async def test_export_of_a_small_project_is_one_page(tmp_path: Path) -> None:
    seen: list[dict[str, str]] = []
    async with make_client(issues_handler(lambda p: 3, seen), token="t") as sonar:
        result = await sonar.export_issues("proj", tmp_path / "issues.zip")
    assert (result.total, result.exported, result.files, result.truncated, result.splits) == (3, 3, 1, False, [])
    assert result.complete
    assert seen == [{"components": "proj", "ps": "500", "p": "1", "additionalFields": "rules"}]
    with zipfile.ZipFile(tmp_path / "issues.zip") as archive:
        assert archive.namelist() == ["issues-1.json"]
        page = json.loads(archive.read("issues-1.json"))
    assert [i["key"] for i in page["issues"]] == ["I-0", "I-1", "I-2"]
    assert page["paging"]["total"] == 3, "pages are stored as the server sent them"


async def test_export_without_issues_makes_an_empty_zip(tmp_path: Path) -> None:
    async with make_client(issues_handler(lambda p: 0), token="t") as sonar:
        result = await sonar.export_issues("proj", tmp_path / "issues.zip")
    assert (result.total, result.exported, result.files) == (0, 0, 0) and result.complete
    assert zipfile.ZipFile(tmp_path / "issues.zip").namelist() == []


async def test_export_pages_through_all_results(tmp_path: Path) -> None:
    async with make_client(issues_handler(lambda p: 1200), token="t") as sonar:
        result = await sonar.export_issues("proj", tmp_path / "issues.zip")
    assert (result.total, result.exported, result.files) == (1200, 1200, 3)
    assert issues_zip_summary(tmp_path / "issues.zip") == {"pages": 3, "issues": 1200}


async def test_more_than_ten_thousand_issues_are_split_by_type_then_severity(tmp_path: Path) -> None:
    by_type = {"CODE_SMELL": 11_000, "BUG": 2_000, "VULNERABILITY": 100, "SECURITY_HOTSPOT": 0}
    by_severity = {"INFO": 100, "MINOR": 5_000, "MAJOR": 5_000, "CRITICAL": 800, "BLOCKER": 100}

    def totals(params: dict[str, str]) -> int:
        if "types" not in params:
            return sum(by_type.values())
        if params["types"] == "CODE_SMELL" and "severities" in params:
            return by_severity[params["severities"]]
        return by_type[params["types"]]

    seen: list[dict[str, str]] = []
    async with make_client(issues_handler(totals, seen), token="t") as sonar:
        result = await sonar.export_issues("proj", tmp_path / "issues.zip")
    assert result.total == 13_100 and result.exported == 13_100 and not result.truncated
    assert result.splits == ["severities", "types"]
    summary = issues_zip_summary(tmp_path / "issues.zip")
    assert summary["issues"] == 13_100 and summary["pages"] == result.files
    assert max(int(p["p"]) for p in seen) <= 20, "no request goes past page 20 (10 000 results)"
    assert {p["types"] for p in seen if "types" in p} == set(by_type)
    # the over-large type is the only one split further
    assert {p["types"] for p in seen if "severities" in p} == {"CODE_SMELL"}


async def test_a_part_that_stays_too_large_is_cut_and_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "MAX_WINDOW", 1000)
    monkeypatch.setattr(client_module, "SPLIT_DIMENSIONS", (("types", ("A", "B")),))

    def totals(params: dict[str, str]) -> int:
        return 3000 if "types" not in params else 1500

    async with make_client(issues_handler(totals), token="t") as sonar:
        result = await sonar.export_issues("proj", tmp_path / "issues.zip")
    assert result.total == 3000 and result.exported == 2000 and result.truncated is True and not result.complete


async def test_a_type_missing_from_the_split_is_reported_as_incomplete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "MAX_WINDOW", 1000)
    monkeypatch.setattr(client_module, "SPLIT_DIMENSIONS", (("types", ("A", "B")),))

    def totals(params: dict[str, str]) -> int:
        return 1500 if "types" not in params else (400 if params["types"] == "A" else 0)

    async with make_client(issues_handler(totals), token="t") as sonar:
        result = await sonar.export_issues("proj", tmp_path / "issues.zip")
    assert result.exported == 400 and result.truncated is True, "1100 issues have an unlisted type"


async def test_an_error_while_paging_is_a_sonar_error(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"errors": [{"msg": "Elasticsearch is down"}]})

    async with make_client(handler, token="t") as sonar:
        with pytest.raises(SonarError) as info:
            await sonar.export_issues("proj", tmp_path / "issues.zip")
    assert "Elasticsearch is down" in str(info.value)


# --------------------------------------------------------------------------- small helpers
def test_report_task_and_dates() -> None:
    text = "projectKey=ss-app\nserverUrl=http://sonarqube:9000\nceTaskId=AY1\nceTaskUrl=http://sonarqube:9000/api/ce/task?id=AY1\n"
    values = read_report_task(text)
    assert values["ceTaskId"] == "AY1" and values["projectKey"] == "ss-app"
    assert values["ceTaskUrl"].endswith("id=AY1"), "only the first = splits"
    from datetime import date

    assert tomorrow(date(2026, 10, 7)) == "2026-10-08" and tomorrow(date(2026, 12, 31)) == "2027-01-01"
