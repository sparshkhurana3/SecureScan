"""A small client for the SonarQube Web API (plan M8 task 5).

Only the calls SecureScan needs: system status, users, tokens, settings, projects, the compute-engine task,
the quality gate, measures, and the issues export. The export is "a few lines, not a parser" (design): it
pages ``/api/issues/search`` and stores every response page as it came, in one zip, which DefectDojo's
``SonarQube Scan`` parser reads. Nothing here interprets findings.

Authentication: a token is sent as the user name of HTTP Basic authentication with an empty password (works on
every SonarQube version); a user name and password are sent as Basic authentication too.

The API cannot page past 10 000 results (``p * ps <= 10000``). ``export_issues`` therefore splits the query by
``types``, then ``severities``, then ``statuses`` (each issue has exactly one value of each, so the parts do not
overlap) whenever a query reports more than 10 000 issues; a part that is still too large is cut at the limit and
the export reports itself as ``truncated`` (the job's coverage note says so).

Unverified until spike S3 has run on Ubuntu: the parameter names of the newest Community Build. They follow the
S3 script (``spikes/s3/run.py``), which was written from the documented API.
"""

from __future__ import annotations

import asyncio
import json
import time
import zipfile
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import httpx

from securescan.logging import get_logger

log = get_logger(__name__)

Sleep = Callable[[float], Awaitable[None]]
Clock = Callable[[], float]

MAX_WINDOW = 10_000  # SonarQube refuses p * ps > 10000
PAGE_SIZE = 500  # the largest ps the API accepts
CE_DONE_STATES = ("SUCCESS", "FAILED", "CANCELED")
SPLIT_DIMENSIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("types", ("CODE_SMELL", "BUG", "VULNERABILITY", "SECURITY_HOTSPOT")),
    ("severities", ("INFO", "MINOR", "MAJOR", "CRITICAL", "BLOCKER")),
    ("statuses", ("OPEN", "CONFIRMED", "REOPENED", "RESOLVED", "CLOSED")),
)
QUALITY_MEASURES = (
    "bugs",
    "vulnerabilities",
    "security_hotspots",
    "code_smells",
    "coverage",
    "duplicated_lines_density",
    "ncloc",
    "reliability_rating",
    "security_rating",
    "sqale_rating",
    "sqale_index",
    "alert_status",
)
MQR_SETTING = "sonar.multi-quality-mode.enabled"


class SonarError(Exception):
    """A SonarQube call failed. ``str(exc)`` is plain language without secrets."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class SonarAuthError(SonarError):
    """401 or 403: the credentials were not accepted or lack the permission."""


class SonarNotReady(SonarError):
    """The server did not reach status UP (or a task did not finish) in time."""


@dataclass
class IssueExport:
    """What ``export_issues`` wrote."""

    path: Path
    total: int  # issues the server reported for the whole project
    exported: int  # issues that are in the zip
    files: int  # JSON pages in the zip
    truncated: bool
    splits: list[str] = field(default_factory=list)  # dimensions used to get under the 10 000 limit

    @property
    def complete(self) -> bool:
        return not self.truncated and self.exported >= self.total


def error_message(response: httpx.Response) -> str:
    """The server's own error text (``errors[].msg``), else the HTTP reason."""
    try:
        data = response.json()
    except ValueError:
        data = None
    if isinstance(data, dict):
        errors = data.get("errors")
        if isinstance(errors, list):
            messages = [str(e.get("msg")) for e in errors if isinstance(e, dict) and e.get("msg")]
            if messages:
                return "; ".join(messages)[:300]
    return (response.reason_phrase or f"HTTP {response.status_code}")[:120]


def tomorrow(today: date | None = None) -> str:
    """ISO date of the day after ``today`` (analysis tokens expire after one day)."""
    return ((today or date.today()) + timedelta(days=1)).isoformat()


class SonarQubeClient:
    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 60.0,
        sleep: Sleep = asyncio.sleep,
        clock: Clock = time.monotonic,
        additional_fields: str | None = "rules",
    ) -> None:
        auth: httpx.Auth | None = None
        if token:
            auth = httpx.BasicAuth(token, "")
        elif username is not None:
            auth = httpx.BasicAuth(username, password or "")
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"), auth=auth, transport=transport, timeout=timeout
        )
        self._sleep = sleep
        self._clock = clock
        self._additional_fields = additional_fields

    async def __aenter__(self) -> SonarQubeClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ plumbing
    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        expect: Sequence[int] = (200,),
        anonymous: bool = False,
    ) -> httpx.Response:
        kwargs: dict[str, Any] = {}
        if anonymous:
            kwargs["auth"] = None
        try:
            response = await self._http.request(
                method, path, params=_clean(params), data=_clean(data), **kwargs
            )
        except httpx.TransportError as exc:
            raise SonarError(f"SonarQube cannot be reached ({type(exc).__name__}).") from exc
        if response.status_code in expect:
            return response
        text = error_message(response)
        if response.status_code in (401, 403):
            raise SonarAuthError(f"SonarQube refused the request ({response.status_code}): {text}", response.status_code)
        raise SonarError(f"SonarQube answered {response.status_code} for {path}: {text}", response.status_code)

    async def _get_json(self, path: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        response = await self._request("GET", path, params=params)
        try:
            body = response.json()
        except ValueError as exc:
            raise SonarError(f"SonarQube sent an unreadable answer for {path}.") from exc
        if not isinstance(body, dict):
            raise SonarError(f"SonarQube sent an unexpected answer for {path}.")
        return body

    # ------------------------------------------------------------------ status
    async def system_status(self) -> str:
        """``UP``, ``STARTING``, ``DB_MIGRATION_NEEDED``, ... or an empty string when unreachable."""
        try:
            response = await self._http.get("/api/system/status", auth=None, timeout=10.0)
            body = response.json()
        except (httpx.HTTPError, ValueError):
            return ""
        if response.status_code != 200 or not isinstance(body, dict):
            return ""
        return str(body.get("status") or "")

    async def migrate_db(self) -> None:
        await self._request("POST", "/api/system/migrate_db", expect=(200, 204), anonymous=True)

    async def wait_until_up(self, timeout_s: float, interval_s: float = 3.0) -> float:
        """Poll the status until ``UP``; returns the seconds waited. Starts a database migration when asked to."""
        started = self._clock()
        migrated = False
        last = ""
        while True:
            last = await self.system_status()
            if last == "UP":
                return self._clock() - started
            if last == "DB_MIGRATION_NEEDED" and not migrated:
                migrated = True
                log.info("sonarqube_db_migration_started")
                try:
                    await self.migrate_db()
                except SonarError as exc:
                    log.warning("sonarqube_db_migration_request_failed", error=str(exc)[:200])
            if self._clock() - started >= timeout_s:
                shown = last or "no answer"
                raise SonarNotReady(
                    f"SonarQube did not become ready within {int(timeout_s)} seconds (last status: {shown})."
                )
            await self._sleep(interval_s)

    # ------------------------------------------------------------------ authentication and users
    async def validate_auth(self) -> bool:
        """True when the credentials of this client are accepted."""
        try:
            response = await self._http.get("/api/authentication/validate")
            body = response.json()
        except (httpx.HTTPError, ValueError):
            return False
        return response.status_code == 200 and isinstance(body, dict) and body.get("valid") is True

    async def change_password(self, login: str, previous: str, new: str) -> None:
        await self._request(
            "POST",
            "/api/users/change_password",
            data={"login": login, "previousPassword": previous, "password": new},
            expect=(204,),
        )

    async def find_user(self, login: str) -> dict[str, Any] | None:
        body = await self._get_json("/api/users/search", {"q": login})
        for user in body.get("users", []) or []:
            if isinstance(user, dict) and user.get("login") == login:
                return user
        return None

    async def create_user(self, login: str, name: str, password: str) -> None:
        await self._request(
            "POST",
            "/api/users/create",
            data={"login": login, "name": name, "password": password, "local": "true"},
        )

    async def add_permission(self, login: str, permission: str) -> None:
        await self._request(
            "POST",
            "/api/permissions/add_user",
            data={"login": login, "permission": permission},
            expect=(204,),
        )

    async def generate_token(
        self,
        name: str,
        token_type: str,
        *,
        login: str | None = None,
        project_key: str | None = None,
        expiration_date: str | None = None,
    ) -> str:
        """A new token (``USER_TOKEN`` or ``PROJECT_ANALYSIS_TOKEN``). The value is returned once."""
        response = await self._request(
            "POST",
            "/api/user_tokens/generate",
            data={
                "name": name,
                "type": token_type,
                "login": login,
                "projectKey": project_key,
                "expirationDate": expiration_date,
            },
        )
        value = response.json().get("token")
        if not isinstance(value, str) or not value:
            raise SonarError("SonarQube did not return a token.")
        return value

    async def revoke_token(self, name: str, *, login: str | None = None) -> None:
        await self._request(
            "POST", "/api/user_tokens/revoke", data={"name": name, "login": login}, expect=(204, 404)
        )

    # ------------------------------------------------------------------ settings and projects
    async def get_setting(self, key: str) -> str | None:
        body = await self._get_json("/api/settings/values", {"keys": key})
        for setting in body.get("settings", []) or []:
            if isinstance(setting, dict) and setting.get("key") == key:
                value = setting.get("value")
                return None if value is None else str(value)
        return None

    async def set_setting(self, key: str, value: str) -> None:
        await self._request("POST", "/api/settings/set", data={"key": key, "value": value}, expect=(204,))

    async def project_exists(self, project_key: str) -> bool:
        body = await self._get_json("/api/projects/search", {"projects": project_key})
        return any(
            isinstance(c, dict) and c.get("key") == project_key for c in body.get("components", []) or []
        )

    async def create_project(self, project_key: str, name: str) -> None:
        await self._request("POST", "/api/projects/create", data={"project": project_key, "name": name[:255]})

    async def ensure_project(self, project_key: str, name: str) -> bool:
        """Create the project when it does not exist. True when it was created."""
        if await self.project_exists(project_key):
            return False
        await self.create_project(project_key, name)
        return True

    # ------------------------------------------------------------------ analysis results
    async def ce_task(self, task_id: str) -> dict[str, Any]:
        body = await self._get_json("/api/ce/task", {"id": task_id})
        task = body.get("task")
        if not isinstance(task, dict):
            raise SonarError("SonarQube sent no compute-engine task.")
        return task

    async def wait_for_ce_task(self, task_id: str, timeout_s: float, interval_s: float = 2.0) -> dict[str, Any]:
        """Poll the compute-engine task until it ends; returns the final task document (any end state)."""
        started = self._clock()
        while True:
            task = await self.ce_task(task_id)
            if str(task.get("status")) in CE_DONE_STATES:
                return task
            if self._clock() - started >= timeout_s:
                raise SonarNotReady(
                    f"SonarQube did not finish processing the analysis within {int(timeout_s)} seconds."
                )
            await self._sleep(interval_s)

    async def quality_gate(self, project_key: str, analysis_id: str | None = None) -> dict[str, Any]:
        """``{"status": "OK|ERROR|WARN|NONE", "conditions": [{metric, status, actual, threshold, comparator}]}``."""
        params: dict[str, Any] = {"analysisId": analysis_id} if analysis_id else {"projectKey": project_key}
        body = await self._get_json("/api/qualitygates/project_status", params)
        status = body.get("projectStatus")
        if not isinstance(status, dict):
            raise SonarError("SonarQube sent no quality gate status.")
        conditions = []
        for cond in status.get("conditions", []) or []:
            if isinstance(cond, dict):
                conditions.append(
                    {
                        "metric": str(cond.get("metricKey") or ""),
                        "status": str(cond.get("status") or ""),
                        "actual": str(cond.get("actualValue") if cond.get("actualValue") is not None else ""),
                        "threshold": str(
                            cond.get("errorThreshold") if cond.get("errorThreshold") is not None else ""
                        ),
                        "comparator": str(cond.get("comparator") or ""),
                    }
                )
        return {"status": str(status.get("status") or "NONE"), "conditions": conditions}

    async def measures(
        self, project_key: str, metric_keys: Iterable[str] = QUALITY_MEASURES
    ) -> dict[str, str | None]:
        body = await self._get_json(
            "/api/measures/component",
            {"component": project_key, "metricKeys": ",".join(metric_keys)},
        )
        component = body.get("component") or {}
        result: dict[str, str | None] = {}
        for measure in component.get("measures", []) or []:
            if isinstance(measure, dict) and measure.get("metric"):
                value = measure.get("value")
                result[str(measure["metric"])] = None if value is None else str(value)
        return result

    # ------------------------------------------------------------------ the issues export
    async def _issues_page(self, project_key: str, page: int, filters: Mapping[str, str]) -> tuple[str, dict[str, Any]]:
        params: dict[str, Any] = {"components": project_key, "ps": PAGE_SIZE, "p": page}
        if self._additional_fields:
            params["additionalFields"] = self._additional_fields
        params.update(filters)
        response = await self._request("GET", "/api/issues/search", params=params)
        try:
            body = response.json()
        except ValueError as exc:
            raise SonarError("SonarQube sent an unreadable issues page.") from exc
        if not isinstance(body, dict):
            raise SonarError("SonarQube sent an unexpected issues page.")
        return response.text, body

    async def export_issues(self, project_key: str, target: Path) -> IssueExport:
        """Write every issue page of the project into the zip at ``target`` (see the module docstring)."""
        state = _ExportState()
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
            first_text, first = await self._issues_page(project_key, 1, {})
            total = _total(first)
            await self._collect(project_key, {}, 0, first_text, first, archive, state)
        return IssueExport(
            path=target,
            total=total,
            exported=state.exported,
            files=state.files,
            truncated=state.truncated or state.exported < total,
            splits=sorted(state.splits),
        )

    async def _collect(
        self,
        project_key: str,
        filters: dict[str, str],
        depth: int,
        first_text: str | None,
        first_body: dict[str, Any] | None,
        archive: zipfile.ZipFile,
        state: _ExportState,
    ) -> None:
        if first_text is None or first_body is None:
            first_text, first_body = await self._issues_page(project_key, 1, filters)
        total = _total(first_body)
        if total == 0:
            return
        if total > MAX_WINDOW and depth < len(SPLIT_DIMENSIONS):
            dimension, values = SPLIT_DIMENSIONS[depth]
            state.splits.add(dimension)
            log.info("sonarqube_export_split", dimension=dimension, total=total)
            for value in values:
                await self._collect(project_key, {**filters, dimension: value}, depth + 1, None, None, archive, state)
            return
        if total > MAX_WINDOW:
            state.truncated = True
        limit = min(total, MAX_WINDOW)
        page = 1
        text, body = first_text, first_body
        while True:
            issues = body.get("issues") or []
            state.add_page(archive, text, len(issues))
            if page * PAGE_SIZE >= limit or not issues:
                break
            page += 1
            text, body = await self._issues_page(project_key, page, filters)


@dataclass
class _ExportState:
    files: int = 0
    exported: int = 0
    truncated: bool = False
    splits: set[str] = field(default_factory=set)

    def add_page(self, archive: zipfile.ZipFile, text: str, count: int) -> None:
        self.files += 1
        self.exported += count
        archive.writestr(f"issues-{self.files}.json", text)


def _total(body: Mapping[str, Any]) -> int:
    paging = body.get("paging")
    if isinstance(paging, dict) and paging.get("total") is not None:
        return int(paging["total"])
    return len(body.get("issues") or [])


def _clean(values: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Drop ``None`` values (optional parameters) and render booleans the way SonarQube reads them."""
    if values is None:
        return None
    result: dict[str, Any] = {}
    for key, value in values.items():
        if value is None:
            continue
        result[key] = ("true" if value else "false") if isinstance(value, bool) else value
    return result


def read_report_task(text: str) -> dict[str, str]:
    """``key=value`` lines of the scanner's ``report-task.txt`` (``ceTaskId``, ``projectKey``, ...)."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def issues_zip_summary(path: Path) -> dict[str, int]:
    """Pages and issues inside an export zip (used by tests and the job log)."""
    pages = 0
    issues = 0
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            pages += 1
            issues += len(json.loads(archive.read(name)).get("issues") or [])
    return {"pages": pages, "issues": issues}
