"""DefectDojo REST client.

One module talks to DefectDojo (design: "one client module to change" on an upgrade). It uses httpx,
sends ``Authorization: Token <key>``, retries connection errors, timeouts and 5xx responses with
exponential backoff, and turns every other failure into one of the exceptions below. Secrets (tokens,
passwords) never appear in an exception message or a log line.

SecureScan never parses scanner output: ``reimport_scan`` uploads the raw report and DefectDojo's own
parser does the rest; ``iter_findings`` and ``get_findings_by_ids`` read the findings back.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from types import TracebackType
from typing import Any

import httpx

from securescan.logging import get_logger, scrub

log = get_logger(__name__)

API = "/api/v2"

# Statuses worth retrying: the server is busy or restarting. Everything else is the caller's problem.
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

# Findings that count as open (design: "active, not duplicate, not false positive, not out of scope
# and not risk accepted").
ACTIVE_FILTER: dict[str, str] = {
    "active": "true",
    "duplicate": "false",
    "false_p": "false",
    "out_of_scope": "false",
    "risk_accepted": "false",
}

MAX_RETRY_AFTER_SECONDS = 60.0
MAX_BACKOFF_SECONDS = 30.0
ID_BATCH = 100


class DefectDojoError(Exception):
    """Any failure talking to DefectDojo. ``status_code`` is None for connection problems."""

    def __init__(
        self, message: str, *, status_code: int | None = None, body: str | None = None
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class DefectDojoUnavailable(DefectDojoError):  # noqa: N818 - reads better than ...Error
    """DefectDojo did not answer, or kept answering 5xx, after the retries. Try again later."""


class DefectDojoRejected(DefectDojoError):
    """DefectDojo answered with a 4xx: the request itself is wrong (or the token is)."""


class DefectDojoAuthError(DefectDojoRejected):
    """401 or 403: the token is missing, revoked, or lacks the privilege."""


class DefectDojoNotFound(DefectDojoRejected):
    """404."""


def _error_text(response: httpx.Response) -> str:
    return scrub(response.text[:500].replace("\n", " "))


@dataclass(frozen=True)
class ReimportRequest:
    """Everything ``POST /api/v2/reimport-scan/`` needs for one raw report (plan M4 task 3)."""

    file_path: Path
    file_name: str
    scan_type: str
    product_type_name: str
    product_name: str
    engagement_name: str
    test_title: str
    version: str | None = None
    commit_hash: str | None = None
    branch_tag: str | None = None
    tags: tuple[str, ...] = ()
    scan_date: date | None = None
    content_type: str = "application/octet-stream"

    def form_fields(self) -> dict[str, Any]:
        """The multipart form fields (the file is sent separately). Booleans are the strings
        DefectDojo's form parser reads."""
        fields: dict[str, Any] = {
            "scan_type": self.scan_type,
            "product_type_name": self.product_type_name,
            "product_name": self.product_name,
            "engagement_name": self.engagement_name,
            "test_title": self.test_title,
            "auto_create_context": "true",
            "deduplication_on_engagement": "true",
            "close_old_findings": "true",
            "deduplication_execution_mode": "async_wait",
            "minimum_severity": "Info",
        }
        if self.version:
            fields["version"] = self.version[:100]
        if self.commit_hash:
            fields["commit_hash"] = self.commit_hash[:100]
        if self.branch_tag:
            fields["branch_tag"] = self.branch_tag[:150]
        if self.tags:
            fields["tags"] = [t[:100] for t in self.tags]
        if self.scan_date is not None:
            fields["scan_date"] = self.scan_date.isoformat()
        return fields


@dataclass(frozen=True)
class ReimportResult:
    """The parts of the reimport response SecureScan uses."""

    test_id: int
    engagement_id: int | None
    product_id: int | None
    product_type_id: int | None
    statistics: dict[str, Any] = field(default_factory=dict)
    deduplication_complete: bool = False

    @property
    def after(self) -> dict[str, Any]:
        value = self.statistics.get("after")
        return value if isinstance(value, dict) else {}

    @classmethod
    def from_response(cls, payload: Mapping[str, Any]) -> ReimportResult:
        test_id = payload.get("test_id")
        if test_id is None and isinstance(payload.get("test"), int):
            test_id = payload["test"]
        if not isinstance(test_id, int):
            raise DefectDojoError("DefectDojo's answer to the import has no test id")
        stats = payload.get("statistics")
        return cls(
            test_id=test_id,
            engagement_id=_int_or_none(payload.get("engagement_id")),
            product_id=_int_or_none(payload.get("product_id")),
            product_type_id=_int_or_none(payload.get("product_type_id")),
            statistics=dict(stats) if isinstance(stats, dict) else {},
            # Absent (an older release) is treated as "not complete": the caller re-reads later.
            deduplication_complete=payload.get("deduplication_complete") is True,
        )


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _chunks(items: Sequence[int], size: int) -> list[list[int]]:
    return [list(items[i : i + size]) for i in range(0, len(items), size)]


Sleep = Callable[[float], Awaitable[None]]


class DefectDojoClient:
    """Async client. Create one per task and close it (``async with`` or ``aclose``)."""

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        *,
        timeout: float = 60.0,
        import_timeout: float = 900.0,
        max_retries: int = 3,
        backoff_base: float = 2.0,
        page_size: int = 200,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleep | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._import_timeout = import_timeout
        self._max_retries = max(0, max_retries)
        self._backoff_base = backoff_base
        self._page_size = max(1, min(page_size, 1000))
        self._sleep: Sleep = sleep or asyncio.sleep
        self._http = httpx.AsyncClient(
            base_url=self._base_url, timeout=timeout, transport=transport, follow_redirects=False
        )
        # None = not probed yet; True = the findings API filters ``?id=1,2,3``; False = it does not.
        self._id_filter_ok: bool | None = None

    def __repr__(self) -> str:  # never show the token
        return f"DefectDojoClient({self._base_url!r})"

    async def __aenter__(self) -> DefectDojoClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    # --- plumbing ---------------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Token {self._token}"
        return headers

    def _delay(self, attempt: int, response: httpx.Response | None) -> float:
        if response is not None:
            retry_after = response.headers.get("retry-after")
            if retry_after and retry_after.isdigit():
                return min(float(retry_after), MAX_RETRY_AFTER_SECONDS)
        return min(self._backoff_base * (2**attempt), MAX_BACKOFF_SECONDS)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        data: Mapping[str, Any] | None = None,
        upload: tuple[Path, str, str] | None = None,
        timeout: float | None = None,
        expected: Sequence[int] = (200,),
    ) -> httpx.Response:
        """Send one request with retries. ``upload`` is ``(path, file name, content type)``; the
        file is opened again for every attempt."""
        attempts = self._max_retries + 1
        last_problem = "no attempt was made"
        response: httpx.Response | None = None
        for attempt in range(attempts):
            handle = None
            files = None
            if upload is not None:
                handle = upload[0].open("rb")
                files = {"file": (upload[1], handle, upload[2])}
            response = None
            try:
                response = await self._http.request(
                    method,
                    path,
                    params=params,
                    json=json_body,
                    data=data,
                    files=files,
                    headers=self._headers(),
                    timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
                )
            except httpx.TransportError as exc:
                last_problem = f"{type(exc).__name__}: {scrub(str(exc))[:200]}"
            finally:
                if handle is not None:
                    handle.close()
            if response is not None:
                status = response.status_code
                if status in expected:
                    return response
                if status not in RETRY_STATUSES:
                    raise self._error_for(method, path, response)
                last_problem = f"HTTP {status}: {_error_text(response)}"
            if attempt + 1 < attempts:
                delay = self._delay(attempt, response)
                log.warning(
                    "defectdojo_retry",
                    method=method,
                    path=path,
                    attempt=attempt + 1,
                    delay_seconds=delay,
                    problem=last_problem[:200],
                )
                await self._sleep(delay)
        raise DefectDojoUnavailable(
            f"DefectDojo did not answer {method} {path} after {attempts} attempt(s): {last_problem}",
            status_code=response.status_code if response is not None else None,
        )

    @staticmethod
    def _error_for(method: str, path: str, response: httpx.Response) -> DefectDojoError:
        status = response.status_code
        text = _error_text(response)
        message = f"DefectDojo refused {method} {path}: HTTP {status}: {text}"
        if status in (401, 403):
            return DefectDojoAuthError(message, status_code=status, body=text)
        if status == 404:
            return DefectDojoNotFound(message, status_code=status, body=text)
        return DefectDojoRejected(message, status_code=status, body=text)

    @staticmethod
    def _json(response: httpx.Response) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise DefectDojoError(
                "DefectDojo returned something that is not JSON", status_code=response.status_code
            ) from exc

    # --- liveness and tokens -------------------------------------------------------------------

    async def ping(self, *, timeout: float = 5.0) -> tuple[bool, int | None, float]:
        """``(answers, http status, seconds)`` for ``GET /api/v2/``; no retries, never raises.

        Anything below 500 counts as "answers" (the API root may demand a token).
        """
        started = time.monotonic()
        try:
            response = await self._http.get(f"{API}/", headers=self._headers(), timeout=timeout)
        except httpx.HTTPError:
            return False, None, time.monotonic() - started
        return response.status_code < 500, response.status_code, time.monotonic() - started

    @classmethod
    async def obtain_token(
        cls,
        base_url: str,
        username: str,
        password: str,
        *,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleep | None = None,
    ) -> str:
        """``POST /api/v2/api-token-auth/``. The password is sent once and not kept."""
        async with cls(
            base_url, None, timeout=timeout, max_retries=2, transport=transport, sleep=sleep
        ) as client:
            response = await client._request(
                "POST",
                f"{API}/api-token-auth/",
                json_body={"username": username, "password": password},
            )
            token = client._json(response).get("token")
        if not isinstance(token, str) or not token:
            raise DefectDojoError("DefectDojo did not return a token")
        return token

    async def user_profile(self) -> dict[str, Any]:
        """``GET /user_profile/``: the user behind the token (``{"user": {...}}``)."""
        payload = self._json(await self._request("GET", f"{API}/user_profile/"))
        user = payload.get("user") if isinstance(payload, dict) else None
        return user if isinstance(user, dict) else {}

    # --- import ----------------------------------------------------------------------------------

    async def reimport_scan(self, request: ReimportRequest) -> ReimportResult:
        """Upload one raw report. The first call creates Product Type, Product, Engagement and Test
        (``auto_create_context``); later calls update the same Test and close what disappeared."""
        response = await self._request(
            "POST",
            f"{API}/reimport-scan/",
            data=request.form_fields(),
            upload=(request.file_path, request.file_name, request.content_type),
            timeout=self._import_timeout,
            expected=(200, 201),
        )
        payload = self._json(response)
        if not isinstance(payload, dict):
            raise DefectDojoError("DefectDojo's answer to the import is not an object")
        return ReimportResult.from_response(payload)

    # --- findings -----------------------------------------------------------------------------------

    async def iter_findings(
        self, test_id: int, *, include_inactive: bool = False, page_size: int | None = None
    ) -> AsyncIterator[list[dict[str, Any]]]:
        """Yield pages of findings of one Test (``limit`` 200, stable order by id).

        ``include_inactive=False`` keeps only open findings; True returns every finding of the Test
        (closed, false positive, duplicate, ...), which history needs for closure tracking.
        """
        size = page_size or self._page_size
        params: dict[str, Any] = {"test": test_id, "limit": size, "offset": 0, "o": "id"}
        if not include_inactive:
            params.update(ACTIVE_FILTER)
        while True:
            payload = self._json(await self._request("GET", f"{API}/findings/", params=params))
            results = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(results, list) or not results:
                return
            yield [r for r in results if isinstance(r, dict)]
            if not payload.get("next"):
                return
            params["offset"] = int(params["offset"]) + len(results)

    async def list_findings(
        self, test_id: int, *, include_inactive: bool = False
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        async for page in self.iter_findings(test_id, include_inactive=include_inactive):
            out.extend(page)
        return out

    async def count_findings(self, params: Mapping[str, Any]) -> int:
        """Number of findings matching ``params`` (``limit=1``, read ``count``)."""
        query = dict(params)
        query["limit"] = 1
        payload = self._json(await self._request("GET", f"{API}/findings/", params=query))
        return int(payload.get("count", 0)) if isinstance(payload, dict) else 0

    async def get_finding(self, finding_id: int) -> dict[str, Any]:
        payload = self._json(await self._request("GET", f"{API}/findings/{finding_id}/"))
        if not isinstance(payload, dict):
            raise DefectDojoError("DefectDojo's finding is not an object")
        return payload

    async def get_findings_by_ids(self, ids: Sequence[int]) -> dict[int, dict[str, Any]]:
        """Current state of many findings by id. Findings that no longer exist are missing from
        the result. Uses ``?id=1,2,3`` when DefectDojo honours it (checked on first use), else one
        request per finding."""
        wanted = list(dict.fromkeys(ids))
        found: dict[int, dict[str, Any]] = {}
        for chunk in _chunks(wanted, ID_BATCH):
            if self._id_filter_ok is not False:
                batch = await self._by_id_filter(chunk)
                if batch is not None:
                    found.update(batch)
                    continue
            for finding_id in chunk:
                try:
                    found[finding_id] = await self.get_finding(finding_id)
                except DefectDojoNotFound:
                    continue
        return found

    async def _by_id_filter(self, chunk: list[int]) -> dict[int, dict[str, Any]] | None:
        """Try the batch filter; None means "the filter is not honoured, use single reads"."""
        params = {"id": ",".join(str(i) for i in chunk), "limit": max(len(chunk), 1), "o": "id"}
        payload = self._json(await self._request("GET", f"{API}/findings/", params=params))
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list):
            self._id_filter_ok = False
            return None
        got = {r["id"]: r for r in results if isinstance(r, dict) and isinstance(r.get("id"), int)}
        count = payload.get("count", len(results))
        # Honoured filter: only requested ids, and the page holds every match.
        if set(got) <= set(chunk) and count == len(results) <= len(chunk):
            self._id_filter_ok = True
            return got
        self._id_filter_ok = False
        log.warning("defectdojo_id_filter_ignored", note="falling back to one request per finding")
        return None

    # --- users (accounts token only) ---------------------------------------------------------------------

    async def find_user(self, username: str) -> dict[str, Any] | None:
        payload = self._json(
            await self._request(
                "GET", f"{API}/users/", params={"username": username, "limit": 100}
            )
        )
        for item in payload.get("results", []) if isinstance(payload, dict) else []:
            if isinstance(item, dict) and item.get("username") == username:
                return item
        return None

    async def get_user(self, user_id: int) -> dict[str, Any]:
        payload = self._json(await self._request("GET", f"{API}/users/{user_id}/"))
        if not isinstance(payload, dict):
            raise DefectDojoError("DefectDojo's user is not an object")
        return payload

    async def create_user(
        self,
        *,
        username: str,
        password: str,
        email: str,
        first_name: str = "",
        last_name: str = "",
        is_staff: bool = False,
        is_superuser: bool = False,
        is_active: bool = True,
    ) -> dict[str, Any]:
        """``POST /users/`` (superuser token). ``email`` is required by DefectDojo."""
        body = {
            "username": username,
            "password": password,
            "email": email,
            "first_name": first_name[:150],
            "last_name": last_name[:150],
            "is_active": is_active,
            "is_staff": is_staff,
            "is_superuser": is_superuser,
        }
        response = await self._request(
            "POST", f"{API}/users/", json_body=body, expected=(200, 201)
        )
        payload = self._json(response)
        if not isinstance(payload, dict) or not isinstance(payload.get("id"), int):
            raise DefectDojoError("DefectDojo did not return the new user")
        return payload

    async def patch_user(self, user_id: int, fields: Mapping[str, Any]) -> dict[str, Any]:
        payload = self._json(
            await self._request("PATCH", f"{API}/users/{user_id}/", json_body=dict(fields))
        )
        return payload if isinstance(payload, dict) else {}

    async def set_user_password(self, user_id: int, password: str) -> None:
        """Set a new password through ``PATCH /users/{id}/``.

        Spike S1 read DefectDojo 3.4.0's serializer as refusing this ("Update of password though API
        is not allowed"). It is kept as one call so the answer is visible in one place: a refusal
        raises ``DefectDojoRejected`` and the caller reports that an Admin must set the password.
        """
        await self._request("PATCH", f"{API}/users/{user_id}/", json_body={"password": password})

    async def set_force_password_reset(self, user_id: int) -> None:
        """Ask DefectDojo to demand a new password at the user's next sign-in. The flag lives on
        ``/user_contact_infos/`` (superuser token). Never set it on a service account: while it is
        set, ``api-token-auth`` refuses the user."""
        payload = self._json(
            await self._request("GET", f"{API}/user_contact_infos/", params={"user": user_id})
        )
        rows = payload.get("results", []) if isinstance(payload, dict) else []
        if rows and isinstance(rows[0], dict) and isinstance(rows[0].get("id"), int):
            await self._request(
                "PATCH",
                f"{API}/user_contact_infos/{rows[0]['id']}/",
                json_body={"force_password_reset": True},
            )
        else:
            await self._request(
                "POST",
                f"{API}/user_contact_infos/",
                json_body={"user": user_id, "force_password_reset": True},
                expected=(200, 201),
            )

    # --- settings, product types, products, tests ------------------------------------------------------------

    async def system_settings(self) -> dict[str, Any]:
        """The (single) system settings row (superuser token)."""
        payload = self._json(await self._request("GET", f"{API}/system_settings/"))
        rows = payload.get("results", []) if isinstance(payload, dict) else []
        if not rows or not isinstance(rows[0], dict):
            raise DefectDojoError("DefectDojo returned no system settings")
        return rows[0]

    async def patch_system_settings(self, settings_id: int, fields: Mapping[str, Any]) -> dict[str, Any]:
        payload = self._json(
            await self._request(
                "PATCH", f"{API}/system_settings/{settings_id}/", json_body=dict(fields)
            )
        )
        return payload if isinstance(payload, dict) else {}

    async def product_types(self, name: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": 200}
        if name is not None:
            params["name"] = name
        payload = self._json(await self._request("GET", f"{API}/product_types/", params=params))
        rows = payload.get("results", []) if isinstance(payload, dict) else []
        return [r for r in rows if isinstance(r, dict) and (name is None or r.get("name") == name)]

    async def create_product_type(self, name: str, description: str = "") -> dict[str, Any]:
        payload = self._json(
            await self._request(
                "POST",
                f"{API}/product_types/",
                json_body={"name": name, "description": description},
                expected=(200, 201),
            )
        )
        return payload if isinstance(payload, dict) else {}

    async def patch_product(self, product_id: int, fields: Mapping[str, Any]) -> dict[str, Any]:
        payload = self._json(
            await self._request("PATCH", f"{API}/products/{product_id}/", json_body=dict(fields))
        )
        return payload if isinstance(payload, dict) else {}

    async def patch_test(self, test_id: int, fields: Mapping[str, Any]) -> dict[str, Any]:
        payload = self._json(
            await self._request("PATCH", f"{API}/tests/{test_id}/", json_body=dict(fields))
        )
        return payload if isinstance(payload, dict) else {}
