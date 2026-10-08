"""GitHub App client: App JWT, narrowed installation tokens, repository listing, branch heads.

Rules (design "GitHub integration", plan M7 task 2):

* The App authenticates with a short-lived JWT (RS256, ``iat`` 60 seconds in the past, ``exp`` 9 minutes
  ahead, ``iss`` the App's client id). Two private keys are supported so rotation needs no downtime.
* An installation token is minted per use. For a clone it is narrowed to one repository with
  ``contents: read``. It lives in memory only and is never logged, stored or put on a command line.
* Requests are serial. ``Retry-After`` and the primary and secondary rate limits are honoured, and the
  client backs off when ``X-RateLimit-Remaining`` drops below ``low_water``.
* Everything goes through the on-demand egress proxy (``proxy_url``) when one is given.
* The ``X-GitHub-Api-Version`` header is pinned from the connection row.

This module never reads the database; ``connection.py`` builds the client from the connection row.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
import jwt

from securescan.logging import get_logger, scrub

log = get_logger(__name__)

DEFAULT_API_BASE_URL = "https://api.github.com"
DEFAULT_GIT_HOST = "github.com"
DEFAULT_API_VERSION = "2026-03-10"
JWT_BACKDATE_SECONDS = 60
JWT_LIFETIME_SECONDS = 9 * 60
RATE_LOW_WATER = 100
MAX_PAGES = 300  # 30 000 repositories
TOKEN_REFRESH_MARGIN_SECONDS = 300

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]


# ------------------------------------------------------------------------------ errors


class GitHubError(Exception):
    """A GitHub call failed. ``str(error)`` is a plain-language sentence safe to show to an Admin."""

    def __init__(self, message: str, *, status: int | None = None, code: str = "github.error") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class GitHubAuthError(GitHubError):
    """GitHub rejected the App's own credentials (wrong App or client id, wrong key, clock skew)."""


class GitHubPermissionError(GitHubError):
    """The App is not allowed to do this (missing permission, suspended, repository not selected)."""


class GitHubNotFound(GitHubError):
    """The installation, repository or branch does not exist or is not visible to the App."""


class GitHubRateLimited(GitHubError):
    """The rate limit is exhausted or nearly so and the wait would be too long."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message, status=429, code="github.rate_limited")
        self.retry_after = retry_after


class GitHubUnreachable(GitHubError):
    """The request never got an answer (network, proxy, DNS, TLS, timeout)."""


# ------------------------------------------------------------------------------ data


@dataclass(frozen=True)
class GitHubAppConfig:
    """The non-secret settings of the connection (from the ``github_connections`` row)."""

    app_id: str
    client_id: str
    installation_id: str
    api_base_url: str = DEFAULT_API_BASE_URL
    git_host: str = DEFAULT_GIT_HOST
    api_version: str = DEFAULT_API_VERSION

    @property
    def api_host(self) -> str:
        return (urlsplit(self.api_base_url).hostname or "").lower()


@dataclass(frozen=True)
class InstallationToken:
    """A short-lived installation token. ``repr`` never shows the token."""

    token: str = field(repr=False)
    expires_at: datetime
    repository: str | None = None  # None: every repository of the installation

    def expires_within(self, seconds: float, now: float) -> bool:
        return self.expires_at.timestamp() - now <= seconds


@dataclass(frozen=True)
class RepositoryInfo:
    id: int
    name: str
    full_name: str
    owner: str
    default_branch: str | None
    private: bool = True
    archived: bool = False
    disabled: bool = False
    fork: bool = False
    html_url: str | None = None


def parse_repository(data: dict[str, Any]) -> RepositoryInfo:
    full_name = str(data["full_name"])
    owner = (data.get("owner") or {}).get("login") or full_name.split("/", 1)[0]
    return RepositoryInfo(
        id=int(data["id"]),
        name=str(data.get("name") or full_name.split("/", 1)[-1]),
        full_name=full_name,
        owner=str(owner),
        default_branch=data.get("default_branch"),
        private=bool(data.get("private", True)),
        archived=bool(data.get("archived", False)),
        disabled=bool(data.get("disabled", False)),
        fork=bool(data.get("fork", False)),
        html_url=data.get("html_url"),
    )


# ------------------------------------------------------------------------------ JWT


def make_app_jwt(client_id: str, private_key_pem: str, *, now: float | None = None) -> str:
    """The App JWT: RS256, ``iat`` now - 60 s (clock drift), ``exp`` now + 9 min, ``iss`` client id."""
    issued = int(time.time() if now is None else now)
    claims = {
        "iat": issued - JWT_BACKDATE_SECONDS,
        "exp": issued + JWT_LIFETIME_SECONDS,
        "iss": client_id,
    }
    return jwt.encode(claims, private_key_pem, algorithm="RS256")


def parse_github_time(value: str) -> datetime:
    """GitHub timestamps are ISO 8601 UTC such as ``2026-10-07T12:00:00Z``."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


_NEXT_LINK = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


def next_link(header: str | None) -> str | None:
    """The ``rel="next"`` URL of a ``Link`` header, or None."""
    if not header:
        return None
    match = _NEXT_LINK.search(header)
    return match.group(1) if match else None


# ------------------------------------------------------------------------------ client


class GitHubClient:
    """Serial, rate-limit-aware client for one GitHub App installation.

    ``private_keys`` are tried in order (active key first); the key that worked is remembered.
    ``http`` may be given in tests (``httpx.AsyncClient(transport=httpx.MockTransport(...))``).
    """

    def __init__(
        self,
        config: GitHubAppConfig,
        private_keys: Sequence[str],
        *,
        http: httpx.AsyncClient | None = None,
        proxy_url: str | None = None,
        timeout: float = 30.0,
        clock: Clock = time.time,
        sleep: Sleeper = asyncio.sleep,
        low_water: int = RATE_LOW_WATER,
        max_wait_s: float = 120.0,
        max_retries: int = 3,
    ) -> None:
        self.config = config
        self._keys = [k for k in private_keys if k]
        self._http = http or httpx.AsyncClient(proxy=proxy_url or None, timeout=timeout)
        self._owns_http = http is None
        self.proxy_url = proxy_url or None
        self._clock = clock
        self._sleep = sleep
        self._low_water = low_water
        self._max_wait_s = max_wait_s
        self._max_retries = max_retries
        self._lock = asyncio.Lock()  # one request at a time
        self._rate: dict[str, tuple[int, float]] = {}  # bucket -> (remaining, reset epoch)
        self._working_key = 0
        self._read_token: InstallationToken | None = None
        self.requests_made = 0

    # -- lifecycle ---------------------------------------------------------------------------------
    async def aclose(self) -> None:
        self._read_token = None
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> GitHubClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # -- rate limit state --------------------------------------------------------------------------
    def rate_remaining(self, bucket: str = "installation") -> int | None:
        entry = self._rate.get(bucket)
        return entry[0] if entry else None

    def rate_reset_at(self, bucket: str = "installation") -> datetime | None:
        entry = self._rate.get(bucket)
        return datetime.fromtimestamp(entry[1], tz=timezone.utc) if entry else None

    def _note_rate_limit(self, bucket: str, response: httpx.Response) -> None:
        remaining = response.headers.get("x-ratelimit-remaining")
        reset = response.headers.get("x-ratelimit-reset")
        if remaining is not None and remaining.isdigit():
            reset_epoch = float(reset) if reset and reset.isdigit() else self._clock() + 60.0
            self._rate[bucket] = (int(remaining), reset_epoch)

    async def _respect_low_water(self, bucket: str) -> None:
        entry = self._rate.get(bucket)
        if entry is None:
            return
        remaining, reset_epoch = entry
        if remaining >= self._low_water:
            return
        wait = reset_epoch - self._clock()
        if wait <= 0:
            del self._rate[bucket]
            return
        if wait > self._max_wait_s:
            raise GitHubRateLimited(
                "GitHub's request limit is almost used up (%d left). It resets in %d minutes."
                % (remaining, int(wait // 60) + 1),
                retry_after=wait,
            )
        log.info("github_rate_backoff", remaining=remaining, wait_seconds=int(wait) + 1)
        await self._sleep(wait + 1.0)
        self._rate.pop(bucket, None)

    def _retry_wait(self, response: httpx.Response) -> float | None:
        """Seconds to wait when this response is a rate-limit answer, else None."""
        if response.status_code not in (403, 429):
            return None
        retry_after = response.headers.get("retry-after")
        if retry_after and retry_after.strip().isdigit():
            return max(float(retry_after.strip()), 1.0)
        if response.headers.get("x-ratelimit-remaining") == "0":
            reset = response.headers.get("x-ratelimit-reset", "")
            if reset.isdigit():
                return max(float(reset) - self._clock(), 1.0)
            return 60.0
        message = _error_message(response).lower()
        if "rate limit" in message or "abuse" in message:
            return 60.0
        return None

    # -- low-level request -------------------------------------------------------------------------
    def _url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            if (urlsplit(path_or_url).hostname or "").lower() != self.config.api_host:
                raise GitHubError(
                    "GitHub sent a link to another host; it was not followed.", code="github.bad_link"
                )
            return path_or_url
        return self.config.api_base_url.rstrip("/") + "/" + path_or_url.lstrip("/")

    def _headers(self, bearer: str) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + bearer,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.config.api_version,
            "User-Agent": "SecureScan",
        }

    async def _request(
        self,
        method: str,
        path: str,
        *,
        bearer: str,
        bucket: str,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        expect: tuple[int, ...] = (200,),
    ) -> httpx.Response:
        url = self._url(path)
        shown = urlsplit(url).path  # only the path is logged: never headers, query or body
        for attempt in range(self._max_retries + 1):
            await self._respect_low_water(bucket)
            async with self._lock:
                try:
                    response = await self._http.request(
                        method, url, headers=self._headers(bearer), json=json_body, params=params
                    )
                except httpx.TimeoutException as exc:
                    raise GitHubUnreachable(
                        "GitHub did not answer in time. Check the egress proxy and the network.",
                        code="github.timeout",
                    ) from exc
                except httpx.HTTPError as exc:
                    raise GitHubUnreachable(
                        "GitHub could not be reached (%s). Check the egress proxy, DNS and the "
                        "organisation's IP allow list." % type(exc).__name__,
                        code="github.unreachable",
                    ) from exc
            self.requests_made += 1
            self._note_rate_limit(bucket, response)
            log.debug("github_request", method=method, path=shown, status=response.status_code)
            if response.status_code in expect:
                return response
            wait = self._retry_wait(response)
            if wait is not None:
                if attempt < self._max_retries and wait <= self._max_wait_s:
                    log.info("github_retry_after", wait_seconds=int(wait), path=shown)
                    await self._sleep(wait)
                    continue
                raise GitHubRateLimited(
                    "GitHub is limiting requests. Try again in about %d minutes." % (int(wait // 60) + 1),
                    retry_after=wait,
                )
            if response.status_code >= 500 and attempt < self._max_retries:
                await self._sleep(float(2**attempt))
                continue
            raise _error_for(response)
        raise GitHubUnreachable("GitHub kept failing; giving up.", code="github.failed")  # pragma: no cover

    # -- App-level calls ---------------------------------------------------------------------------
    def _key_order(self) -> list[int]:
        count = len(self._keys)
        return [(self._working_key + i) % count for i in range(count)]

    async def _app_request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        expect: tuple[int, ...] = (200,),
    ) -> httpx.Response:
        """A call authenticated with the App JWT; tries the second key when the first is rejected."""
        if not self._keys:
            raise GitHubAuthError(
                "No private key is stored for the GitHub App. Upload one in Settings.",
                code="github.no_key",
            )
        last: GitHubAuthError | None = None
        for index in self._key_order():
            token = make_app_jwt(self.config.client_id, self._keys[index], now=self._clock())
            try:
                response = await self._request(
                    method, path, bearer=token, bucket="app", json_body=json_body, expect=expect
                )
            except GitHubAuthError as exc:
                last = exc
                continue
            self._working_key = index
            return response
        raise last or GitHubAuthError("GitHub rejected the App's private key.", code="github.bad_key")

    async def get_installation(self) -> dict[str, Any]:
        """``GET /app/installations/{id}``: account login, permissions, suspension."""
        response = await self._app_request("GET", "/app/installations/%s" % self.config.installation_id)
        data: dict[str, Any] = response.json()
        return data

    async def mint_installation_token(
        self, *, repository_id: int | None = None, repository: str | None = None
    ) -> InstallationToken:
        """A new installation token with ``contents: read``.

        With ``repository_id`` (preferred, survives renames) or ``repository`` (``owner/name`` or name)
        the token is narrowed to that single repository; with neither it covers the installation.
        """
        body: dict[str, Any] = {"permissions": {"contents": "read"}}
        scope: str | None = None
        if repository_id is not None:
            body["repository_ids"] = [int(repository_id)]
            scope = str(repository or repository_id)
        elif repository:
            body["repositories"] = [repository.split("/")[-1]]
            scope = repository
        response = await self._app_request(
            "POST",
            "/app/installations/%s/access_tokens" % self.config.installation_id,
            json_body=body,
            expect=(201,),
        )
        data = response.json()
        return InstallationToken(
            token=str(data["token"]),
            expires_at=parse_github_time(str(data["expires_at"])),
            repository=scope,
        )

    async def mint_clone_token(
        self, repository: str, repository_id: int | None = None
    ) -> InstallationToken:
        """The token a clone job uses: one repository, ``contents: read``, kept in memory only."""
        return await self.mint_installation_token(repository_id=repository_id, repository=repository)

    async def read_token(self) -> InstallationToken:
        """A cached installation-wide read token for listing and polling (refreshed before it expires)."""
        cached = self._read_token
        if cached is None or cached.expires_within(TOKEN_REFRESH_MARGIN_SECONDS, self._clock()):
            cached = await self.mint_installation_token()
            self._read_token = cached
        return cached

    # -- installation-level calls ------------------------------------------------------------------
    async def list_installation_repositories(
        self, token: InstallationToken | None = None
    ) -> list[RepositoryInfo]:
        """Every repository the installation can reach (paginated, 100 per page)."""
        active = token or await self.read_token()
        repositories: list[RepositoryInfo] = []
        path: str | None = "/installation/repositories?per_page=100"
        for _ in range(MAX_PAGES):
            if path is None:
                break
            response = await self._request(
                "GET", path, bearer=active.token, bucket="installation"
            )
            data = response.json()
            repositories.extend(parse_repository(item) for item in data.get("repositories", []))
            path = next_link(response.headers.get("link"))
        return repositories

    async def get_branch_head(
        self,
        owner: str,
        repo: str,
        branch: str,
        token: InstallationToken | None = None,
    ) -> str | None:
        """The commit SHA at the head of ``branch``; None when the branch or repository is empty or gone."""
        active = token or await self.read_token()
        path = "/repos/%s/%s/branches/%s" % (
            quote(owner, safe=""),
            quote(repo, safe=""),
            quote(branch, safe="/"),
        )
        try:
            response = await self._request("GET", path, bearer=active.token, bucket="installation")
        except GitHubNotFound:
            return None
        sha = (response.json().get("commit") or {}).get("sha")
        return str(sha) if sha else None


# ------------------------------------------------------------------------------ error mapping


def _error_message(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return ""
    message = data.get("message") if isinstance(data, dict) else None
    return scrub(str(message))[:300] if message else ""


def _error_for(response: httpx.Response) -> GitHubError:
    status = response.status_code
    detail = _error_message(response)
    suffix = (" GitHub said: %s" % detail) if detail else ""
    if status == 401:
        return GitHubAuthError(
            "GitHub rejected the App's credentials. Check the App id, the client id and the private "
            "key, and make sure this machine's clock is correct." + suffix,
            status=status,
            code="github.unauthorized",
        )
    if status == 403:
        return GitHubPermissionError(
            "GitHub refused the request. The App may be suspended or may lack the Contents: read "
            "permission." + suffix,
            status=status,
            code="github.forbidden",
        )
    if status == 404:
        return GitHubNotFound(
            "GitHub could not find it. Check the installation id, and that the App is installed on "
            "the organisation and can see the repository." + suffix,
            status=status,
            code="github.not_found",
        )
    if status == 422:
        return GitHubPermissionError(
            "GitHub could not create a token for this repository. The App may not have access to it."
            + suffix,
            status=status,
            code="github.unprocessable",
        )
    return GitHubError("GitHub answered with an unexpected error (%d)." % status + suffix, status=status)


def explain_error(exc: BaseException) -> str:
    """One plain sentence for any failure, safe to store and show."""
    if isinstance(exc, GitHubError):
        return scrub(str(exc))
    return "Unexpected problem: %s" % scrub(type(exc).__name__)
