"""The GitHub App client with a mock transport and a fake clock (no network, no real waiting)."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import httpx
import jwt
import pytest

from securescan.integrations.github import app as github_app
from securescan.integrations.github.app import (
    GitHubAppConfig,
    GitHubAuthError,
    GitHubClient,
    GitHubError,
    GitHubNotFound,
    GitHubPermissionError,
    GitHubRateLimited,
    GitHubUnreachable,
    InstallationToken,
    make_app_jwt,
    next_link,
    parse_github_time,
)
from tests.unit.github_helpers import FakeClock, RecordingLogger, rsa_pair

CONFIG = GitHubAppConfig(
    app_id="123",
    client_id="Iv1.abcdef",
    installation_id="777",
    api_base_url="https://api.github.com",
    git_host="github.com",
    api_version="2026-03-10",
)
TOKEN = "ghs_" + "A1b2C3d4" * 5  # 40 characters after the prefix
EXPIRES = "2026-10-07T13:00:00Z"
Handler = Callable[[httpx.Request], httpx.Response]


def token_response(token: str = TOKEN) -> httpx.Response:
    return httpx.Response(201, json={"token": token, "expires_at": EXPIRES})


def make_client(
    handler: Handler,
    clock: FakeClock | None = None,
    keys: list[str] | None = None,
    **options: Any,
) -> GitHubClient:
    clock = clock or FakeClock()
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return GitHubClient(
        CONFIG,
        keys if keys is not None else [rsa_pair(0)[0]],
        http=http,
        clock=clock,
        sleep=clock.sleep,
        **options,
    )


def installation_token(clock: FakeClock) -> InstallationToken:
    return InstallationToken(
        token=TOKEN, expires_at=datetime.fromtimestamp(clock() + 3600, tz=timezone.utc)
    )


# --------------------------------------------------------------------------- the App JWT
def test_jwt_claims_and_algorithm() -> None:
    private, public = rsa_pair(0)
    now = 1_800_000_000.0
    token = make_app_jwt("Iv1.abcdef", private, now=now)
    assert jwt.get_unverified_header(token)["alg"] == "RS256"
    claims = jwt.decode(
        token,
        public,
        algorithms=["RS256"],
        options={"verify_exp": False, "verify_iat": False, "verify_nbf": False},
    )
    assert claims == {"iat": int(now) - 60, "exp": int(now) + 9 * 60, "iss": "Iv1.abcdef"}


def test_jwt_expires_nine_minutes_after_it_was_issued() -> None:
    private, public = rsa_pair(0)
    token = make_app_jwt("Iv1.abcdef", private, now=1_800_000_000.0)
    claims = jwt.decode(
        token,
        public,
        algorithms=["RS256"],
        options={"verify_exp": False, "verify_iat": False},
    )
    assert claims["exp"] - 1_800_000_000 == 9 * 60  # GitHub allows at most 10 minutes
    assert 1_800_000_000 - claims["iat"] == 60  # back-dated against clock drift


# --------------------------------------------------------------------------- token narrowing
async def test_clone_token_is_narrowed_to_one_repository_by_id() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        seen["version"] = request.headers["x-github-api-version"]
        seen["accept"] = request.headers["accept"]
        seen["auth"] = request.headers["authorization"]
        return token_response()

    client = make_client(handler)
    token = await client.mint_clone_token("sona/payroll", 42)
    assert seen["method"] == "POST"
    assert seen["path"] == "/app/installations/777/access_tokens"
    assert seen["body"] == {"repository_ids": [42], "permissions": {"contents": "read"}}
    assert seen["version"] == "2026-03-10"
    assert seen["accept"] == "application/vnd.github+json"
    assert seen["auth"].startswith("Bearer ") and seen["auth"] != "Bearer " + TOKEN
    assert token.token == TOKEN
    assert token.expires_at == datetime(2026, 10, 7, 13, 0, tzinfo=timezone.utc)
    assert token.repository == "sona/payroll"


async def test_clone_token_without_an_id_is_narrowed_by_name() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return token_response()

    client = make_client(handler)
    await client.mint_clone_token("sona/payroll")
    assert bodies == [{"repositories": ["payroll"], "permissions": {"contents": "read"}}]


async def test_installation_wide_token_still_asks_only_for_contents_read() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return token_response()

    await make_client(handler).mint_installation_token()
    assert bodies == [{"permissions": {"contents": "read"}}]


def test_token_repr_never_shows_the_token() -> None:
    token = InstallationToken(token=TOKEN, expires_at=datetime(2026, 10, 7, tzinfo=timezone.utc))
    assert TOKEN not in repr(token)
    assert TOKEN not in str(token)


async def test_read_token_is_cached_until_close_to_expiry() -> None:
    clock = FakeClock(now=datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc).timestamp())
    mints: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        mints.append(1)
        return token_response()

    client = make_client(handler, clock)
    await client.read_token()
    await client.read_token()
    assert len(mints) == 1
    clock.now = datetime(2026, 10, 7, 12, 56, tzinfo=timezone.utc).timestamp()  # 4 minutes left
    await client.read_token()
    assert len(mints) == 2


# --------------------------------------------------------------------------- no secrets in logs
async def test_tokens_and_keys_never_reach_the_log(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = RecordingLogger()
    monkeypatch.setattr(github_app, "log", recorder)
    private, _public = rsa_pair(0)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return token_response()
        if request.url.path == "/installation/repositories":
            return httpx.Response(200, json={"repositories": []})
        return httpx.Response(
            404, json={"message": "Not Found: the credential %s is invalid" % TOKEN}
        )

    client = make_client(handler)
    await client.list_installation_repositories()
    assert await client.get_branch_head("sona", "payroll", "main") is None
    logged = recorder.text()
    assert recorder.records, "the client should log its requests"
    assert TOKEN not in logged
    assert "BEGIN" not in logged
    assert private[40:80] not in logged
    assert "authorization" not in logged.lower()


async def test_error_messages_scrub_token_shapes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"message": "Validation failed for %s" % TOKEN})

    client = make_client(handler)
    with pytest.raises(GitHubPermissionError) as caught:
        await client.mint_clone_token("sona/payroll", 1)
    assert TOKEN not in str(caught.value)


# --------------------------------------------------------------------------- rate limits
async def test_retry_after_is_honoured() -> None:
    clock = FakeClock()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(403, headers={"Retry-After": "7"}, json={"message": "slow down"})
        return token_response()

    client = make_client(handler, clock)
    token = await client.mint_installation_token()
    assert token.token == TOKEN
    assert clock.sleeps == [7.0]
    assert len(calls) == 2


async def test_primary_limit_waits_for_the_reset_time() -> None:
    clock = FakeClock()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            reset = str(int(clock() + 30))
            return httpx.Response(
                403,
                headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset},
                json={"message": "API rate limit exceeded"},
            )
        return token_response()

    client = make_client(handler, clock)
    await client.mint_installation_token()
    assert clock.sleeps == [30.0]


async def test_secondary_limit_without_headers_backs_off_a_minute() -> None:
    clock = FakeClock()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(403, json={"message": "You exceeded a secondary rate limit."})
        return token_response()

    await make_client(handler, clock).mint_installation_token()
    assert clock.sleeps == [60.0]


async def test_a_wait_longer_than_the_limit_raises_rate_limited() -> None:
    clock = FakeClock()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "900"}, json={"message": "limit"})

    client = make_client(handler, clock, max_wait_s=120.0)
    with pytest.raises(GitHubRateLimited) as caught:
        await client.mint_installation_token()
    assert caught.value.retry_after == 900.0
    assert clock.sleeps == []


async def test_backs_off_when_the_remaining_budget_is_low() -> None:
    clock = FakeClock()
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.method == "POST":
            return token_response()
        return httpx.Response(
            200,
            headers={
                "X-RateLimit-Remaining": "50",
                "X-RateLimit-Reset": str(int(clock() + 20)),
            },
            json={"commit": {"sha": "a" * 40}},
        )

    client = make_client(handler, clock, low_water=100)
    token = installation_token(clock)
    assert await client.get_branch_head("sona", "payroll", "main", token) == "a" * 40
    assert client.rate_remaining() == 50
    assert clock.sleeps == []
    assert await client.get_branch_head("sona", "payroll", "main", token) == "a" * 40
    assert clock.sleeps == [21.0]  # waited for the reset (plus one second) before the second call
    assert len(calls) == 2


async def test_low_budget_with_a_distant_reset_raises_instead_of_sleeping() -> None:
    clock = FakeClock()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "X-RateLimit-Remaining": "10",
                "X-RateLimit-Reset": str(int(clock() + 1800)),
            },
            json={"commit": {"sha": "b" * 40}},
        )

    client = make_client(handler, clock, low_water=100, max_wait_s=60.0)
    token = installation_token(clock)
    await client.get_branch_head("sona", "payroll", "main", token)
    with pytest.raises(GitHubRateLimited):
        await client.get_branch_head("sona", "payroll", "main", token)
    assert clock.sleeps == []


async def test_a_permission_403_is_not_retried() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(403, json={"message": "Resource not accessible by integration"})

    client = make_client(handler)
    with pytest.raises(GitHubPermissionError):
        await client.mint_installation_token()
    assert len(calls) == 1


async def test_server_errors_are_retried_with_back_off() -> None:
    clock = FakeClock()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) < 3:
            return httpx.Response(502)
        return token_response()

    await make_client(handler, clock).mint_installation_token()
    assert clock.sleeps == [1.0, 2.0]


# --------------------------------------------------------------------------- errors in plain words
async def test_unauthorized_means_check_the_app_credentials() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    with pytest.raises(GitHubAuthError) as caught:
        await make_client(handler).get_installation()
    assert "private key" in str(caught.value) and "clock" in str(caught.value)


async def test_missing_installation_is_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    with pytest.raises(GitHubNotFound) as caught:
        await make_client(handler).get_installation()
    assert "installation id" in str(caught.value)


async def test_network_failure_is_reported_as_unreachable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    with pytest.raises(GitHubUnreachable) as caught:
        await make_client(handler).get_installation()
    assert "egress proxy" in str(caught.value)


async def test_no_private_key_is_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    with pytest.raises(GitHubAuthError):
        await make_client(handler, keys=[]).get_installation()


async def test_second_key_is_tried_when_the_first_is_rejected() -> None:
    keys = [rsa_pair(0)[0], rsa_pair(1)[0]]
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) == 1:
            return httpx.Response(401, json={"message": "A JSON web token could not be decoded"})
        return token_response()

    client = make_client(handler, keys=keys)
    await client.mint_installation_token()
    assert len(attempts) == 2
    await client.mint_installation_token()  # the working key is remembered
    assert len(attempts) == 3


# --------------------------------------------------------------------------- listing and heads
NEXT_PAGE = "https://api.github.com/installation/repositories?per_page=100&page=2"


def repo(repo_id: int, name: str, branch: str = "main") -> dict[str, Any]:
    return {
        "id": repo_id,
        "name": name,
        "full_name": "sona/" + name,
        "owner": {"login": "sona"},
        "default_branch": branch,
        "private": True,
    }


async def test_repository_listing_follows_pagination() -> None:
    pages: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return token_response()
        pages.append(str(request.url))
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json={"total_count": 3, "repositories": [repo(3, "c")]})
        return httpx.Response(
            200,
            headers={"Link": '<%s>; rel="next"' % (NEXT_PAGE,)},
            json={"total_count": 3, "repositories": [repo(1, "a"), repo(2, "b", "develop")]},
        )

    repositories = await make_client(handler).list_installation_repositories()
    assert [r.full_name for r in repositories] == ["sona/a", "sona/b", "sona/c"]
    assert repositories[1].default_branch == "develop"
    assert repositories[0].owner == "sona"
    assert len(pages) == 2
    assert "per_page=100" in pages[0]


async def test_a_next_link_to_another_host_is_not_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return token_response()
        return httpx.Response(
            200,
            headers={"Link": '<https://evil.example.com/steal?page=2>; rel="next"'},
            json={"repositories": [repo(1, "a")]},
        )

    with pytest.raises(GitHubError):
        await make_client(handler).list_installation_repositories()


async def test_branch_head_returns_the_sha_and_keeps_slashes_in_branch_names() -> None:
    clock = FakeClock()
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, json={"name": "feature/x", "commit": {"sha": "c" * 40}})

    client = make_client(handler, clock)
    sha = await client.get_branch_head("sona", "payroll", "feature/x", installation_token(clock))
    assert sha == "c" * 40
    assert paths == ["/repos/sona/payroll/branches/feature/x"]


async def test_branch_head_is_none_for_an_empty_repository() -> None:
    clock = FakeClock()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Branch not found"})

    client = make_client(handler, clock)
    assert await client.get_branch_head("sona", "empty", "main", installation_token(clock)) is None


async def test_requests_are_serial() -> None:
    import asyncio

    clock = FakeClock()
    active = 0
    peak = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0)  # give the other tasks a chance to start their requests
        active -= 1
        return httpx.Response(200, json={"commit": {"sha": "d" * 40}})

    client = make_client(handler, clock)
    token = installation_token(clock)
    await asyncio.gather(
        *[client.get_branch_head("sona", "r%d" % i, "main", token) for i in range(5)]
    )
    assert peak == 1
    assert client.requests_made == 5


# --------------------------------------------------------------------------- small helpers
def test_next_link_parsing() -> None:
    header = (
        '<https://api.github.com/x?page=1>; rel="prev", '
        '<https://api.github.com/x?page=3>; rel="next"'
    )
    assert next_link(header) == "https://api.github.com/x?page=3"
    assert next_link('<https://api.github.com/x?page=1>; rel="prev"') is None
    assert next_link(None) is None


def test_github_time_is_utc() -> None:
    parsed = parse_github_time("2026-10-07T13:00:00Z")
    assert parsed == datetime(2026, 10, 7, 13, 0, tzinfo=timezone.utc)
