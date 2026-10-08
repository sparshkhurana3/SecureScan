"""The registry client: image names, the token flow, digests and paged tag lists (no network)."""

from __future__ import annotations

import hashlib

import httpx
import pytest

from securescan.integrations.registry import (
    DOCKER_HUB_REGISTRY,
    ImageName,
    RegistryClient,
    RegistryError,
    next_link,
    parse_image_name,
    parse_www_authenticate,
    registry_hosts,
    valid_digest,
)

DIGEST = "sha256:" + "ab" * 32


def test_parse_image_name_for_docker_hub_ghcr_and_quay() -> None:
    hub = parse_image_name("postgres")
    assert (hub.registry, hub.repository) == (DOCKER_HUB_REGISTRY, "library/postgres") and hub.is_docker_hub
    assert parse_image_name("semgrep/semgrep").repository == "semgrep/semgrep"
    assert parse_image_name("docker.io/library/node").repository == "library/node"
    ghcr = parse_image_name("ghcr.io/gitleaks/gitleaks")
    assert (ghcr.registry, ghcr.repository) == ("ghcr.io", "gitleaks/gitleaks") and not ghcr.is_docker_hub
    quay = parse_image_name("quay.io/skopeo/stable")
    assert (quay.registry, quay.repository) == ("quay.io", "skopeo/stable")
    assert parse_image_name("localhost:5000/team/app").registry == "localhost:5000"


@pytest.mark.parametrize("bad", ["", "  ", "image@sha256:" + "a" * 64, "image:tag", "has space/x", "reg.io/x:1"])
def test_parse_image_name_refuses_tags_digests_and_junk(bad: str) -> None:
    with pytest.raises(RegistryError):
        parse_image_name(bad)


def test_registry_hosts_include_the_docker_hub_token_service() -> None:
    assert registry_hosts(parse_image_name("postgres")) == {DOCKER_HUB_REGISTRY, "auth.docker.io"}
    assert registry_hosts(parse_image_name("ghcr.io/a/b")) == {"ghcr.io"}


def test_parse_www_authenticate() -> None:
    header = 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/postgres:pull"'
    assert parse_www_authenticate(header) == {
        "realm": "https://auth.docker.io/token", "service": "registry.docker.io",
        "scope": "repository:library/postgres:pull",
    }  # fmt: skip
    assert parse_www_authenticate('Basic realm="x"') == {}


def test_next_link_and_valid_digest() -> None:
    assert next_link('</v2/x/tags/list?last=b&n=1000>; rel="next"') == "/v2/x/tags/list?last=b&n=1000"
    assert next_link(None) is None and next_link('<a>; rel="prev"') is None
    assert valid_digest(DIGEST) == DIGEST and valid_digest("sha256:short") is None and valid_digest(None) is None


def hub_handler(log: list[str], *, head_digest: str | None = DIGEST, pages: bool = False):
    """A fake Docker Hub: 401 with a Bearer challenge, a token endpoint, manifests and a paged tag list."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        log.append("%s %s" % (request.method, url))
        if request.url.host == "auth.docker.io":
            assert "scope=repository%3Alibrary%2Fpostgres%3Apull" in url and "service=registry.docker.io" in url
            return httpx.Response(200, json={"token": "tok-1"})
        if request.headers.get("Authorization") != "Bearer tok-1":
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'},
            )
        path = request.url.path
        if path.endswith("/manifests/18.6"):
            assert "application/vnd.oci.image.index.v1+json" in request.headers["Accept"]
            headers = {"Docker-Content-Digest": head_digest} if head_digest else {}
            return httpx.Response(200, headers=headers, content=b"{}" if request.method == "GET" else b"")
        if path.endswith("/manifests/gone"):
            return httpx.Response(404)
        if path.endswith("/tags/list"):
            if pages and request.url.params.get("last") is None:
                return httpx.Response(
                    200, json={"tags": ["18.5", "18.6"]},
                    headers={"Link": '</v2/library/postgres/tags/list?n=1000&last=18.6>; rel="next"'},
                )  # fmt: skip
            if pages:
                return httpx.Response(200, json={"tags": ["18.7"]})
            return httpx.Response(200, json={"tags": ["18.6", "18.7"]})
        return httpx.Response(404)

    return handler


async def test_manifest_digest_follows_the_token_flow() -> None:
    log: list[str] = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(hub_handler(log))) as http:
        client = RegistryClient(http=http)
        assert await client.manifest_digest(parse_image_name("postgres"), "18.6") == DIGEST
        # the second call reuses the token: no new token request
        await client.manifest_digest(parse_image_name("postgres"), "18.6")
    assert sum("auth.docker.io" in line for line in log) == 1
    assert log[0].startswith("HEAD https://registry-1.docker.io/v2/library/postgres/manifests/18.6")


async def test_manifest_digest_of_a_missing_tag_is_none() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(hub_handler([]))) as http:
        assert await RegistryClient(http=http).manifest_digest(parse_image_name("postgres"), "gone") is None


async def test_manifest_digest_falls_back_to_hashing_the_manifest() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(hub_handler([], head_digest=None))) as http:
        digest = await RegistryClient(http=http).manifest_digest(parse_image_name("postgres"), "18.6")
    assert digest == "sha256:" + hashlib.sha256(b"{}").hexdigest()


async def test_list_tags_follows_next_links_on_the_same_host() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(hub_handler([], pages=True))) as http:
        tags = await RegistryClient(http=http).list_tags(parse_image_name("postgres"))
    assert tags == ["18.5", "18.6", "18.7"]


async def test_list_tags_stops_at_the_page_limit() -> None:
    def endless(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization") is None:
            return httpx.Response(401, headers={"WWW-Authenticate": 'Bearer realm="https://auth.docker.io/token"'})
        if request.url.host == "auth.docker.io":
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(200, json={"tags": ["1"]}, headers={"Link": '</v2/library/postgres/tags/list?last=1>; rel="next"'})

    async def run() -> list[str]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(_with_token(endless))) as http:
            return await RegistryClient(http=http, max_tag_pages=3).list_tags(parse_image_name("postgres"))

    assert len(await run()) == 3


def _with_token(inner):  # type: ignore[no-untyped-def]
    """Serve the token endpoint and require the token on the registry host."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "auth.docker.io":
            return httpx.Response(200, json={"token": "t"})
        if request.headers.get("Authorization") != "Bearer t":
            return httpx.Response(401, headers={"WWW-Authenticate": 'Bearer realm="https://auth.docker.io/token"'})
        return inner(request)

    return handler


async def test_errors_are_plain_sentences() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)  # no challenge

    async with httpx.AsyncClient(transport=httpx.MockTransport(refuse)) as http:
        with pytest.raises(RegistryError, match="requires a login"):
            await RegistryClient(http=http).list_tags(parse_image_name("postgres"))

    def limited(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    async with httpx.AsyncClient(transport=httpx.MockTransport(limited)) as http:
        with pytest.raises(RegistryError, match="rate-limited"):
            await RegistryClient(http=http).manifest_digest(parse_image_name("postgres"), "18.6")

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(down)) as http:
        with pytest.raises(RegistryError, match="egress proxy"):
            await RegistryClient(http=http).list_tags(parse_image_name("ghcr.io/a/b"))


async def test_an_insecure_token_realm_is_refused() -> None:
    def insecure(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, headers={"WWW-Authenticate": 'Bearer realm="http://auth.example/token"'})

    async with httpx.AsyncClient(transport=httpx.MockTransport(insecure)) as http:
        with pytest.raises(RegistryError, match="insecure"):
            await RegistryClient(http=http).list_tags(ImageName("reg.example", "a/b", "reg.example/a/b"))
