"""A read-only container registry client (Docker Registry HTTP API v2).

Used by the monthly image-update proposals (``securescan/jobs/image_updates.py``) to learn what digest a
tag points to now and which newer tags exist. It never pulls an image and never writes anything.

* Docker Hub, GHCR and Quay use the same token flow: the first request answers ``401`` with
  ``WWW-Authenticate: Bearer realm=...,service=...``; the client fetches an anonymous pull token from
  the realm and repeats the request. Only public images are read, so no credential is involved.
* Requests go through the on-demand egress proxy (``proxy_url``). The proxy's allowlist must contain the
  registry host and, for Docker Hub, ``auth.docker.io`` (see ``registry_hosts``).
* The manifest digest of a tag is the ``Docker-Content-Digest`` header of ``HEAD /v2/<repo>/manifests/<tag>``
  with the index and manifest media types accepted. That is the digest ``docker buildx imagetools inspect``
  prints, so it matches what ``scripts/pin_images.py`` pins.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlsplit

import httpx

from securescan.logging import get_logger

log = get_logger(__name__)

DOCKER_HUB_REGISTRY = "registry-1.docker.io"
DOCKER_HUB_AUTH = "auth.docker.io"
_HUB_ALIASES = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"})
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)
TAGS_PAGE_SIZE = 1000
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_AUTH_PARAM = re.compile(r'([A-Za-z_]+)="([^"]*)"')
_NEXT_LINK = re.compile(r"<([^>]+)>\s*;\s*rel=\"?next\"?")


class RegistryError(Exception):
    """A registry call failed. The message is a plain sentence safe to show to an Admin."""


@dataclass(frozen=True)
class ImageName:
    """An image reference split into registry host and repository path."""

    registry: str
    repository: str
    original: str

    @property
    def is_docker_hub(self) -> bool:
        return self.registry == DOCKER_HUB_REGISTRY


def parse_image_name(name: str) -> ImageName:
    """``postgres`` -> Docker Hub ``library/postgres``; ``ghcr.io/gitleaks/gitleaks`` -> GHCR.

    The name carries no tag and no digest.
    """
    text = name.strip()
    if not text or "@" in text or text.endswith(":") or any(c.isspace() for c in text):
        raise RegistryError("'%s' is not an image name." % text[:80])
    first, _, rest = text.partition("/")
    has_registry = bool(rest) and ("." in first or ":" in first or first == "localhost")
    if has_registry:
        registry, repository = first.lower(), rest
        if registry in _HUB_ALIASES:
            registry = DOCKER_HUB_REGISTRY
    else:
        registry, repository = DOCKER_HUB_REGISTRY, text
    if registry == DOCKER_HUB_REGISTRY and "/" not in repository:
        repository = "library/" + repository
    if ":" in repository:
        raise RegistryError("'%s' must not contain a tag." % text[:80])
    return ImageName(registry=registry, repository=repository, original=text)


def registry_hosts(image: ImageName) -> set[str]:
    """The hosts the egress proxy must allow to read this image's metadata."""
    hosts = {image.registry}
    if image.is_docker_hub:
        hosts.add(DOCKER_HUB_AUTH)
    return hosts


def parse_www_authenticate(header: str) -> dict[str, str]:
    """``Bearer realm="...",service="...",scope="..."`` -> ``{"realm": ..., "service": ..., ...}``."""
    if not header.lower().startswith("bearer"):
        return {}
    return {key.lower(): value for key, value in _AUTH_PARAM.findall(header)}


def next_link(header: str | None) -> str | None:
    """The target of ``Link: <...>; rel="next"`` (relative or absolute), or None."""
    if not header:
        return None
    match = _NEXT_LINK.search(header)
    return match.group(1) if match else None


def valid_digest(value: str | None) -> str | None:
    if value and _DIGEST.match(value.strip()):
        return value.strip()
    return None


class RegistryClient:
    """Anonymous, read-only registry access. Create one per run and ``await aclose()`` it."""

    def __init__(
        self,
        *,
        proxy_url: str | None = None,
        timeout: float = 30.0,
        max_tag_pages: int = 30,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self._http = http or httpx.AsyncClient(proxy=proxy_url or None, timeout=timeout)
        self._owns_http = http is None
        self._tokens: dict[tuple[str, str], str] = {}
        self.max_tag_pages = max_tag_pages

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # ------------------------------------------------------------------------------ public

    async def manifest_digest(self, image: ImageName, reference: str) -> str | None:
        """The digest ``reference`` (a tag) points to now; None when the tag does not exist."""
        url = "https://%s/v2/%s/manifests/%s" % (image.registry, image.repository, quote(reference, safe=""))
        response = await self._request("HEAD", url, image, accept=MANIFEST_ACCEPT)
        if response.status_code == 404:
            return None
        self._expect_ok(response, image, "read the manifest of %s:%s" % (image.original, reference))
        digest = valid_digest(response.headers.get("Docker-Content-Digest"))
        if digest:
            return digest
        # A registry that omits the header on HEAD: fetch the manifest and hash the exact bytes.
        response = await self._request("GET", url, image, accept=MANIFEST_ACCEPT)
        if response.status_code == 404:
            return None
        self._expect_ok(response, image, "read the manifest of %s:%s" % (image.original, reference))
        return valid_digest(response.headers.get("Docker-Content-Digest")) or (
            "sha256:" + hashlib.sha256(response.content).hexdigest()
        )

    async def list_tags(self, image: ImageName) -> list[str]:
        """Every tag of the repository (paged; at most ``max_tag_pages`` pages)."""
        url: str | None = "https://%s/v2/%s/tags/list?%s" % (
            image.registry,
            image.repository,
            urlencode({"n": TAGS_PAGE_SIZE}),
        )
        tags: list[str] = []
        pages = 0
        while url and pages < self.max_tag_pages:
            response = await self._request("GET", url, image, accept="application/json")
            self._expect_ok(response, image, "list the tags of %s" % image.original)
            try:
                body: Any = response.json()
            except ValueError as exc:
                raise RegistryError("The registry answered with something that is not JSON.") from exc
            page = body.get("tags") if isinstance(body, dict) else None
            if isinstance(page, list):
                tags.extend(str(t) for t in page if isinstance(t, str))
            pages += 1
            link = next_link(response.headers.get("Link"))
            url = urljoin(url, link) if link else None
            if url and urlsplit(url).hostname != image.registry:
                break  # never follow a link to another host
        return tags

    # ------------------------------------------------------------------------------ plumbing

    async def _request(
        self, method: str, url: str, image: ImageName, *, accept: str
    ) -> httpx.Response:
        key = (image.registry, image.repository)
        for attempt in (1, 2):
            headers = {"Accept": accept}
            token = self._tokens.get(key)
            if token:
                headers["Authorization"] = "Bearer " + token
            try:
                response = await self._http.request(method, url, headers=headers, follow_redirects=False)
            except httpx.HTTPError as exc:
                raise RegistryError(
                    "The registry %s could not be reached (%s). Check the egress proxy and its allowlist."
                    % (image.registry, type(exc).__name__)
                ) from exc
            if response.status_code == 401 and attempt == 1:
                params = parse_www_authenticate(response.headers.get("WWW-Authenticate", ""))
                if not params.get("realm"):
                    raise RegistryError("The registry %s requires a login." % image.registry)
                self._tokens[key] = await self._fetch_token(image, params)
                continue
            return response
        raise RegistryError("The registry %s refused the anonymous token." % image.registry)

    async def _fetch_token(self, image: ImageName, params: dict[str, str]) -> str:
        realm = params["realm"]
        if urlsplit(realm).scheme != "https":
            raise RegistryError("The registry %s asked for a token over an insecure channel." % image.registry)
        query = {"scope": "repository:%s:pull" % image.repository}
        if params.get("service"):
            query["service"] = params["service"]
        try:
            response = await self._http.get(realm + ("&" if "?" in realm else "?") + urlencode(query))
        except httpx.HTTPError as exc:
            raise RegistryError(
                "The registry token service %s could not be reached (%s). Check the egress allowlist."
                % (urlsplit(realm).hostname, type(exc).__name__)
            ) from exc
        if response.status_code != 200:
            raise RegistryError(
                "The registry token service answered %d for %s." % (response.status_code, image.original)
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise RegistryError("The registry token service answered with something that is not JSON.") from exc
        token = body.get("token") or body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise RegistryError("The registry token service gave no token.")
        return token

    @staticmethod
    def _expect_ok(response: httpx.Response, image: ImageName, what: str) -> None:
        if response.status_code == 429:
            raise RegistryError("The registry %s rate-limited the request; try again later." % image.registry)
        if response.status_code >= 400:
            raise RegistryError("Could not %s (the registry answered %d)." % (what, response.status_code))
