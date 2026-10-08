"""The GitHub connection row: loading it, its private keys, a client built from it, and the test.

Private keys are stored encrypted as ``Credential`` rows of kind ``github_app_key`` (two slots, for
rotation without downtime). When a slot has no uploaded key, ``SECURESCAN_GITHUB_APP_KEY_<n>_FILE``
(a Docker secret) is used instead.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import get_settings
from securescan.db.models.applications import Application
from securescan.db.models.credentials import Credential
from securescan.db.models.github import GitHubConnection
from securescan.domain.credentials import reveal_secret
from securescan.integrations.github.app import (
    GitHubAppConfig,
    GitHubClient,
    GitHubError,
    explain_error,
)
from securescan.integrations.github.git import GitError, git_ls_remote, repository_url
from securescan.logging import get_logger
from securescan.runner.egress import EgressError, egress_lease
from securescan.util import utcnow

log = get_logger(__name__)

MIN_RSA_BITS = 2048


class GitHubConfigError(Exception):
    """The connection is not usable as configured (plain-language message)."""


def validate_private_key(pem: str) -> str:
    """Check an uploaded App private key and return its fingerprint (``SHA256:...``).

    Raises ``ValueError`` with a plain-language message.
    """
    text = pem.strip()
    if "PRIVATE KEY" not in text:
        raise ValueError("This does not look like a private key. Upload the .pem file GitHub gave you.")
    try:
        key = serialization.load_pem_private_key(text.encode("utf-8"), password=None)
    except TypeError as exc:
        raise ValueError("The private key is protected by a password, which is not supported.") from exc
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("The private key could not be read. Upload the original .pem file.") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("GitHub App keys are RSA keys; this one is not.")
    if key.key_size < MIN_RSA_BITS:
        raise ValueError("The private key is too short (at least 2048 bits are needed).")
    return key_fingerprint(key)


def key_fingerprint(key: rsa.RSAPrivateKey) -> str:
    """The fingerprint GitHub shows for the key: SHA-256 of the DER public key, base64."""
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")
    return "SHA256:" + digest


async def get_connection(
    session: AsyncSession, *, enabled_only: bool = False
) -> GitHubConnection | None:
    """The (single) GitHub connection, or None."""
    stmt = select(GitHubConnection).order_by(GitHubConnection.created_at).limit(1)
    if enabled_only:
        stmt = stmt.where(GitHubConnection.enabled.is_(True))
    return await session.scalar(stmt)


def config_of(connection: GitHubConnection) -> GitHubAppConfig:
    return GitHubAppConfig(
        app_id=connection.app_id,
        client_id=connection.client_id,
        installation_id=connection.installation_id,
        api_base_url=connection.api_base_url,
        git_host=connection.git_host,
        api_version=connection.api_version,
    )


def github_hosts(connection: GitHubConnection) -> set[str]:
    """Hosts the worker needs for this connection: the API host, the git host and codeload."""
    hosts = {(urlsplit(connection.api_base_url).hostname or "").lower(), connection.git_host.lower()}
    if connection.git_host.lower() == "github.com":
        hosts.add("codeload.github.com")
    return {h for h in hosts if h}


async def _slot_credential(
    session: AsyncSession, connection: GitHubConnection, slot: int
) -> Credential | None:
    credential_id = connection.key_1_credential_id if slot == 1 else connection.key_2_credential_id
    if credential_id is None:
        return None
    credential = await session.get(Credential, credential_id)
    if credential is None or credential.revoked_at is not None:
        return None
    return credential


async def key_slots(session: AsyncSession, connection: GitHubConnection) -> dict[int, Credential | None]:
    return {1: await _slot_credential(session, connection, 1), 2: await _slot_credential(session, connection, 2)}


async def load_private_keys(session: AsyncSession, connection: GitHubConnection) -> list[str]:
    """The private keys to try, the active one first. Plaintext lives only in the returned list."""
    settings = get_settings()
    fallback = {1: settings.github_app_key_1, 2: settings.github_app_key_2}
    order = [1, 2] if connection.active_key != 2 else [2, 1]
    keys: list[str] = []
    for slot in order:
        credential = await _slot_credential(session, connection, slot)
        if credential is not None:
            keys.append(reveal_secret(credential))
        elif fallback[slot].strip():
            keys.append(fallback[slot].strip())
    return keys


@asynccontextmanager
async def github_client(
    session: AsyncSession,
    connection: GitHubConnection,
    *,
    max_wait_s: float = 120.0,
) -> AsyncIterator[GitHubClient]:
    """A ``GitHubClient`` that reaches GitHub through the egress proxy; closed on exit."""
    keys = await load_private_keys(session, connection)
    if not keys:
        raise GitHubConfigError("No private key is stored for the GitHub App. Upload one in Settings.")
    async with egress_lease(github_hosts(connection)) as proxy_url:
        client = GitHubClient(
            config_of(connection), keys, proxy_url=proxy_url or None, max_wait_s=max_wait_s
        )
        try:
            yield client
        finally:
            await client.aclose()


# ------------------------------------------------------------------------------ the connection test


@dataclass
class ConnectionTestResult:
    ok: bool
    message: str
    repositories: int = 0
    org_login: str | None = None


async def run_connection_test(
    session: AsyncSession, connection: GitHubConnection
) -> ConnectionTestResult:
    """Mint a token, list repositories and run ``git ls-remote`` on one; problems in plain words.

    The result is also stored on the connection row (``last_test_*``); the caller commits.
    """
    problems: list[str] = []
    repositories = 0
    org_login: str | None = None
    try:
        async with github_client(session, connection) as client:
            installation = await client.get_installation()
            account = installation.get("account") or {}
            org_login = account.get("login")
            if installation.get("suspended_at"):
                problems.append("The App installation is suspended on GitHub. Ask the organisation owner to unsuspend it.")
            permissions = installation.get("permissions") or {}
            if permissions and permissions.get("contents") not in ("read", "write"):
                problems.append(
                    "The App does not have the Contents: read permission. Change the App's permissions "
                    "and have the organisation owner approve the change."
                )
            listed = await client.list_installation_repositories()
            repositories = len(listed)
            if repositories == 0:
                problems.append(
                    "The App is installed but can reach no repositories. Select repositories for the "
                    "installation in GitHub."
                )
            else:
                sample = next((r for r in listed if not r.disabled and r.default_branch), listed[0])
                token = await client.mint_clone_token(sample.full_name, sample.id)
                try:
                    await git_ls_remote(
                        repository_url(connection.git_host, sample.full_name),
                        "HEAD",
                        token=token.token,
                        proxy_url=await _proxy_url(),
                    )
                except GitError as exc:
                    problems.append("%s (tested on %s)" % (exc, sample.full_name))
                finally:
                    del token
    except GitHubError as exc:
        problems.append(explain_error(exc))
    except GitHubConfigError as exc:
        problems.append(str(exc))
    except EgressError as exc:
        problems.append("The egress proxy could not be started: %s" % exc)
    except Exception as exc:  # noqa: BLE001 - the test must always produce an answer
        log.warning("github_test_unexpected", error=type(exc).__name__)
        problems.append(explain_error(exc))

    ok = not problems
    message = (
        "Token minted, %d repositories, ls-remote ok" % repositories if ok else "\n".join(problems)
    )
    connection.last_test_at = utcnow()
    connection.last_test_ok = ok
    connection.last_test_message = message[:2000]
    if org_login and connection.org_login is None:
        connection.org_login = str(org_login)[:200]
    return ConnectionTestResult(ok=ok, message=message, repositories=repositories, org_login=org_login)


async def _proxy_url() -> str | None:
    """The proxy URL for git (the test holds a lease, so the proxy is already running)."""
    settings = get_settings()
    return settings.egress_proxy_url if settings.egress_enabled and settings.egress_proxy_url else None


# ------------------------------------------------------------------------------ clone access for scans


@dataclass(frozen=True)
class CloneGrant:
    """What a clone job needs for one repository of the connected organisation.

    ``token`` is a one-hour installation token narrowed to this repository with ``contents: read``.
    Use it as the password of an HTTPS clone through a credential helper (never in the URL), and run
    git with ``HTTPS_PROXY=<proxy_url>`` when ``proxy_url`` is set. The grant is valid only inside the
    ``async with`` block that produced it, which also keeps the egress proxy running.
    """

    token: str = field(repr=False)
    expires_at: datetime
    proxy_url: str | None
    git_host: str
    full_name: str


@asynccontextmanager
async def clone_grant(session: AsyncSession, full_name: str) -> AsyncIterator[CloneGrant]:
    """Mint a narrowed clone token for ``owner/name`` and hold the egress proxy open meanwhile.

    Raises ``GitHubConfigError`` when no enabled connection exists, ``GitHubError`` when GitHub refuses.
    """
    connection = await get_connection(session, enabled_only=True)
    if connection is None:
        raise GitHubConfigError("The GitHub connection is not configured or is switched off.")
    repository_id = await session.scalar(
        select(Application.github_repo_id).where(Application.github_full_name == full_name).limit(1)
    )
    async with github_client(session, connection) as client:
        token = await client.mint_clone_token(
            full_name, int(repository_id) if repository_id else None
        )
        yield CloneGrant(
            token=token.token,
            expires_at=token.expires_at,
            proxy_url=client.proxy_url,
            git_host=connection.git_host,
            full_name=full_name,
        )
