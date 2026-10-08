"""GitHub integration: the connection, its test, repository discovery and the discovered repositories.

``GET|PUT /integrations/github`` (Admin) manage the single GitHub App connection. The App's private
keys are write-only: they are validated, stored encrypted and never returned (only a fingerprint).
``POST /integrations/github/test`` and ``/sync`` need outbound access, which only the worker has, so
they hand the work to the worker (queue ``github``); the test waits a few seconds for the answer.
``GET /integrations/github/repositories`` (Analyst) lists the discovered repositories with their
poller state, for the repository picker.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Query, Request, Response
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import Conflict, NotFound, UnprocessableEntity
from securescan.auth.roles import AdminUser, AnalystUser, CurrentUser
from securescan.config import get_settings
from securescan.db.models.applications import Application
from securescan.db.models.credentials import Credential
from securescan.db.models.enums import CredentialKind
from securescan.db.models.github import GitHubConnection, RepositoryHead
from securescan.db.repositories.common import escape_like
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.domain.credentials import store_credential
from securescan.integrations.github.app import (
    DEFAULT_API_BASE_URL,
    DEFAULT_API_VERSION,
    DEFAULT_GIT_HOST,
)
from securescan.integrations.github.connection import (
    get_connection,
    key_slots,
    validate_private_key,
)
from securescan.jobs.enqueue import defer
from securescan.jobs.github_discovery import github_sync, github_test
from securescan.util import utcnow

router = APIRouter(tags=["github"])

RUNNING_MARKER = "The test is running."
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_COUNT = re.compile(r"^Token minted, (\d+) repositories")


# --------------------------------------------------------------------------- models
class KeySlotOut(BaseModel):
    present: bool
    source: Literal["uploaded", "secret_file"] | None = None
    fingerprint: str | None = None
    added_at: datetime | None = None


class GitHubConnectionOut(BaseModel):
    id: uuid.UUID
    name: str
    org_login: str | None
    app_id: str
    client_id: str
    installation_id: str
    api_base_url: str
    git_host: str
    api_version: str
    active_key: int
    enabled: bool
    key_1: KeySlotOut
    key_2: KeySlotOut
    last_test_at: datetime | None
    last_test_ok: bool | None
    last_test_message: str | None
    last_sync_at: datetime | None
    last_poll_at: datetime | None
    last_poll_ok: bool | None
    last_poll_message: str | None
    rate_limit_remaining: int | None
    rate_limit_reset_at: datetime | None
    updated_at: datetime


class GitHubStatusOut(BaseModel):
    configured: bool
    connection: GitHubConnectionOut | None = None


class GitHubConnectionIn(BaseModel):
    """The connection settings. Omitted private keys keep the stored ones."""

    name: str = Field(default="Corporate GitHub", min_length=1, max_length=200)
    app_id: str = Field(min_length=1, max_length=64, pattern=r"^[0-9A-Za-z_.-]+$")
    client_id: str = Field(min_length=1, max_length=128, pattern=r"^[0-9A-Za-z_.-]+$")
    installation_id: str = Field(pattern=r"^[0-9]{1,20}$")
    api_base_url: str = Field(default=DEFAULT_API_BASE_URL, max_length=255)
    git_host: str = Field(default=DEFAULT_GIT_HOST, max_length=255)
    api_version: str = Field(default=DEFAULT_API_VERSION, pattern=r"^\d{4}-\d{2}-\d{2}$")
    private_key_1: SecretStr | None = None
    private_key_2: SecretStr | None = None
    clear_key_2: bool = False
    active_key: Literal[1, 2] = 1
    enabled: bool = True

    @field_validator("api_base_url")
    @classmethod
    def _api_url(cls, value: str) -> str:
        parts = urlsplit(value.strip())
        allowed = ("https", "http") if get_settings().is_dev else ("https",)
        if parts.scheme not in allowed or not parts.hostname or not _HOST.match(parts.hostname):
            raise ValueError("The API address must be an https:// address such as https://api.github.com")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("The API address must not contain credentials, a query or a fragment")
        return value.strip().rstrip("/")

    @field_validator("git_host")
    @classmethod
    def _git_host(cls, value: str) -> str:
        host = value.strip().lower()
        if not _HOST.match(host):
            raise ValueError("The git host must be a host name such as github.com")
        return host


class GitHubTestOut(BaseModel):
    status: Literal["ok", "failed", "running"]
    message: str
    problems: list[str] = Field(default_factory=list)
    repositories: int | None = None
    tested_at: datetime | None = None


class QueuedOut(BaseModel):
    queued: bool
    detail: str


class GitHubRepositoryOut(BaseModel):
    application_id: uuid.UUID
    github_repo_id: int
    full_name: str | None
    default_branch: str | None
    confirmed: bool
    automatic: bool
    removed: bool
    removed_at: datetime | None
    archived: bool
    last_seen_sha: str | None
    last_scanned_sha: str | None
    last_seen_at: datetime | None
    last_scanned_at: datetime | None
    last_scan_id: uuid.UUID | None
    last_poll_error: str | None


# --------------------------------------------------------------------------- helpers
async def _connection_out(db: DbSession, row: GitHubConnection) -> GitHubConnectionOut:
    settings = get_settings()
    slots = await key_slots(db, row)
    fallbacks = {1: settings.github_app_key_1.strip(), 2: settings.github_app_key_2.strip()}

    def slot_out(slot: int, credential: Credential | None) -> KeySlotOut:
        if credential is not None:
            return KeySlotOut(
                present=True,
                source="uploaded",
                fingerprint=credential.public_material,
                added_at=credential.created_at,
            )
        if fallbacks[slot]:
            return KeySlotOut(present=True, source="secret_file")
        return KeySlotOut(present=False)

    return GitHubConnectionOut(
        id=row.id,
        name=row.name,
        org_login=row.org_login,
        app_id=row.app_id,
        client_id=row.client_id,
        installation_id=row.installation_id,
        api_base_url=row.api_base_url,
        git_host=row.git_host,
        api_version=row.api_version,
        active_key=row.active_key,
        enabled=row.enabled,
        key_1=slot_out(1, slots[1]),
        key_2=slot_out(2, slots[2]),
        last_test_at=row.last_test_at,
        last_test_ok=row.last_test_ok,
        last_test_message=row.last_test_message,
        last_sync_at=row.last_sync_at,
        last_poll_at=row.last_poll_at,
        last_poll_ok=row.last_poll_ok,
        last_poll_message=row.last_poll_message,
        rate_limit_remaining=row.rate_limit_remaining,
        rate_limit_reset_at=row.rate_limit_reset_at,
        updated_at=row.updated_at,
    )


def _check_key(pem: str, label: str) -> str:
    try:
        return validate_private_key(pem)
    except ValueError as exc:
        raise UnprocessableEntity("%s: %s" % (label, exc), code="github.invalid_key") from exc


async def _replace_key(
    db: DbSession, row: GitHubConnection, slot: int, pem: str, fingerprint: str, user: CurrentUser
) -> None:
    previous_id = row.key_1_credential_id if slot == 1 else row.key_2_credential_id
    previous = await db.get(Credential, previous_id) if previous_id else None
    if previous is not None and previous.revoked_at is None:
        previous.revoked_at = utcnow()
    credential = await store_credential(
        db,
        kind=CredentialKind.GITHUB_APP_KEY,
        name="GitHub App key %d" % slot,
        secret=pem,
        public_material=fingerprint,
        extra={"slot": slot},
        created_by_id=user.id,
    )
    if slot == 1:
        row.key_1_credential_id = credential.id
    else:
        row.key_2_credential_id = credential.id


def parse_repository_count(message: str | None) -> int | None:
    match = _COUNT.match(message or "")
    return int(match.group(1)) if match else None


def _test_out(row: GitHubConnection) -> GitHubTestOut:
    if row.last_test_ok is None and row.last_test_at is None:
        if row.last_test_message == RUNNING_MARKER:
            return GitHubTestOut(status="running", message=RUNNING_MARKER)
        return GitHubTestOut(status="running", message="The connection has not been tested yet.")
    message = row.last_test_message or ""
    ok = bool(row.last_test_ok)
    return GitHubTestOut(
        status="ok" if ok else "failed",
        message=message,
        problems=[] if ok else [line for line in message.split("\n") if line],
        repositories=parse_repository_count(message) if ok else None,
        tested_at=row.last_test_at,
    )


# --------------------------------------------------------------------------- endpoints
@router.get(
    "/integrations/github", response_model=GitHubStatusOut, summary="The GitHub connection (Admin)"
)
async def get_github_connection(db: DbSession, user: AdminUser) -> GitHubStatusOut:
    row = await get_connection(db)
    if row is None:
        return GitHubStatusOut(configured=False)
    return GitHubStatusOut(configured=True, connection=await _connection_out(db, row))


@router.put(
    "/integrations/github",
    response_model=GitHubStatusOut,
    summary="Create or change the GitHub connection (Admin)",
)
async def put_github_connection(
    body: GitHubConnectionIn, request: Request, db: DbSession, user: AdminUser
) -> GitHubStatusOut:
    settings = get_settings()
    row = await get_connection(db)
    creating = row is None
    key_1 = body.private_key_1.get_secret_value() if body.private_key_1 else None
    key_2 = body.private_key_2.get_secret_value() if body.private_key_2 else None
    fingerprints: dict[int, str] = {}
    if key_1:
        fingerprints[1] = _check_key(key_1, "Private key 1")
    if key_2:
        fingerprints[2] = _check_key(key_2, "Private key 2")
    now = utcnow()
    if row is None:
        row = GitHubConnection(
            name=body.name,
            app_id=body.app_id,
            client_id=body.client_id,
            installation_id=body.installation_id,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
    slots: dict[int, Credential | None] = {1: None, 2: None}
    if not creating:
        slots = await key_slots(db, row)
    has_key_1 = bool(key_1) or slots[1] is not None or bool(settings.github_app_key_1.strip())
    has_key_2 = (
        (bool(key_2) or slots[2] is not None or bool(settings.github_app_key_2.strip()))
        and not (body.clear_key_2 and not key_2)
    )
    if not has_key_1 and not has_key_2:
        raise UnprocessableEntity(
            "Upload the GitHub App's private key (the .pem file GitHub gave you).",
            code="github.key_required",
        )
    if body.active_key == 2 and not has_key_2:
        raise UnprocessableEntity(
            "Key 2 is the active key but no second key is stored.", code="github.active_key_missing"
        )
    if body.active_key == 1 and not has_key_1:
        raise UnprocessableEntity(
            "Key 1 is the active key but no first key is stored.", code="github.active_key_missing"
        )
    connection_changed = not creating and (
        row.app_id != body.app_id
        or row.client_id != body.client_id
        or row.installation_id != body.installation_id
        or row.api_base_url != body.api_base_url
        or row.git_host != body.git_host
    )
    row.name = body.name
    row.app_id = body.app_id
    row.client_id = body.client_id
    row.installation_id = body.installation_id
    row.api_base_url = body.api_base_url
    row.git_host = body.git_host
    row.api_version = body.api_version
    row.active_key = body.active_key
    row.enabled = body.enabled
    row.updated_at = now
    if connection_changed:
        row.last_test_at = None
        row.last_test_ok = None
        row.last_test_message = None
        row.org_login = None
    await db.flush()
    replaced: list[int] = []
    if key_1:
        await _replace_key(db, row, 1, key_1, fingerprints[1], user)
        replaced.append(1)
    if key_2:
        await _replace_key(db, row, 2, key_2, fingerprints[2], user)
        replaced.append(2)
    elif body.clear_key_2 and slots[2] is not None:
        slots[2].revoked_at = now
        row.key_2_credential_id = None
        replaced.append(-2)
    await record_audit(
        db,
        user,
        "integration.github.create" if creating else "integration.github.update",
        "github_connection",
        row.id,
        {
            "app_id": row.app_id,
            "installation_id": row.installation_id,
            "api_base_url": row.api_base_url,
            "api_version": row.api_version,
            "active_key": row.active_key,
            "enabled": row.enabled,
            "keys_replaced": replaced,
            "key_fingerprints": [fingerprints[s] for s in sorted(fingerprints)],
        },
        request,
    )
    await db.commit()
    return GitHubStatusOut(configured=True, connection=await _connection_out(db, row))


@router.post(
    "/integrations/github/test",
    response_model=GitHubTestOut,
    summary="Test the GitHub connection (Admin)",
    description=(
        "Mints a token, lists the repositories and runs git ls-remote on one. The test runs in the "
        "worker; the answer is returned when it is ready, or with status 202 and status 'running' "
        "when it takes longer than `wait` seconds (read it again with GET /integrations/github)."
    ),
)
async def test_github_connection(
    request: Request,
    response: Response,
    db: DbSession,
    user: AdminUser,
    wait: Annotated[int, Query(ge=0, le=120, description="Seconds to wait for the answer")] = 45,
) -> GitHubTestOut:
    row = await get_connection(db)
    if row is None:
        raise NotFound("The GitHub connection is not configured yet", code="github.not_configured")
    row.last_test_at = None
    row.last_test_ok = None
    row.last_test_message = RUNNING_MARKER
    await record_audit(db, user, "integration.github.test_requested", "github_connection", row.id, {}, request)
    await db.commit()
    await defer(github_test, queueing_lock="github_test")
    for _ in range(wait):
        await asyncio.sleep(1.0)
        await db.refresh(row)
        if row.last_test_at is not None:
            return _test_out(row)
    response.status_code = 202
    return GitHubTestOut(status="running", message=RUNNING_MARKER)


@router.post(
    "/integrations/github/sync",
    response_model=QueuedOut,
    status_code=202,
    summary="Run repository discovery now (Admin)",
)
async def sync_github(request: Request, db: DbSession, user: AdminUser) -> QueuedOut:
    row = await get_connection(db)
    if row is None or not row.enabled:
        raise Conflict("The GitHub connection is missing or switched off", code="github.not_enabled")
    await record_audit(db, user, "integration.github.sync", "github_connection", row.id, {}, request)
    await db.commit()
    job_id = await defer(github_sync, queueing_lock="github_sync")
    if job_id is None:
        return QueuedOut(queued=False, detail="A sync is already waiting to run.")
    return QueuedOut(queued=True, detail="Discovery will run in a moment; refresh the repository list.")


@router.get(
    "/integrations/github/repositories",
    response_model=CursorPage[GitHubRepositoryOut],
    summary="Repositories found on GitHub",
)
async def list_github_repositories(
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    q: Annotated[str | None, Query(description="Repository name contains")] = None,
    confirmed: bool | None = None,
    automatic: bool | None = None,
    removed: bool | None = None,
    include_archived: bool = False,
) -> CursorPage[GitHubRepositoryOut]:
    stmt = select(Application).where(Application.github_repo_id.is_not(None))
    if not include_archived:
        stmt = stmt.where(Application.archived_at.is_(None))
    if q:
        stmt = stmt.where(Application.github_full_name.ilike(f"%{escape_like(q)}%", escape="\\"))
    if confirmed is not None:
        stmt = stmt.where(Application.confirmed.is_(confirmed))
    if automatic is not None:
        stmt = stmt.where(Application.automatic.is_(automatic))
    if removed is True:
        stmt = stmt.where(Application.github_removed_at.is_not(None))
    elif removed is False:
        stmt = stmt.where(Application.github_removed_at.is_(None))
    result = await paginate(db, stmt, key=[Application.name, Application.id], params=page, descending=False)
    ids = [a.id for a in result.items]
    heads: dict[tuple[uuid.UUID, str], RepositoryHead] = {}
    if ids:
        rows = await db.scalars(select(RepositoryHead).where(RepositoryHead.application_id.in_(ids)))
        heads = {(h.application_id, h.branch): h for h in rows.all()}
    items: list[GitHubRepositoryOut] = []
    for app in result.items:
        head = heads.get((app.id, app.default_branch or ""))
        items.append(
            GitHubRepositoryOut(
                application_id=app.id,
                github_repo_id=int(app.github_repo_id or 0),
                full_name=app.github_full_name,
                default_branch=app.default_branch,
                confirmed=app.confirmed,
                automatic=app.automatic,
                removed=app.github_removed_at is not None,
                removed_at=app.github_removed_at,
                archived=app.archived_at is not None,
                last_seen_sha=head.last_seen_sha if head else None,
                last_scanned_sha=head.last_scanned_sha if head else None,
                last_seen_at=head.last_seen_at if head else None,
                last_scanned_at=head.last_scanned_at if head else None,
                last_scan_id=head.last_scan_id if head else None,
                last_poll_error=head.last_poll_error if head else None,
            )
        )
    return CursorPage(items=items, next_cursor=result.next_cursor)
