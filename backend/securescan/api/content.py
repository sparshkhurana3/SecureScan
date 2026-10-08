"""Scanner content: versions of rules, templates and vulnerability databases, and manual updates.

* ``GET /api/v1/content-versions`` (Analyst): the history of ``ContentVersion`` rows, newest first, filterable by
  feed and active flag.
* ``POST /api/v1/content-versions/updates`` (Admin): queue an update of one feed now (``content_update`` task,
  maintenance queue). The worker runs it; the answer is ``202``.
* ``GET`` and ``PUT /api/v1/content/nvd-key`` (Admin): whether an NVD API key is configured, and storing a new
  one (encrypted, kind ``nvd_key``; older keys are revoked). The key is never returned.

Updaters and their rules: ``securescan/jobs/updaters.py`` and ``content/README.md``.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import ServiceUnavailable, UnprocessableEntity
from securescan.api.schemas import ORMModel
from securescan.auth.roles import AdminUser, AnalystUser
from securescan.config import get_settings
from securescan.db.models.content import ContentVersion
from securescan.db.models.credentials import Credential
from securescan.db.models.enums import ContentFeed, CredentialKind
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.domain.credentials import get_active_credential_by_kind, store_credential
from securescan.util import utcnow

router = APIRouter(tags=["content"])

_KEY_SHAPE = re.compile(r"^[A-Za-z0-9._-]{8,200}$")


class ContentVersionOut(ORMModel):
    id: uuid.UUID
    feed: ContentFeed
    version: str
    path: str | None
    source_commit: str | None
    built_at: datetime | None
    fetched_at: datetime
    regression_result: str
    regression_detail: dict[str, Any]
    active: bool
    activated_at: datetime | None
    created_at: datetime


class UpdateIn(BaseModel):
    feed: ContentFeed


class UpdateAccepted(BaseModel):
    feed: ContentFeed
    queued: bool = Field(description="false when an update of this feed is already waiting in the queue")
    message: str


class NvdKeyIn(BaseModel):
    key: SecretStr

    @field_validator("key")
    @classmethod
    def _shape(cls, value: SecretStr) -> SecretStr:
        if not _KEY_SHAPE.match(value.get_secret_value().strip()):
            raise ValueError("The NVD API key looks wrong: it is 8 to 200 letters, digits, dots, dashes or underscores.")
        return value


class NvdKeyStatus(BaseModel):
    configured: bool
    source: str = Field(description="credential (stored in Settings), environment (secret file) or none")
    mirror: bool = Field(description="a Dependency-Check NVD mirror URL is configured")
    stored_at: datetime | None = None


@router.get(
    "/content-versions",
    response_model=CursorPage[ContentVersionOut],
    summary="Versions of scanner content",
)
async def list_content_versions(
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    feed: Annotated[ContentFeed | None, Query(description="Only this feed")] = None,
    active: Annotated[bool | None, Query(description="Only the active versions (true) or the others (false)")] = None,
) -> CursorPage[ContentVersionOut]:
    stmt = select(ContentVersion)
    if feed is not None:
        stmt = stmt.where(ContentVersion.feed == feed)
    if active is not None:
        stmt = stmt.where(ContentVersion.active.is_(active))
    result = await paginate(db, stmt, key=[ContentVersion.fetched_at, ContentVersion.id], params=page, descending=True)
    return CursorPage(
        items=[ContentVersionOut.model_validate(row) for row in result.items], next_cursor=result.next_cursor
    )


@router.post(
    "/content-versions/updates",
    response_model=UpdateAccepted,
    status_code=202,
    summary="Start an update of one feed now (Admin)",
)
async def start_update(body: UpdateIn, db: DbSession, user: AdminUser, request: Request) -> UpdateAccepted:
    from securescan.jobs.enqueue import defer
    from securescan.jobs.updaters import content_update

    await record_audit(db, user, "content.update_requested", "content_feed", body.feed.value, {"feed": body.feed.value}, request=request)
    await db.commit()
    try:
        job_id = await defer(content_update, queueing_lock=f"content_update:{body.feed.value}", feed=body.feed.value)
    except Exception as exc:  # noqa: BLE001 - the queue is unreachable; say so in words
        raise ServiceUnavailable("The update could not be queued: the job queue is not reachable.", code="content.queue_unavailable") from exc
    if job_id is None:
        return UpdateAccepted(feed=body.feed, queued=False, message="An update of this feed is already waiting to run.")
    return UpdateAccepted(feed=body.feed, queued=True, message="The update was queued; the worker starts it shortly.")


@router.get("/content/nvd-key", response_model=NvdKeyStatus, summary="Is an NVD API key configured? (Admin)")
async def nvd_key_status(db: DbSession, user: AdminUser) -> NvdKeyStatus:
    settings = get_settings()
    credential = await get_active_credential_by_kind(db, CredentialKind.NVD_KEY)
    mirror = bool(settings.nvd_datafeed_url.strip())
    if credential is not None:
        return NvdKeyStatus(configured=True, source="credential", mirror=mirror, stored_at=credential.created_at)
    if settings.nvd_api_key:
        return NvdKeyStatus(configured=True, source="environment", mirror=mirror)
    return NvdKeyStatus(configured=False, source="none", mirror=mirror)


@router.put("/content/nvd-key", response_model=NvdKeyStatus, summary="Store the NVD API key (Admin)")
async def store_nvd_key(body: NvdKeyIn, db: DbSession, user: AdminUser, request: Request) -> NvdKeyStatus:
    key = body.key.get_secret_value().strip()
    if not _KEY_SHAPE.match(key):
        raise UnprocessableEntity("The NVD API key looks wrong.", code="content.bad_nvd_key")
    now = utcnow()
    older = (
        await db.scalars(
            select(Credential).where(Credential.kind == CredentialKind.NVD_KEY, Credential.revoked_at.is_(None))
        )
    ).all()
    for credential in older:
        credential.revoked_at = now
    created = await store_credential(
        db,
        kind=CredentialKind.NVD_KEY,
        name="NVD API key",
        secret=key,
        created_by_id=getattr(user, "id", None),
    )
    await record_audit(db, user, "credential.create", "credential", created.id, {"kind": CredentialKind.NVD_KEY.value}, request=request)
    await db.commit()
    return NvdKeyStatus(
        configured=True, source="credential", mirror=bool(get_settings().nvd_datafeed_url.strip()), stored_at=created.created_at
    )
