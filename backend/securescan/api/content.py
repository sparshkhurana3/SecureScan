"""Scanner content: versions of rules, templates and vulnerability databases, and manual updates.

* ``GET /api/v1/content-versions`` (Analyst): the history of ``ContentVersion`` rows, newest first, filterable by
  feed and active flag.
* ``POST /api/v1/content-versions/updates`` (Admin): queue an update of one feed now (``content_update`` task,
  maintenance queue). The worker runs it; the answer is ``202``.

Updaters and their rules: ``securescan/jobs/updaters.py`` and ``content/README.md``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import ServiceUnavailable
from securescan.api.schemas import ORMModel
from securescan.auth.roles import AdminUser, AnalystUser
from securescan.db.models.content import ContentVersion
from securescan.db.models.enums import ContentFeed
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.jobs.scanner_health import ALL_FEEDS

router = APIRouter(tags=["content"])


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

    @field_validator("feed")
    @classmethod
    def _updated(cls, value: ContentFeed) -> ContentFeed:
        if value not in ALL_FEEDS:
            raise ValueError("This feed is no longer updated: its scanner was removed.")
        return value


class UpdateAccepted(BaseModel):
    feed: ContentFeed
    queued: bool = Field(description="false when an update of this feed is already waiting in the queue")
    message: str


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
