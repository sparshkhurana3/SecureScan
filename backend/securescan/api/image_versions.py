"""Scanner image versions: the monthly proposals, their regression result, and the Admin's decision.

Admin only (Settings -> Scanner images). Every decision is audited (``image.approve``, ``image.reject``,
``image.deactivate``). An approved row becomes the digest the next scan uses for its tool; the lock file
``deploy/images.lock.yaml`` follows in the next release commit (``lock_line`` shows the line to put there).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import Conflict
from securescan.api.schemas import ORMModel
from securescan.auth.roles import AdminUser
from securescan.db.models.images import ImageVersion
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.domain.image_updates import (
    SOURCE_PROPOSAL,
    SOURCE_REJECTED,
    approve_image_version,
    deactivate_image_version,
    lock_yaml_line,
    public_detail,
    reject_image_version,
)

router = APIRouter(tags=["image-versions"])

ImageState = Literal["pending", "active", "retired", "rejected"]


class ImageVersionOut(ORMModel):
    id: uuid.UUID
    tool: str
    image: str
    tag: str | None
    digest: str
    source: str
    state: ImageState
    scope: str | None = None
    reason: str | None = None
    previous_tag: str | None = None
    previous_digest: str | None = None
    regression_result: str
    regression_detail: dict[str, Any]
    active: bool
    proposed_at: datetime
    approved_by_id: uuid.UUID | None
    approved_at: datetime | None
    notes: str | None
    lock_line: str


class ApproveBody(BaseModel):
    acknowledge_skipped: bool = Field(
        default=False,
        description="Required when no regression check could be run: confirms that the image was tested by hand.",
    )


class RejectBody(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class QueuedOut(BaseModel):
    queued: bool
    detail: str


def state_of(row: ImageVersion) -> ImageState:
    if row.active:
        return "active"
    if row.source == SOURCE_REJECTED:
        return "rejected"
    if row.approved_at is not None:
        return "retired"
    return "pending"


def to_out(row: ImageVersion) -> ImageVersionOut:
    detail = public_detail(row.regression_detail)
    return ImageVersionOut(
        id=row.id,
        tool=row.tool,
        image=row.image,
        tag=row.tag,
        digest=row.digest,
        source=row.source,
        state=state_of(row),
        scope=detail.get("scope"),
        reason=detail.get("reason"),
        previous_tag=detail.get("previous_tag"),
        previous_digest=detail.get("previous_digest"),
        regression_result=row.regression_result,
        regression_detail=detail,
        active=row.active,
        proposed_at=row.proposed_at,
        approved_by_id=row.approved_by_id,
        approved_at=row.approved_at,
        notes=row.notes,
        lock_line=lock_yaml_line(row),
    )


@router.get(
    "/image-versions",
    response_model=CursorPage[ImageVersionOut],
    summary="List scanner image proposals and approved images (Admin)",
)
async def list_image_versions(
    db: DbSession,
    user: AdminUser,
    page: PageDep,
    state: Annotated[ImageState | None, Query(description="Only rows in this state")] = None,
    tool: str | None = None,
) -> CursorPage[ImageVersionOut]:
    stmt = select(ImageVersion)
    if tool:
        stmt = stmt.where(ImageVersion.tool == tool)
    if state == "active":
        stmt = stmt.where(ImageVersion.active.is_(True))
    elif state == "rejected":
        stmt = stmt.where(ImageVersion.source == SOURCE_REJECTED)
    elif state == "retired":
        stmt = stmt.where(ImageVersion.active.is_(False), ImageVersion.approved_at.is_not(None))
    elif state == "pending":
        stmt = stmt.where(
            ImageVersion.source == SOURCE_PROPOSAL,
            ImageVersion.active.is_(False),
            ImageVersion.approved_at.is_(None),
        )
    result = await paginate(
        db, stmt, key=[ImageVersion.proposed_at, ImageVersion.id], params=page, descending=True
    )
    return CursorPage(items=[to_out(r) for r in result.items], next_cursor=result.next_cursor)


@router.post(
    "/image-versions/check",
    response_model=QueuedOut,
    status_code=202,
    summary="Look for new scanner images now (Admin)",
)
async def check_now(request: Request, db: DbSession, user: AdminUser) -> QueuedOut:
    from securescan.jobs.image_updates import queue_check_now

    await record_audit(db, user, "image.check", "image_version", None, {}, request)
    await db.commit()
    job_id = await queue_check_now()
    if job_id is None:
        return QueuedOut(queued=False, detail="A check is already waiting in the queue.")
    return QueuedOut(queued=True, detail="The check was queued. New proposals appear here within minutes.")


@router.get("/image-versions/{image_version_id}", response_model=ImageVersionOut, summary="Get an image version (Admin)")
async def get_image_version(image_version_id: uuid.UUID, db: DbSession, user: AdminUser) -> ImageVersionOut:
    return to_out(await get_or_404(db, ImageVersion, image_version_id, "Image version"))


@router.post(
    "/image-versions/{image_version_id}/approve",
    response_model=ImageVersionOut,
    summary="Approve a proposal: the next scan uses its digest (Admin)",
)
async def approve(
    image_version_id: uuid.UUID, body: ApproveBody, request: Request, db: DbSession, user: AdminUser
) -> ImageVersionOut:
    row = await get_or_404(db, ImageVersion, image_version_id, "Image version")
    await approve_image_version(db, row, user, acknowledge_skipped=body.acknowledge_skipped, request=request)
    await db.commit()
    return to_out(row)


@router.post(
    "/image-versions/{image_version_id}/reject",
    response_model=ImageVersionOut,
    summary="Reject a proposal (Admin)",
)
async def reject(
    image_version_id: uuid.UUID, body: RejectBody, request: Request, db: DbSession, user: AdminUser
) -> ImageVersionOut:
    row = await get_or_404(db, ImageVersion, image_version_id, "Image version")
    await reject_image_version(db, row, user, note=body.note, request=request)
    await db.commit()
    return to_out(row)


@router.post(
    "/image-versions/{image_version_id}/deactivate",
    response_model=ImageVersionOut,
    summary="Stop using an approved image; scans fall back to the lock file (Admin)",
)
async def deactivate(
    image_version_id: uuid.UUID, request: Request, db: DbSession, user: AdminUser
) -> ImageVersionOut:
    row = await get_or_404(db, ImageVersion, image_version_id, "Image version")
    await deactivate_image_version(db, row, user, request=request)
    await db.commit()
    return to_out(row)


@router.post(
    "/image-versions/{image_version_id}/regression",
    response_model=QueuedOut,
    status_code=202,
    summary="Run the regression check of a proposal again (Admin)",
)
async def rerun_regression(
    image_version_id: uuid.UUID, request: Request, db: DbSession, user: AdminUser
) -> QueuedOut:
    from securescan.jobs.image_updates import queue_regression

    row = await get_or_404(db, ImageVersion, image_version_id, "Image version")
    pending = row.source == SOURCE_PROPOSAL and not row.active and row.approved_at is None
    if not pending:
        raise Conflict("Only a pending proposal can be tested again.", code="image.not_pending")
    if row.regression_result == "testing":
        raise Conflict("The regression check is running now.", code="image.regression_running")
    scope = str((row.regression_detail or {}).get("scope") or "")
    if scope == "release":
        raise Conflict("Platform images have no regression check.", code="image.release_scope")
    row.regression_result = "pending"
    await record_audit(
        db, user, "image.regression_rerun", "image_version", row.id, {"tool": row.tool, "tag": row.tag}, request
    )
    await db.commit()
    job_id = await queue_regression(str(row.id))
    return QueuedOut(
        queued=job_id is not None,
        detail="The regression check was queued." if job_id is not None else "It is already queued.",
    )

