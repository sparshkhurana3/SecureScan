"""Applications: the inventory unit. Analysts read, create and edit; Admins archive."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import Conflict, Forbidden, UnprocessableEntity
from securescan.api.schemas import Criticality, DataClassification, Hosting, ORMModel
from securescan.auth.roles import AdminUser, AnalystUser
from securescan.db.models.applications import Application
from securescan.db.models.enums import AppType, Verdict
from securescan.db.models.vendors import Vendor
from securescan.db.repositories.applications import (
    application_filters,
    find_application_by_name,
    select_applications,
)
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.domain.inventory import normalise_tags, validate_application_rules
from securescan.util import utcnow

router = APIRouter(tags=["applications"])


class ApplicationOut(ORMModel):
    id: uuid.UUID
    name: str
    type: AppType
    vendor_id: uuid.UUID | None
    vendor_product: str | None
    hosting: str | None
    description: str | None
    criticality: str | None
    data_classification: str | None
    tags: list[str]
    confirmed: bool
    automatic: bool
    github_repo_id: int | None
    github_full_name: str | None
    default_branch: str | None
    dd_product_id: int | None
    cached_counts: dict[str, Any]
    cached_counts_at: datetime | None
    last_scan_at: datetime | None
    last_scan_id: uuid.UUID | None
    last_verdict: Verdict | None
    archived_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ApplicationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    type: AppType = AppType.INTERNAL
    vendor_id: uuid.UUID | None = None
    vendor_product: str | None = Field(default=None, max_length=200)
    hosting: Hosting | None = None
    description: str | None = Field(default=None, max_length=4000)
    criticality: Criticality | None = None
    data_classification: DataClassification | None = None
    tags: list[str] = Field(default_factory=list)
    confirmed: bool = True
    automatic: bool = False
    github_repo_id: int | None = None
    github_full_name: str | None = Field(default=None, max_length=255)
    default_branch: str | None = Field(default=None, max_length=255)


class ApplicationUpdate(BaseModel):
    """Only the fields present in the request are changed."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    vendor_id: uuid.UUID | None = None
    vendor_product: str | None = Field(default=None, max_length=200)
    hosting: Hosting | None = None
    description: str | None = Field(default=None, max_length=4000)
    criticality: Criticality | None = None
    data_classification: DataClassification | None = None
    tags: list[str] | None = None
    confirmed: bool | None = None
    automatic: bool | None = None
    default_branch: str | None = Field(default=None, max_length=255)
    archived: bool | None = Field(default=None, description="Admin only: archive or restore")


async def _require_vendor(db: DbSession, vendor_id: uuid.UUID | None) -> None:
    if vendor_id is not None and await db.get(Vendor, vendor_id) is None:
        raise UnprocessableEntity("The vendor does not exist", code="application.vendor_unknown")


@router.get("/applications", response_model=CursorPage[ApplicationOut], summary="List applications")
async def list_applications(
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    app_type: Annotated[AppType | None, Query(alias="type")] = None,
    vendor_id: uuid.UUID | None = None,
    q: Annotated[str | None, Query(description="Name contains")] = None,
    confirmed: bool | None = None,
    automatic: bool | None = None,
    last_scan_after: datetime | None = None,
    last_scan_before: datetime | None = None,
    never_scanned: bool | None = None,
    min_critical: Annotated[int | None, Query(ge=0, description="Open Critical findings at least")] = None,
    min_high: Annotated[int | None, Query(ge=0, description="Open High findings at least")] = None,
    include_archived: bool = False,
    sort: Annotated[str, Query(pattern="^(created|name)$")] = "created",
) -> CursorPage[ApplicationOut]:
    conditions = application_filters(
        app_type=app_type,
        vendor_id=vendor_id,
        q=q,
        confirmed=confirmed,
        automatic=automatic,
        last_scan_after=last_scan_after,
        last_scan_before=last_scan_before,
        never_scanned=never_scanned,
        min_critical=min_critical,
        min_high=min_high,
        include_archived=include_archived,
    )
    stmt = select_applications(conditions)
    if sort == "name":
        result = await paginate(
            db, stmt, key=[Application.name, Application.id], params=page, descending=False
        )
    else:
        result = await paginate(db, stmt, key=[Application.created_at, Application.id], params=page)
    return CursorPage(
        items=[ApplicationOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@router.post("/applications", response_model=ApplicationOut, status_code=201, summary="Create an application")
async def create_application(
    body: ApplicationCreate, request: Request, db: DbSession, user: AnalystUser
) -> ApplicationOut:
    validate_application_rules(body.type, body.vendor_id)
    await _require_vendor(db, body.vendor_id)
    if await find_application_by_name(db, body.name) is not None:
        raise Conflict("An application with this name exists", code="application.duplicate_name")
    now = utcnow()
    row = Application(
        name=body.name.strip(),
        type=body.type,
        vendor_id=body.vendor_id,
        vendor_product=body.vendor_product,
        hosting=body.hosting,
        description=body.description,
        criticality=body.criticality,
        data_classification=body.data_classification,
        tags=normalise_tags(body.tags),
        confirmed=body.confirmed,
        automatic=body.automatic,
        github_repo_id=body.github_repo_id,
        github_full_name=body.github_full_name,
        default_branch=body.default_branch,
        cached_counts={},
        created_by_id=user.id,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise Conflict(
            "An application with this name or GitHub repository exists",
            code="application.duplicate",
        ) from exc
    await record_audit(
        db, user, "application.create", "application", row.id,
        {"name": row.name, "type": row.type.value}, request,
    )  # fmt: skip
    await db.commit()
    return ApplicationOut.model_validate(row)


@router.get("/applications/{application_id}", response_model=ApplicationOut, summary="Get an application")
async def get_application(application_id: uuid.UUID, db: DbSession, user: AnalystUser) -> ApplicationOut:
    row = await get_or_404(db, Application, application_id, "Application")
    return ApplicationOut.model_validate(row)


@router.patch("/applications/{application_id}", response_model=ApplicationOut, summary="Edit an application")
async def update_application(
    application_id: uuid.UUID,
    body: ApplicationUpdate,
    request: Request,
    db: DbSession,
    user: AnalystUser,
) -> ApplicationOut:
    row = await get_or_404(db, Application, application_id, "Application")
    changes = body.model_dump(exclude_unset=True)
    archived = changes.pop("archived", None)
    if archived is not None and not user.is_admin:
        raise Forbidden("Only an Admin can archive or restore an application", code="auth.insufficient_role")
    if "name" in changes and changes["name"] is not None:
        if await find_application_by_name(db, changes["name"], exclude_id=row.id) is not None:
            raise Conflict("An application with this name exists", code="application.duplicate_name")
        changes["name"] = changes["name"].strip()
    if "vendor_id" in changes:
        validate_application_rules(row.type, changes["vendor_id"])
        await _require_vendor(db, changes["vendor_id"])
    if "tags" in changes and changes["tags"] is not None:
        changes["tags"] = normalise_tags(changes["tags"])
    for field in ("name", "confirmed", "automatic", "tags"):
        if field in changes and changes[field] is None:
            changes.pop(field)
    before = {k: getattr(row, k) for k in changes}
    for key, value in changes.items():
        setattr(row, key, value)
    if archived is True and row.archived_at is None:
        row.archived_at = utcnow()
        changes["archived"] = True
    elif archived is False and row.archived_at is not None:
        row.archived_at = None
        changes["archived"] = False
    row.updated_at = utcnow()
    await record_audit(
        db, user, "application.update", "application", row.id,
        {"changed": sorted(changes), "before": {k: _plain(v) for k, v in before.items()}}, request,
    )  # fmt: skip
    await db.commit()
    return ApplicationOut.model_validate(row)


@router.delete("/applications/{application_id}", status_code=204, summary="Archive an application (Admin)")
async def archive_application(
    application_id: uuid.UUID, request: Request, db: DbSession, user: AdminUser
) -> Response:
    """History is kept forever, so deleting archives: the application drops out of default lists."""
    row = await get_or_404(db, Application, application_id, "Application")
    if row.archived_at is None:
        row.archived_at = utcnow()
        row.updated_at = utcnow()
        await record_audit(db, user, "application.archive", "application", row.id, {"name": row.name}, request)
        await db.commit()
    return Response(status_code=204)


def _plain(value: Any) -> Any:
    return str(value) if isinstance(value, (uuid.UUID, datetime)) else value

