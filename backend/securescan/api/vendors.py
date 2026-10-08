"""Vendors (only for vendor applications)."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import Conflict, Forbidden
from securescan.api.schemas import ORMModel, RiskTier
from securescan.auth.roles import AdminUser, AnalystUser
from securescan.db.models.vendors import Vendor
from securescan.db.repositories.applications import find_vendor_by_name
from securescan.db.repositories.common import escape_like, get_or_404
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.util import utcnow

router = APIRouter(tags=["vendors"])


class VendorOut(ORMModel):
    id: uuid.UUID
    name: str
    contact_name: str | None
    contact_email: str | None
    risk_tier: str | None
    notes: str | None
    archived_at: datetime | None
    created_at: datetime
    updated_at: datetime


class VendorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_email: str | None = Field(default=None, max_length=320)
    risk_tier: RiskTier | None = None
    notes: str | None = Field(default=None, max_length=4000)


class VendorUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_email: str | None = Field(default=None, max_length=320)
    risk_tier: RiskTier | None = None
    notes: str | None = Field(default=None, max_length=4000)
    archived: bool | None = Field(default=None, description="Admin only")


@router.get("/vendors", response_model=CursorPage[VendorOut], summary="List vendors")
async def list_vendors(
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    q: str | None = None,
    risk_tier: RiskTier | None = None,
    include_archived: bool = False,
) -> CursorPage[VendorOut]:
    stmt = select(Vendor)
    if not include_archived:
        stmt = stmt.where(Vendor.archived_at.is_(None))
    if q:
        stmt = stmt.where(Vendor.name.ilike(f"%{escape_like(q)}%", escape="\\"))
    if risk_tier:
        stmt = stmt.where(Vendor.risk_tier == risk_tier)
    result = await paginate(db, stmt, key=[Vendor.name, Vendor.id], params=page, descending=False)
    return CursorPage(
        items=[VendorOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@router.post("/vendors", response_model=VendorOut, status_code=201, summary="Create a vendor")
async def create_vendor(
    body: VendorCreate, request: Request, db: DbSession, user: AnalystUser
) -> VendorOut:
    if await find_vendor_by_name(db, body.name) is not None:
        raise Conflict("A vendor with this name exists", code="vendor.duplicate_name")
    now = utcnow()
    row = Vendor(
        name=body.name.strip(),
        contact_name=body.contact_name,
        contact_email=body.contact_email,
        risk_tier=body.risk_tier,
        notes=body.notes,
        created_by_id=user.id,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.flush()
    await record_audit(db, user, "vendor.create", "vendor", row.id, {"name": row.name}, request)
    await db.commit()
    return VendorOut.model_validate(row)


@router.get("/vendors/{vendor_id}", response_model=VendorOut, summary="Get a vendor")
async def get_vendor(vendor_id: uuid.UUID, db: DbSession, user: AnalystUser) -> VendorOut:
    return VendorOut.model_validate(await get_or_404(db, Vendor, vendor_id, "Vendor"))


@router.patch("/vendors/{vendor_id}", response_model=VendorOut, summary="Edit a vendor")
async def update_vendor(
    vendor_id: uuid.UUID, body: VendorUpdate, request: Request, db: DbSession, user: AnalystUser
) -> VendorOut:
    row = await get_or_404(db, Vendor, vendor_id, "Vendor")
    changes = body.model_dump(exclude_unset=True)
    archived = changes.pop("archived", None)
    if archived is not None and not user.is_admin:
        raise Forbidden("Only an Admin can archive or restore a vendor", code="auth.insufficient_role")
    if changes.get("name") is None:
        changes.pop("name", None)
    elif await find_vendor_by_name(db, changes["name"], exclude_id=row.id) is not None:
        raise Conflict("A vendor with this name exists", code="vendor.duplicate_name")
    for key, value in changes.items():
        setattr(row, key, value)
    if archived is True and row.archived_at is None:
        row.archived_at = utcnow()
    elif archived is False:
        row.archived_at = None
    row.updated_at = utcnow()
    await record_audit(
        db, user, "vendor.update", "vendor", row.id, {"changed": sorted(body.model_fields_set)}, request
    )
    await db.commit()
    return VendorOut.model_validate(row)


@router.delete("/vendors/{vendor_id}", status_code=204, summary="Archive a vendor (Admin)")
async def archive_vendor(
    vendor_id: uuid.UUID, request: Request, db: DbSession, user: AdminUser
) -> Response:
    row = await get_or_404(db, Vendor, vendor_id, "Vendor")
    if row.archived_at is None:
        row.archived_at = utcnow()
        row.updated_at = utcnow()
        await record_audit(db, user, "vendor.archive", "vendor", row.id, {"name": row.name}, request)
        await db.commit()
    return Response(status_code=204)
