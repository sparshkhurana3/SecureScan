"""Scan profiles: list and read (Analyst), add a version and switch versions on or off (Admin).

A profile is versioned YAML (see ``securescan/runner/profiles.py``). A stored version never changes; to
change a profile an Admin posts the new YAML, which becomes the next version of the same name. Scans
use the newest active version unless a request names one.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import UnprocessableEntity
from securescan.api.schemas import ORMModel
from securescan.auth.roles import AdminUser, AnalystUser
from securescan.db.models.profiles import ScanProfile
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.domain.scans import validate_profile_error
from securescan.runner.profiles import (
    ProfileError,
    profile_body,
    profile_sha256,
    validate_profile_yaml,
)
from securescan.util import new_id, utcnow

router = APIRouter(tags=["profiles"])

MAX_YAML_BYTES = 64 * 1024


class ProfileOut(ORMModel):
    id: uuid.UUID
    name: str
    version: int
    kind: str
    mode: str | None = None
    description: str | None
    tools: list[str] = Field(default_factory=list)
    active: bool
    sha256: str
    created_at: datetime


class ProfileDetail(ProfileOut):
    body_yaml: str
    body: dict[str, Any]


class ProfileCreate(BaseModel):
    yaml: str = Field(min_length=10, description="The profile as YAML (see scanners/profiles/code-standard.yaml)")


class ProfileUpdate(BaseModel):
    active: bool


def _tools_of(body: dict[str, Any]) -> list[str]:
    jobs = body.get("jobs") if isinstance(body, dict) else None
    return [str(j.get("tool")) for j in jobs or [] if isinstance(j, dict) and j.get("tool")]


def to_out(row: ScanProfile) -> ProfileOut:
    out = ProfileOut.model_validate(row)
    out.tools = _tools_of(row.body)
    out.mode = (row.body or {}).get("mode")
    return out


def to_detail(row: ScanProfile) -> ProfileDetail:
    out = to_out(row)
    return ProfileDetail(**out.model_dump(), body_yaml=row.body_yaml, body=row.body)


@router.get("/profiles", response_model=CursorPage[ProfileOut], summary="List scan profiles")
async def list_profiles(
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    kind: Annotated[str | None, Query(pattern="^(sast|dast)$")] = None,
    name: str | None = None,
    include_inactive: bool = False,
) -> CursorPage[ProfileOut]:
    stmt = select(ScanProfile)
    if kind:
        stmt = stmt.where(ScanProfile.kind == kind)
    if name:
        stmt = stmt.where(ScanProfile.name == name)
    if not include_inactive:
        stmt = stmt.where(ScanProfile.active.is_(True))
    result = await paginate(db, stmt, key=[ScanProfile.created_at, ScanProfile.id], params=page)
    return CursorPage(items=[to_out(r) for r in result.items], next_cursor=result.next_cursor)


@router.get("/profiles/{profile_id}", response_model=ProfileDetail, summary="Get a scan profile")
async def get_profile(profile_id: uuid.UUID, db: DbSession, user: AnalystUser) -> ProfileDetail:
    return to_detail(await get_or_404(db, ScanProfile, profile_id, "Profile"))


@router.post(
    "/profiles",
    response_model=ProfileDetail,
    status_code=201,
    summary="Add a profile or a new version of one (Admin)",
)
async def create_profile(
    body: ProfileCreate, request: Request, db: DbSession, user: AdminUser
) -> ProfileDetail:
    if len(body.yaml.encode("utf-8")) > MAX_YAML_BYTES:
        raise UnprocessableEntity("The profile YAML is larger than 64 KB", code="profile.too_large")
    try:
        doc = validate_profile_yaml(body.yaml)
    except ProfileError as exc:
        raise validate_profile_error(exc) from exc
    latest = await db.scalar(
        select(func.max(ScanProfile.version)).where(ScanProfile.name == doc.profile)
    )
    version = (latest or 0) + 1
    if doc.version is not None and doc.version != version:
        raise UnprocessableEntity(
            f"The next version of {doc.profile!r} is {version}; the YAML says {doc.version}. "
            "Leave out 'version' or set it to the next number.",
            code="profile.version_mismatch",
        )
    row = ScanProfile(
        id=new_id(),
        name=doc.profile,
        version=version,
        kind=doc.kind,
        description=doc.description,
        body_yaml=body.yaml,
        body=profile_body(doc, version),
        sha256=profile_sha256(body.yaml),
        active=True,
        created_by_id=user.id,
        created_at=utcnow(),
    )
    db.add(row)
    await db.flush()
    await record_audit(
        db, user, "profile.create", "profile", row.id,
        {"name": row.name, "version": row.version, "tools": doc.tools}, request,
    )  # fmt: skip
    await db.commit()
    return to_detail(row)


@router.patch("/profiles/{profile_id}", response_model=ProfileOut, summary="Switch a profile version on or off (Admin)")
async def update_profile(
    profile_id: uuid.UUID, body: ProfileUpdate, request: Request, db: DbSession, user: AdminUser
) -> ProfileOut:
    row = await get_or_404(db, ScanProfile, profile_id, "Profile")
    if row.active != body.active:
        row.active = body.active
        await record_audit(
            db, user, "profile.update", "profile", row.id,
            {"name": row.name, "version": row.version, "active": body.active}, request,
        )  # fmt: skip
        await db.commit()
    return to_out(row)
