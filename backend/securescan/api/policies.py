"""Verdict policies (Admin): thresholds by data classification, by application, or the default."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select, update

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import Conflict, UnprocessableEntity
from securescan.api.schemas import DataClassification, ORMModel
from securescan.auth.roles import AdminUser
from securescan.db.models.applications import Application
from securescan.db.models.policies import Policy
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.domain.policy import DEFAULT_THRESHOLDS, Thresholds
from securescan.util import utcnow

router = APIRouter(tags=["policies"])


class PolicyOut(ORMModel):
    id: uuid.UUID
    name: str
    data_classification: str | None
    application_id: uuid.UUID | None
    is_default: bool
    thresholds: dict[str, Any]
    version: int
    active: bool
    created_at: datetime
    updated_at: datetime


class PolicyCreate(BaseModel):
    """A policy applies to one application, to one data classification, or (``is_default``) to all
    the rest. Thresholds: ``{"fail": {"critical": 1, "high": 6}, "conditional": {"high": 1}}``."""

    name: str = Field(min_length=1, max_length=200)
    data_classification: DataClassification | None = None
    application_id: uuid.UUID | None = None
    is_default: bool = False
    thresholds: Thresholds = Field(default_factory=Thresholds)
    active: bool = True

    @model_validator(mode="after")
    def _one_scope(self) -> PolicyCreate:
        scopes = [self.is_default, self.data_classification is not None, self.application_id is not None]
        if sum(scopes) != 1:
            raise ValueError(
                "choose exactly one scope: is_default, a data classification, or an application"
            )
        return self


class PolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    thresholds: Thresholds | None = None
    active: bool | None = None


@router.get("/policies", response_model=CursorPage[PolicyOut], summary="List verdict policies (Admin)")
async def list_policies(
    db: DbSession, user: AdminUser, page: PageDep, active: bool | None = None
) -> CursorPage[PolicyOut]:
    stmt = select(Policy)
    if active is not None:
        stmt = stmt.where(Policy.active.is_(active))
    result = await paginate(db, stmt, key=[Policy.created_at, Policy.id], params=page)
    return CursorPage(
        items=[PolicyOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@router.get(
    "/policies/builtin",
    summary="The built-in default thresholds used when no policy matches (Admin)",
)
async def builtin_policy(user: AdminUser) -> dict[str, Any]:
    return {"name": "Built-in default", "thresholds": DEFAULT_THRESHOLDS}


@router.post("/policies", response_model=PolicyOut, status_code=201, summary="Create a policy (Admin)")
async def create_policy(
    body: PolicyCreate, request: Request, db: DbSession, user: AdminUser
) -> PolicyOut:
    if body.application_id is not None and await db.get(Application, body.application_id) is None:
        raise UnprocessableEntity("The application does not exist", code="policy.application_unknown")
    if body.data_classification is not None:
        clash = await db.scalar(
            select(Policy.id).where(
                Policy.active.is_(True),
                Policy.application_id.is_(None),
                Policy.data_classification == body.data_classification,
            )
        )
        if clash is not None and body.active:
            raise Conflict(
                "An active policy already exists for this data classification. "
                "Edit or deactivate it first.",
                code="policy.duplicate_classification",
            )
    if body.application_id is not None and body.active:
        clash = await db.scalar(
            select(Policy.id).where(Policy.active.is_(True), Policy.application_id == body.application_id)
        )
        if clash is not None:
            raise Conflict(
                "An active policy already exists for this application. Edit or deactivate it first.",
                code="policy.duplicate_application",
            )
    if body.is_default and body.active:
        await db.execute(update(Policy).where(Policy.is_default.is_(True)).values(is_default=False))
    now = utcnow()
    policy = Policy(
        name=body.name,
        data_classification=body.data_classification,
        application_id=body.application_id,
        is_default=body.is_default and body.active,
        thresholds=body.thresholds.as_dict(),
        version=1,
        active=body.active,
        created_by_id=user.id,
        created_at=now,
        updated_at=now,
    )
    db.add(policy)
    await db.flush()
    await record_audit(
        db,
        user,
        "policy.create",
        "policy",
        policy.id,
        {"name": policy.name, "thresholds": policy.thresholds},
        request,
    )
    await db.commit()
    return PolicyOut.model_validate(policy)


@router.patch("/policies/{policy_id}", response_model=PolicyOut, summary="Change a policy (Admin)")
async def update_policy(
    policy_id: uuid.UUID, body: PolicyUpdate, request: Request, db: DbSession, user: AdminUser
) -> PolicyOut:
    policy = await get_or_404(db, Policy, policy_id, "Policy")
    changed: dict[str, Any] = {}
    if body.name is not None and body.name != policy.name:
        policy.name = body.name
        changed["name"] = body.name
    if body.thresholds is not None and body.thresholds.as_dict() != policy.thresholds:
        policy.thresholds = body.thresholds.as_dict()
        policy.version += 1  # scans keep the version they were judged by in their verdict detail
        changed["thresholds"] = policy.thresholds
    if body.active is not None and body.active != policy.active:
        policy.active = body.active
        if not body.active:
            policy.is_default = False
        changed["active"] = body.active
    if changed:
        policy.updated_at = utcnow()
        await record_audit(db, user, "policy.update", "policy", policy.id, changed, request)
    await db.commit()
    return PolicyOut.model_validate(policy)
