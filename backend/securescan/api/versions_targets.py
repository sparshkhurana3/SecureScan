"""Application versions and their targets (repository, upload, image or URL)."""

from __future__ import annotations

import uuid
from datetime import datetime
from types import SimpleNamespace
from typing import Annotated, Any

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import Conflict, Forbidden, UnprocessableEntity
from securescan.api.schemas import BlackoutWindow, LabelKind, ORMModel
from securescan.auth.roles import AdminUser, AnalystUser
from securescan.db.models.applications import Application
from securescan.db.models.artifacts import Artifact
from securescan.db.models.credentials import Credential
from securescan.db.models.enums import ArtifactKind, CredentialKind, TargetEnvironment, TargetKind
from securescan.db.models.targets import Target
from securescan.db.models.versions import ApplicationVersion
from securescan.db.repositories.applications import (
    application_of_version,
    find_version_by_label,
    target_filters,
)
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.domain.dast_rules import target_hosts
from securescan.domain.inventory import validate_cron, validate_scope_patterns, validate_target_rules
from securescan.util import utcnow

router = APIRouter(tags=["versions", "targets"])


# --------------------------------------------------------------------------- versions
class VersionOut(ORMModel):
    id: uuid.UUID
    application_id: uuid.UUID
    label: str
    label_kind: str
    description: str | None
    commit_sha: str | None
    dd_engagement_id: int | None
    archived_at: datetime | None
    created_at: datetime
    updated_at: datetime


class VersionCreate(BaseModel):
    label: str = Field(min_length=1, max_length=255)
    label_kind: LabelKind = "branch"
    description: str | None = Field(default=None, max_length=4000)
    commit_sha: str | None = Field(default=None, max_length=64)


class VersionUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=4000)
    commit_sha: str | None = Field(default=None, max_length=64)
    archived: bool | None = Field(default=None, description="Admin only")


@router.get(
    "/applications/{application_id}/versions",
    response_model=CursorPage[VersionOut],
    summary="List the versions of an application",
)
async def list_versions(
    application_id: uuid.UUID,
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    include_archived: bool = False,
) -> CursorPage[VersionOut]:
    await get_or_404(db, Application, application_id, "Application")
    stmt = select(ApplicationVersion).where(ApplicationVersion.application_id == application_id)
    if not include_archived:
        stmt = stmt.where(ApplicationVersion.archived_at.is_(None))
    result = await paginate(
        db, stmt, key=[ApplicationVersion.created_at, ApplicationVersion.id], params=page
    )
    return CursorPage(
        items=[VersionOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@router.post(
    "/applications/{application_id}/versions",
    response_model=VersionOut,
    status_code=201,
    summary="Create a version",
)
async def create_version(
    application_id: uuid.UUID, body: VersionCreate, request: Request, db: DbSession, user: AnalystUser
) -> VersionOut:
    await get_or_404(db, Application, application_id, "Application")
    if await find_version_by_label(db, application_id, body.label) is not None:
        raise Conflict("This application already has a version with that label", code="version.duplicate_label")
    now = utcnow()
    row = ApplicationVersion(
        application_id=application_id,
        label=body.label,
        label_kind=body.label_kind,
        description=body.description,
        commit_sha=body.commit_sha,
        created_by_id=user.id,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.flush()
    await record_audit(
        db, user, "version.create", "version", row.id,
        {"application_id": str(application_id), "label": row.label}, request,
    )  # fmt: skip
    await db.commit()
    return VersionOut.model_validate(row)


@router.get("/versions/{version_id}", response_model=VersionOut, summary="Get a version")
async def get_version(version_id: uuid.UUID, db: DbSession, user: AnalystUser) -> VersionOut:
    return VersionOut.model_validate(await get_or_404(db, ApplicationVersion, version_id, "Version"))


@router.patch("/versions/{version_id}", response_model=VersionOut, summary="Edit a version")
async def update_version(
    version_id: uuid.UUID, body: VersionUpdate, request: Request, db: DbSession, user: AnalystUser
) -> VersionOut:
    row = await get_or_404(db, ApplicationVersion, version_id, "Version")
    changes = body.model_dump(exclude_unset=True)
    archived = changes.pop("archived", None)
    if archived is not None and not user.is_admin:
        raise Forbidden("Only an Admin can archive or restore a version", code="auth.insufficient_role")
    for key, value in changes.items():
        setattr(row, key, value)
    if archived is True and row.archived_at is None:
        row.archived_at = utcnow()
    elif archived is False:
        row.archived_at = None
    row.updated_at = utcnow()
    await record_audit(
        db, user, "version.update", "version", row.id, {"changed": sorted(body.model_fields_set)}, request
    )
    await db.commit()
    return VersionOut.model_validate(row)


@router.delete("/versions/{version_id}", status_code=204, summary="Archive a version (Admin)")
async def archive_version(
    version_id: uuid.UUID, request: Request, db: DbSession, user: AdminUser
) -> Response:
    row = await get_or_404(db, ApplicationVersion, version_id, "Version")
    if row.archived_at is None:
        row.archived_at = utcnow()
        row.updated_at = utcnow()
        await record_audit(db, user, "version.archive", "version", row.id, {"label": row.label}, request)
        await db.commit()
    return Response(status_code=204)


# --------------------------------------------------------------------------- targets
class TargetOut(ORMModel):
    id: uuid.UUID
    version_id: uuid.UUID
    kind: TargetKind
    name: str | None
    locator: str
    environment: TargetEnvironment | None
    environment_set_by_id: uuid.UUID | None
    environment_set_at: datetime | None
    credential_id: uuid.UUID | None
    login_profile_id: uuid.UUID | None
    upload_artifact_id: uuid.UUID | None
    default_branch: str | None
    scope_includes: list[str]
    scope_excludes: list[str]
    api_spec_type: str | None
    api_spec_locator: str | None
    api_spec_artifact_id: uuid.UUID | None
    rate_limit_rps: int | None
    blackout_windows: list[dict[str, Any]]
    dast_cron: str | None
    host_approved: bool
    vendor_authorization_artifact_id: uuid.UUID | None
    vendor_authorized_from: datetime | None
    vendor_authorized_until: datetime | None
    vendor_contact: str | None
    vendor_authorization_notes: str | None
    archived_at: datetime | None
    created_at: datetime
    updated_at: datetime


class TargetFields(BaseModel):
    """Fields that can be set when creating a target and changed later."""

    name: str | None = Field(default=None, max_length=200)
    credential_id: uuid.UUID | None = None
    login_profile_id: uuid.UUID | None = None
    default_branch: str | None = Field(default=None, max_length=255)
    scope_includes: list[str] | None = None
    scope_excludes: list[str] | None = None
    api_spec_type: Annotated[str | None, Field(pattern="^(openapi|graphql|soap)$")] = None
    api_spec_locator: str | None = Field(default=None, max_length=2000)
    api_spec_artifact_id: uuid.UUID | None = None
    rate_limit_rps: int | None = Field(default=None, ge=1, le=1000)
    blackout_windows: list[BlackoutWindow] | None = None
    dast_cron: str | None = Field(default=None, max_length=100)
    host_approved: bool | None = Field(default=None, description="Admin only")
    vendor_authorization_artifact_id: uuid.UUID | None = None
    vendor_authorized_from: datetime | None = None
    vendor_authorized_until: datetime | None = None
    vendor_contact: str | None = Field(default=None, max_length=2000)
    vendor_authorization_notes: str | None = Field(default=None, max_length=4000)


class TargetCreate(TargetFields):
    kind: TargetKind
    locator: str | None = Field(default=None, max_length=2000)
    environment: TargetEnvironment | None = None
    upload_artifact_id: uuid.UUID | None = None


class TargetUpdate(TargetFields):
    locator: str | None = Field(default=None, max_length=2000)
    environment: TargetEnvironment | None = None
    archived: bool | None = Field(default=None, description="Admin only")


# The credential kinds a target kind may carry. Everything else (an NVD key, the GitHub App key, the DefectDojo and
# SonarQube tokens, DAST logins, a registry login on a repository) is refused: the secret would be sent to whatever
# host the target's locator names, and an Analyst chooses the locator.
CREDENTIAL_KINDS_BY_TARGET: dict[TargetKind, tuple[CredentialKind, ...]] = {
    TargetKind.VENDOR_REPO: (CredentialKind.DEPLOY_KEY, CredentialKind.VENDOR_TOKEN),
    TargetKind.IMAGE: (CredentialKind.REGISTRY,),
}


def _check_credential(
    credential: Credential,
    *,
    target_kind: TargetKind,
    application_id: uuid.UUID,
    version_id: uuid.UUID,
    target_id: uuid.UUID | None,
    is_admin: bool,
) -> None:
    """The credential must be of a kind this target kind uses and must belong to this application and version."""
    allowed = CREDENTIAL_KINDS_BY_TARGET.get(target_kind, ())
    if credential.kind not in allowed:
        raise UnprocessableEntity(
            "A %s target cannot use a %s credential" % (target_kind.value, credential.kind.value),
            code="target.credential_kind",
        )
    if credential.application_id is None:
        # Only an Admin may attach a credential that belongs to no application (a shared registry login).
        if not is_admin:
            raise Forbidden("Only an Admin can attach a shared credential", code="auth.insufficient_role")
    elif credential.application_id != application_id:
        raise UnprocessableEntity("This credential belongs to another application", code="target.credential_scope")
    if credential.version_id is not None and credential.version_id != version_id:
        raise UnprocessableEntity("This credential belongs to another version", code="target.credential_scope")
    bound = (credential.extra or {}).get("target_id")
    if bound is not None and str(bound) != str(target_id):
        raise UnprocessableEntity("This credential belongs to another target", code="target.credential_scope")


async def _check_references(
    db: DbSession,
    values: dict[str, Any],
    *,
    target_kind: TargetKind,
    application_id: uuid.UUID,
    version_id: uuid.UUID,
    is_admin: bool,
    target_id: uuid.UUID | None = None,
) -> None:
    """Referenced credentials and artifacts must exist, be of the right kind and belong to this application."""
    for field in ("credential_id", "login_profile_id"):
        ref = values.get(field)
        if ref is None:
            continue
        credential = await db.get(Credential, ref)
        if credential is None or credential.revoked_at is not None:
            raise UnprocessableEntity(f"{field} does not exist", code=f"target.{field}_unknown")
        if field == "login_profile_id":
            if credential.kind != CredentialKind.DAST_LOGIN:
                raise UnprocessableEntity(
                    "The login profile must be a dast_login credential", code="target.login_profile_kind"
                )
            if credential.application_id is not None and credential.application_id != application_id:
                raise UnprocessableEntity(
                    "This login profile belongs to another application", code="target.credential_scope"
                )
            if credential.version_id is not None and credential.version_id != version_id:
                raise UnprocessableEntity(
                    "This login profile belongs to another version", code="target.credential_scope"
                )
        else:
            _check_credential(
                credential,
                target_kind=target_kind,
                application_id=application_id,
                version_id=version_id,
                target_id=target_id,
                is_admin=is_admin,
            )
    for field, kind in (
        ("upload_artifact_id", ArtifactKind.UPLOAD),
        ("api_spec_artifact_id", ArtifactKind.UPLOAD),
        ("vendor_authorization_artifact_id", ArtifactKind.UPLOAD),
    ):
        ref = values.get(field)
        if ref is None:
            continue
        artifact = await db.get(Artifact, ref)
        if artifact is None or artifact.kind not in (kind, ArtifactKind.DOCUMENT):
            raise UnprocessableEntity(f"{field} is not a finished upload", code=f"target.{field}_unknown")


def _host_signature(locator: str | None, api_spec_locator: str | None) -> frozenset[tuple[str, int]] | None:
    """The (host, port) pairs a web scan of these locators contacts; None when they cannot be read."""
    try:
        hosts = target_hosts(SimpleNamespace(locator=locator, api_spec_locator=api_spec_locator))
    except ValueError:
        return None
    return frozenset((info.host, info.port) for info in hosts)


NOT_NULL_FIELDS = ("host_approved", "scope_includes", "scope_excludes", "blackout_windows")


def _prepare(values: dict[str, Any]) -> dict[str, Any]:
    for field in NOT_NULL_FIELDS:
        if field in values and values[field] is None:
            values.pop(field)
    if values.get("scope_includes") is not None:
        values["scope_includes"] = validate_scope_patterns(values["scope_includes"])
    if values.get("scope_excludes") is not None:
        values["scope_excludes"] = list(values["scope_excludes"])
    if values.get("dast_cron"):
        values["dast_cron"] = validate_cron(values["dast_cron"])
    if values.get("blackout_windows") is not None:
        values["blackout_windows"] = [
            w if isinstance(w, dict) else w.model_dump(mode="json", exclude_none=True)
            for w in values["blackout_windows"]
        ]
    return values


@router.get(
    "/versions/{version_id}/targets", response_model=CursorPage[TargetOut], summary="List the targets of a version"
)
async def list_version_targets(
    version_id: uuid.UUID,
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    include_archived: bool = False,
) -> CursorPage[TargetOut]:
    await get_or_404(db, ApplicationVersion, version_id, "Version")
    stmt = select(Target).where(*target_filters(version_id=version_id, include_archived=include_archived))
    result = await paginate(db, stmt, key=[Target.created_at, Target.id], params=page)
    return CursorPage(
        items=[TargetOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@router.get("/targets", response_model=CursorPage[TargetOut], summary="List targets across applications")
async def list_targets(
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    application_id: uuid.UUID | None = None,
    kind: TargetKind | None = None,
    environment: TargetEnvironment | None = None,
    include_archived: bool = False,
) -> CursorPage[TargetOut]:
    stmt = select(Target).where(
        *target_filters(
            application_id=application_id,
            kind=kind,
            environment=environment,
            include_archived=include_archived,
        )
    )
    result = await paginate(db, stmt, key=[Target.created_at, Target.id], params=page)
    return CursorPage(
        items=[TargetOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@router.post(
    "/versions/{version_id}/targets", response_model=TargetOut, status_code=201, summary="Create a target"
)
async def create_target(
    version_id: uuid.UUID, body: TargetCreate, request: Request, db: DbSession, user: AnalystUser
) -> TargetOut:
    await get_or_404(db, ApplicationVersion, version_id, "Version")
    application = await application_of_version(db, version_id)
    assert application is not None  # noqa: S101 - the version exists, so does its application
    values = _prepare(body.model_dump(exclude={"kind", "locator", "environment"}, exclude_unset=True))
    if values.get("host_approved") and not user.is_admin:
        raise Forbidden("Only an Admin can approve a host", code="auth.insufficient_role")
    await _check_references(
        db,
        {**values, "upload_artifact_id": body.upload_artifact_id},
        target_kind=body.kind,
        application_id=application.id,
        version_id=version_id,
        is_admin=user.is_admin,
    )
    locator = validate_target_rules(
        kind=body.kind,
        locator=body.locator,
        environment=body.environment,
        application_type=application.type,
        login_profile_id=body.login_profile_id,
        upload_artifact_id=body.upload_artifact_id,
    )
    now = utcnow()
    row = Target(
        version_id=version_id,
        kind=body.kind,
        locator=locator,
        environment=body.environment,
        environment_set_by_id=user.id if body.environment else None,
        environment_set_at=now if body.environment else None,
        scope_includes=values.pop("scope_includes", []),
        scope_excludes=values.pop("scope_excludes", []),
        blackout_windows=values.pop("blackout_windows", []),
        created_by_id=user.id,
        created_at=now,
        updated_at=now,
        **values,
    )
    db.add(row)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise UnprocessableEntity("A referenced record does not exist", code="target.invalid_reference") from exc
    await record_audit(
        db, user, "target.create", "target", row.id,
        {"kind": row.kind.value, "environment": row.environment.value if row.environment else None,
         "version_id": str(version_id)}, request,
    )  # fmt: skip
    await db.commit()
    return TargetOut.model_validate(row)


@router.get("/targets/{target_id}", response_model=TargetOut, summary="Get a target")
async def get_target(target_id: uuid.UUID, db: DbSession, user: AnalystUser) -> TargetOut:
    return TargetOut.model_validate(await get_or_404(db, Target, target_id, "Target"))


@router.patch("/targets/{target_id}", response_model=TargetOut, summary="Edit a target")
async def update_target(
    target_id: uuid.UUID, body: TargetUpdate, request: Request, db: DbSession, user: AnalystUser
) -> TargetOut:
    row = await get_or_404(db, Target, target_id, "Target")
    application = await application_of_version(db, row.version_id)
    assert application is not None  # noqa: S101
    changes = _prepare(body.model_dump(exclude_unset=True))
    archived = changes.pop("archived", None)
    if (archived is not None or changes.get("host_approved") is not None) and not user.is_admin:
        raise Forbidden("Only an Admin can archive a target or approve a host", code="auth.insufficient_role")
    await _check_references(
        db,
        changes,
        target_kind=row.kind,
        application_id=application.id,
        version_id=row.version_id,
        is_admin=user.is_admin,
        target_id=row.id,
    )
    old_environment = row.environment
    old_locator = row.locator
    old_hosts = _host_signature(row.locator, row.api_spec_locator) if row.kind == TargetKind.URL else None
    old_spec_artifact = row.api_spec_artifact_id
    new_environment = changes.pop("environment", old_environment) if "environment" in body.model_fields_set else old_environment
    new_login = changes["login_profile_id"] if "login_profile_id" in changes else row.login_profile_id
    new_locator = changes.pop("locator", None) if "locator" in body.model_fields_set else None
    if row.kind != TargetKind.ZIP:
        validated = validate_target_rules(
            kind=row.kind,
            locator=new_locator or row.locator,
            environment=new_environment,
            application_type=application.type,
            login_profile_id=new_login,
            upload_artifact_id=row.upload_artifact_id,
        )
        row.locator = validated
    elif new_login is not None or new_environment is not None:
        raise UnprocessableEntity("Zip targets have no environment or login profile", code="target.environment_not_allowed")
    locator_before_edit = old_locator
    for key, value in changes.items():
        setattr(row, key, value)
    if row.credential_id is not None and not user.is_admin and row.locator != locator_before_edit:
        # The credential travels to whatever host the locator names; an Analyst may not re-point it.
        raise UnprocessableEntity(
            "This target has a credential. Revoke it before changing the repository or image, "
            "then add a new one for the new location.",
            code="target.locator_locked",
        )
    if new_environment != old_environment:
        row.environment = new_environment
        row.environment_set_by_id = user.id
        row.environment_set_at = utcnow()
        await record_audit(
            db, user, "target.environment_change", "target", row.id,
            {"from": old_environment.value if old_environment else None,
             "to": new_environment.value if new_environment else None}, request,
        )  # fmt: skip
    if row.host_approved and changes.get("host_approved") is not True:
        # An approval covers the host(s) the Admin saw. A different host or API specification needs a new approval.
        new_hosts = _host_signature(row.locator, row.api_spec_locator) if row.kind == TargetKind.URL else None
        hosts_changed = row.kind == TargetKind.URL and (
            new_hosts is None or old_hosts is None or not new_hosts <= old_hosts
        )
        spec_changed = row.api_spec_artifact_id != old_spec_artifact and not user.is_admin
        if hosts_changed or spec_changed:
            row.host_approved = False
            await record_audit(
                db, user, "target.host_approval_cleared", "target", row.id,
                {"reason": "address changed" if hosts_changed else "api specification changed"}, request,
            )  # fmt: skip
    if archived is True and row.archived_at is None:
        row.archived_at = utcnow()
    elif archived is False:
        row.archived_at = None
    row.updated_at = utcnow()
    await record_audit(
        db, user, "target.update", "target", row.id, {"changed": sorted(body.model_fields_set)}, request
    )
    await db.commit()
    return TargetOut.model_validate(row)


@router.delete("/targets/{target_id}", status_code=204, summary="Archive a target (Admin)")
async def archive_target(
    target_id: uuid.UUID, request: Request, db: DbSession, user: AdminUser
) -> Response:
    row = await get_or_404(db, Target, target_id, "Target")
    if row.archived_at is None:
        row.archived_at = utcnow()
        row.updated_at = utcnow()
        await record_audit(db, user, "target.archive", "target", row.id, {"locator": row.locator}, request)
        await db.commit()
    return Response(status_code=204)

