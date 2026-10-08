"""Web scans (DAST): target validation, what a target may run, a Start wrapper and login profiles.

* ``POST /dast/targets/check``: before a target is saved, show how its address resolves and whether the
  allowlist accepts it (and which modes its environment allows). No database access, nothing is stored.
* ``GET /dast/targets/{id}/options``: every web scan profile with "allowed" or the rule that forbids it, in
  plain words. The portal enables or disables its Start buttons from this; the rules themselves are enforced
  where scans are created (``domain/dast_rules.py``), the portal only reflects them.
* ``POST /dast/targets/{id}/scans``: start a web scan of a target (default profile by environment: baseline for
  production, full for UAT). Same creation path as ``POST /scans``.
* ``POST|GET /dast/login-profiles``, ``DELETE /dast/login-profiles/{id}``: stored login profiles for UAT
  targets. The settings are stored in the clear (they are not secret), the user name, password, one-time code
  seed or header token are encrypted. Secrets are never returned.

Stopping a running web scan is ``POST /scans/{id}/cancel``: the job's container stops and its proxy is removed.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Header, Request, Response
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import NotFound, Problem, UnprocessableEntity
from securescan.api.scans import ScanDetail, load_detail
from securescan.api.schemas import ORMModel
from securescan.auth.roles import AnalystUser
from securescan.config import get_settings
from securescan.db.models.applications import Application
from securescan.db.models.credentials import Credential
from securescan.db.models.enums import CredentialKind, ScanTrigger, TargetEnvironment, TargetKind
from securescan.db.models.profiles import ScanProfile
from securescan.db.models.targets import Target
from securescan.db.models.versions import ApplicationVersion
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.domain.credentials import store_credential
from securescan.domain.dast_rules import (
    LoginSecret,
    LoginSettings,
    allowed_modes,
    check_allowlist,
    check_scan_allowed_async,
    parse_cidrs,
    resolve_hosts,
    target_hosts,
)
from securescan.domain.scans import check_idempotency_key, create_scan_result
from securescan.runner.profiles import ProfileDoc
from securescan.util import utcnow

router = APIRouter(tags=["dast"])

DEFAULT_PROFILE = {
    TargetEnvironment.PRODUCTION: "dast-baseline",
    TargetEnvironment.UAT: "dast-full",
}


# --------------------------------------------------------------------------- target check
class TargetCheckIn(BaseModel):
    locator: str = Field(min_length=8, max_length=2000, description="The web address of the target")
    environment: TargetEnvironment | None = None
    api_spec_locator: str | None = Field(default=None, max_length=2000)
    host_approved: bool = Field(default=False, description="Whether an Admin approved the host explicitly")
    has_login_profile: bool = False


class HostCheckOut(BaseModel):
    host: str
    port: int
    scheme: str
    addresses: list[str]


class TargetCheckOut(BaseModel):
    url: str
    hosts: list[HostCheckOut]
    allowlist_configured: bool
    allowed: bool
    code: str | None = None
    reason: str | None = None
    modes: list[str] = Field(description="Scan modes the environment accepts: baseline, full, api, nuclei")


@router.post(
    "/dast/targets/check",
    response_model=TargetCheckOut,
    summary="Check a web address against the DAST allowlist",
    description="Resolves the host (and the API definition host) and tells whether a scan would be accepted. "
    "Nothing is stored.",
)
async def check_target(body: TargetCheckIn, user: AnalystUser) -> TargetCheckOut:
    probe = _probe(body)
    try:
        hosts = target_hosts(probe)
    except ValueError as exc:
        raise UnprocessableEntity(str(exc), code="target.invalid_url") from exc
    resolved = await resolve_hosts([h.host for h in hosts])
    code: str | None = None
    reason: str | None = None
    accepted = True
    try:
        check_allowlist(probe, resolved=resolved)
    except Problem as exc:
        accepted, code, reason = False, exc.code, str(exc.detail or exc)
    return TargetCheckOut(
        url=str(body.locator).strip(),
        hosts=[
            HostCheckOut(host=h.host, port=h.port, scheme=h.scheme, addresses=list(resolved.get(h.host, [])))
            for h in hosts
        ],
        allowlist_configured=bool(parse_cidrs(get_settings().dast_cidrs)),
        allowed=accepted,
        code=code,
        reason=reason,
        modes=allowed_modes(body.environment, has_login=body.has_login_profile),
    )


def _probe(body: TargetCheckIn) -> Any:
    import types

    return types.SimpleNamespace(
        kind=TargetKind.URL,
        locator=body.locator,
        api_spec_locator=body.api_spec_locator,
        host_approved=body.host_approved,
    )


# --------------------------------------------------------------------------- what a target may run
class ScanOption(BaseModel):
    profile: str
    version: int
    mode: str
    tools: list[str]
    allowed: bool
    code: str | None = None
    reason: str | None = None


class ScanOptionsOut(BaseModel):
    target_id: uuid.UUID
    environment: TargetEnvironment | None
    default_profile: str | None
    options: list[ScanOption]


async def _target_context(db: DbSession, target_id: uuid.UUID) -> tuple[Target, ApplicationVersion, Application]:
    target = await get_or_404(db, Target, target_id, "Target")
    if target.kind != TargetKind.URL:
        raise UnprocessableEntity("This target is not a web address.", code="scan.target_kind_mismatch")
    version = await get_or_404(db, ApplicationVersion, target.version_id, "Version")
    application = await get_or_404(db, Application, version.application_id, "Application")
    return target, version, application


@router.get(
    "/dast/targets/{target_id}/options",
    response_model=ScanOptionsOut,
    summary="The web scan profiles a target accepts, with the rule that forbids the others",
)
async def target_options(target_id: uuid.UUID, db: DbSession, user: AnalystUser) -> ScanOptionsOut:
    target, _version, application = await _target_context(db, target_id)
    rows = (
        await db.scalars(
            select(ScanProfile)
            .where(ScanProfile.kind == "dast", ScanProfile.active.is_(True))
            .order_by(ScanProfile.name, ScanProfile.version.desc())
        )
    ).all()
    newest: dict[str, ScanProfile] = {}
    for row in rows:
        newest.setdefault(row.name, row)
    options: list[ScanOption] = []
    for name in sorted(newest):
        row = newest[name]
        try:
            doc = ProfileDoc.model_validate(row.body)
        except Exception:  # noqa: BLE001 - a damaged stored profile is skipped, not fatal
            continue
        allowed, code, reason = True, None, None
        try:
            await check_scan_allowed_async(doc, [target], application=application)
        except Problem as exc:
            allowed, code, reason = False, exc.code, str(exc.detail or exc)
        options.append(
            ScanOption(
                profile=name,
                version=row.version,
                mode=str(doc.mode),
                tools=list(doc.tools),
                allowed=allowed,
                code=code,
                reason=reason,
            )
        )
    return ScanOptionsOut(
        target_id=target.id,
        environment=target.environment,
        default_profile=DEFAULT_PROFILE.get(target.environment) if target.environment else None,
        options=options,
    )


# --------------------------------------------------------------------------- start
class DastScanCreate(BaseModel):
    profile: str | None = Field(
        default=None,
        min_length=2,
        max_length=100,
        description="dast-baseline, dast-full or dast-api; default by environment",
    )
    profile_version: int | None = Field(default=None, ge=1)
    options: dict[str, Any] = Field(default_factory=dict)


@router.post(
    "/dast/targets/{target_id}/scans",
    response_model=ScanDetail,
    status_code=202,
    summary="Start a web scan of a target",
    description="Production targets accept dast-baseline only: anything else is a 403 problem that names "
    "the rule. Web scans run one at a time; a second scan waits in the queue.",
)
async def start_dast_scan(
    target_id: uuid.UUID,
    body: DastScanCreate,
    request: Request,
    response: Response,
    db: DbSession,
    user: AnalystUser,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> ScanDetail:
    target, version, _application = await _target_context(db, target_id)
    if target.environment is None:
        raise UnprocessableEntity(
            "This web address has no environment tag. Tag it production or uat first.",
            code="target.environment_required",
        )
    profile = body.profile or DEFAULT_PROFILE[target.environment]
    key = f"{user.id}:{check_idempotency_key(idempotency_key)}" if idempotency_key else None
    result = await create_scan_result(
        db,
        version_id=version.id,
        profile_name=profile,
        trigger=ScanTrigger.USER,
        requested_by=user,
        target_ids=[target.id],
        options=body.options,
        idempotency_key=key,
        profile_version=body.profile_version,
    )
    detail = await load_detail(db, result.scan, replayed=result.replayed, collapsed=result.collapsed)
    await db.commit()
    if result.replayed:
        response.headers["Idempotent-Replayed"] = "true"
    if result.collapsed:
        response.headers["X-Scan-Collapsed"] = "true"
    return detail


# --------------------------------------------------------------------------- login profiles
class LoginProfileIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    settings: LoginSettings
    username: SecretStr | None = None
    password: SecretStr | None = None
    totp_secret: SecretStr | None = None
    header_value: SecretStr | None = None
    expires_at: datetime | None = Field(default=None, description="When the account or token expires")
    application_id: uuid.UUID | None = None
    version_id: uuid.UUID | None = None


class LoginProfileOut(ORMModel):
    id: uuid.UUID
    name: str
    method: str
    verification_method: str | None
    application_id: uuid.UUID | None
    version_id: uuid.UUID | None
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


def _login_out(credential: Credential) -> LoginProfileOut:
    extra = credential.extra or {}
    return LoginProfileOut(
        id=credential.id,
        name=credential.name,
        method=str(extra.get("method", "")),
        verification_method=extra.get("verification_method"),
        application_id=credential.application_id,
        version_id=credential.version_id,
        expires_at=credential.expires_at,
        last_used_at=credential.last_used_at,
        revoked_at=credential.revoked_at,
        created_at=credential.created_at,
    )


def _plain(value: SecretStr | None) -> str | None:
    return value.get_secret_value() if value is not None else None


@router.post(
    "/dast/login-profiles",
    response_model=LoginProfileOut,
    status_code=201,
    summary="Store a login profile for web scans of UAT targets",
    description="Form, JSON, header-token or browser login. The user name, password, one-time code seed "
    "and token are encrypted and never returned. A verification (how to tell a logged-in session) is mandatory.",
)
async def create_login_profile(
    body: LoginProfileIn, request: Request, db: DbSession, user: AnalystUser
) -> LoginProfileOut:
    secret = LoginSecret(
        username=_plain(body.username),
        password=_plain(body.password),
        totp_secret=_plain(body.totp_secret),
        header_value=_plain(body.header_value),
    )
    try:
        secret.check_for(body.settings)
    except ValueError as exc:
        raise UnprocessableEntity(str(exc), code="dast_login.secret_incomplete") from exc
    if body.version_id is not None:
        await get_or_404(db, ApplicationVersion, body.version_id, "Version")
    if body.application_id is not None:
        await get_or_404(db, Application, body.application_id, "Application")
    now = utcnow()
    if body.expires_at is not None and body.expires_at <= now:
        raise UnprocessableEntity("The expiry date is in the past.", code="dast_login.expired")
    credential = await store_credential(
        db,
        kind=CredentialKind.DAST_LOGIN,
        name=body.name,
        secret=secret.to_json(),
        expires_at=body.expires_at,
        application_id=body.application_id,
        version_id=body.version_id,
        extra=body.settings.model_dump(mode="json", exclude_none=True),
        created_by_id=user.id,
    )
    await record_audit(
        db,
        user,
        "dast_login.create",
        "credential",
        credential.id,
        {"name": body.name, "method": body.settings.method},
        request,
    )
    await db.commit()
    return _login_out(credential)


@router.get(
    "/dast/login-profiles",
    response_model=CursorPage[LoginProfileOut],
    summary="List login profiles (without secrets)",
)
async def list_login_profiles(
    db: DbSession, user: AnalystUser, page: PageDep, include_revoked: bool = False
) -> CursorPage[LoginProfileOut]:
    stmt = select(Credential).where(Credential.kind == CredentialKind.DAST_LOGIN)
    if not include_revoked:
        stmt = stmt.where(Credential.revoked_at.is_(None))
    result = await paginate(db, stmt, key=[Credential.created_at, Credential.id], params=page, descending=True)
    return CursorPage(items=[_login_out(c) for c in result.items], next_cursor=result.next_cursor)


@router.delete(
    "/dast/login-profiles/{profile_id}",
    response_model=LoginProfileOut,
    summary="Revoke a login profile",
    description="Targets that still refer to it fail their next web scan with a clear reason.",
)
async def revoke_login_profile(
    profile_id: uuid.UUID, request: Request, db: DbSession, user: AnalystUser
) -> LoginProfileOut:
    credential = await get_or_404(db, Credential, profile_id, "Login profile")
    if credential.kind != CredentialKind.DAST_LOGIN:
        raise NotFound("Login profile not found", code="login_profile.not_found")
    if credential.revoked_at is None:
        credential.revoked_at = utcnow()
        credential.updated_at = utcnow()
        await record_audit(db, user, "dast_login.revoke", "credential", credential.id, {"name": credential.name}, request)
    await db.commit()
    return _login_out(credential)

