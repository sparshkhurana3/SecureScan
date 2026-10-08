"""Vendor access credentials: deploy keys and vendor-issued tokens for ``vendor_repo`` targets.

* ``POST /credentials/deploy-key`` generates an ed25519 key pair for a vendor repository target, stores
  the private key encrypted and returns the public key for the vendor to add as a read-only deploy key.
* ``POST /credentials/vendor-token`` stores a token the vendor issued (fine-grained, Contents: read)
  together with its expiry date.

A credential belongs to one application version (one assessment). Secrets are never returned, logged
or written to audit details; the private key is shown to nobody.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Annotated

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Query, Request, Response
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import Conflict, NotFound, UnprocessableEntity
from securescan.api.schemas import ORMModel
from securescan.auth.roles import AnalystUser
from securescan.db.models.applications import Application
from securescan.db.models.credentials import Credential
from securescan.db.models.enums import AppType, CredentialKind, TargetKind
from securescan.db.models.targets import Target
from securescan.db.models.versions import ApplicationVersion
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain.audit import record_audit
from securescan.domain.credentials import store_credential
from securescan.util import ensure_utc, utcnow

router = APIRouter(tags=["credentials"])

VENDOR_KINDS = (CredentialKind.DEPLOY_KEY, CredentialKind.VENDOR_TOKEN)
MAX_TOKEN_LENGTH = 1024
MIN_TOKEN_LENGTH = 20
MAX_TOKEN_LIFETIME = timedelta(days=366 * 2)


# --------------------------------------------------------------------------- key generation
def _ssh_fingerprint(public_line: str) -> str:
    """``SHA256:...`` fingerprint of an OpenSSH public key line, as GitHub shows it."""
    blob = base64.b64decode(public_line.split()[1])
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    return "SHA256:" + digest.rstrip("=")


def generate_deploy_key(comment: str) -> tuple[str, str, str]:
    """A new ed25519 key pair: (private key in OpenSSH PEM, public key line, fingerprint).

    The public line is ``ssh-ed25519 <base64> <comment>``, the format GitHub's "Add deploy key" takes.
    """
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode("ascii")
    public_line = (
        private.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode("ascii")
    )
    safe_comment = "".join(ch for ch in comment if ch.isalnum() or ch in "-_.@:")[:80]
    if safe_comment:
        public_line = "%s %s" % (public_line, safe_comment)
    return private_pem, public_line, _ssh_fingerprint(public_line)


# --------------------------------------------------------------------------- models
class CredentialOut(ORMModel):
    """Metadata of a credential. The secret is never part of it."""

    id: uuid.UUID
    kind: CredentialKind
    name: str
    target_id: uuid.UUID | None = None
    application_id: uuid.UUID | None
    version_id: uuid.UUID | None
    public_key: str | None = None
    fingerprint: str | None = None
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class DeployKeyIn(BaseModel):
    target_id: uuid.UUID
    replace: bool = Field(
        default=False, description="Revoke the target's current credential and create a new one"
    )


class DeployKeyOut(CredentialOut):
    instructions: str


class VendorTokenIn(BaseModel):
    target_id: uuid.UUID
    token: SecretStr
    expires_at: datetime = Field(description="When the vendor's token expires (required)")
    replace: bool = False

    @field_validator("token")
    @classmethod
    def _token_shape(cls, value: SecretStr) -> SecretStr:
        text = value.get_secret_value()
        if not (MIN_TOKEN_LENGTH <= len(text) <= MAX_TOKEN_LENGTH) or any(
            ch.isspace() or not ch.isprintable() for ch in text
        ):
            raise ValueError("The token must be 20 to 1024 characters with no spaces or line breaks")
        return value


def _credential_out(credential: Credential) -> CredentialOut:
    extra = credential.extra or {}
    raw_target = extra.get("target_id")
    return CredentialOut(
        id=credential.id,
        kind=credential.kind,
        name=credential.name,
        target_id=uuid.UUID(str(raw_target)) if raw_target else None,
        application_id=credential.application_id,
        version_id=credential.version_id,
        public_key=credential.public_material if credential.kind == CredentialKind.DEPLOY_KEY else None,
        fingerprint=extra.get("fingerprint"),
        expires_at=credential.expires_at,
        last_used_at=credential.last_used_at,
        revoked_at=credential.revoked_at,
        created_at=credential.created_at,
    )


async def _vendor_target(db: DbSession, target_id: uuid.UUID) -> tuple[Target, ApplicationVersion, Application]:
    target = await get_or_404(db, Target, target_id, "Target")
    if target.kind != TargetKind.VENDOR_REPO:
        raise UnprocessableEntity(
            "Deploy keys and vendor tokens are for vendor repository targets", code="credential.target_kind"
        )
    if target.archived_at is not None:
        raise UnprocessableEntity("This target is archived", code="credential.target_archived")
    version = await get_or_404(db, ApplicationVersion, target.version_id, "Version")
    application = await get_or_404(db, Application, version.application_id, "Application")
    if application.type != AppType.VENDOR:
        raise UnprocessableEntity(
            "Vendor access belongs to vendor applications", code="credential.not_vendor_application"
        )
    return target, version, application


async def _current_credential(db: DbSession, target: Target) -> Credential | None:
    if target.credential_id is None:
        return None
    current = await db.get(Credential, target.credential_id)
    if current is None or current.revoked_at is not None:
        return None
    return current


async def _retire_current(db: DbSession, target: Target, replace: bool) -> Credential | None:
    """Revoke the target's current vendor credential when ``replace``; refuse when not."""
    current = await _current_credential(db, target)
    if current is None or current.kind not in VENDOR_KINDS:
        return None
    if not replace:
        raise Conflict(
            "This target already has a %s. Send replace=true to revoke it and create a new one."
            % ("deploy key" if current.kind == CredentialKind.DEPLOY_KEY else "vendor token"),
            code="credential.exists",
        )
    current.revoked_at = utcnow()
    return current


INSTRUCTIONS = (
    "Ask the vendor to add this public key to the repository as a deploy key: Settings, Deploy keys, "
    "Add deploy key, paste the key, leave 'Allow write access' unticked. The vendor's organisation may "
    "first need to allow deploy keys."
)


# --------------------------------------------------------------------------- endpoints
@router.post(
    "/credentials/deploy-key",
    response_model=DeployKeyOut,
    status_code=201,
    summary="Generate a read-only deploy key for a vendor repository",
)
async def create_deploy_key(
    body: DeployKeyIn, request: Request, db: DbSession, user: AnalystUser
) -> DeployKeyOut:
    target, version, application = await _vendor_target(db, body.target_id)
    revoked = await _retire_current(db, target, body.replace)
    private_pem, public_line, fingerprint = generate_deploy_key("securescan-%s" % target.id)
    credential = await store_credential(
        db,
        kind=CredentialKind.DEPLOY_KEY,
        name=("Deploy key for %s (%s)" % (application.name, target.locator))[:200],
        secret=private_pem,
        public_material=public_line,
        application_id=application.id,
        version_id=version.id,
        extra={"target_id": str(target.id), "fingerprint": fingerprint, "algorithm": "ed25519"},
        created_by_id=user.id,
    )
    del private_pem
    target.credential_id = credential.id
    target.updated_at = utcnow()
    await record_audit(
        db,
        user,
        "credential.deploy_key_create",
        "credential",
        credential.id,
        {
            "target_id": str(target.id),
            "version_id": str(version.id),
            "fingerprint": fingerprint,
            "replaced": str(revoked.id) if revoked else None,
        },
        request,
    )
    await db.commit()
    out = _credential_out(credential)
    return DeployKeyOut(**out.model_dump(), instructions=INSTRUCTIONS)


@router.post(
    "/credentials/vendor-token",
    response_model=CredentialOut,
    status_code=201,
    summary="Store a token issued by the vendor",
)
async def create_vendor_token(
    body: VendorTokenIn, request: Request, db: DbSession, user: AnalystUser
) -> CredentialOut:
    target, version, application = await _vendor_target(db, body.target_id)
    now = utcnow()
    expires_at = ensure_utc(body.expires_at)
    if expires_at <= now:
        raise UnprocessableEntity("The token's expiry date is in the past", code="credential.expired")
    if expires_at - now > MAX_TOKEN_LIFETIME:
        raise UnprocessableEntity(
            "The expiry date is more than two years away; check it", code="credential.expiry_too_far"
        )
    revoked = await _retire_current(db, target, body.replace)
    credential = await store_credential(
        db,
        kind=CredentialKind.VENDOR_TOKEN,
        name=("Vendor token for %s (%s)" % (application.name, target.locator))[:200],
        secret=body.token.get_secret_value(),
        expires_at=expires_at,
        application_id=application.id,
        version_id=version.id,
        extra={"target_id": str(target.id)},
        created_by_id=user.id,
    )
    target.credential_id = credential.id
    target.updated_at = now
    await record_audit(
        db,
        user,
        "credential.vendor_token_create",
        "credential",
        credential.id,
        {
            "target_id": str(target.id),
            "version_id": str(version.id),
            "expires_at": expires_at.isoformat(),
            "replaced": str(revoked.id) if revoked else None,
        },
        request,
    )
    await db.commit()
    return _credential_out(credential)


@router.get(
    "/credentials",
    response_model=CursorPage[CredentialOut],
    summary="List vendor deploy keys and tokens (metadata only)",
)
async def list_credentials(
    db: DbSession,
    user: AnalystUser,
    page: PageDep,
    version_id: uuid.UUID | None = None,
    application_id: uuid.UUID | None = None,
    kind: Annotated[CredentialKind | None, Query(description="deploy_key or vendor_token")] = None,
    include_revoked: bool = False,
) -> CursorPage[CredentialOut]:
    if kind is not None and kind not in VENDOR_KINDS:
        raise UnprocessableEntity(
            "Only deploy keys and vendor tokens can be listed here", code="credential.kind_not_listed"
        )
    stmt = select(Credential).where(Credential.kind.in_(VENDOR_KINDS))
    if kind is not None:
        stmt = stmt.where(Credential.kind == kind)
    if version_id is not None:
        stmt = stmt.where(Credential.version_id == version_id)
    if application_id is not None:
        stmt = stmt.where(Credential.application_id == application_id)
    if not include_revoked:
        stmt = stmt.where(Credential.revoked_at.is_(None))
    result = await paginate(db, stmt, key=[Credential.created_at, Credential.id], params=page)
    return CursorPage(
        items=[_credential_out(c) for c in result.items], next_cursor=result.next_cursor
    )


@router.delete(
    "/credentials/{credential_id}",
    status_code=204,
    summary="Revoke a vendor deploy key or token",
)
async def revoke_credential(
    credential_id: uuid.UUID, request: Request, db: DbSession, user: AnalystUser
) -> Response:
    credential = await get_or_404(db, Credential, credential_id, "Credential")
    if credential.kind not in VENDOR_KINDS:
        raise NotFound("Credential not found", code="credential.not_found")
    if credential.revoked_at is None:
        credential.revoked_at = utcnow()
        targets = await db.scalars(select(Target).where(Target.credential_id == credential.id))
        for target in targets.all():
            target.credential_id = None
            target.updated_at = utcnow()
        await record_audit(
            db,
            user,
            "credential.revoke",
            "credential",
            credential.id,
            {"kind": credential.kind.value},
            request,
        )
        await db.commit()
    return Response(status_code=204)
