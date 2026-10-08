"""Encrypted credentials: store, read, and the expiry alerts.

``store_credential`` encrypts with ``securescan.security.secrets`` using the credential id as
context, so a ciphertext copied to another row no longer decrypts. Plaintext secrets exist only in
memory, only inside the code that needs them (never on a command line, never in a log).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import get_settings
from securescan.db.models.credentials import Credential
from securescan.db.models.enums import CredentialKind
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.logging import get_logger
from securescan.observability.metrics import CREDENTIALS_EXPIRING
from securescan.security.secrets import current_key_id, decrypt_secret, encrypt_secret
from securescan.util import new_id, utcnow

log = get_logger(__name__)


def credential_context(credential_id: uuid.UUID) -> str:
    return f"credential:{credential_id}"


async def store_credential(
    session: AsyncSession,
    *,
    kind: CredentialKind,
    name: str,
    secret: str,
    expires_at: datetime | None = None,
    public_material: str | None = None,
    application_id: uuid.UUID | None = None,
    version_id: uuid.UUID | None = None,
    extra: dict[str, Any] | None = None,
    created_by_id: uuid.UUID | None = None,
) -> Credential:
    """Encrypt ``secret`` and add the Credential row (no commit)."""
    credential_id = new_id()
    row = Credential(
        id=credential_id,
        kind=kind,
        name=name,
        ciphertext=encrypt_secret(secret, credential_context(credential_id)),
        key_id=current_key_id(),
        public_material=public_material,
        application_id=application_id,
        version_id=version_id,
        extra=extra or {},
        expires_at=expires_at,
        created_by_id=created_by_id,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    session.add(row)
    await session.flush()
    return row


def reveal_secret(credential: Credential) -> str:
    """Decrypt a credential's secret. Call only where the secret is used."""
    return decrypt_secret(credential.ciphertext, credential_context(credential.id))


async def get_active_credential_by_kind(
    session: AsyncSession, kind: CredentialKind
) -> Credential | None:
    """The newest non-revoked credential of a kind (service tokens such as the NVD key)."""
    return await session.scalar(
        select(Credential)
        .where(Credential.kind == kind, Credential.revoked_at.is_(None))
        .order_by(Credential.created_at.desc())
        .limit(1)
    )


async def expiring_credentials(
    session: AsyncSession, *, days: int | None = None, now: datetime | None = None
) -> list[Credential]:
    """Credentials that expire within ``days`` (default 14) and are not revoked."""
    window = days if days is not None else get_settings().credential_expiry_alert_days
    horizon = (now or utcnow()) + timedelta(days=window)
    rows = await session.scalars(
        select(Credential)
        .where(
            Credential.revoked_at.is_(None),
            Credential.expires_at.is_not(None),
            Credential.expires_at <= horizon,
        )
        .order_by(Credential.expires_at)
    )
    return list(rows.all())


async def run_expiry_alerts(session: AsyncSession) -> int:
    """Set the gauge and write one audit notice per expiring credential (once each).

    Admins see the notices in the audit log (action ``credential.expiring``) and on the health page.
    Returns the number of credentials in the alert window.
    """
    rows = await expiring_credentials(session)
    CREDENTIALS_EXPIRING.set(len(rows))
    now = utcnow()
    for credential in rows:
        if credential.expiry_alert_sent_at is not None:
            continue
        credential.expiry_alert_sent_at = now
        await record_audit(
            session,
            SYSTEM_ACTOR,
            "credential.expiring",
            "credential",
            credential.id,
            {
                "kind": credential.kind.value,
                "name": credential.name,
                "expires_at": credential.expires_at.isoformat() if credential.expires_at else None,
            },
        )
        log.warning(
            "credential_expiring", credential_id=str(credential.id), kind=credential.kind.value
        )
    return len(rows)
