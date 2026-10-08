"""More credential alerts on top of the 14-day expiry notice (hook of ``credential_expiry_alerts``).

``domain/credentials.run_expiry_alerts`` (M2) already writes one ``credential.expiring`` audit event
per credential 14 days before it expires. This hook adds two notices that matter for vendor access,
each written once per credential (Admins see them in the audit log and on the health page):

* ``credential.expired``: the credential's expiry date has passed and it is not revoked.
* ``credential.unused_warning``: a deploy key or vendor token has not been used for 11 months. GitHub
  removes deploy keys and tokens that stay unused for a year, so a yearly re-assessment should expect
  to re-establish access.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.db.models.audit import AuditEvent
from securescan.db.models.credentials import Credential
from securescan.db.models.enums import CredentialKind
from securescan.db.session import session_scope
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.jobs.hooks import periodic_hook
from securescan.logging import get_logger
from securescan.util import ensure_utc, utcnow

log = get_logger(__name__)

UNUSED_WARNING_DAYS = 335  # 11 months; GitHub removes keys and tokens unused for a year
UNUSED_KINDS = (CredentialKind.DEPLOY_KEY, CredentialKind.VENDOR_TOKEN)


def has_expired(expires_at: datetime | None, revoked_at: datetime | None, now: datetime) -> bool:
    return expires_at is not None and revoked_at is None and ensure_utc(expires_at) <= now


def is_unused_too_long(
    kind: CredentialKind,
    created_at: datetime,
    last_used_at: datetime | None,
    revoked_at: datetime | None,
    now: datetime,
) -> bool:
    """True for a deploy key or vendor token whose last use (or creation) is 335 days ago or more."""
    if kind not in UNUSED_KINDS or revoked_at is not None:
        return False
    reference = ensure_utc(last_used_at or created_at)
    return now - reference >= timedelta(days=UNUSED_WARNING_DAYS)


async def _already_alerted(session: AsyncSession, action: str, ids: list[str]) -> set[str]:
    if not ids:
        return set()
    rows = await session.scalars(
        select(AuditEvent.object_id).where(
            AuditEvent.action == action, AuditEvent.object_id.in_(ids)
        )
    )
    return {str(r) for r in rows.all() if r is not None}


async def alert_expired(session: AsyncSession, now: datetime) -> int:
    rows = (
        await session.scalars(
            select(Credential).where(
                Credential.revoked_at.is_(None),
                Credential.expires_at.is_not(None),
                Credential.expires_at <= now,
            )
        )
    ).all()
    done = await _already_alerted(session, "credential.expired", [str(c.id) for c in rows])
    count = 0
    for credential in rows:
        if str(credential.id) in done:
            continue
        await record_audit(
            session,
            SYSTEM_ACTOR,
            "credential.expired",
            "credential",
            credential.id,
            {
                "kind": credential.kind.value,
                "name": credential.name,
                "expired_at": credential.expires_at.isoformat() if credential.expires_at else None,
            },
        )
        count += 1
    return count


async def alert_unused(session: AsyncSession, now: datetime) -> int:
    cutoff = now - timedelta(days=UNUSED_WARNING_DAYS)
    rows = (
        await session.scalars(
            select(Credential).where(
                Credential.kind.in_(UNUSED_KINDS),
                Credential.revoked_at.is_(None),
                Credential.created_at <= cutoff,
            )
        )
    ).all()
    candidates = [
        c
        for c in rows
        if is_unused_too_long(c.kind, c.created_at, c.last_used_at, c.revoked_at, now)
    ]
    done = await _already_alerted(session, "credential.unused_warning", [str(c.id) for c in candidates])
    count = 0
    for credential in candidates:
        if str(credential.id) in done:
            continue
        await record_audit(
            session,
            SYSTEM_ACTOR,
            "credential.unused_warning",
            "credential",
            credential.id,
            {
                "kind": credential.kind.value,
                "name": credential.name,
                "last_used_at": credential.last_used_at.isoformat() if credential.last_used_at else None,
            },
        )
        count += 1
    return count


@periodic_hook("credential_expiry_alerts")
async def credential_extra_alerts(timestamp: int) -> None:
    now = utcnow()
    async with session_scope() as session:
        expired = await alert_expired(session, now)
        unused = await alert_unused(session, now)
    log.info("credential_extra_alerts", expired=expired, unused=unused)
