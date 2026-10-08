"""DefectDojo accounts for SecureScan users (design, "Accounts and access").

Open-source DefectDojo has no single sign-on, so the first time an Admin or Analyst signs in to
SecureScan a matching local DefectDojo user is created through the API with the ``securescan-accounts``
(superuser) token: Admins as superusers, Analysts as staff users (staff sees every Asset). The random
initial password is stored encrypted, shown once in the portal, and DefectDojo is told to demand a new
one at first login. DefectDojo itself is only reachable through the gateway, which requires a valid
SecureScan session, so losing Entra access removes access to DefectDojo's login page as well.

Also here: disabling and re-enabling accounts (Admin action, and automatically after 90 days without
sign-in), and detection of break-glass use of DefectDojo's built-in ``admin`` account.
"""

from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.auth.hooks import on_login
from securescan.config import get_settings
from securescan.db.models.audit import AuditEvent
from securescan.db.models.enums import UserRole
from securescan.db.models.users import User
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.integrations.defectdojo.client import (
    DefectDojoClient,
    DefectDojoError,
    DefectDojoNotFound,
)
from securescan.integrations.defectdojo.factory import DefectDojoNotConfigured, accounts_client
from securescan.logging import get_logger
from securescan.observability.metrics import BREAK_GLASS_LOGINS
from securescan.security.secrets import decrypt_secret, encrypt_secret
from securescan.util import ensure_utc, utcnow

log = get_logger(__name__)

ACCOUNT_OBJECT = "defectdojo_account"
ADMIN_OBJECT = "defectdojo_admin"

RESERVED_USERNAMES = frozenset({"admin", "securescan-sync", "securescan-accounts"})
_USERNAME_INVALID = re.compile(r"[^A-Za-z0-9@.+_-]")
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_LOWER = "abcdefghijkmnopqrstuvwxyz"
_DIGITS = "23456789"
_SYMBOLS = "!#%*+-=?@_"

# Audit actions that explain why an account is disabled (used to decide on re-enabling at sign-in).
ACTION_DISABLE = "defectdojo_account.disable"
ACTION_EXPIRE = "defectdojo_account.expire"
ACTION_ENABLE = "defectdojo_account.enable"


def generate_password(length: int = 20) -> str:
    """A random password with at least one upper-case letter, lower-case letter, digit and symbol
    (DefectDojo's validators), without look-alike characters. Uses ``secrets`` only."""
    if length < 12:
        raise ValueError("a generated password needs at least 12 characters")
    pools = (_UPPER, _LOWER, _DIGITS, _SYMBOLS)
    alphabet = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def username_candidate(user: User) -> str:
    """DefectDojo user name: the local part of the Entra UPN (else the e-mail, else a short id),
    lower case, reduced to the characters Django allows."""
    source = user.upn or user.email or ""
    local = source.split("@", 1)[0] if "@" in source else source
    cleaned = _USERNAME_INVALID.sub("_", local.strip().lower())[:140].strip("._-")
    return cleaned or f"user-{user.oid[:8].lower()}"


def split_name(name: str | None) -> tuple[str, str]:
    parts = (name or "").split()
    if not parts:
        return "", ""
    return parts[0][:150], " ".join(parts[1:])[:150]


def desired_flags(role: UserRole) -> dict[str, bool]:
    """Admins are superusers; every user is staff (staff sees all Assets)."""
    return {"is_superuser": role == UserRole.ADMIN, "is_staff": True}


async def unique_username(session: AsyncSession, user: User) -> str:
    """The candidate name, with a short suffix when another SecureScan user already holds it or it is
    one of the service names."""
    candidate = username_candidate(user)
    taken = await session.scalar(
        select(User.id).where(User.dd_username == candidate, User.id != user.id).limit(1)
    )
    if candidate in RESERVED_USERNAMES or taken is not None:
        return f"{candidate[:130]}-{user.oid.replace('-', '')[:6].lower()}"
    return candidate


@dataclass(frozen=True)
class AccountView:
    """What the portal shows about the signed-in user's DefectDojo account."""

    status: str  # ready | unavailable | disabled
    username: str | None
    login_url: str
    initial_password: str | None  # only on the first read
    password_shown: bool
    must_change_password: bool
    disabled: bool
    detail: str | None = None


def _remote_differs(remote: dict[str, Any], flags: dict[str, bool]) -> dict[str, bool]:
    return {k: v for k, v in flags.items() if bool(remote.get(k)) != v}


async def ensure_account(
    session: AsyncSession, client: DefectDojoClient, user: User, *, actor: Any = SYSTEM_ACTOR
) -> bool:
    """Create the DefectDojo account of ``user`` when there is none, otherwise bring its role flags
    in line with the user's role and re-enable it after an automatic expiry. Returns True when a new
    account was created. DefectDojo is called before the database is written, so a failure leaves
    nothing half-done in SecureScan (a user created in DefectDojo but not recorded is adopted at the
    next sign-in). No commit."""
    flags = desired_flags(user.role)
    if user.dd_user_id is not None:
        try:
            remote = await client.get_user(user.dd_user_id)
        except DefectDojoNotFound:
            log.warning("defectdojo_account_gone", user_id=str(user.id))
            user.dd_user_id = None
            user.dd_username = None
        else:
            await _sync_existing(session, client, user, remote, flags)
            return False

    username = await unique_username(session, user)
    existing = await client.find_user(username)
    if existing is not None and isinstance(existing.get("id"), int):
        # Created by hand, or by an earlier attempt that did not get to record it: link, do not touch
        # the password (it is not ours to know).
        user.dd_user_id = int(existing["id"])
        user.dd_username = username
        changes = _remote_differs(existing, flags)
        if changes:
            await client.patch_user(user.dd_user_id, changes)
        user.updated_at = utcnow()
        await record_audit(
            session, actor, "defectdojo_account.adopt", ACCOUNT_OBJECT, user.id,
            {"username": username, "changed": sorted(changes)},
        )
        return False

    password = generate_password()
    first, last = split_name(user.name)
    created = await client.create_user(
        username=username,
        password=password,
        email=user.email or user.upn or f"{username}@securescan.invalid",
        first_name=first,
        last_name=last,
        **flags,
    )
    user.dd_user_id = int(created["id"])
    user.dd_username = username
    user.dd_initial_secret = encrypt_secret(password, _secret_context(user))
    user.dd_secret_shown_at = None
    user.dd_disabled = False
    user.dd_disabled_at = None
    user.updated_at = utcnow()
    must_change = True
    try:
        await client.set_force_password_reset(user.dd_user_id)
    except DefectDojoError as exc:
        must_change = False
        log.warning("defectdojo_force_reset_failed", user_id=str(user.id), error=str(exc)[:200])
    await record_audit(
        session, actor, "defectdojo_account.create", ACCOUNT_OBJECT, user.id,
        {
            "username": username,
            "role": user.role.value,
            "superuser": flags["is_superuser"],
            "forced_change": must_change,  # (a key with "password" in it would be masked)
        },
    )
    return True


def _secret_context(user: User) -> str:
    return f"user-dd:{user.id}"


async def last_disable_reason(session: AsyncSession, user_id: uuid.UUID) -> str | None:
    """``expire`` when the latest enable/disable event of the account was the automatic expiry,
    ``disable`` for an Admin's disable, None when there is none."""
    action = await session.scalar(
        select(AuditEvent.action)
        .where(
            AuditEvent.object_type == ACCOUNT_OBJECT,
            AuditEvent.object_id == str(user_id),
            AuditEvent.action.in_([ACTION_DISABLE, ACTION_EXPIRE, ACTION_ENABLE]),
        )
        .order_by(AuditEvent.created_at.desc())
        .limit(1)
    )
    if action == ACTION_EXPIRE:
        return "expire"
    if action == ACTION_DISABLE:
        return "disable"
    return None


async def _sync_existing(
    session: AsyncSession,
    client: DefectDojoClient,
    user: User,
    remote: dict[str, Any],
    flags: dict[str, bool],
) -> None:
    changes: dict[str, bool] = _remote_differs(remote, flags)
    reenable = False
    if user.dd_disabled and await last_disable_reason(session, user.id) == "expire":
        # The person is signing in again, so the account was not abandoned: undo the automatic expiry.
        reenable = True
        changes["is_active"] = True
    if changes and user.dd_user_id is not None:
        await client.patch_user(user.dd_user_id, changes)
        await record_audit(
            session, SYSTEM_ACTOR, "defectdojo_account.update", ACCOUNT_OBJECT, user.id,
            {"changed": sorted(changes), "role": user.role.value},
        )
    if reenable:
        user.dd_disabled = False
        user.dd_disabled_at = None
        user.updated_at = utcnow()
        await record_audit(
            session, SYSTEM_ACTOR, ACTION_ENABLE, ACCOUNT_OBJECT, user.id,
            {"reason": "signed in again after automatic expiry"},
        )


@on_login
async def provision_defectdojo_account(db: AsyncSession, user: User) -> None:
    """After-sign-in hook: create or update the user's DefectDojo account. Failures (DefectDojo down,
    ``dojo-init`` not finished) are logged by the hook runner and never block sign-in; the portal's
    account page retries."""
    try:
        client = await accounts_client(db, quick=True)
    except DefectDojoNotConfigured as exc:
        log.warning("defectdojo_provisioning_skipped", reason=str(exc)[:200])
        return
    try:
        await ensure_account(db, client, user)
    finally:
        await client.aclose()


# --- the signed-in user's account page ---------------------------------------------------------------------


async def read_account(session: AsyncSession, user: User) -> AccountView:
    """State for ``GET /me/defectdojo-account``. Tries to provision a missing account; returns the
    initial password once (it is cleared as it is read)."""
    settings = get_settings()
    login_url = settings.defectdojo_public_url
    if user.dd_user_id is None:
        try:
            client = await accounts_client(session, quick=True)
            try:
                await ensure_account(session, client, user, actor=user)
            finally:
                await client.aclose()
        except (DefectDojoNotConfigured, DefectDojoError) as exc:
            log.warning("defectdojo_account_unavailable", error=str(exc)[:200])
            return AccountView(
                status="unavailable",
                username=None,
                login_url=login_url,
                initial_password=None,
                password_shown=False,
                must_change_password=False,
                disabled=False,
                detail="DefectDojo is not ready yet. Try again in a few minutes.",
            )
    initial: str | None = None
    if user.dd_initial_secret:
        initial = decrypt_secret(user.dd_initial_secret, _secret_context(user))
        user.dd_initial_secret = None
        user.dd_secret_shown_at = utcnow()
        await record_audit(
            session, user, "defectdojo_account.password_shown", ACCOUNT_OBJECT, user.id, {}
        )
    return AccountView(
        status="disabled" if user.dd_disabled else "ready",
        username=user.dd_username,
        login_url=login_url,
        initial_password=initial,
        password_shown=user.dd_secret_shown_at is not None,
        must_change_password=initial is not None,
        disabled=user.dd_disabled,
    )


class PasswordResetUnavailable(Exception):  # noqa: N818 - reads better than ...Error
    """DefectDojo refused to change the password through its API."""


async def reset_password(
    session: AsyncSession, client: DefectDojoClient, user: User, request: Any = None
) -> str:
    """Give the user a new random DefectDojo password, returned once (never stored). Raises
    ``PasswordResetUnavailable`` when DefectDojo does not let the API change passwords. No commit."""
    if user.dd_user_id is None:
        raise PasswordResetUnavailable("There is no DefectDojo account to reset yet.")
    password = generate_password()
    try:
        await client.set_user_password(user.dd_user_id, password)
    except DefectDojoNotFound as exc:
        raise PasswordResetUnavailable("The DefectDojo account no longer exists.") from exc
    except DefectDojoError as exc:
        raise PasswordResetUnavailable(
            "DefectDojo does not allow SecureScan to change this password. "
            "Ask an Admin to set a new one in DefectDojo (Users)."
        ) from exc
    user.dd_initial_secret = None
    user.dd_secret_shown_at = utcnow()
    try:
        await client.set_force_password_reset(user.dd_user_id)
    except DefectDojoError as exc:
        log.warning("defectdojo_force_reset_failed", user_id=str(user.id), error=str(exc)[:200])
    await record_audit(
        session, user, "defectdojo_account.reset", ACCOUNT_OBJECT, user.id, {}, request
    )
    return password


# --- disable, enable, expire -----------------------------------------------------------------------------------


async def set_account_active(
    session: AsyncSession,
    client: DefectDojoClient,
    user: User,
    *,
    active: bool,
    actor: Any,
    action: str,
    reason: str,
    request: Any = None,
) -> None:
    """Disable (``is_active=false``) or enable the user's DefectDojo account and record why. No commit."""
    if user.dd_user_id is None:
        raise LookupError("the user has no DefectDojo account")
    await client.patch_user(user.dd_user_id, {"is_active": active})
    now = utcnow()
    user.dd_disabled = not active
    user.dd_disabled_at = None if active else now
    user.updated_at = now
    await record_audit(
        session, actor, action, ACCOUNT_OBJECT, user.id,
        {"username": user.dd_username, "reason": reason},
        request,
    )


def last_activity(user: User) -> datetime:
    """When the account was last in use: the later of the last sign-in and the last change of the user
    row (an Admin re-enabling an account touches the row, which restarts the clock)."""
    moments = [ensure_utc(user.created_at)]
    if user.last_login is not None:
        moments.append(ensure_utc(user.last_login))
    if user.updated_at is not None:
        moments.append(ensure_utc(user.updated_at))
    return max(moments)


def is_expired(user: User, now: datetime, days: int) -> bool:
    """True for an enabled DefectDojo account whose user has been inactive for more than ``days``."""
    if user.dd_user_id is None or user.dd_disabled:
        return False
    return now - last_activity(user) > timedelta(days=days)


async def expire_inactive_accounts(
    session: AsyncSession, client: DefectDojoClient, *, now: datetime | None = None
) -> list[uuid.UUID]:
    """Disable the DefectDojo accounts of users who have not signed in for the configured number of
    days (default 90). A failure for one user is logged and that user is retried the next night.
    Returns the ids of the users disabled. No commit."""
    moment = now or utcnow()
    days = get_settings().defectdojo_account_expiry_days
    users = (
        await session.scalars(
            select(User).where(User.dd_user_id.is_not(None), User.dd_disabled.is_(False))
        )
    ).all()
    expired: list[uuid.UUID] = []
    for user in users:
        if not is_expired(user, moment, days):
            continue
        try:
            await set_account_active(
                session, client, user, active=False, actor=SYSTEM_ACTOR, action=ACTION_EXPIRE,
                reason=f"no sign-in for more than {days} days",
            )
        except DefectDojoNotFound:
            log.warning("defectdojo_account_gone", user_id=str(user.id))
            continue
        except DefectDojoError as exc:  # leave this one for tomorrow, carry on with the others
            log.warning("account_expiry_failed", user_id=str(user.id), error=str(exc)[:200])
            continue
        expired.append(user.id)
    return expired


# --- break-glass detection ---------------------------------------------------------------------------------------


async def _last_admin_login_seen(session: AsyncSession) -> str | None:
    event = await session.scalar(
        select(AuditEvent)
        .where(AuditEvent.object_type == ADMIN_OBJECT)
        .order_by(AuditEvent.created_at.desc())
        .limit(1)
    )
    if event is None:
        return None
    value = (event.detail or {}).get("last_login")
    return str(value) if value else ""


async def record_admin_baseline(session: AsyncSession, admin: dict[str, Any]) -> None:
    """``dojo-init`` calls this once: from now on only a *different* ``last_login`` of DefectDojo's
    ``admin`` user counts as break-glass use."""
    await record_audit(
        session, SYSTEM_ACTOR, "defectdojo.admin_baseline", ADMIN_OBJECT, "admin",
        {"last_login": admin.get("last_login") or ""},
    )


async def check_break_glass(session: AsyncSession, client: DefectDojoClient) -> bool:
    """True (with an audit event and the ``break_glass_logins`` metric) when DefectDojo's built-in
    ``admin`` account has signed in since the last check. Normal operation never uses it."""
    name = get_settings().defectdojo_admin_username
    admin = await client.find_user(name)
    if admin is None:
        return False
    current = admin.get("last_login") or ""
    seen = await _last_admin_login_seen(session)
    if seen is None and not current:
        await record_admin_baseline(session, admin)
        return False
    if seen is not None and seen == current:
        return False
    if not current:
        return False
    BREAK_GLASS_LOGINS.labels(tool="defectdojo").inc()
    log.warning("defectdojo_break_glass_login", username=name, last_login=current)
    await record_audit(
        session, SYSTEM_ACTOR, "defectdojo.break_glass_login", ADMIN_OBJECT, "admin",
        {"username": name, "last_login": current, "previous": seen or ""},
    )
    return True
