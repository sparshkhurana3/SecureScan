"""``python -m securescan dojo-init``: configure a fresh DefectDojo (plan M4 task 2).

Runs as a one-shot container after DefectDojo's ``uwsgi`` is up, and on every start of the stack. It
changes only what is missing, so restarts and upgrades are safe:

1. wait until the DefectDojo API answers;
2. log in once as the built-in ``admin`` (password from the ``dd_admin_password`` secret) and keep that
   token in memory only: it is never stored;
3. make sure the two service accounts exist, each with a token stored encrypted as a credential:
   ``securescan-sync`` (staff, imports and reads findings) and ``securescan-accounts`` (superuser,
   creates users and changes system settings; deviation 5 in the plan);
4. with the superuser token: turn deduplication on (off by default in DefectDojo) and create the two
   product types ``Internal Applications`` and ``Vendor Applications``;
5. note the ``admin`` account's ``last_login`` as the baseline for break-glass detection.

A service account's password is generated here, kept encrypted next to its token (so a revoked token
can be replaced) and never shown. The built-in ``admin`` account stays a break-glass account.
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import Settings, get_settings
from securescan.db.engine import dispose_engine
from securescan.db.models.enums import CredentialKind
from securescan.db.session import session_scope
from securescan.domain.accounts import _last_admin_login_seen, generate_password, record_admin_baseline
from securescan.domain.credentials import (
    get_active_credential_by_kind,
    reveal_secret,
    store_credential,
)
from securescan.integrations.defectdojo.client import (
    DefectDojoAuthError,
    DefectDojoClient,
    DefectDojoError,
    DefectDojoRejected,
    Sleep,
)
from securescan.integrations.defectdojo.mapping import PRODUCT_TYPES
from securescan.logging import get_logger
from securescan.security.secrets import decrypt_secret, encrypt_secret
from securescan.util import utcnow

log = get_logger(__name__)


class InitError(Exception):
    """Setup cannot continue; the message says what to do."""


@dataclass(frozen=True)
class ServiceAccount:
    username: str
    kind: CredentialKind
    is_staff: bool
    is_superuser: bool
    purpose: str


def service_accounts(settings: Settings) -> tuple[ServiceAccount, ServiceAccount]:
    return (
        ServiceAccount(
            settings.defectdojo_sync_username,
            CredentialKind.DEFECTDOJO_TOKEN,
            is_staff=True,
            is_superuser=False,
            purpose="import and read findings",
        ),
        ServiceAccount(
            settings.defectdojo_accounts_username,
            CredentialKind.DEFECTDOJO_ADMIN_TOKEN,
            is_staff=False,
            is_superuser=True,
            purpose="accounts and system settings",
        ),
    )


def password_context(credential_id: object) -> str:
    return f"credential-password:{credential_id}"


async def wait_for_defectdojo(
    base_url: str,
    seconds: float,
    *,
    interval: float = 5.0,
    transport: httpx.AsyncBaseTransport | None = None,
    sleep: Sleep | None = None,
) -> bool:
    """Poll ``GET /api/v2/`` until DefectDojo answers (any status below 500) or time runs out."""
    pause: Sleep = sleep or asyncio.sleep
    waited = 0.0
    async with DefectDojoClient(base_url, None, transport=transport, max_retries=0) as probe:
        while True:
            answers, status, _ = await probe.ping()
            if answers:
                log.info("defectdojo_answers", status=status, waited_seconds=int(waited))
                return True
            if waited >= seconds:
                return False
            await pause(interval)
            waited += interval


async def admin_token(
    settings: Settings,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    sleep: Sleep | None = None,
    attempts: int = 10,
) -> str:
    """Log in as DefectDojo's ``admin``. The account is created by DefectDojo's initializer, which
    finishes before ``uwsgi`` starts, but give it a little time."""
    pause: Sleep = sleep or asyncio.sleep
    last: Exception | None = None
    for _ in range(attempts):
        try:
            return await DefectDojoClient.obtain_token(
                settings.defectdojo_url,
                settings.defectdojo_admin_username,
                settings.defectdojo_admin_password,
                transport=transport,
                sleep=sleep,
            )
        except DefectDojoRejected as exc:
            last = exc
            await pause(6.0)
    raise InitError(
        "DefectDojo refused the admin login. Check that the secret dd_admin_password is the password "
        f"the initializer used ({last})."
    )


async def _token_profile(
    base_url: str, token: str, transport: httpx.AsyncBaseTransport | None
) -> dict[str, object] | None:
    """The user behind ``token`` (flags included), or None when the token is no longer valid."""
    async with DefectDojoClient(base_url, token, transport=transport, max_retries=2) as probe:
        try:
            return await probe.user_profile()
        except DefectDojoAuthError:
            return None


def _flags_differ(user: dict[str, object], account: ServiceAccount) -> dict[str, bool]:
    wanted = {"is_staff": account.is_staff, "is_superuser": account.is_superuser, "is_active": True}
    return {k: v for k, v in wanted.items() if bool(user.get(k)) != v}


async def ensure_service_account(
    session: AsyncSession,
    admin: DefectDojoClient,
    base_url: str,
    account: ServiceAccount,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    sleep: Sleep | None = None,
) -> tuple[str, list[str]]:
    """Make sure ``account`` exists in DefectDojo with a working token stored as a credential.

    Returns ``(token, changes)``; ``changes`` is empty when everything was already in place. No commit.
    """
    changes: list[str] = []
    credential = await get_active_credential_by_kind(session, account.kind)
    user = await admin.find_user(account.username)

    if credential is not None:
        token = reveal_secret(credential)
        profile = await _token_profile(base_url, token, transport)
        if profile is not None:
            wrong = _flags_differ(profile, account)
            if wrong and user is not None:
                await admin.patch_user(int(user["id"]), wrong)
                changes.append(f"corrected {account.username}: {', '.join(sorted(wrong))}")
            return token, changes
        log.warning("service_token_invalid", username=account.username)

    stored_password: str | None = None
    if credential is not None:
        envelope = (credential.extra or {}).get("password_enc")
        if isinstance(envelope, str):
            stored_password = decrypt_secret(envelope, password_context(credential.id))

    user_id: int
    if user is None:
        password = generate_password(32)
        created = await admin.create_user(
            username=account.username,
            password=password,
            email=f"{account.username}@securescan.invalid",
            first_name="SecureScan",
            last_name=account.username.replace("securescan-", "").title(),
            is_staff=account.is_staff,
            is_superuser=account.is_superuser,
        )
        user_id = int(created["id"])
        changes.append(f"created DefectDojo user {account.username} ({account.purpose})")
    else:
        if stored_password is None:
            raise InitError(
                f"The DefectDojo user {account.username} exists but SecureScan has no stored token "
                "or password for it (the SecureScan database was restored without it?). Delete the "
                f"user {account.username} in DefectDojo (Users) only if it owns no findings, or "
                "restore the credential from a backup, then run dojo-init again."
            )
        password = stored_password
        user_id = int(user["id"])
        wrong = _flags_differ(user, account)
        if wrong:
            await admin.patch_user(user_id, wrong)
            changes.append(f"corrected {account.username}: {', '.join(sorted(wrong))}")

    token = await DefectDojoClient.obtain_token(
        base_url, account.username, password, transport=transport, sleep=sleep
    )
    if credential is not None:
        credential.revoked_at = utcnow()
    stored = await store_credential(
        session,
        kind=account.kind,
        name=account.username,
        secret=token,
        extra={"username": account.username, "dd_user_id": user_id},
    )
    stored.extra = {
        **stored.extra,
        "password_enc": encrypt_secret(password, password_context(stored.id)),
    }
    changes.append(f"stored a token for {account.username}")
    return token, changes


async def ensure_deduplication(client: DefectDojoClient) -> list[str]:
    """Turn deduplication on in the system settings (off by default). Superuser token."""
    current = await client.system_settings()
    if current.get("enable_deduplication") is True:
        return []
    await client.patch_system_settings(int(current["id"]), {"enable_deduplication": True})
    return ["enabled deduplication in the system settings"]


async def ensure_product_types(client: DefectDojoClient) -> list[str]:
    """Create ``Internal Applications`` and ``Vendor Applications`` when missing."""
    changes: list[str] = []
    for name in PRODUCT_TYPES:
        if await client.product_types(name):
            continue
        await client.create_product_type(name, f"SecureScan: {name}")
        changes.append(f"created product type {name}")
    return changes


async def ensure_admin_baseline(
    session: AsyncSession, admin: DefectDojoClient, settings: Settings
) -> list[str]:
    """Remember the built-in admin's ``last_login`` once, so later sign-ins can be detected."""
    if await _last_admin_login_seen(session) is not None:
        return []
    found = await admin.find_user(settings.defectdojo_admin_username)
    if found is None:
        return []
    await record_admin_baseline(session, found)
    return ["recorded the break-glass baseline of the admin account"]


async def initialise(
    settings: Settings,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    sleep: Sleep | None = None,
) -> list[str]:
    """The whole setup; returns the list of changes (empty on a repeat run)."""
    if not settings.defectdojo_admin_password:
        raise InitError(
            "The DefectDojo admin password is not configured "
            "(SECURESCAN_DEFECTDOJO_ADMIN_PASSWORD_FILE should point at the dd_admin_password secret)."
        )
    base_url = settings.defectdojo_url
    if not await wait_for_defectdojo(
        base_url, settings.defectdojo_init_wait_seconds, transport=transport, sleep=sleep
    ):
        raise InitError(f"DefectDojo did not answer at {base_url} within the waiting time.")
    token = await admin_token(settings, transport=transport, sleep=sleep)
    sync_account, accounts_account = service_accounts(settings)
    changes: list[str] = []
    async with DefectDojoClient(base_url, token, transport=transport, sleep=sleep) as admin:
        async with session_scope() as db:
            _, c1 = await ensure_service_account(
                db, admin, base_url, sync_account, transport=transport, sleep=sleep
            )
            accounts_token, c2 = await ensure_service_account(
                db, admin, base_url, accounts_account, transport=transport, sleep=sleep
            )
            changes += c1 + c2
        async with DefectDojoClient(
            base_url, accounts_token, transport=transport, sleep=sleep
        ) as accounts:
            changes += await ensure_deduplication(accounts)
            changes += await ensure_product_types(accounts)
        async with session_scope() as db:
            changes += await ensure_admin_baseline(db, admin, settings)
    return changes


async def _main() -> int:
    settings = get_settings()
    try:
        changes = await initialise(settings)
    except InitError as exc:
        log.error("dojo_init_failed", error=str(exc))
        print(f"dojo-init: {exc}", file=sys.stderr)
        return 1
    except DefectDojoError as exc:
        log.error("dojo_init_failed", error=str(exc)[:500])
        print(f"dojo-init: DefectDojo reported a problem: {str(exc)[:300]}", file=sys.stderr)
        return 1
    finally:
        await dispose_engine()
    if changes:
        for line in changes:
            log.info("dojo_init_changed", change=line)
            print(f"dojo-init: {line}")
    else:
        print("dojo-init: nothing to change")
    return 0


def run() -> int:
    """Entry point of ``python -m securescan dojo-init``."""
    return asyncio.run(_main())
