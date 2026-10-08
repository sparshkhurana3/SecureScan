"""``python -m securescan sonar-init``: first-time setup of the on-demand SonarQube server (plan M8 task 5).

The same steps run inside ``ensure_running()`` (``securescan/jobs/sonarqube_lifecycle.py``) every time the
server is started for a job, so a scan on a fresh installation needs no separate command. They change only what
is missing, so repeating them is safe:

1. the built-in ``admin`` account: when its password is still the default ``admin`` it is changed to the one in
   the ``sonarqube_admin_password`` secret (``SECURESCAN_SONARQUBE_ADMIN_PASSWORD_FILE``);
2. a local service user (``securescan-sonar``) with the least global permissions that let it create projects
   and run analyses (``provisioning``, ``scan``); its password is random and never kept: the worker works with
   a token;
3. a ``USER_TOKEN`` for that user, stored encrypted as a credential of kind ``sonarqube_token`` (replaced when
   the stored one no longer works, for example after the SonarQube database was reset);
4. the "Standard Experience" mode (``sonar.multi-quality-mode.enabled=false``), so that issues carry the
   ``type`` and ``severity`` fields DefectDojo's parser reads. Unverified until spike S3 has run: the setting
   name is the one the S3 script uses; a failure to set it is reported, not fatal.

The command itself only talks to an already running server (it cannot start containers); when the server is
stopped it says so and exits 0, because the first SonarQube job starts the server and runs these steps.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import Settings, get_settings
from securescan.db.engine import dispose_engine
from securescan.db.models.enums import CredentialKind
from securescan.db.session import session_scope
from securescan.domain.accounts import generate_password
from securescan.domain.credentials import (
    get_active_credential_by_kind,
    reveal_secret,
    store_credential,
)
from securescan.integrations.sonarqube.client import (
    MQR_SETTING,
    SonarError,
    SonarQubeClient,
)
from securescan.logging import get_logger
from securescan.util import utcnow

log = get_logger(__name__)

DEFAULT_ADMIN_PASSWORD = "admin"  # noqa: S105 - SonarQube's documented initial password
SERVICE_PERMISSIONS = ("provisioning", "scan")
CREDENTIAL_NAME = "SonarQube service token"


class SonarInitError(Exception):
    """Setup cannot continue; the message says what to do (plain language, no secrets)."""


async def stored_service_token(session: AsyncSession) -> str | None:
    """The decrypted service token, or None when none was stored yet."""
    credential = await get_active_credential_by_kind(session, CredentialKind.SONARQUBE_TOKEN)
    if credential is None:
        return None
    return reveal_secret(credential)


def _client(
    settings: Settings,
    *,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> SonarQubeClient:
    return SonarQubeClient(
        settings.sonarqube_url, token=token, username=username, password=password, transport=transport
    )


async def ensure_admin_password(
    settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None
) -> list[str]:
    """Make the configured password the admin password. Returns the changes made."""
    configured = settings.sonarqube_admin_password
    if not configured:
        raise SonarInitError(
            "The SonarQube admin password is not configured "
            "(SECURESCAN_SONARQUBE_ADMIN_PASSWORD_FILE should point at the sonarqube_admin_password secret)."
        )
    async with _client(settings, username="admin", password=configured, transport=transport) as admin:
        if await admin.validate_auth():
            return []
    async with _client(
        settings, username="admin", password=DEFAULT_ADMIN_PASSWORD, transport=transport
    ) as default:
        if not await default.validate_auth():
            raise SonarInitError(
                "The SonarQube admin password is neither the configured one nor the initial one. "
                "Reset the SonarQube database volume or set the secret to the current password."
            )
        await default.change_password("admin", DEFAULT_ADMIN_PASSWORD, configured)
    return ["changed the SonarQube admin password"]


async def ensure_service_user(admin: SonarQubeClient, login: str) -> list[str]:
    """The local service user and its global permissions."""
    changes: list[str] = []
    if await admin.find_user(login) is None:
        await admin.create_user(login, "SecureScan service", generate_password(32))
        changes.append(f"created the service user {login}")
    for permission in SERVICE_PERMISSIONS:
        try:
            await admin.add_permission(login, permission)
        except SonarError as exc:
            if exc.status != 400:  # 400: the permission is already granted
                raise
    return changes


async def ensure_service_token(
    session: AsyncSession,
    settings: Settings,
    admin: SonarQubeClient,
    login: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[str]:
    """A working ``USER_TOKEN`` of the service user in the credentials table."""
    credential = await get_active_credential_by_kind(session, CredentialKind.SONARQUBE_TOKEN)
    if credential is not None:
        async with _client(settings, token=reveal_secret(credential), transport=transport) as probe:
            if await probe.validate_auth():
                return []
        credential.revoked_at = utcnow()
        log.warning("sonarqube_service_token_invalid", credential_id=str(credential.id))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    token = await admin.generate_token(f"securescan-service-{stamp}", "USER_TOKEN", login=login)
    await store_credential(
        session,
        kind=CredentialKind.SONARQUBE_TOKEN,
        name=CREDENTIAL_NAME,
        secret=token,
        extra={"login": login},
    )
    return ["created and stored the SonarQube service token"]


async def ensure_standard_experience(admin: SonarQubeClient) -> list[str]:
    """Standard Experience mode (issues with type and severity). A failure is reported, not raised."""
    try:
        current = await admin.get_setting(MQR_SETTING)
    except SonarError:
        current = None
    if current is not None and current.lower() == "false":
        return []
    try:
        await admin.set_setting(MQR_SETTING, "false")
    except SonarError as exc:
        log.warning("sonarqube_standard_experience_failed", error=str(exc)[:200])
        return [f"could not switch SonarQube to Standard Experience mode ({str(exc)[:120]})"]
    return ["switched SonarQube to Standard Experience mode"]


async def initialise(
    session: AsyncSession,
    settings: Settings | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[str]:
    """The whole setup against a running server. Returns the list of changes (empty on a repeat run).

    Does not commit: the caller's ``session_scope`` does.
    """
    cfg = settings or get_settings()
    changes = await ensure_admin_password(cfg, transport=transport)
    async with _client(
        cfg, username="admin", password=cfg.sonarqube_admin_password, transport=transport
    ) as admin:
        changes += await ensure_service_user(admin, cfg.sonarqube_service_user)
        changes += await ensure_service_token(
            session, cfg, admin, cfg.sonarqube_service_user, transport=transport
        )
        changes += await ensure_standard_experience(admin)
    for change in changes:
        log.info("sonar_init_changed", change=change)
    return changes


async def needs_initialisation(
    settings: Settings | None = None, *, transport: httpx.AsyncBaseTransport | None = None
) -> bool:
    """True while the admin password is still the default (the trigger of the setup inside ``ensure_running``)."""
    cfg = settings or get_settings()
    if not cfg.sonarqube_admin_password:
        return False
    async with _client(
        cfg, username="admin", password=cfg.sonarqube_admin_password, transport=transport
    ) as admin:
        if await admin.validate_auth():
            return False
    async with _client(
        cfg, username="admin", password=DEFAULT_ADMIN_PASSWORD, transport=transport
    ) as default:
        return await default.validate_auth()


async def _main() -> int:
    settings = get_settings()
    try:
        async with _client(settings) as probe:
            status = await probe.system_status()
        if status != "UP":
            print(
                "sonar-init: SonarQube is not running (it is started on demand by the first SonarQube scan, "
                "which also runs this setup). Nothing to do."
            )
            return 0
        async with session_scope() as db:
            changes = await initialise(db, settings)
    except SonarInitError as exc:
        log.error("sonar_init_failed", error=str(exc))
        print(f"sonar-init: {exc}", file=sys.stderr)
        return 1
    except SonarError as exc:
        log.error("sonar_init_failed", error=str(exc)[:300])
        print(f"sonar-init: SonarQube reported a problem: {str(exc)[:300]}", file=sys.stderr)
        return 1
    finally:
        await dispose_engine()
    if changes:
        for line in changes:
            print(f"sonar-init: {line}")
    else:
        print("sonar-init: nothing to change")
    return 0


def run() -> int:
    """Entry point of ``python -m securescan sonar-init``."""
    return asyncio.run(_main())
