"""Build DefectDojo clients from the tokens ``dojo-init`` stored as credentials.

Two service accounts exist (plan section 8.3):

* ``securescan-sync`` (staff): imports and reads findings. Credential kind ``defectdojo_token``.
* ``securescan-accounts`` (superuser): creates and changes users and system settings. Credential kind
  ``defectdojo_admin_token``.

The break-glass ``admin`` account is never used here and its token is never stored.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import get_settings
from securescan.db.models.enums import CredentialKind
from securescan.domain.credentials import get_active_credential_by_kind, reveal_secret
from securescan.integrations.defectdojo.client import DefectDojoClient


class DefectDojoNotConfigured(Exception):  # noqa: N818 - reads better than ...Error
    """``dojo-init`` has not stored the token yet (DefectDojo is still starting, or setup failed)."""


async def _token(session: AsyncSession, kind: CredentialKind) -> str:
    credential = await get_active_credential_by_kind(session, kind)
    if credential is None:
        raise DefectDojoNotConfigured(
            f"No DefectDojo token of kind {kind.value} is stored yet; run dojo-init "
            "(it starts with the stack and is repeated until DefectDojo answers)."
        )
    return reveal_secret(credential)


def _client(token: str, *, quick: bool) -> DefectDojoClient:
    settings = get_settings()
    return DefectDojoClient(
        settings.defectdojo_url,
        token,
        timeout=5.0 if quick else settings.defectdojo_timeout_seconds,
        import_timeout=settings.defectdojo_import_timeout_seconds,
        max_retries=0 if quick else settings.defectdojo_max_retries,
        page_size=settings.defectdojo_page_size,
    )


async def sync_client(session: AsyncSession, *, quick: bool = False) -> DefectDojoClient:
    """Client for imports and finding reads. ``quick``: short timeout, no retries (sign-in paths)."""
    return _client(await _token(session, CredentialKind.DEFECTDOJO_TOKEN), quick=quick)


async def accounts_client(session: AsyncSession, *, quick: bool = False) -> DefectDojoClient:
    """Client with superuser rights, for provisioning accounts. Use it for nothing else."""
    return _client(await _token(session, CredentialKind.DEFECTDOJO_ADMIN_TOKEN), quick=quick)
