"""Nightly DefectDojo account maintenance (plan M4 task 7).

* ``account_expiry`` (04:00 UTC): disable the DefectDojo accounts of users who have not signed in to
  SecureScan for 90 days; the account comes back by itself at their next sign-in.
* The same run checks DefectDojo's built-in ``admin`` account: a changed ``last_login`` means someone
  used the break-glass account, which raises the ``break_glass_logins`` metric and an audit event.
"""

from __future__ import annotations

from securescan.db.session import session_scope
from securescan.domain.accounts import check_break_glass, expire_inactive_accounts
from securescan.integrations.defectdojo.client import DefectDojoError
from securescan.integrations.defectdojo.factory import DefectDojoNotConfigured, accounts_client
from securescan.jobs.hooks import periodic_hook
from securescan.logging import get_logger

log = get_logger(__name__)


async def run_account_maintenance() -> dict[str, int]:
    """Expire inactive accounts and look for break-glass use. Returns what happened."""
    try:
        async with session_scope() as db:
            client = await accounts_client(db)
    except DefectDojoNotConfigured as exc:
        log.warning("account_maintenance_skipped", reason=str(exc)[:200])
        return {"expired": 0, "break_glass": 0}
    result = {"expired": 0, "break_glass": 0}
    try:
        async with session_scope() as db:
            result["expired"] = len(await expire_inactive_accounts(db, client))
        async with session_scope() as db:
            result["break_glass"] = int(await check_break_glass(db, client))
    except DefectDojoError as exc:
        log.error("account_maintenance_failed", error=str(exc)[:300])
        raise
    finally:
        await client.aclose()
    log.info("account_maintenance_done", **result)
    return result


@periodic_hook("account_expiry")
async def account_expiry_hook(timestamp: int) -> None:
    await run_account_maintenance()
