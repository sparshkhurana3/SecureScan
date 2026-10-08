"""Nightly refresh of "state now" in the finding history (plan M4 task 5).

Triage happens in DefectDojo; history rows keep the state at scan time forever and carry the finding's
current state next to it. Every night at 02:00 UTC this task reads the current state of every distinct
DefectDojo finding id in the history, with no time window, and updates ``state_now``. A finding that
DefectDojo no longer has becomes ``deleted``; no history row is ever removed.
"""

from __future__ import annotations

from sqlalchemy import select

from securescan.db.models.applications import Application
from securescan.db.models.history import FindingHistory
from securescan.db.session import session_scope
from securescan.domain.history import RefreshStats, refresh_application_counts, refresh_finding_states
from securescan.integrations.defectdojo.client import DefectDojoClient, DefectDojoError
from securescan.integrations.defectdojo.factory import DefectDojoNotConfigured, sync_client
from securescan.jobs.hooks import periodic_hook
from securescan.logging import get_logger

log = get_logger(__name__)

BATCH = 200


async def refresh_all_states(client: DefectDojoClient, *, batch_size: int = BATCH) -> RefreshStats:
    """Refresh ``state_now`` for every distinct finding id in the history, in id order, one short
    transaction per batch (a failure keeps the batches before it)."""
    total = RefreshStats()
    last_id = -1
    while True:
        async with session_scope() as db:
            ids = list(
                (
                    await db.scalars(
                        select(FindingHistory.dd_finding_id)
                        .where(FindingHistory.dd_finding_id > last_id)
                        .distinct()
                        .order_by(FindingHistory.dd_finding_id)
                        .limit(batch_size)
                    )
                ).all()
            )
            if not ids:
                break
            stats = await refresh_finding_states(db, client, ids)
        last_id = ids[-1]
        total.checked += stats.checked
        total.missing += stats.missing
        total.rows_updated += stats.rows_updated
        for state, number in stats.states.items():
            total.states[state] = total.states.get(state, 0) + number
    return total


async def refresh_all_application_counts() -> int:
    """Recompute the cached open counts of every application that has been scanned."""
    done = 0
    last_name = ""
    while True:
        async with session_scope() as db:
            apps = list(
                (
                    await db.scalars(
                        select(Application)
                        .where(Application.last_scan_id.is_not(None), Application.name > last_name)
                        .order_by(Application.name)
                        .limit(100)
                    )
                ).all()
            )
            if not apps:
                break
            for application in apps:
                await refresh_application_counts(db, application)
        last_name = apps[-1].name
        done += len(apps)
    return done


async def run_history_state_refresh() -> dict[str, int]:
    """The task body (also callable by hand, plan M4 acceptance: "run by hand")."""
    try:
        async with session_scope() as db:
            client = await sync_client(db)
    except DefectDojoNotConfigured as exc:
        log.warning("history_refresh_skipped", reason=str(exc)[:200])
        return {"checked": 0}
    try:
        stats = await refresh_all_states(client)
    except DefectDojoError as exc:
        log.error("history_refresh_failed", error=str(exc)[:300])
        raise
    finally:
        await client.aclose()
    applications = await refresh_all_application_counts()
    log.info(
        "history_state_refreshed",
        checked=stats.checked,
        missing=stats.missing,
        rows_updated=stats.rows_updated,
        states=stats.states,
        applications=applications,
    )
    return {
        "checked": stats.checked,
        "missing": stats.missing,
        "rows_updated": stats.rows_updated,
        "applications": applications,
    }


@periodic_hook("history_state_refresh")
async def history_state_refresh_hook(timestamp: int) -> None:
    await run_history_state_refresh()
