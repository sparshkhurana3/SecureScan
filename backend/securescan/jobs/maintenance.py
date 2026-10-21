"""Periodic tasks. All times are UTC (Procrastinate evaluates cron in UTC).

Every periodic task of plan M2 is registered here under its final name. Most are skeletons: they
call ``run_periodic(name, timestamp)``, which does nothing until a later milestone registers the
implementation with ``@periodic_hook(name)`` (see ``securescan/jobs/hooks.py``). Two are real in M2:
``credential_expiry_alerts`` and ``session_cleanup``.

A ``queueing_lock`` per task stops a backlog of identical runs piling up while the worker is down.
"""

from __future__ import annotations

from securescan.config import get_settings
from securescan.db.session import session_scope
from securescan.domain.credentials import run_expiry_alerts
from securescan.domain.uploads import gc_stale_uploads
from securescan.auth.session import delete_expired_sessions
from securescan.jobs.app import app
from securescan.jobs.hooks import run_periodic
from securescan.logging import get_logger

log = get_logger(__name__)


def _poll_cron() -> str:
    minutes = get_settings().github_poll_interval_minutes
    return f"*/{minutes} * * * *" if 1 <= minutes < 60 else "*/10 * * * *"


@app.periodic(cron="*/5 * * * *")
@app.task(name="stalled_jobs", queue="maintenance", queueing_lock="stalled_jobs")
async def stalled_jobs(timestamp: int) -> None:
    """M3: re-queue or fail scan jobs whose worker stopped; re-defer queued jobs lost before defer."""
    await run_periodic("stalled_jobs", timestamp)


@app.periodic(cron="0 * * * *")
@app.task(name="workspace_gc", queue="maintenance", queueing_lock="workspace_gc")
async def workspace_gc(timestamp: int) -> None:
    """M3: remove workspaces older than 24 hours."""
    await run_periodic("workspace_gc", timestamp)


@app.periodic(cron="0 2 * * *")
@app.task(name="history_state_refresh", queue="maintenance", queueing_lock="history_state_refresh")
async def history_state_refresh(timestamp: int) -> None:
    """M4: refresh ``state_now`` of every finding in the history from DefectDojo."""
    await run_periodic("history_state_refresh", timestamp)


@app.periodic(cron="0 1 * * *")
@app.task(name="github_discovery", queue="github", queueing_lock="github_discovery")
async def github_discovery(timestamp: int) -> None:
    """M7: list the repositories the GitHub App can reach."""
    await run_periodic("github_discovery", timestamp)


@app.periodic(cron=_poll_cron())
@app.task(name="github_poll", queue="github", queueing_lock="github_poll")
async def github_poll(timestamp: int) -> None:
    """M7: compare default-branch heads and enqueue change scans."""
    await run_periodic("github_poll", timestamp)


@app.periodic(cron="30 7 * * *")
@app.task(name="grype_db_update", queue="maintenance", queueing_lock="grype_db_update")
async def grype_db_update(timestamp: int) -> None:
    """M8: update the Grype vulnerability database (after Anchore's 06:00 build)."""
    await run_periodic("grype_db_update", timestamp)


@app.periodic(cron="0 3 * * 6")
@app.task(
    name="rules_and_templates_update",
    queue="maintenance",
    queueing_lock="rules_and_templates_update",
)
async def rules_and_templates_update(timestamp: int) -> None:
    """M8: weekly Semgrep rules and Nuclei templates update behind the regression run."""
    await run_periodic("rules_and_templates_update", timestamp)


@app.periodic(cron="0 4 1 * *")
@app.task(name="image_update_proposals", queue="maintenance", queueing_lock="image_update_proposals")
async def image_update_proposals(timestamp: int) -> None:
    """M11: monthly proposals for new scanner image digests."""
    await run_periodic("image_update_proposals", timestamp)


@app.periodic(cron="0 4 * * *")
@app.task(name="account_expiry", queue="maintenance", queueing_lock="account_expiry")
async def account_expiry(timestamp: int) -> None:
    """M4: disable DefectDojo accounts unused for 90 days; check break-glass use."""
    await run_periodic("account_expiry", timestamp)


@app.periodic(cron="0 5 * * *")
@app.task(
    name="credential_expiry_alerts", queue="maintenance", queueing_lock="credential_expiry_alerts"
)
async def credential_expiry_alerts(timestamp: int) -> None:
    """Set the expiring-credentials gauge and record one audit notice per credential."""
    async with session_scope() as db:
        count = await run_expiry_alerts(db)
    log.info("credential_expiry_alerts", expiring=count)
    await run_periodic("credential_expiry_alerts", timestamp)


@app.periodic(cron="*/5 * * * *")
@app.task(name="egress_idle_stop", queue="maintenance", queueing_lock="egress_idle_stop")
async def egress_idle_stop(timestamp: int) -> None:
    """M7: stop the shared egress proxy after 5 idle minutes."""
    await run_periodic("egress_idle_stop", timestamp)


@app.periodic(cron="15 * * * *")
@app.task(name="session_cleanup", queue="maintenance", queueing_lock="session_cleanup")
async def session_cleanup(timestamp: int) -> None:
    """Delete expired login sessions and abort stale chunked uploads."""
    async with session_scope() as db:
        sessions_deleted = await delete_expired_sessions(db)
        uploads_aborted = await gc_stale_uploads(db)
    log.info("session_cleanup", sessions_deleted=sessions_deleted, uploads_aborted=uploads_aborted)
