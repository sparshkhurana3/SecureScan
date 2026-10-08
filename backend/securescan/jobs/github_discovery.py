"""GitHub discovery and the connection test (queue ``github``).

* ``github_discovery`` (periodic, 01:00 UTC, registered in ``maintenance.py``): the nightly run.
* ``github_sync`` (task): the same run on demand, deferred by ``POST /integrations/github/sync``.
* ``github_test`` (task): the connection test, deferred by ``POST /integrations/github/test``. Both
  need the egress proxy, which only the worker may start, so the API hands the work to the worker.
"""

from __future__ import annotations

from securescan.db.session import session_scope
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.integrations.github.app import GitHubError, explain_error
from securescan.integrations.github.connection import (
    GitHubConfigError,
    get_connection,
    github_client,
    run_connection_test,
)
from securescan.integrations.github.discovery import (
    DiscoveryResult,
    SqlDiscoveryStore,
    run_discovery,
)
from securescan.jobs.app import app
from securescan.jobs.hooks import periodic_hook
from securescan.logging import get_logger
from securescan.runner.egress import EgressError
from securescan.util import utcnow

log = get_logger(__name__)


@periodic_hook("github_discovery")
async def nightly_discovery(timestamp: int) -> None:
    await run_github_discovery(trigger="nightly")


@app.task(name="github_sync", queue="github", queueing_lock="github_sync")
async def github_sync() -> None:
    """Run discovery now (Settings: "Sync now")."""
    await run_github_discovery(trigger="manual")


@app.task(name="github_test", queue="github", queueing_lock="github_test")
async def github_test() -> None:
    """Mint a token, list repositories and run ``git ls-remote``; the result is stored on the connection."""
    async with session_scope() as session:
        connection = await get_connection(session)
        if connection is None:
            return
        result = await run_connection_test(session, connection)
        await record_audit(
            session,
            SYSTEM_ACTOR,
            "integration.github.test",
            "github_connection",
            connection.id,
            {"ok": result.ok, "repositories": result.repositories},
        )


async def run_github_discovery(*, trigger: str) -> DiscoveryResult | None:
    """List the App's repositories and apply them to the inventory. None when it cannot run."""
    async with session_scope() as session:
        connection = await get_connection(session, enabled_only=True)
        if connection is None:
            log.debug("github_discovery_skipped", reason="no enabled connection", trigger=trigger)
            return None
        try:
            async with github_client(session, connection) as client:
                repositories = await client.list_installation_repositories()
        except (GitHubError, GitHubConfigError, EgressError) as exc:
            message = explain_error(exc) if isinstance(exc, GitHubError) else str(exc)
            log.warning("github_discovery_failed", reason=message[:200], trigger=trigger)
            await record_audit(
                session,
                SYSTEM_ACTOR,
                "github.discovery_failed",
                "github_connection",
                connection.id,
                {"trigger": trigger, "reason": message[:500]},
            )
            return None
        result = await run_discovery(repositories, SqlDiscoveryStore(session))
        connection.last_sync_at = utcnow()
        await record_audit(
            session,
            SYSTEM_ACTOR,
            "github.discovery",
            "github_connection",
            connection.id,
            {
                "trigger": trigger,
                "seen": result.seen,
                "created": result.created,
                "updated": result.updated,
                "removed": result.removed,
                "restored": result.restored,
                "new_repositories": result.created_names[:50],
            },
        )
        return result
