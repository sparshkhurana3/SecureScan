"""The GitHub change poller (periodic task ``github_poll``, queue ``github``, every 10 minutes).

Reads the default-branch head of every repository in the automatic set and enqueues a ``code-standard``
scan when it differs from the last scanned commit (rules in ``integrations/github/poller.py``). The
status shown in Settings (last run, remaining rate limit) is written to the connection row.
"""

from __future__ import annotations

import time
from datetime import datetime

from sqlalchemy import func, select

from securescan.config import get_settings
from securescan.db.engine import get_sessionmaker
from securescan.db.models.applications import Application
from securescan.db.models.enums import ScheduleKind
from securescan.db.models.schedules import Schedule
from securescan.integrations.github.app import GitHubError, explain_error
from securescan.integrations.github.connection import (
    GitHubConfigError,
    get_connection,
    github_client,
)
from securescan.integrations.github.poller import (
    PollResult,
    SqlPollStore,
    automatic_conditions,
    run_poll,
)
from securescan.jobs.hooks import periodic_hook
from securescan.logging import get_logger
from securescan.observability.metrics import GITHUB_POLL_LAST_SUCCESS, GITHUB_RATE_LIMIT_REMAINING
from securescan.runner.egress import EgressError
from securescan.util import ensure_utc, utcnow

log = get_logger(__name__)

# A run may start a little early (the periodic clock is not exact): allow this much slack.
INTERVAL_SLACK_SECONDS = 60


def poll_due(interval_minutes: int | None, last_poll_at: datetime | None, now: datetime) -> bool:
    """False when a custom poll interval (Settings) has not elapsed since the last run."""
    if not interval_minutes or last_poll_at is None:
        return True
    elapsed = (now - ensure_utc(last_poll_at)).total_seconds()
    return elapsed >= interval_minutes * 60 - INTERVAL_SLACK_SECONDS


@periodic_hook("github_poll")
async def poll_github(timestamp: int) -> None:
    await run_github_poll()


async def run_github_poll() -> PollResult | None:
    """One poll run. Returns None when polling is off, not due, or there is nothing to poll."""
    settings = get_settings()
    async with get_sessionmaker()() as session:
        connection = await get_connection(session, enabled_only=True)
        if connection is None:
            log.debug("github_poll_skipped", reason="no enabled connection")
            return None
        poll_schedule = await session.scalar(
            select(Schedule)
            .where(Schedule.kind == ScheduleKind.POLL)
            .order_by(Schedule.created_at)
            .limit(1)
        )
        interval = settings.github_poll_interval_minutes
        if poll_schedule is not None:
            if not poll_schedule.enabled:
                log.debug("github_poll_skipped", reason="polling switched off")
                return None
            interval = poll_schedule.poll_interval_minutes or interval
            if not poll_due(poll_schedule.poll_interval_minutes, connection.last_poll_at, utcnow()):
                return None
        count = await session.scalar(
            select(func.count()).select_from(Application).where(*automatic_conditions())
        )
        if not count:
            connection.last_poll_at = utcnow()
            connection.last_poll_ok = True
            connection.last_poll_message = "No repositories are in the automatic set."
            GITHUB_POLL_LAST_SUCCESS.set(time.time())  # nothing to poll is not a failure
            await session.commit()
            return None
        try:
            async with github_client(session, connection, max_wait_s=15.0) as client:
                result = await run_poll(
                    client,
                    SqlPollStore(session),
                    budget=settings.github_poll_request_budget,
                    max_scans=settings.github_poll_max_scans_per_run,
                    interval_seconds=float(interval * 60),
                )
        except (GitHubError, GitHubConfigError, EgressError) as exc:
            message = explain_error(exc) if isinstance(exc, GitHubError) else str(exc)
            await session.rollback()
            connection = await get_connection(session, enabled_only=True)
            if connection is not None:
                connection.last_poll_at = utcnow()
                connection.last_poll_ok = False
                connection.last_poll_message = message[:1000]
                await session.commit()
            log.warning("github_poll_failed", reason=message[:200])
            return None
        connection.last_poll_at = utcnow()
        connection.last_poll_ok = result.ok
        connection.last_poll_message = result.summary()[:1000]
        if result.rate_remaining is not None:
            connection.rate_limit_remaining = result.rate_remaining
            connection.rate_limit_reset_at = result.rate_reset_at
            GITHUB_RATE_LIMIT_REMAINING.set(result.rate_remaining)
        if result.ok:
            GITHUB_POLL_LAST_SUCCESS.set(time.time())
        await session.commit()
        return result
