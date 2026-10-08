"""Scanner health: feed ages, update outcomes and the data behind ``GET /api/v1/scanner-health``.

* Feed age gauges (``securescan_feed_age_seconds{feed}``) are computed at scrape time from the moment the active
  content version was built or fetched, so they keep growing between updates without a periodic task. The moments
  are loaded when the worker starts and refreshed after every update; the API process records them when
  ``/scanner-health`` or ``/content-versions`` is read.
* ``securescan_content_update_failed{feed}`` is 1 after a failed update and 0 after a successful one (the alert
  metric of plan M8 task 6); ``securescan_content_update_last_success_timestamp{feed}`` is the last success.
* ``securescan_feed_stale{feed}`` is 1 when the active version is older than its limit (7 days for the
  vulnerability databases, 30 days for rules and templates; design "Observability").
* Dependency-Check cannot read its data while the updater rewrites it, so scans wait for ``feed_updating`` to end.

Age of a feed: databases (``grype_db``, ``nvd_data``) are as old as the day the upstream built them
(``built_at``); rules and templates are as old as the last successful check or fetch (``fetched_at``), because
upstream may legitimately have no newer commit.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from prometheus_client import Gauge
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import Settings, get_settings
from securescan.db.models.content import ContentVersion
from securescan.db.models.enums import ContentFeed, JobState
from securescan.db.models.images import ImageVersion
from securescan.db.models.jobs import ScanJob
from securescan.jobs.hooks import worker_startup_hook
from securescan.logging import get_logger
from securescan.observability.metrics import FEED_AGE_SECONDS, REGISTRY
from securescan.util import ensure_utc, utcnow

log = get_logger(__name__)

DATABASE_FEEDS = (ContentFeed.GRYPE_DB, ContentFeed.NVD_DATA)
CONTENT_FEEDS = (ContentFeed.SEMGREP_RULES, ContentFeed.NUCLEI_TEMPLATES)
ALL_FEEDS = (
    ContentFeed.GRYPE_DB,
    ContentFeed.NVD_DATA,
    ContentFeed.SEMGREP_RULES,
    ContentFeed.NUCLEI_TEMPLATES,
)
FEED_LABELS = {
    ContentFeed.GRYPE_DB.value: "Grype vulnerability database",
    ContentFeed.NVD_DATA.value: "Dependency-Check NVD data",
    ContentFeed.SEMGREP_RULES.value: "Semgrep rules",
    ContentFeed.NUCLEI_TEMPLATES.value: "Nuclei templates",
}
# The scan tool that reads each feed.
FEED_TOOLS = {
    ContentFeed.GRYPE_DB.value: "syft-grype",
    ContentFeed.NVD_DATA.value: "dependency-check",
    ContentFeed.SEMGREP_RULES.value: "semgrep",
    ContentFeed.NUCLEI_TEMPLATES.value: "nuclei",
}

UPDATE_FAILED = Gauge(
    "securescan_content_update_failed",
    "1 when the last update of a content feed failed (the previous version stays active)",
    ["feed"],
    registry=REGISTRY,
)
UPDATE_LAST_SUCCESS = Gauge(
    "securescan_content_update_last_success_timestamp",
    "Unix time of the last successful update of a content feed",
    ["feed"],
    registry=REGISTRY,
)
FEED_STALE = Gauge(
    "securescan_feed_stale",
    "1 when the active version of a content feed is older than its limit",
    ["feed"],
    registry=REGISTRY,
)

_reference_times: dict[str, float] = {}
_failed: dict[str, bool] = {}
_updating: set[str] = set()


# --------------------------------------------------------------------------- pure helpers
def feed_value(feed: ContentFeed | str) -> str:
    return feed.value if isinstance(feed, ContentFeed) else str(feed)


def limit_days(feed: ContentFeed | str, settings: Settings | None = None) -> int:
    """Alert threshold in days: 7 for the vulnerability databases, 30 for rules and templates."""
    cfg = settings or get_settings()
    if feed_value(feed) in {f.value for f in DATABASE_FEEDS}:
        return cfg.feed_max_age_days_database
    return cfg.feed_max_age_days_content


def reference_time(feed: ContentFeed | str, row: ContentVersion | Any) -> datetime | None:
    """The moment the feed's age counts from (see the module docstring)."""
    built = getattr(row, "built_at", None)
    fetched = getattr(row, "fetched_at", None)
    chosen = (built or fetched) if feed_value(feed) in {f.value for f in DATABASE_FEEDS} else (fetched or built)
    return ensure_utc(chosen) if chosen is not None else None


def age_seconds(reference: datetime | None, now: datetime | None = None) -> float | None:
    if reference is None:
        return None
    return max(0.0, ((now or utcnow()) - ensure_utc(reference)).total_seconds())


def is_stale(feed: ContentFeed | str, age: float | None, settings: Settings | None = None) -> bool:
    """A feed without any version counts as stale; otherwise stale when older than its limit."""
    if age is None:
        return True
    return age > limit_days(feed, settings) * 86400


@dataclass
class FeedStatus:
    feed: str
    label: str
    tool: str
    version: str | None
    path: str | None
    source_commit: str | None
    built_at: datetime | None
    fetched_at: datetime | None
    activated_at: datetime | None
    age_seconds: float | None
    limit_days: int
    stale: bool
    regression_result: str | None
    update_failed: bool


def feed_status(
    feed: ContentFeed | str,
    row: ContentVersion | Any | None,
    *,
    now: datetime | None = None,
    settings: Settings | None = None,
) -> FeedStatus:
    name = feed_value(feed)
    reference = reference_time(feed, row) if row is not None else None
    age = age_seconds(reference, now)
    return FeedStatus(
        feed=name,
        label=FEED_LABELS.get(name, name),
        tool=FEED_TOOLS.get(name, ""),
        version=getattr(row, "version", None),
        path=getattr(row, "path", None),
        source_commit=getattr(row, "source_commit", None),
        built_at=getattr(row, "built_at", None),
        fetched_at=getattr(row, "fetched_at", None),
        activated_at=getattr(row, "activated_at", None),
        age_seconds=age,
        limit_days=limit_days(feed, settings),
        stale=is_stale(feed, age, settings),
        regression_result=getattr(row, "regression_result", None),
        update_failed=_update_failed(name),
    )


def _update_failed(feed: str) -> bool:
    return _failed.get(feed, False)


# --------------------------------------------------------------------------- gauges
def record_feed_clock(feed: ContentFeed | str, reference: datetime | None) -> None:
    """Remember the moment ``feed``'s age counts from; the age gauge follows the wall clock from then on."""
    name = feed_value(feed)
    if reference is None:
        _reference_times.pop(name, None)
        return
    _reference_times[name] = ensure_utc(reference).timestamp()
    FEED_AGE_SECONDS.labels(feed=name).set_function(lambda n=name: _age_now(n))
    FEED_STALE.labels(feed=name).set_function(lambda n=name: _stale_now(n))


def _age_now(feed: str) -> float:
    stamp = _reference_times.get(feed)
    return max(0.0, time.time() - stamp) if stamp is not None else float("nan")


def _stale_now(feed: str) -> float:
    stamp = _reference_times.get(feed)
    if stamp is None:
        return 1.0
    return 1.0 if time.time() - stamp > limit_days(feed) * 86400 else 0.0


def record_update_result(feed: ContentFeed | str, ok: bool) -> None:
    """The alert metric of plan M8 task 6: set on a failed update, cleared on a successful one."""
    name = feed_value(feed)
    _failed[name] = not ok
    UPDATE_FAILED.labels(feed=name).set(0 if ok else 1)
    if ok:
        UPDATE_LAST_SUCCESS.labels(feed=name).set(time.time())


# --------------------------------------------------------------------------- database reads
async def active_versions(session: AsyncSession) -> dict[str, ContentVersion]:
    """The active ``ContentVersion`` per feed (feeds without one are absent)."""
    rows = (
        await session.scalars(select(ContentVersion).where(ContentVersion.active.is_(True)))
    ).all()
    return {feed_value(row.feed): row for row in rows}


async def refresh_feed_clocks(session: AsyncSession) -> dict[str, FeedStatus]:
    """Load the active versions, set the gauges and return the status of every feed."""
    active = await active_versions(session)
    statuses: dict[str, FeedStatus] = {}
    for feed in ALL_FEEDS:
        row = active.get(feed.value)
        record_feed_clock(feed, reference_time(feed, row) if row is not None else None)
        statuses[feed.value] = feed_status(feed, row)
    return statuses


async def tool_busy(session: AsyncSession, tool: str) -> bool:
    """True while a job of ``tool`` is preparing or running."""
    count = await session.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(ScanJob.tool == tool, ScanJob.state.in_([JobState.PREPARING, JobState.RUNNING]))
    )
    return bool(count)


async def last_runs_by_tool(session: AsyncSession) -> dict[str, dict[str, datetime | None]]:
    """``{tool: {"success": last good finish, "failure": last failed or timed-out finish}}``."""
    result: dict[str, dict[str, datetime | None]] = {}
    good = await session.execute(
        select(ScanJob.tool, func.max(ScanJob.finished_at))
        .where(ScanJob.state.in_([JobState.COMPLETED, JobState.COMPLETED_PARTIAL]))
        .group_by(ScanJob.tool)
    )
    for tool, moment in good.all():
        result.setdefault(str(tool), {"success": None, "failure": None})["success"] = moment
    bad = await session.execute(
        select(ScanJob.tool, func.max(ScanJob.finished_at))
        .where(ScanJob.state.in_([JobState.FAILED, JobState.TIMED_OUT]))
        .group_by(ScanJob.tool)
    )
    for tool, moment in bad.all():
        result.setdefault(str(tool), {"success": None, "failure": None})["failure"] = moment
    return result


async def approved_images(session: AsyncSession) -> dict[str, ImageVersion]:
    """The newest active, approved image row per tool."""
    rows = (
        await session.scalars(
            select(ImageVersion)
            .where(ImageVersion.active.is_(True), ImageVersion.approved_at.is_not(None))
            .order_by(ImageVersion.approved_at)
        )
    ).all()
    return {row.tool: row for row in rows}  # later rows (newer approval) overwrite earlier ones


# --------------------------------------------------------------------------- update exclusion
class FeedUpdate:
    """``async with FeedUpdate("nvd_data"):`` marks the feed as being rewritten (single worker process)."""

    def __init__(self, feed: ContentFeed | str) -> None:
        self.feed = feed_value(feed)

    async def __aenter__(self) -> FeedUpdate:
        _updating.add(self.feed)
        return self

    async def __aexit__(self, *_exc: object) -> None:
        _updating.discard(self.feed)


def feed_updating(feed: ContentFeed | str) -> bool:
    return feed_value(feed) in _updating


async def wait_feed_idle(
    feed: ContentFeed | str,
    timeout_s: float,
    *,
    interval_s: float = 15.0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> bool:
    """Wait until ``feed`` is no longer being updated. True when it is idle, False on timeout."""
    started = clock()
    while feed_updating(feed):
        if clock() - started >= timeout_s:
            return False
        await sleep(interval_s)
    return True


# --------------------------------------------------------------------------- worker start-up
@worker_startup_hook
async def load_feed_clocks() -> None:
    """Set the feed age gauges from the database when the worker starts."""
    from securescan.db.session import session_scope

    try:
        async with session_scope() as db:
            statuses = await refresh_feed_clocks(db)
    except Exception as exc:  # noqa: BLE001 - the database may not be migrated yet; never block start-up
        log.warning("feed_clocks_not_loaded", error=type(exc).__name__)
        return
    log.info("feed_clocks_loaded", feeds={k: v.version for k, v in statuses.items()})
