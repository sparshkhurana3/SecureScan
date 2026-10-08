"""Prometheus metrics.

One registry per process (``REGISTRY``). The api serves it at ``GET /metrics``, the worker on its
own port (``SECURESCAN_WORKER_METRICS_PORT``). The gateway does not proxy ``/metrics``.

Every metric of the design's observability table is registered here, so later milestones only call
``.set()``, ``.inc()`` or ``.observe()``. Gauges derived from the database (queue depth, oldest queued
age, dead letters, credentials expiring) are computed by ``refresh_db_gauges`` on scrape.
"""

from __future__ import annotations

import shutil
import time
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import get_settings
from securescan.logging import get_logger

log = get_logger(__name__)

REGISTRY = CollectorRegistry(auto_describe=True)
CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

_NS = "securescan"

# --- queue and jobs --------------------------------------------------------------------------
QUEUE_DEPTH = Gauge(f"{_NS}_queue_depth", "Procrastinate jobs waiting, by queue", ["queue"], registry=REGISTRY)
OLDEST_QUEUED_AGE = Gauge(
    f"{_NS}_oldest_queued_job_age_seconds", "Age of the oldest queued scan job", registry=REGISTRY
)
JOBS_TOTAL = Counter(
    f"{_NS}_jobs_total", "Finished scan jobs", ["tool", "state"], registry=REGISTRY
)
JOB_DURATION = Histogram(
    f"{_NS}_job_duration_seconds",
    "Scan job duration",
    ["tool"],
    buckets=(10, 30, 60, 120, 300, 600, 1200, 1800, 3600, 7200, 14400, 28800),
    registry=REGISTRY,
)
PERIODIC_RUNS = Counter(
    f"{_NS}_periodic_runs_total", "Periodic task executions", ["task"], registry=REGISTRY
)

# --- DefectDojo import ---------------------------------------------------------------------------
IMPORT_LAG = Gauge(
    f"{_NS}_import_lag_seconds", "Age of the oldest pending DefectDojo import", registry=REGISTRY
)
IMPORT_DEAD_LETTERS = Gauge(
    f"{_NS}_import_dead_letters", "Imports that exhausted their retries", registry=REGISTRY
)

# --- GitHub, SonarQube, egress ---------------------------------------------------------------------
GITHUB_POLL_LAST_SUCCESS = Gauge(
    f"{_NS}_github_poll_last_success_timestamp", "Unix time of the last successful poll", registry=REGISTRY
)
GITHUB_RATE_LIMIT_REMAINING = Gauge(
    f"{_NS}_github_rate_limit_remaining", "GitHub rate limit remaining at the last poll", registry=REGISTRY
)
SONARQUBE_START_SECONDS = Gauge(
    f"{_NS}_sonarqube_start_seconds", "Seconds the last SonarQube start took", registry=REGISTRY
)
EGRESS_PROXY_UP = Gauge(
    f"{_NS}_egress_proxy_up", "1 while the shared egress proxy container runs", registry=REGISTRY
)

# --- capacity, feeds, backups ----------------------------------------------------------------------
DISK_USED_RATIO = Gauge(
    f"{_NS}_disk_used_ratio", "Used fraction of a volume", ["volume"], registry=REGISTRY
)
FEED_AGE_SECONDS = Gauge(
    f"{_NS}_feed_age_seconds", "Age of a scanner content feed", ["feed"], registry=REGISTRY
)
BACKUP_LAST_SUCCESS = Gauge(
    f"{_NS}_backup_last_success_timestamp", "Unix time of the last successful backup", registry=REGISTRY
)

# --- security events -----------------------------------------------------------------------------
BREAK_GLASS_LOGINS = Counter(
    f"{_NS}_break_glass_logins_total", "Use of a break-glass admin account", ["tool"], registry=REGISTRY
)
LOGINS_TOTAL = Counter(
    f"{_NS}_logins_total", "Sign-in attempts", ["outcome"], registry=REGISTRY
)
CREDENTIALS_EXPIRING = Gauge(
    f"{_NS}_credentials_expiring", "Credentials expiring within the alert window", registry=REGISTRY
)

# --- API ---------------------------------------------------------------------------------------------
HTTP_REQUEST_SECONDS = Histogram(
    f"{_NS}_http_request_duration_seconds",
    "API request latency",
    ["method", "route", "status"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
    registry=REGISTRY,
)

UP = Gauge(f"{_NS}_up", "1 when the process is running", ["component"], registry=REGISTRY)


def render_prometheus() -> bytes:
    """The registry in the Prometheus text format."""
    return generate_latest(REGISTRY)


def observe_request(method: str, route: str, status: int, seconds: float) -> None:
    HTTP_REQUEST_SECONDS.labels(method=method, route=route, status=str(status)).observe(seconds)


def update_disk_gauges() -> dict[str, float]:
    """Set the disk-use gauges for the data, artifacts and content volumes; return the ratios."""
    settings = get_settings()
    ratios: dict[str, float] = {}
    for volume, path in (
        ("data", settings.data_root),
        ("artifacts", settings.artifacts_root),
        ("content", settings.content_root),
    ):
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            continue
        ratio = round(usage.used / usage.total, 4) if usage.total else 0.0
        DISK_USED_RATIO.labels(volume=volume).set(ratio)
        ratios[volume] = ratio
    return ratios


_QUEUE_SQL = text(
    "SELECT queue_name, count(*) FROM procrastinate_jobs WHERE status = 'todo' GROUP BY queue_name"
)
_OLDEST_SQL = text("SELECT min(created_at) FROM scan_jobs WHERE state = 'queued'")
_IMPORT_LAG_SQL = text(
    "SELECT min(created_at) FROM sync_outbox WHERE state IN ('pending', 'processing')"
)
_DEAD_SQL = text("SELECT count(*) FROM sync_outbox WHERE state = 'dead_letter'")
_EXPIRING_SQL = text(
    "SELECT count(*) FROM credentials WHERE revoked_at IS NULL AND expires_at IS NOT NULL "
    "AND expires_at < now() + make_interval(days => :days)"
)

_last_refresh = 0.0


async def refresh_db_gauges(session: AsyncSession, *, min_interval: float = 5.0) -> dict[str, Any]:
    """Recompute the gauges that come from the database. Returns the values for the health page.

    Throttled to once per ``min_interval`` seconds per process; failures are logged and swallowed
    (a scrape must work even while the database is unavailable).
    """
    global _last_refresh  # noqa: PLW0603 - process-wide throttle
    now = time.monotonic()
    values: dict[str, Any] = {}
    if now - _last_refresh < min_interval:
        return values
    _last_refresh = now
    try:
        for queue, count in (await session.execute(_QUEUE_SQL)).all():
            QUEUE_DEPTH.labels(queue=queue).set(count)
            values.setdefault("queue_depth", {})[queue] = count
    except Exception as exc:  # noqa: BLE001 - the procrastinate table may not exist yet
        await session.rollback()
        log.warning("queue_gauge_failed", error=str(exc)[:200])
    try:
        oldest = (await session.execute(_OLDEST_SQL)).scalar()
        age = 0.0
        if oldest is not None:
            age = max(0.0, time.time() - oldest.timestamp())
        OLDEST_QUEUED_AGE.set(age)
        values["oldest_queued_job_age_seconds"] = age
        lag_from = (await session.execute(_IMPORT_LAG_SQL)).scalar()
        lag = 0.0 if lag_from is None else max(0.0, time.time() - lag_from.timestamp())
        IMPORT_LAG.set(lag)
        values["import_lag_seconds"] = lag
        dead = int((await session.execute(_DEAD_SQL)).scalar() or 0)
        IMPORT_DEAD_LETTERS.set(dead)
        values["import_dead_letters"] = dead
        days = get_settings().credential_expiry_alert_days
        expiring = int((await session.execute(_EXPIRING_SQL, {"days": days})).scalar() or 0)
        CREDENTIALS_EXPIRING.set(expiring)
        values["credentials_expiring"] = expiring
    except Exception as exc:  # noqa: BLE001
        await session.rollback()
        log.warning("db_gauge_failed", error=str(exc)[:200])
    values["disk_used_ratio"] = update_disk_gauges()
    return values


def snapshot() -> dict[str, list[dict[str, Any]]]:
    """All samples of the registry as JSON-friendly data (``GET /api/v1/admin/health``)."""
    result: dict[str, list[dict[str, Any]]] = {}
    for family in REGISTRY.collect():
        samples = [
            {"labels": dict(sample.labels), "value": sample.value}
            for sample in family.samples
            if not sample.name.endswith(("_bucket", "_created"))
        ]
        if samples:
            result[family.name] = samples
    return result
