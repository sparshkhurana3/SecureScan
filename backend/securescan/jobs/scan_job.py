"""The ``scan_job`` task: runs one tool job of a scan (queue ``scans``).

The work is in ``securescan/runner/executor.py``; this module is the Procrastinate shell:

* ``scan_job(job_id)`` calls ``execute_job``. Only launcher and Docker exceptions leave it (they are
  retried, ``RetryStrategy(max_attempts=2)``); a tool's exit code, a bad report or an unreachable
  repository end the job as ``failed`` with the reason on the job and the task returns normally.
* the periodic hooks ``stalled_jobs`` (every 5 minutes) and ``workspace_gc`` (hourly), and a worker
  start-up hook, give the crash recovery of ``runner/recovery.py`` (plan M3 task 4).

Locks are chosen when the job is deferred (``domain/scans.py``): ``queueing_lock`` per application,
version, target, tool and source reference; ``lock`` ``tool:<name>:<slot>`` (``slot = job id mod
max_parallel``) so that a tool never exceeds its cap; ``dast`` for DAST tools.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

from procrastinate import RetryStrategy

from securescan.jobs.app import app
from securescan.jobs.hooks import periodic_hook, worker_startup_hook
from securescan.logging import bind_job_context, clear_job_context, get_logger
from securescan.runner.executor import execute_job
from securescan.runner.launcher import LauncherError

log = get_logger(__name__)

MAX_ATTEMPTS = 2
WORKER_NAME = "securescan-worker"


def is_last_attempt(attempts: int) -> bool:
    """``attempts`` is how many times Procrastinate already ran the job (0 on the first run)."""
    return attempts + 1 >= MAX_ATTEMPTS


@app.task(
    name="scan_job",
    queue="scans",
    pass_context=True,
    retry=RetryStrategy(max_attempts=MAX_ATTEMPTS, exponential_wait=30, retry_exceptions={LauncherError}),
)
async def scan_job(context: Any, job_id: str) -> None:
    """Run one ``ScanJob``. Idempotent: a finished job is left alone."""
    job = getattr(context, "job", None)
    attempts = int(getattr(job, "attempts", 0) or 0)
    procrastinate_id = getattr(job, "id", None)
    bind_job_context(job_id=job_id)
    try:
        await execute_job(
            uuid.UUID(job_id),
            last_attempt=is_last_attempt(attempts),
            procrastinate_job_id=int(procrastinate_id) if procrastinate_id is not None else None,
            worker_name=WORKER_NAME,
        )
    finally:
        clear_job_context()


@periodic_hook("stalled_jobs")
async def recover_stalled_jobs(timestamp: int) -> None:
    """Re-queue or fail jobs whose worker stopped; re-defer queued jobs lost before the defer."""
    from securescan.runner.recovery import recover_jobs

    await recover_jobs()


@periodic_hook("workspace_gc")
async def collect_workspaces(timestamp: int) -> None:
    """Delete workspace directories older than 24 hours that no live job owns."""
    from securescan.runner.recovery import gc_workspaces

    await gc_workspaces()


@worker_startup_hook
async def recover_at_startup() -> None:
    """After a restart no job of this worker is alive: sort out whatever was in flight."""
    from securescan.runner.recovery import recover_jobs

    if os.environ.get("PYTEST_CURRENT_TEST"):  # unit tests run the registered start-up hooks without a database
        return
    try:
        await recover_jobs(stale_after_s=0)
    except Exception as exc:  # noqa: BLE001 - the periodic task retries; the worker must still start
        log.warning("startup_recovery_failed", error=type(exc).__name__)
