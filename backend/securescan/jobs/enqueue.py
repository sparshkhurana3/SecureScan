"""Enqueue helpers.

Procrastinate defers jobs through its own connection pool, which cannot join a SQLAlchemy
transaction. The reliable pattern is therefore *state first, queue second*:

1. In one transaction write the domain row (for example ``ScanJob`` with ``state=queued``) and
   ``await session.commit()``.
2. Then ``await defer(task, ..., **kwargs)``.
3. If the process dies between 1 and 2, the periodic ``stalled_jobs`` task re-defers rows that are
   still ``queued`` without a live Procrastinate job. ``queueing_lock`` makes the re-defer
   idempotent (the second defer is refused with ``AlreadyEnqueued`` and ``defer`` returns None).

Every task must therefore be safe to run twice.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from procrastinate.exceptions import AlreadyEnqueued

from securescan.logging import get_logger

if TYPE_CHECKING:
    from procrastinate.tasks import Task

log = get_logger(__name__)


async def defer(
    task: Task,
    *,
    lock: str | None = None,
    queueing_lock: str | None = None,
    schedule_at: datetime | None = None,
    schedule_in: timedelta | None = None,
    priority: int | None = None,
    **task_kwargs: Any,
) -> int | None:
    """Defer ``task`` with ``task_kwargs`` (JSON-serialisable). Returns the job id, or None when a
    job with the same ``queueing_lock`` is already waiting."""
    options: dict[str, Any] = {}
    if lock is not None:
        options["lock"] = lock
    if queueing_lock is not None:
        options["queueing_lock"] = queueing_lock
    if schedule_at is not None:
        options["schedule_at"] = schedule_at
    if schedule_in is not None:
        options["schedule_in"] = {"seconds": int(schedule_in.total_seconds())}
    if priority is not None:
        options["priority"] = priority
    configured = task.configure(**options) if options else task
    try:
        job_id = await configured.defer_async(**task_kwargs)
    except AlreadyEnqueued:
        log.info("defer_collapsed", task=task.name, queueing_lock=queueing_lock)
        return None
    return int(job_id)
