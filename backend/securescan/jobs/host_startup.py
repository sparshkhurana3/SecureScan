"""Worker start-up work of M11: the host check and the backup-age gauge.

``securescan/runner/host_check.py`` holds the logic. This module only registers it with the worker
(``load_tasks()`` imports every module of ``securescan/jobs/``).

* ``verify_host``: cgroup v2, kernel limits and the Docker version, seen from inside the container.
  With ``SECURESCAN_HOST_CHECK=enforce`` (the production default) a failed blocking check raises, the
  worker exits with the reason in its log and starts no scan.
* ``start_backup_gauge``: reads the status file that ``scripts/backup.sh`` leaves on the data volume
  and keeps ``securescan_backup_last_success_timestamp`` current (every 5 minutes).
"""

from __future__ import annotations

import asyncio

from securescan.config import get_settings
from securescan.jobs.hooks import worker_startup_hook
from securescan.logging import get_logger
from securescan.runner.host_check import enforce_host_check, refresh_backup_gauge

log = get_logger(__name__)

BACKUP_GAUGE_SECONDS = 300.0
_BACKGROUND: set[asyncio.Task[None]] = set()


@worker_startup_hook
async def verify_host() -> None:
    """Refuse to work on a host that cannot enforce container limits (see ``host_check_mode``)."""
    await enforce_host_check(get_settings())


async def _backup_gauge_loop() -> None:
    while True:
        try:
            refresh_backup_gauge(get_settings())
        except Exception as exc:  # noqa: BLE001 - a bad status file must never stop the worker
            log.warning("backup_gauge_failed", error=type(exc).__name__)
        await asyncio.sleep(BACKUP_GAUGE_SECONDS)


@worker_startup_hook
async def start_backup_gauge() -> None:
    status = refresh_backup_gauge(get_settings())
    log.info("backup_status", last_success=status.last_success if status else None)
    task = asyncio.get_running_loop().create_task(_backup_gauge_loop())
    _BACKGROUND.add(task)
    task.add_done_callback(_BACKGROUND.discard)
