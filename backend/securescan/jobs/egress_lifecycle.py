"""Egress proxy lifecycle: the periodic idle stop and the worker start-up check.

The proxy itself (start, allowlist, leases) lives in ``securescan/runner/egress.py``. This module wires
it into the worker: ``egress_idle_stop`` (every 5 minutes, registered in ``maintenance.py``) stops the
shared squid container after ``SECURESCAN_EGRESS_IDLE_MINUTES`` without use, and on start-up the
``securescan_egress_proxy_up`` gauge is set from the real container state.
"""

from __future__ import annotations

from securescan.jobs.hooks import periodic_hook, worker_startup_hook
from securescan.logging import get_logger
from securescan.runner.egress import egress_idle_stop, get_egress_manager

log = get_logger(__name__)


@periodic_hook("egress_idle_stop")
async def stop_idle_egress_proxy(timestamp: int) -> None:
    """Stop and remove the shared egress proxy when it has been idle long enough."""
    stopped = await egress_idle_stop()
    if stopped:
        log.info("egress_proxy_stopped_idle")


@worker_startup_hook
async def reconcile_egress_proxy() -> None:
    """Set the proxy gauge from the container's real state (a restart may find it still running)."""
    try:
        running = await get_egress_manager().reconcile()
    except Exception as exc:  # noqa: BLE001 - Docker may not be reachable yet; never block start-up
        log.warning("egress_reconcile_failed", error=type(exc).__name__)
        return
    log.info("egress_reconciled", running=running)
