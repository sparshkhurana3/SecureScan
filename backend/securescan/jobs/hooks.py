"""Extension points for later milestones, so ``maintenance.py`` never needs editing.

Periodic tasks (``github_poll``, ``grype_db_update``, ...) are registered once, in ``maintenance.py``,
as thin wrappers that call ``run_periodic(<name>, timestamp)``. A later milestone supplies the real
logic by registering a hook under the same name in its own module::

    from securescan.jobs.hooks import periodic_hook

    @periodic_hook("github_poll")
    async def poll_repositories(timestamp: int) -> None: ...

Worker start-up work (for example reading the daemon-side data path, checking the host) registers
with ``@worker_startup_hook`` and runs once before the worker takes jobs.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from securescan.logging import get_logger
from securescan.observability.metrics import PERIODIC_RUNS

log = get_logger(__name__)

PeriodicHook = Callable[[int], Awaitable[None]]
StartupHook = Callable[[], Awaitable[None]]

_PERIODIC: dict[str, PeriodicHook] = {}
_STARTUP: list[StartupHook] = []

# The periodic task names of plan M2 task 2 (plus ``session_cleanup``, implemented in M2).
PERIODIC_TASK_NAMES = (
    "stalled_jobs",
    "workspace_gc",
    "history_state_refresh",
    "github_discovery",
    "github_poll",
    "grype_db_update",
    "nvd_update",
    "rules_and_templates_update",
    "image_update_proposals",
    "account_expiry",
    "credential_expiry_alerts",
    "sonarqube_idle_stop",
    "egress_idle_stop",
)


def periodic_hook(name: str) -> Callable[[PeriodicHook], PeriodicHook]:
    """Register the implementation of the periodic task ``name`` (one hook per name)."""
    if name not in PERIODIC_TASK_NAMES:
        raise ValueError(f"unknown periodic task {name!r}")

    def decorator(func: PeriodicHook) -> PeriodicHook:
        _PERIODIC[name] = func
        return func

    return decorator


def has_periodic_hook(name: str) -> bool:
    return name in _PERIODIC


async def run_periodic(name: str, timestamp: int) -> bool:
    """Run the hook registered for ``name``; a no-op returning False when there is none yet."""
    PERIODIC_RUNS.labels(task=name).inc()
    hook = _PERIODIC.get(name)
    if hook is None:
        log.debug("periodic_noop", task=name)
        return False
    log.info("periodic_start", task=name)
    await hook(timestamp)
    log.info("periodic_done", task=name)
    return True


def worker_startup_hook(func: StartupHook) -> StartupHook:
    _STARTUP.append(func)
    return func


async def run_startup_hooks() -> None:
    for hook in list(_STARTUP):
        log.info("worker_startup_hook", hook=getattr(hook, "__name__", "?"))
        await hook()
