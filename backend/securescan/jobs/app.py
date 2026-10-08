"""The Procrastinate application: job queue on the ``securescan`` PostgreSQL database.

Define a task in any module of ``securescan/jobs/`` (it is imported automatically by
``load_tasks()``, which both the worker and the api call at start)::

    from securescan.jobs.app import app

    @app.task(queue="scans", name="scan_job", retry=RetryStrategy(max_attempts=2, ...),
              pass_context=False)
    async def scan_job(job_id: str) -> None: ...

Queues: ``scans``, ``imports``, ``reports``, ``maintenance``, ``github``. Tasks must be idempotent
and safe to retry. See docs/backend-conventions.md for locks, queueing locks and enqueueing.
"""

from __future__ import annotations

import importlib
import pkgutil

from procrastinate import App, PsycopgConnector

import securescan.jobs as jobs_package
from securescan.db.engine import psycopg_conninfo

QUEUES = ["scans", "imports", "reports", "maintenance", "github"]

# Modules of securescan/jobs that are infrastructure, not task definitions.
_NOT_TASK_MODULES = frozenset({"app", "worker", "enqueue", "hooks"})

app = App(connector=PsycopgConnector(conninfo=psycopg_conninfo()))


def load_tasks() -> list[str]:
    """Import every task module so its ``@app.task`` / ``@app.periodic`` definitions register.

    Returns the module names imported. Import errors are not swallowed: a broken task module must
    stop the worker rather than silently drop its tasks.
    """
    imported: list[str] = []
    for info in sorted(pkgutil.iter_modules(jobs_package.__path__), key=lambda m: m.name):
        if info.name in _NOT_TASK_MODULES or info.name.startswith("_"):
            continue
        importlib.import_module(f"{jobs_package.__name__}.{info.name}")
        imported.append(info.name)
    # hooks must be importable by task modules, so import it explicitly last
    importlib.import_module(f"{jobs_package.__name__}.hooks")
    return imported
