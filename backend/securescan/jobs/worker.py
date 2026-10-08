"""The worker process: Procrastinate worker plus a Prometheus metrics server.

``python -m securescan worker`` calls ``run()``. It exposes metrics on
``SECURESCAN_WORKER_METRICS_PORT`` (default 9100, internal to the Compose network), imports every task
module, runs the registered start-up hooks, then works the queues until it receives SIGTERM.
"""

from __future__ import annotations

import asyncio

from prometheus_client import start_http_server

from securescan.config import get_settings
from securescan.jobs.app import QUEUES, app, load_tasks
from securescan.jobs.hooks import run_startup_hooks
from securescan.logging import configure_logging, get_logger
from securescan.observability.metrics import REGISTRY, UP

log = get_logger(__name__)


async def _serve() -> None:
    settings = get_settings()
    async with app.open_async():
        await run_startup_hooks()
        log.info(
            "worker_started",
            queues=QUEUES,
            concurrency=settings.worker_concurrency,
            tasks=sorted(app.tasks),
        )
        await app.run_worker_async(
            queues=QUEUES,
            concurrency=settings.worker_concurrency,
            name="securescan-worker",
        )


def run() -> int:
    settings = get_settings()
    configure_logging(settings.log_level)
    modules = load_tasks()
    log.info("tasks_loaded", modules=modules)
    start_http_server(settings.worker_metrics_port, addr=settings.worker_metrics_host, registry=REGISTRY)
    UP.labels(component="worker").set(1)
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        pass
    return 0
