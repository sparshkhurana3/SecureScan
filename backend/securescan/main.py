"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

import psycopg
from fastapi import FastAPI, Response, status

from securescan import __version__
from securescan.api.middleware import RequestMiddleware
from securescan.api.problems import install_problem_handlers
from securescan.api.router import build_api_router
from securescan.config import get_settings
from securescan.db.engine import dispose_engine, psycopg_conninfo
from securescan.db.session import session_scope
from securescan.jobs.app import app as procrastinate_app
from securescan.jobs.app import load_tasks
from securescan.logging import configure_logging, get_logger
from securescan.observability import metrics

log = get_logger(__name__)

OPENAPI_TAGS = [
    {"name": "auth", "description": "Entra ID sign-in, sessions, current user"},
    {"name": "applications", "description": "Application inventory"},
    {"name": "versions", "description": "Application versions"},
    {"name": "targets", "description": "Scan targets (repositories, uploads, images, URLs)"},
    {"name": "vendors", "description": "Vendors"},
    {"name": "uploads", "description": "Chunked, resumable uploads"},
    {"name": "audit", "description": "Audit log (Admin)"},
    {"name": "admin", "description": "Administration and system health (Admin)"},
]


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    metrics.UP.labels(component="api").set(1)
    stack = AsyncExitStack()
    try:
        load_tasks()
        await stack.enter_async_context(procrastinate_app.open_async())
    except Exception as exc:  # noqa: BLE001 - the api still serves reads without the queue
        log.warning("queue_unavailable", error=str(exc)[:300])
    log.info("api_started", version=__version__, env=settings.env)
    try:
        yield
    finally:
        await stack.aclose()
        await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="SecureScan",
        version=__version__,
        description="SecureScan API (RFC 9457 problem details, cursor pagination).",
        openapi_url="/api/v1/openapi.json",
        docs_url="/api/v1/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_tags=OPENAPI_TAGS,
        lifespan=lifespan,
    )
    install_problem_handlers(app)
    app.add_middleware(RequestMiddleware)
    app.include_router(build_api_router())

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(response: Response) -> dict[str, str]:
        try:
            async with await psycopg.AsyncConnection.connect(
                psycopg_conninfo(), connect_timeout=3
            ) as conn:
                await conn.execute("select 1")
        except Exception:  # noqa: BLE001 - readiness reports any failure as not ready
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "database unavailable"}
        return {"status": "ready"}

    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint() -> Response:
        try:
            async with session_scope() as db:
                await metrics.refresh_db_gauges(db)
        except Exception as exc:  # noqa: BLE001 - a scrape must work without the database
            log.warning("metrics_refresh_failed", error=str(exc)[:200])
        return Response(metrics.render_prometheus(), media_type=metrics.CONTENT_TYPE_LATEST)

    return app


app = create_app()
