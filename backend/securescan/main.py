"""FastAPI application factory."""

from __future__ import annotations

import psycopg
from fastapi import FastAPI, Response, status
from sqlalchemy.engine import make_url

from securescan.config import get_settings


def _conninfo() -> str:
    settings = get_settings()
    url = make_url(settings.database_url).set(drivername="postgresql")
    if settings.database_password and not url.password:
        url = url.set(password=settings.database_password)
    return url.render_as_string(hide_password=False)


def create_app() -> FastAPI:
    app = FastAPI(title="SecureScan", version="0.1.0", docs_url=None, redoc_url=None)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(response: Response) -> dict[str, str]:
        try:
            async with await psycopg.AsyncConnection.connect(_conninfo(), connect_timeout=3) as conn:
                await conn.execute("select 1")
        except Exception:  # noqa: BLE001 - readiness reports any failure as not ready
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "database unavailable"}
        return {"status": "ready"}

    return app


app = create_app()
