"""Administration: system health for the Settings page (the gateway does not proxy /metrics)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import text

from securescan import __version__
from securescan.auth.roles import AdminUser
from securescan.db.session import DbSession
from securescan.observability import metrics

router = APIRouter(tags=["admin"])


class HealthOut(BaseModel):
    status: str
    version: str
    database: str
    values: dict[str, Any]
    metrics: dict[str, list[dict[str, Any]]]


@router.get("/admin/health", response_model=HealthOut, summary="System health (Admin)")
async def admin_health(db: DbSession, user: AdminUser) -> HealthOut:
    """The same values as ``/metrics`` as JSON. Worker-side gauges are only on the worker's port."""
    database = "ok"
    try:
        await db.execute(text("select 1"))
    except Exception:  # noqa: BLE001 - reported, not raised
        database = "unavailable"
    values: dict[str, Any] = {}
    if database == "ok":
        values = await metrics.refresh_db_gauges(db, min_interval=0.0)
    return HealthOut(
        status="ok" if database == "ok" else "degraded",
        version=__version__,
        database=database,
        values=values,
        metrics=metrics.snapshot(),
    )
