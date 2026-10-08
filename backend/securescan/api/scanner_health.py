"""Scanner health (Admin): image digests, approved images, last runs and the age of every content feed.

``GET /api/v1/scanner-health`` backs the Settings page of the same name (plan M8 task 8, design FR-26). The API
container may not have the scanner catalogue or the pinned image variables (they belong to the worker); then the
tool list falls back to the tools that ever ran and the digest of their last job. Reading the page also refreshes
the feed-age gauges of the API process.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from securescan.auth.roles import AdminUser
from securescan.db.models.jobs import ScanJob
from securescan.db.session import DbSession
from securescan.jobs.scanner_health import (
    FEED_TOOLS,
    approved_images,
    last_runs_by_tool,
    refresh_feed_clocks,
)
from securescan.runner.catalogue import CatalogueEntry, CatalogueError, load_catalogue, resolve_image
from securescan.util import utcnow

router = APIRouter(tags=["scanner-health"])


class ApprovedImageOut(BaseModel):
    image: str
    tag: str | None
    digest: str
    approved_at: datetime | None


class ToolHealthOut(BaseModel):
    tool: str
    role: str = Field(description="scanner: a job tool of a profile; support: an image the platform runs for it")
    description: str = ""
    image: str | None = None
    tag: str | None = None
    digest: str | None = Field(default=None, description="The digest this installation runs (pinned)")
    digest_source: str | None = Field(default=None, description="override, env, catalogue, lock, tag or unresolved")
    last_job_digest: str | None = Field(default=None, description="Digest recorded by the newest job of the tool")
    approved_image: ApprovedImageOut | None = None
    max_parallel: int | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    feed: str | None = Field(default=None, description="The content feed the tool reads, if any")


class FeedHealthOut(BaseModel):
    feed: str
    label: str
    tool: str
    version: str | None
    path: str | None
    source_commit: str | None
    built_at: datetime | None
    fetched_at: datetime | None
    activated_at: datetime | None
    age_seconds: float | None
    limit_days: int
    stale: bool
    regression_result: str | None
    update_failed: bool


class ScannerHealthOut(BaseModel):
    status: str = Field(description="ok, or attention when a feed is stale or an update failed")
    generated_at: datetime
    tools: list[ToolHealthOut]
    feeds: list[FeedHealthOut]
    notes: list[str]


async def last_job_digests(db: Any) -> dict[str, str]:
    """The ``image_digest`` of each tool's newest job that recorded one."""
    newest = (
        select(ScanJob.tool, func.max(ScanJob.created_at).label("moment"))
        .where(ScanJob.image_digest.is_not(None))
        .group_by(ScanJob.tool)
        .subquery()
    )
    rows = await db.execute(
        select(ScanJob.tool, ScanJob.image_digest).join(
            newest, (ScanJob.tool == newest.c.tool) & (ScanJob.created_at == newest.c.moment)
        )
    )
    return {str(tool): str(digest) for tool, digest in rows.all() if digest}


def tool_row(
    tool: str,
    entry: CatalogueEntry | None,
    runs: dict[str, dict[str, datetime | None]],
    digests: dict[str, str],
    approved: dict[str, Any],
) -> ToolHealthOut:
    row = ToolHealthOut(tool=tool, role="scanner")
    feed_for_tool = {value: feed for feed, value in FEED_TOOLS.items()}
    row.feed = feed_for_tool.get(tool)
    row.last_job_digest = digests.get(tool)
    last = runs.get(tool) or {}
    row.last_success_at = last.get("success")
    row.last_failure_at = last.get("failure")
    chosen = approved.get(tool)
    if chosen is not None:
        row.approved_image = ApprovedImageOut(
            image=chosen.image, tag=chosen.tag, digest=chosen.digest, approved_at=chosen.approved_at
        )
    if entry is None:
        return row
    row.role = "scanner" if entry.target_kinds else "support"
    row.description = entry.description
    row.max_parallel = entry.max_parallel
    row.image = entry.image.name
    row.tag = entry.image.tag
    try:
        resolved = resolve_image(entry)
    except CatalogueError:
        row.digest_source = "unresolved"
    else:
        row.digest = resolved.digest
        row.digest_source = resolved.source
    if chosen is not None:
        row.digest = chosen.digest
        row.digest_source = "override"
    return row


@router.get("/scanner-health", response_model=ScannerHealthOut, summary="Scanner health (Admin)")
async def scanner_health(db: DbSession, user: AdminUser) -> ScannerHealthOut:
    """Per tool: configured image and digest, approved image, last successful and failed run; per feed: version,
    age and limit. A feed older than its limit (7 days for databases, 30 for rules and templates) is stale."""
    notes: list[str] = []
    try:
        catalogue = load_catalogue()
    except CatalogueError:
        catalogue = {}
        notes.append("The scanner catalogue is not available to the API; digests come from the newest job of each tool.")
    runs = await last_runs_by_tool(db)
    digests = await last_job_digests(db)
    approved = await approved_images(db)
    names = sorted({*catalogue, *runs, *digests})
    tools = [tool_row(name, catalogue.get(name), runs, digests, approved) for name in names]
    tools.sort(key=lambda t: (t.role != "scanner", t.tool))
    statuses = await refresh_feed_clocks(db)
    feeds = [FeedHealthOut(**asdict(status)) for status in statuses.values()]
    attention = [f.label for f in feeds if f.stale or f.update_failed]
    if attention:
        notes.append("Needs attention: " + ", ".join(attention) + ".")
    return ScannerHealthOut(
        status="attention" if attention else "ok",
        generated_at=utcnow(),
        tools=tools,
        feeds=feeds,
        notes=notes,
    )
