"""Monthly scanner image update proposals (plan M11 task 3).

``image_update_proposals`` (registered in ``maintenance.py``, 04:00 on the 1st of the month) calls the hook
below: it reads ``deploy/images.lock.yaml``, asks each registry through the egress proxy what the tag of
every image points to now and which newer tag exists, stores new digests as ``ImageVersion`` proposals and
queues one regression test per runtime image (``jobs/regression.py``). An Admin approves in Settings
(``api/image_versions.py``); the catalogue loader then overlays the approved digest.

The logic (tag series, storing, approving) is in
``securescan/domain/image_updates.py``; this module only wires it to the queue and the proxy.
"""

from __future__ import annotations

import time
from typing import Any

from prometheus_client import Gauge
from sqlalchemy import func, select

from securescan.config import get_settings
from securescan.db.models.images import ImageVersion
from securescan.db.session import session_scope
from securescan.domain.image_updates import (
    SOURCE_PROPOSAL,
    STATIC_RUNTIME_LOCKS,
    ProposalSummary,
    egress_hosts_for,
    load_lock_images,
    primary_tool_by_lock,
    run_proposals,
)
from securescan.integrations.registry import RegistryClient
from securescan.jobs.enqueue import defer
from securescan.jobs.hooks import periodic_hook
from securescan.jobs.regression import image_regression
from securescan.logging import get_logger
from securescan.observability.metrics import REGISTRY
from securescan.runner.catalogue import find_scanners_dir
from securescan.runner.egress import egress_lease

log = get_logger(__name__)

PENDING_PROPOSALS = Gauge(
    "securescan_image_proposals_pending",
    "Image update proposals waiting for an Admin decision",
    registry=REGISTRY,
)


def catalogue_locks() -> dict[str, str]:
    """``{lock name: catalogue tool}`` for every catalogue entry that names a lock (empty when the catalogue is unavailable)."""
    from securescan.runner.catalogue import CatalogueError, catalogue_available, load_catalogue

    if not catalogue_available():
        return {}
    try:
        entries = load_catalogue()
    except (CatalogueError, OSError):
        return {}
    return primary_tool_by_lock(entries)


async def count_pending() -> int:
    async with session_scope() as session:
        total = await session.scalar(
            select(func.count())
            .select_from(ImageVersion)
            .where(
                ImageVersion.source == SOURCE_PROPOSAL,
                ImageVersion.active.is_(False),
                ImageVersion.approved_at.is_(None),
            )
        )
    return int(total or 0)


async def run_image_update_proposals() -> ProposalSummary:
    """One proposal run: registry lookups, new rows, regression tests queued. Safe to run twice."""
    settings = get_settings()
    images = load_lock_images(find_scanners_dir(settings))
    if not images:
        log.warning("image_updates_no_lock_file")
        summary = ProposalSummary()
        summary.notes.append("deploy/images.lock.yaml could not be found, so nothing was checked.")
        return summary
    by_lock = catalogue_locks()
    runtime = set(STATIC_RUNTIME_LOCKS) | set(by_lock)
    async with egress_lease(egress_hosts_for(images)) as proxy_url:
        registry = RegistryClient(
            proxy_url=proxy_url or None,
            timeout=settings.image_registry_timeout_seconds,
            max_tag_pages=settings.image_update_max_tag_pages,
        )
        try:
            summary = await run_proposals(
                session_scope, registry, images, tool_by_lock=by_lock, runtime_locks=runtime
            )
        finally:
            await registry.aclose()
    for item in summary.new:
        if item.job_tool is None:
            continue
        await defer(
            image_regression,
            lock="regression",
            queueing_lock="image_regression:%s" % item.id,
            image_version_id=str(item.id),
        )
    PENDING_PROPOSALS.set(await count_pending())
    log.info(
        "image_updates_done",
        checked=summary.checked,
        new=len(summary.new),
        already_known=summary.already_known,
        notes=len(summary.notes),
    )
    for note in summary.notes:
        log.info("image_updates_note", note=note)
    return summary


@periodic_hook("image_update_proposals")
async def propose_image_updates(timestamp: int) -> None:
    await run_image_update_proposals()


async def queue_check_now() -> int | None:
    """Queue a proposal run now (the Settings button). Collapses with a run that is already waiting."""
    from securescan.jobs.maintenance import image_update_proposals

    task: Any = image_update_proposals
    return await defer(task, queueing_lock="image_update_proposals", timestamp=int(time.time()))


async def queue_regression(image_version_id: str) -> int | None:
    """Queue the regression test of one proposal again (the Settings button)."""
    return await defer(
        image_regression,
        lock="regression",
        queueing_lock="image_regression:%s" % image_version_id,
        image_version_id=image_version_id,
    )
