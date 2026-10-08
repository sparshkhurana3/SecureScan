"""Seed the scan profiles from ``scanners/profiles/*.yaml`` (see ``securescan/runner/profiles.py``)."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from securescan.logging import get_logger
from securescan.runner.profiles import seed_profiles

log = get_logger(__name__)


async def seed(session: AsyncSession) -> None:
    inserted = await seed_profiles(session)
    if inserted:
        log.info("profiles_seeded", profiles=inserted)
