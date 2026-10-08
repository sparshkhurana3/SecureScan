"""``python -m securescan migrate``: apply Alembic migrations to head, then run the seeders.

The Alembic configuration is built in code (the container image does not ship ``alembic.ini``);
``backend/alembic.ini`` exists for developers running ``alembic check`` or ``alembic revision``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from alembic import command
from alembic.config import Config

from securescan.config import get_settings
from securescan.db.engine import dispose_engine
from securescan.db.seed import run_seeders
from securescan.logging import configure_logging, get_logger

log = get_logger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return config


async def _seed() -> list[str]:
    try:
        return await run_seeders()
    finally:
        await dispose_engine()


def run() -> int:
    configure_logging(get_settings().log_level)
    log.info("migrate_start")
    command.upgrade(alembic_config(), "head")
    seeded = asyncio.run(_seed())
    log.info("migrate_done", seeders=seeded)
    return 0
