"""Seeders: idempotent data that must exist after every migration (profiles, built-in template, ...).

A seeder is a module in ``securescan/db/seeds/`` with ``async def seed(session: AsyncSession) -> None``.
``python -m securescan migrate`` runs all of them, in file-name order, after the schema is at head,
each in its own transaction. A seeder must be safe to run on every start (insert what is missing,
never overwrite what an Admin changed).
"""

from __future__ import annotations

import importlib
import pkgutil

import securescan.db.seeds as seeds_package
from securescan.db.session import session_scope
from securescan.logging import get_logger

log = get_logger(__name__)


async def run_seeders() -> list[str]:
    ran: list[str] = []
    for info in sorted(pkgutil.iter_modules(seeds_package.__path__), key=lambda m: m.name):
        module = importlib.import_module(f"{seeds_package.__name__}.{info.name}")
        seed = getattr(module, "seed", None)
        if not callable(seed):
            continue
        async with session_scope() as db:
            await seed(db)
        log.info("seeded", seeder=info.name)
        ran.append(info.name)
    return ran
