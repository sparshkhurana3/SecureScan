"""Alembic environment (synchronous psycopg engine; the URL comes from SecureScan's settings)."""

from __future__ import annotations

from typing import Any

from alembic import context
from sqlalchemy import create_engine, pool

import securescan.db.models  # noqa: F401 - registers every table on Base.metadata
from securescan.db.base import Base
from securescan.db.engine import build_url

config = context.config
target_metadata = Base.metadata


def include_object(obj: Any, name: str | None, type_: str, reflected: bool, compare_to: Any) -> bool:
    """Procrastinate owns its tables, types and indexes (created by revision 0002); skip them."""
    if type_ == "table":
        return not (name or "").startswith("procrastinate_")
    table = getattr(obj, "table", None)
    if table is not None and table.name.startswith("procrastinate_"):
        return False
    return True


def run_migrations_offline() -> None:
    url = build_url().render_as_string(hide_password=False)
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        include_object=include_object,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(build_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            include_object=include_object,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
