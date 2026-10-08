"""Apply the Procrastinate schema (job queue tables, types, functions, triggers).

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-07

Procrastinate version this revision was written for: 3.10 (``procrastinate>=3.10`` in
pyproject.toml). The SQL is ``procrastinate/sql/schema.sql`` from the *installed* package, read at
migration time and applied verbatim; the installed version is printed so it appears in the migrate
log. When Procrastinate is upgraded, add a NEW revision that applies that release's
``procrastinate/sql/migrations/*.sql`` files in order (see docs/backend-conventions.md); never edit
this one. Downgrading drops the queue tables and types (the functions remain; use a fresh database for a
full reset).
"""

from __future__ import annotations

from importlib import metadata, resources

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def _read_schema() -> str:
    path = resources.files("procrastinate").joinpath("sql", "schema.sql")
    return path.read_text(encoding="utf-8")


def upgrade() -> None:
    version = metadata.version("procrastinate")
    print(f"applying Procrastinate {version} schema.sql")
    sql = _read_schema()
    # Run the script as one multi-statement command on the raw DBAPI connection: no bind-parameter
    # parsing (the script contains ':' and '%'), same transaction as the rest of the migration.
    raw = op.get_bind().connection
    cursor = raw.cursor()
    try:
        cursor.execute(sql)
    finally:
        cursor.close()


def downgrade() -> None:
    for statement in (
        "DROP TABLE IF EXISTS procrastinate_events CASCADE",
        "DROP TABLE IF EXISTS procrastinate_periodic_defers CASCADE",
        "DROP TABLE IF EXISTS procrastinate_jobs CASCADE",
        "DROP TABLE IF EXISTS procrastinate_workers CASCADE",
    ):
        op.execute(statement)
    op.execute("DROP TYPE IF EXISTS procrastinate_job_event_type CASCADE")
    op.execute("DROP TYPE IF EXISTS procrastinate_job_status CASCADE")
