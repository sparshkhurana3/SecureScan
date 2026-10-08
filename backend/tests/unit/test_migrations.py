"""The initial migration must describe exactly the tables the models define.

The migration file is parsed with ``ast`` (it is never imported or run here), so this test needs
no database. Tables, columns, nullability, index and unique-constraint names and the PostgreSQL
enum types are compared. ``alembic check`` against a real database (``dev.py migrate`` first) is
the complete drift test.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from sqlalchemy import UniqueConstraint

import securescan.db.models  # noqa: F401 - registers the tables
from securescan.db.base import Base
from securescan.db.models.enums import PG_ENUM_NAMES

VERSIONS = Path(__file__).resolve().parents[2] / "securescan" / "db" / "migrations" / "versions"
INITIAL = VERSIONS / "0001_initial_schema.py"


def _const(node: ast.AST) -> Any:
    return node.value if isinstance(node, ast.Constant) else None


def _attr_call(node: ast.AST, owner: str, attr: str) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == attr
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == owner
    )


class Parsed:
    def __init__(self) -> None:
        self.columns: dict[str, dict[str, bool]] = {}
        self.uniques: dict[str, set[str]] = {}
        self.indexes: dict[str, set[str]] = {}
        self.enums: dict[str, list[str]] = {}
        tree = ast.parse(INITIAL.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if _attr_call(node, "op", "create_table"):
                assert isinstance(node, ast.Call)
                table = _const(node.args[0])
                self.columns[table] = {}
                self.uniques[table] = set()
                self.indexes.setdefault(table, set())
                for arg in node.args[1:]:
                    if _attr_call(arg, "sa", "Column"):
                        assert isinstance(arg, ast.Call)
                        nullable = {k.arg: _const(k.value) for k in arg.keywords}.get("nullable")
                        self.columns[table][_const(arg.args[0])] = bool(nullable)
                    elif _attr_call(arg, "sa", "UniqueConstraint"):
                        assert isinstance(arg, ast.Call)
                        names = {k.arg: _const(k.value) for k in arg.keywords}
                        self.uniques[table].add(names["name"])
            elif _attr_call(node, "op", "create_index"):
                assert isinstance(node, ast.Call)
                self.indexes.setdefault(_const(node.args[1]), set()).add(_const(node.args[0]))
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "ENUM"
            ):
                names = {k.arg: _const(k.value) for k in node.keywords}
                self.enums[names["name"]] = [_const(a) for a in node.args]


def test_initial_migration_creates_exactly_the_model_tables() -> None:
    parsed = Parsed()
    assert set(parsed.columns) == set(Base.metadata.tables)


def test_columns_and_nullability_match() -> None:
    parsed = Parsed()
    for name, table in Base.metadata.tables.items():
        model_columns = {c.name: c.nullable for c in table.columns}
        assert parsed.columns[name] == model_columns, name


def test_indexes_and_unique_constraints_match() -> None:
    parsed = Parsed()
    for name, table in Base.metadata.tables.items():
        model_indexes = {i.name for i in table.indexes}
        assert parsed.indexes.get(name, set()) == model_indexes, name
        model_uniques = {
            c.name for c in table.constraints if isinstance(c, UniqueConstraint) and c.name
        }
        assert parsed.uniques[name] == model_uniques, name


def test_enum_types_match_the_python_enums() -> None:
    parsed = Parsed()
    assert set(parsed.enums) == set(PG_ENUM_NAMES)
    for pg_name, enum_cls in PG_ENUM_NAMES.items():
        assert parsed.enums[pg_name] == [m.value for m in enum_cls], pg_name


def test_model_enum_columns_use_the_declared_type_names() -> None:
    for table in Base.metadata.tables.values():
        for column in table.columns:
            enum_name = getattr(column.type, "name", None)
            if getattr(column.type, "enums", None):
                assert enum_name in PG_ENUM_NAMES, (table.name, column.name)


def test_identifier_names_fit_postgresql() -> None:
    parsed = Parsed()
    for names in [*parsed.indexes.values(), *parsed.uniques.values()]:
        for name in names:
            assert len(name) <= 63, name


def test_revision_chain_is_linear_and_complete() -> None:
    revisions: dict[str, str | None] = {}
    for path in sorted(VERSIONS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        values = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                values[node.targets[0].id] = _const(node.value)
        revisions[values["revision"]] = values["down_revision"]
    assert revisions["0001"] is None
    assert revisions["0002"] == "0001"
    heads = set(revisions) - {v for v in revisions.values() if v}
    assert len(heads) == 1


def test_procrastinate_revision_reads_the_installed_schema() -> None:
    text = (VERSIONS / "0002_procrastinate_schema.py").read_text(encoding="utf-8")
    assert 'resources.files("procrastinate")' in text
    assert "schema.sql" in text
