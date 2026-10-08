"""Declarative base, naming convention and the enum helper shared by every model."""

from __future__ import annotations

import enum
from typing import Any

from sqlalchemy import Enum, MetaData
from sqlalchemy.orm import DeclarativeBase

from securescan.util import new_id, utcnow

# Constraint names are explicit in the migrations and follow this convention, so ``alembic check``
# finds no drift. PostgreSQL limits identifiers to 63 characters.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class of all models. Do not name a column ``metadata`` (reserved by SQLAlchemy)."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _enum_values(enum_cls: type[enum.Enum]) -> list[str]:
    return [member.value for member in enum_cls]


def pg_enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    """A native PostgreSQL enum column type whose labels are the Python enum *values*."""
    kwargs: dict[str, Any] = {"name": name, "values_callable": _enum_values}
    return Enum(enum_cls, validate_strings=True, **kwargs)


__all__ = ["NAMING_CONVENTION", "Base", "new_id", "pg_enum", "utcnow"]
