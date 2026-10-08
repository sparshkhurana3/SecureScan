"""Shared fixtures for the unit tests (no database, no network)."""

from __future__ import annotations

import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from securescan.config import get_settings

TEST_MASTER_KEY = "0123456789abcdef" * 4  # 64 hex characters


def clear_caches() -> None:
    get_settings.cache_clear()
    from securescan.security import secrets as secrets_module

    secrets_module.get_keyring.cache_clear()


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fresh settings per test; artifacts and content roots point into the test's tmp dir."""
    monkeypatch.setenv("SECURESCAN_ARTIFACTS_ROOT", str(tmp_path / "artifacts"))
    monkeypatch.setenv("SECURESCAN_CONTENT_ROOT", str(tmp_path / "content"))
    monkeypatch.setenv("SECURESCAN_DATA_ROOT", str(tmp_path / "data"))
    clear_caches()
    yield
    clear_caches()


@pytest.fixture
def master_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """Configure a master key for tests that encrypt or decrypt secrets."""
    monkeypatch.setenv("SECURESCAN_MASTER_KEY", TEST_MASTER_KEY)
    clear_caches()
    return TEST_MASTER_KEY


class FakeScalars:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)


class FakeSession:
    """The few AsyncSession methods the services use, backed by lists (no database)."""

    def __init__(self, rows: list[Any] | None = None) -> None:
        self.added: list[Any] = []
        self.rows: list[Any] = rows or []
        self.executed: list[Any] = []
        self.commits = 0
        self.last_statement: Any = None

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        return None

    async def scalar(self, stmt: Any) -> Any:
        self.last_statement = stmt
        if self.rows:
            return self.rows[0]
        return self.added[0] if self.added else None

    async def scalars(self, stmt: Any) -> FakeScalars:
        self.last_statement = stmt
        return FakeScalars(self.rows)

    async def get(self, model: Any, ident: Any) -> Any:
        for obj in [*self.added, *self.rows]:
            if getattr(obj, "id", None) == ident:
                return obj
        return None

    async def execute(self, stmt: Any, *args: Any, **kwargs: Any) -> Any:
        self.executed.append(stmt)
        return types.SimpleNamespace(rowcount=0)


@pytest.fixture
def fake_session() -> FakeSession:
    return FakeSession()
