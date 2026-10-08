"""Database engine and connection settings (async SQLAlchemy, psycopg 3)."""

from __future__ import annotations

from functools import lru_cache

from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from securescan.config import get_settings


def build_url() -> URL:
    """SQLAlchemy URL for the main database, with the password from ``DATABASE_PASSWORD(_FILE)``."""
    settings = get_settings()
    url = make_url(settings.database_url)
    if url.drivername in ("postgresql", "postgres"):
        url = url.set(drivername="postgresql+psycopg")
    if settings.database_password and not url.password:
        url = url.set(password=settings.database_password)
    return url


def psycopg_conninfo() -> str:
    """libpq connection URI for psycopg and Procrastinate (no SQLAlchemy driver suffix)."""
    url = build_url().set(drivername="postgresql")
    return url.render_as_string(hide_password=False)


@lru_cache
def get_engine() -> AsyncEngine:
    settings = get_settings()
    return create_async_engine(
        build_url(),
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_pool_size,
        pool_pre_ping=True,
    )


@lru_cache
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False)


async def dispose_engine() -> None:
    """Close the connection pool (application shutdown)."""
    if get_engine.cache_info().currsize:
        await get_engine().dispose()


def reset_engine_cache() -> None:
    """Forget the cached engine and sessionmaker (tests that change the settings)."""
    get_sessionmaker.cache_clear()
    get_engine.cache_clear()
