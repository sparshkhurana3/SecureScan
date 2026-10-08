"""Session helpers: the FastAPI dependency and a standalone transaction scope for jobs."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.db.engine import get_sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency. It never commits: call ``await session.commit()`` in the endpoint.

    (Since FastAPI 0.118 the exit code of a yield dependency runs after the response is sent, so a
    commit there would race with the client.) Uncommitted work is rolled back when the session closes.
    """
    async with get_sessionmaker()() as session:
        yield session


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """One transaction for jobs and scripts: commits on success, rolls back on any error."""
    async with get_sessionmaker()() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise


DbSession = Annotated[AsyncSession, Depends(get_session)]
