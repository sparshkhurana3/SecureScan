"""Fixtures for the integration tests (real PostgreSQL, the real FastAPI app, no mocks).

Run with the Compose ``test`` profile up (``python scripts/dev.py up --profile test``; deploy/compose.test.yaml
publishes the database on 127.0.0.1:55432 and DefectDojo on 127.0.0.1:8080) and, from the repository root::

    SECURESCAN_INTEGRATION=1 \\
    SECURESCAN_DATABASE_URL="postgresql+psycopg://securescan@localhost:55432/securescan?sslmode=verify-full&sslrootcert=$PWD/deploy/secrets/tls/ca.crt" \\
    SECURESCAN_DATABASE_PASSWORD=$(cat deploy/secrets/securescan_db_password) \\
    SECURESCAN_MASTER_KEY=$(python -c "import os;print(os.urandom(32).hex())") \\
    DD_URL=http://127.0.0.1:8080 DD_ADMIN_PASSWORD=$(cat deploy/secrets/dd_admin_password) \\
    python scripts/dev.py test integration

(DD_URL and DD_ADMIN_PASSWORD are read by the contract tests.)

Without ``SECURESCAN_INTEGRATION=1`` every test marked ``@pytest.mark.integration`` is skipped.

Fixtures
--------
``migrated_database``  (session) runs the Alembic migrations to head once.
``database``           (function) fresh engine per test (async pools are bound to the test's event
                       loop) and the application's tables emptied afterwards.
``sign_in``            ``await sign_in(role)`` creates a user and a session row directly and returns a
                       ``SignedIn`` with the cookie token and CSRF token.
``api``                an ``httpx.AsyncClient`` talking to the app in-process; ``api_as(role)`` returns
                       a client already carrying that user's cookies and CSRF header.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass

import httpx
import pytest
from sqlalchemy import text

from securescan.auth.session import create_session
from securescan.config import get_settings
from securescan.db.engine import dispose_engine, reset_engine_cache
from securescan.db.models.enums import UserRole
from securescan.db.models.users import User
from securescan.db.session import session_scope
from securescan.util import new_id, utcnow

INTEGRATION = os.environ.get("SECURESCAN_INTEGRATION") == "1"

# Tables emptied between tests (audit_events is append-only; TRUNCATE is not blocked by its trigger).
APPLICATION_TABLES = (
    "sync_outbox, finding_history, reports, report_templates, scan_jobs, scans, schedules, "
    "repository_heads, github_connections, targets, credentials, uploads, artifacts, "
    "application_versions, applications, vendors, policies, scan_profiles, content_versions, "
    "image_versions, sessions, audit_events, users"
)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if INTEGRATION:
        return
    skip = pytest.mark.skip(reason="set SECURESCAN_INTEGRATION=1 and start the compose test profile")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def migrated_database() -> Iterator[None]:
    from alembic import command

    from securescan.db.migrate import alembic_config

    get_settings.cache_clear()
    command.upgrade(alembic_config(), "head")
    yield


@pytest.fixture
async def database(migrated_database: None) -> AsyncIterator[None]:
    reset_engine_cache()
    yield
    async with session_scope() as db:
        await db.execute(text(f"TRUNCATE {APPLICATION_TABLES} CASCADE"))
    await dispose_engine()
    reset_engine_cache()


@dataclass
class SignedIn:
    user_id: uuid.UUID
    role: UserRole
    token: str
    csrf: str


@pytest.fixture
def sign_in(database: None) -> Callable[[UserRole], Awaitable[SignedIn]]:
    async def _sign_in(role: UserRole = UserRole.ANALYST) -> SignedIn:
        async with session_scope() as db:
            user = User(
                id=new_id(),
                oid=f"test-{uuid.uuid4()}",
                name=f"Test {role.value}",
                email=f"{role.value.lower()}@example.com",
                role=role,
                roles=[role.value],
                last_login=utcnow(),
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            db.add(user)
            await db.flush()
            token, row = await create_session(db, user)
            return SignedIn(user_id=user.id, role=role, token=token, csrf=row.csrf_token)

    return _sign_in


@pytest.fixture
async def api(database: None) -> AsyncIterator[httpx.AsyncClient]:
    from securescan.main import create_app

    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as client:
        yield client


@pytest.fixture
def api_as(
    api: httpx.AsyncClient, sign_in: Callable[[UserRole], Awaitable[SignedIn]]
) -> Callable[[UserRole], Awaitable[httpx.AsyncClient]]:
    async def _api_as(role: UserRole = UserRole.ANALYST) -> httpx.AsyncClient:
        who = await sign_in(role)
        settings = get_settings()
        api.cookies.set(settings.session_cookie_name, who.token, domain="testserver")
        api.cookies.set(settings.csrf_cookie_name, who.csrf, domain="testserver")
        api.headers[settings.csrf_header_name] = who.csrf
        return api

    return _api_as
