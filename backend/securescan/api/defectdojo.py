"""DefectDojo integration endpoints: status, import queue (outbox) and account administration."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import Conflict, NotFound, ServiceUnavailable
from securescan.auth.roles import AdminUser, AnalystUser
from securescan.config import get_settings
from securescan.db.models.applications import Application
from securescan.db.models.enums import CredentialKind, ImportState, OutboxState, UserRole
from securescan.db.models.jobs import ScanJob
from securescan.db.models.outbox import SyncOutbox
from securescan.db.models.scans import Scan
from securescan.db.models.users import User
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain.accounts import (
    ACTION_DISABLE,
    ACTION_ENABLE,
    last_activity,
    set_account_active,
)
from securescan.domain.audit import record_audit
from securescan.domain.credentials import get_active_credential_by_kind
from securescan.integrations.defectdojo.client import DefectDojoClient, DefectDojoError
from securescan.integrations.defectdojo.factory import DefectDojoNotConfigured, accounts_client
from securescan.jobs.enqueue import defer
from securescan.jobs.import_job import import_job, import_lock
from securescan.util import utcnow

router = APIRouter(tags=["defectdojo"])


class DefectDojoStatusOut(BaseModel):
    reachable: bool
    http_status: int | None
    latency_ms: int | None
    expected_version: str
    public_url: str
    tokens_ready: bool
    accounts_token_ready: bool
    last_import_at: datetime | None
    queue_depth: int
    oldest_pending_seconds: int | None
    dead_letters: int


class OutboxItemOut(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID
    scan_id: uuid.UUID | None
    tool: str | None
    application_name: str | None
    state: OutboxState
    attempts: int
    next_attempt_at: datetime
    last_error: str | None
    created_at: datetime
    completed_at: datetime | None


class DefectDojoAccountOut(BaseModel):
    user_id: uuid.UUID
    name: str | None
    email: str | None
    role: UserRole
    has_account: bool
    dd_username: str | None
    dd_user_id: int | None
    disabled: bool
    disabled_at: datetime | None
    password_waiting: bool  # the initial password has not been shown yet
    last_login: datetime | None
    expires_at: datetime | None


@router.get(
    "/integrations/defectdojo",
    response_model=DefectDojoStatusOut,
    summary="Is DefectDojo reachable, and how is the import queue",
)
async def defectdojo_status(db: DbSession, user: AnalystUser) -> DefectDojoStatusOut:
    settings = get_settings()
    async with DefectDojoClient(settings.defectdojo_url, None, max_retries=0) as probe:
        reachable, status, seconds = await probe.ping()
    sync_token = await get_active_credential_by_kind(db, CredentialKind.DEFECTDOJO_TOKEN)
    accounts_token = await get_active_credential_by_kind(db, CredentialKind.DEFECTDOJO_ADMIN_TOKEN)
    last_import = await db.scalar(select(func.max(ScanJob.dd_imported_at)))
    waiting = (OutboxState.PENDING, OutboxState.PROCESSING)
    depth = int(
        await db.scalar(select(func.count()).select_from(SyncOutbox).where(SyncOutbox.state.in_(waiting)))
        or 0
    )
    oldest = await db.scalar(select(func.min(SyncOutbox.created_at)).where(SyncOutbox.state.in_(waiting)))
    dead = int(
        await db.scalar(
            select(func.count()).select_from(SyncOutbox).where(SyncOutbox.state == OutboxState.DEAD_LETTER)
        )
        or 0
    )
    return DefectDojoStatusOut(
        reachable=reachable,
        http_status=status,
        latency_ms=int(seconds * 1000) if reachable else None,
        expected_version=settings.defectdojo_version,
        public_url=settings.defectdojo_public_url,
        tokens_ready=sync_token is not None,
        accounts_token_ready=accounts_token is not None,
        last_import_at=last_import,
        queue_depth=depth,
        oldest_pending_seconds=int(time.time() - oldest.timestamp()) if oldest else None,
        dead_letters=dead,
    )


@router.get(
    "/integrations/defectdojo/outbox",
    response_model=CursorPage[OutboxItemOut],
    summary="The import queue (Admin)",
)
async def list_outbox(
    db: DbSession,
    user: AdminUser,
    page: PageDep,
    state: Annotated[OutboxState | None, Query(description="pending, processing, done, dead_letter")] = None,
) -> CursorPage[OutboxItemOut]:
    stmt = select(SyncOutbox)
    if state is not None:
        stmt = stmt.where(SyncOutbox.state == state)
    result = await paginate(db, stmt, key=[SyncOutbox.created_at, SyncOutbox.id], params=page)
    rows: list[SyncOutbox] = result.items
    details: dict[uuid.UUID, tuple[uuid.UUID, str, str]] = {}
    if rows:
        for job_id, scan_id, tool, app_name in (
            await db.execute(
                select(ScanJob.id, ScanJob.scan_id, ScanJob.tool, Application.name)
                .join(Scan, Scan.id == ScanJob.scan_id)
                .join(Application, Application.id == Scan.application_id)
                .where(ScanJob.id.in_([r.job_id for r in rows]))
            )
        ).all():
            details[job_id] = (scan_id, tool, app_name)
    items = []
    for row in rows:
        found = details.get(row.job_id)
        items.append(
            OutboxItemOut(
                id=row.id,
                job_id=row.job_id,
                scan_id=found[0] if found else None,
                tool=found[1] if found else None,
                application_name=found[2] if found else None,
                state=row.state,
                attempts=row.attempts,
                next_attempt_at=row.next_attempt_at,
                last_error=row.last_error,
                created_at=row.created_at,
                completed_at=row.completed_at,
            )
        )
    return CursorPage(items=items, next_cursor=result.next_cursor)


@router.post(
    "/integrations/defectdojo/outbox/{outbox_id}/replay",
    response_model=OutboxItemOut,
    summary="Try a failed import again (Admin)",
)
async def replay_outbox(
    outbox_id: uuid.UUID, request: Request, db: DbSession, user: AdminUser
) -> OutboxItemOut:
    row = await get_or_404(db, SyncOutbox, outbox_id, "Import")
    if row.state not in (OutboxState.DEAD_LETTER, OutboxState.PENDING):
        raise Conflict(
            "Only a failed or waiting import can be replayed.", code="outbox.not_replayable"
        )
    job = await get_or_404(db, ScanJob, row.job_id, "Scan job")
    scan = await get_or_404(db, Scan, job.scan_id, "Scan")
    now = utcnow()
    previous = row.state.value
    row.state = OutboxState.PENDING
    row.attempts = 0
    row.next_attempt_at = now
    row.created_at = now  # a replay gets a fresh 7 days
    row.updated_at = now
    row.payload = {}
    job.import_state = ImportState.PENDING
    await record_audit(
        db, user, "import.replay", "scan_job", job.id, {"outbox_id": str(row.id), "was": previous}, request
    )
    await db.commit()
    await defer(
        import_job,
        lock=import_lock(scan.version_id, job.tool),
        queueing_lock=f"import:{row.id}",
        outbox_id=str(row.id),
    )
    return OutboxItemOut(
        id=row.id,
        job_id=job.id,
        scan_id=scan.id,
        tool=job.tool,
        application_name=None,
        state=row.state,
        attempts=row.attempts,
        next_attempt_at=row.next_attempt_at,
        last_error=row.last_error,
        created_at=row.created_at,
        completed_at=row.completed_at,
    )


# --- accounts (Admin) ------------------------------------------------------------------------------------------------------


def _account_out(user: User, expiry_days: int) -> DefectDojoAccountOut:
    return DefectDojoAccountOut(
        user_id=user.id,
        name=user.name,
        email=user.email,
        role=user.role,
        has_account=user.dd_user_id is not None,
        dd_username=user.dd_username,
        dd_user_id=user.dd_user_id,
        disabled=user.dd_disabled,
        disabled_at=user.dd_disabled_at,
        password_waiting=bool(user.dd_initial_secret),
        last_login=user.last_login,
        expires_at=(last_activity(user) + timedelta(days=expiry_days))
        if user.dd_user_id is not None and not user.dd_disabled
        else None,
    )


@router.get(
    "/admin/defectdojo-accounts",
    response_model=CursorPage[DefectDojoAccountOut],
    summary="DefectDojo accounts of SecureScan users (Admin)",
)
async def list_accounts(db: DbSession, user: AdminUser, page: PageDep) -> CursorPage[DefectDojoAccountOut]:
    days = get_settings().defectdojo_account_expiry_days
    result = await paginate(db, select(User), key=[User.created_at, User.id], params=page)
    return CursorPage(
        items=[_account_out(u, days) for u in result.items], next_cursor=result.next_cursor
    )


async def _toggle(
    user_id: uuid.UUID, request: Request, db: DbSession, admin: AdminUser, *, active: bool
) -> DefectDojoAccountOut:
    target = await get_or_404(db, User, user_id, "User")
    if target.dd_user_id is None:
        raise NotFound(
            "This user has no DefectDojo account yet (it is created at their next sign-in).",
            code="defectdojo_account.not_found",
        )
    if target.dd_disabled == (not active):
        raise Conflict(
            "The account is already " + ("enabled." if active else "disabled."),
            code="defectdojo_account.no_change",
        )
    try:
        client = await accounts_client(db)
    except DefectDojoNotConfigured as exc:
        raise ServiceUnavailable(
            "DefectDojo is not set up yet.", code="defectdojo.not_configured"
        ) from exc
    try:
        await set_account_active(
            db,
            client,
            target,
            active=active,
            actor=admin,
            action=ACTION_ENABLE if active else ACTION_DISABLE,
            reason="changed by an Admin",
            request=request,
        )
    except DefectDojoError as exc:
        raise ServiceUnavailable(
            "DefectDojo did not accept the change. Try again in a moment.",
            code="defectdojo.unavailable",
        ) from exc
    finally:
        await client.aclose()
    await db.commit()
    return _account_out(target, get_settings().defectdojo_account_expiry_days)


@router.post(
    "/admin/defectdojo-accounts/{user_id}/disable",
    response_model=DefectDojoAccountOut,
    summary="Disable a user's DefectDojo account (Admin)",
)
async def disable_account(
    user_id: uuid.UUID, request: Request, db: DbSession, user: AdminUser
) -> DefectDojoAccountOut:
    return await _toggle(user_id, request, db, user, active=False)


@router.post(
    "/admin/defectdojo-accounts/{user_id}/enable",
    response_model=DefectDojoAccountOut,
    summary="Enable a user's DefectDojo account (Admin)",
)
async def enable_account(
    user_id: uuid.UUID, request: Request, db: DbSession, user: AdminUser
) -> DefectDojoAccountOut:
    return await _toggle(user_id, request, db, user, active=True)
