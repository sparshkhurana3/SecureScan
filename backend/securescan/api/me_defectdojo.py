"""The signed-in user's DefectDojo account: username, the one-time initial password, and reset."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.api.problems import Forbidden, NotFound, ServiceUnavailable
from securescan.auth.roles import AnalystUser
from securescan.config import get_settings
from securescan.db.models.users import User
from securescan.db.session import DbSession
from securescan.domain.accounts import (
    PasswordResetUnavailable,
    read_account,
    reset_password,
)
from securescan.integrations.defectdojo.client import DefectDojoError
from securescan.integrations.defectdojo.factory import DefectDojoNotConfigured, accounts_client

router = APIRouter(tags=["defectdojo"])

NO_STORE = "no-store"


class DefectDojoAccountOut(BaseModel):
    status: str  # ready | unavailable | disabled
    username: str | None
    login_url: str
    initial_password: str | None
    password_shown: bool
    must_change_password: bool
    disabled: bool
    detail: str | None


class PasswordResetOut(BaseModel):
    username: str | None
    login_url: str
    password: str
    must_change_password: bool


async def _load_user(db: AsyncSession, user_id: uuid.UUID) -> User:
    row = await db.get(User, user_id)
    if row is None:
        raise NotFound("Your user record was not found.", code="user.not_found")
    return row


@router.get(
    "/me/defectdojo-account",
    response_model=DefectDojoAccountOut,
    summary="Your DefectDojo account. The initial password is returned once.",
)
async def my_defectdojo_account(
    response: Response, db: DbSession, user: AnalystUser
) -> DefectDojoAccountOut:
    response.headers["Cache-Control"] = NO_STORE
    row = await _load_user(db, user.id)
    view = await read_account(db, row)
    await db.commit()
    return DefectDojoAccountOut(
        status=view.status,
        username=view.username,
        login_url=view.login_url,
        initial_password=view.initial_password,
        password_shown=view.password_shown,
        must_change_password=view.must_change_password,
        disabled=view.disabled,
        detail=view.detail,
    )


@router.post(
    "/me/defectdojo-account/reset",
    response_model=PasswordResetOut,
    summary="Set a new random DefectDojo password for yourself (shown once)",
)
async def reset_my_defectdojo_password(
    request: Request, response: Response, db: DbSession, user: AnalystUser
) -> PasswordResetOut:
    response.headers["Cache-Control"] = NO_STORE
    row = await _load_user(db, user.id)
    if row.dd_user_id is None:
        raise NotFound(
            "You do not have a DefectDojo account yet. Open this page again in a moment.",
            code="defectdojo_account.not_found",
        )
    if row.dd_disabled:
        raise Forbidden(
            "Your DefectDojo account is disabled. Ask an Admin to enable it.",
            code="defectdojo_account.disabled",
        )
    try:
        client = await accounts_client(db)
    except DefectDojoNotConfigured as exc:
        raise ServiceUnavailable(
            "DefectDojo is not ready yet. Try again in a few minutes.", code="defectdojo.not_configured"
        ) from exc
    try:
        password = await reset_password(db, client, row, request)
    except PasswordResetUnavailable as exc:
        raise ServiceUnavailable(str(exc), code="defectdojo_account.reset_unavailable") from exc
    except DefectDojoError as exc:
        raise ServiceUnavailable(
            "DefectDojo did not answer. Try again in a moment.", code="defectdojo.unavailable"
        ) from exc
    finally:
        await client.aclose()
    await db.commit()
    return PasswordResetOut(
        username=row.dd_username,
        login_url=get_settings().defectdojo_public_url,
        password=password,
        must_change_password=True,
    )
