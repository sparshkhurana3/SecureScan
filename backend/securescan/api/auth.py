"""Sign-in, sign-out and the current user."""

from __future__ import annotations

import hmac
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from securescan.api.problems import BadRequest, Forbidden, ServiceUnavailable, Unauthorized
from securescan.auth import session as sessions
from securescan.auth.oidc import (
    LOGIN_COOKIE,
    LOGIN_COOKIE_MAX_AGE,
    LOGIN_COOKIE_PATH,
    OidcClient,
    OidcError,
    new_login_state,
    seal_login_state,
    unseal_login_state,
)
from securescan.auth.hooks import run_login_hooks
from securescan.auth.roles import AnyUser, OptionalUser, resolve_role
from securescan.config import get_settings
from securescan.db.models.enums import UserRole
from securescan.db.models.users import User
from securescan.db.repositories.users import upsert_user
from securescan.db.session import DbSession
from securescan.domain.audit import client_ip, record_audit
from securescan.logging import get_logger
from securescan.observability.metrics import LOGINS_TOTAL
from securescan.security.secrets import SecretsError

router = APIRouter(tags=["auth"])
log = get_logger(__name__)


class MeOut(BaseModel):
    id: uuid.UUID
    name: str | None
    email: str | None
    role: UserRole
    roles: list[str]
    csrf_token: str
    last_login: datetime | None
    defectdojo_url: str


@router.get("/auth/login", status_code=302, summary="Start the Microsoft Entra ID sign-in")
async def login(
    next_path: Annotated[str | None, Query(alias="next", description="Relative path to return to")] = None,
) -> RedirectResponse:
    settings = get_settings()
    state = new_login_state(next_path)
    try:
        url = await OidcClient().authorization_url(state)
        sealed = seal_login_state(state)
    except (OidcError, SecretsError) as exc:
        log.warning("login_unavailable", error=str(exc))
        raise ServiceUnavailable(
            "Sign-in is not available right now. Ask an administrator to check the identity provider settings.",
            code="auth.provider_unavailable",
        ) from exc
    response = RedirectResponse(url, status_code=302)
    response.set_cookie(
        LOGIN_COOKIE,
        sealed,
        max_age=LOGIN_COOKIE_MAX_AGE,
        path=LOGIN_COOKIE_PATH,
        secure=settings.cookies_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/auth/callback", status_code=302, summary="Finish the sign-in (redirect target of the provider)")
async def callback(
    request: Request,
    db: DbSession,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    settings = get_settings()
    if error:
        LOGINS_TOTAL.labels(outcome="provider_error").inc()
        raise BadRequest("The identity provider refused the sign-in.", code="auth.provider_error")
    sealed = request.cookies.get(LOGIN_COOKIE)
    if not sealed or not code or not state:
        raise BadRequest("The sign-in request is incomplete. Start again.", code="auth.invalid_callback")
    try:
        login_state = unseal_login_state(sealed)
        if not hmac.compare_digest(state, login_state.state):
            raise OidcError("The sign-in state does not match. Start again.")
        identity = await OidcClient().complete(code, login_state)
    except OidcError as exc:
        LOGINS_TOTAL.labels(outcome="failed").inc()
        raise BadRequest(str(exc), code="auth.invalid_callback") from exc

    role = resolve_role(identity.roles)
    if role is None:
        await record_audit(
            db,
            identity.email or identity.oid,
            "auth.login_denied",
            "user",
            identity.oid,
            {"reason": "no Admin or Analyst role", "roles": identity.roles},
            request,
        )
        await db.commit()
        LOGINS_TOTAL.labels(outcome="denied").inc()
        raise Forbidden(
            "Your account has neither the Admin nor the Analyst role. "
            "Ask your administrator to assign one in Microsoft Entra ID.",
            code="auth.no_role",
        )

    user = await upsert_user(db, identity, role)
    await run_login_hooks(db, user)
    token, row = await sessions.create_session(
        db, user, ip=client_ip(request), user_agent=request.headers.get("user-agent")
    )
    await record_audit(db, user, "auth.login", "user", user.id, {"role": role.value}, request)
    await db.commit()
    LOGINS_TOTAL.labels(outcome="success").inc()

    response = RedirectResponse(settings.public_url.rstrip("/") + login_state.next_path, status_code=302)
    sessions.set_session_cookies(response, token, row.csrf_token)
    response.delete_cookie(LOGIN_COOKIE, path=LOGIN_COOKIE_PATH)
    return response


@router.post("/auth/logout", status_code=204, summary="Sign out")
async def logout(request: Request, db: DbSession, user: OptionalUser) -> Response:
    if user is not None:
        await sessions.revoke_session(db, user.session_id)
        await record_audit(db, user, "auth.logout", "user", user.id, None, request)
        await db.commit()
    response = Response(status_code=204)
    sessions.clear_session_cookies(response)
    return response


@router.get("/auth/check", status_code=204, summary="Session check for the gateway (DefectDojo host)")
async def auth_check(request: Request, db: DbSession) -> Response:
    """204 with a valid session cookie, 401 without. The gateway calls this with ``auth_request``."""
    token = request.cookies.get(get_settings().session_cookie_name)
    active = await sessions.load_active_session(db, token) if token else None
    if active is None:
        raise Unauthorized("No valid session", code="auth.required")
    return Response(status_code=204)


@router.get("/me", response_model=MeOut, summary="The signed-in user")
async def me(user: AnyUser, db: DbSession, response: Response) -> MeOut:
    row = await db.get(User, user.id)
    settings = get_settings()
    response.set_cookie(
        settings.csrf_cookie_name,
        user.csrf_token,
        max_age=settings.session_max_hours * 3600,
        domain=settings.cookie_domain or None,
        path="/",
        secure=settings.cookies_secure,
        httponly=False,
        samesite="lax",
    )
    return MeOut(
        id=user.id,
        name=user.name,
        email=user.email,
        role=user.role,
        roles=list(row.roles) if row is not None else [],
        csrf_token=user.csrf_token,
        last_login=row.last_login if row is not None else None,
        defectdojo_url=settings.defectdojo_public_url,
    )
