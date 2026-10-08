"""One pure-ASGI middleware for the three cross-cutting concerns of every request.

* request id: ``X-Request-ID`` (accepted from the gateway or generated), bound to the log context
  and returned in the response;
* API metrics: latency per method, route template and status;
* audit safety net: a successful state-changing request by a signed-in user that did not call
  ``record_audit`` gets a generic ``http.<method>`` audit event, so a forgotten audit call in a
  later milestone still leaves a trace.

It is a plain ASGI class (not ``BaseHTTPMiddleware``) so server-sent events and streaming
downloads are not buffered.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

import structlog
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from securescan.db.session import session_scope
from securescan.domain.audit import record_audit
from securescan.logging import get_logger
from securescan.observability.metrics import observe_request

log = get_logger(__name__)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
# Endpoints that are not state changes worth a generic audit event.
_NO_SAFETY_AUDIT = ("/api/v1/auth/",)


class RequestMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state: dict[str, Any] = scope.setdefault("state", {})
        incoming = dict(scope.get("headers") or []).get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _REQUEST_ID.match(incoming) else uuid.uuid4().hex
        state["request_id"] = request_id
        structlog.contextvars.bind_contextvars(request_id=request_id)
        status = {"code": 500}
        started = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
                MutableHeaders(scope=message).append("X-Request-ID", request_id)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            route = scope.get("route")
            template = getattr(route, "path", None) or "unmatched"
            observe_request(scope["method"], template, status["code"], time.perf_counter() - started)
            structlog.contextvars.unbind_contextvars("request_id")
        await self._safety_audit(scope, state, status["code"])

    async def _safety_audit(self, scope: Scope, state: dict[str, Any], code: int) -> None:
        method = scope["method"]
        path = scope.get("path", "")
        if (
            method in SAFE_METHODS
            or code >= 400
            or state.get("audited")
            or not state.get("actor_id")
            or path.startswith(_NO_SAFETY_AUDIT)
        ):
            return
        route = scope.get("route")
        template = getattr(route, "path", None) or path
        try:
            async with session_scope() as db:
                await record_audit(
                    db,
                    state["actor_id"],
                    f"http.{method.lower()}",
                    "route",
                    template,
                    {"status": code, "actor": state.get("actor_label")},
                )
        except Exception as exc:  # noqa: BLE001 - never turn a finished request into an error
            log.warning("safety_audit_failed", error=str(exc)[:200], route=template)
