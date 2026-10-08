"""RFC 9457 problem details.

Raise a ``Problem`` (or one of the subclasses) anywhere in the request path; the handlers
installed by ``install_problem_handlers`` turn it into ``application/problem+json``::

    raise NotFound("Application not found")
    raise Conflict("An application with this name exists", code="application.duplicate_name")
    raise UnprocessableEntity("Production targets accept baseline scans only",
                              code="dast.production_baseline_only")

Responses carry ``type``, ``title``, ``status``, ``detail``, ``instance`` and, when given, the
extension members ``code`` (a stable machine-readable string) and ``errors`` (field errors).
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from securescan.logging import get_logger

log = get_logger(__name__)

PROBLEM_JSON = "application/problem+json"
TYPE_PREFIX = "urn:securescan:problem:"


def _title(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return "Error"


class Problem(Exception):  # noqa: N818 - the RFC calls it a problem
    """An error that is reported to the client as RFC 9457 problem details."""

    status: int = 500
    slug: str = "internal-error"

    def __init__(
        self,
        detail: str | None = None,
        *,
        status: int | None = None,
        title: str | None = None,
        code: str | None = None,
        type_: str | None = None,
        errors: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
        **extensions: Any,
    ) -> None:
        super().__init__(detail or title or _title(status or self.status))
        self.status_code = status if status is not None else self.status
        self.title = title or _title(self.status_code)
        self.detail = detail
        self.code = code
        self.type = type_ or (TYPE_PREFIX + self.slug)
        self.errors = errors
        self.headers = headers or {}
        self.extensions = extensions

    def to_dict(self, instance: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"type": self.type, "title": self.title, "status": self.status_code}
        if self.detail:
            body["detail"] = self.detail
        if instance:
            body["instance"] = instance
        if self.code:
            body["code"] = self.code
        if self.errors:
            body["errors"] = self.errors
        body.update(self.extensions)
        return body


class BadRequest(Problem):
    status = 400
    slug = "bad-request"


class Unauthorized(Problem):
    status = 401
    slug = "unauthorized"


class Forbidden(Problem):
    status = 403
    slug = "forbidden"


class NotFound(Problem):
    status = 404
    slug = "not-found"


class Conflict(Problem):
    status = 409
    slug = "conflict"


class PayloadTooLarge(Problem):
    status = 413
    slug = "payload-too-large"


class UnprocessableEntity(Problem):
    status = 422
    slug = "unprocessable-entity"


class TooManyRequests(Problem):
    status = 429
    slug = "too-many-requests"


class ServiceUnavailable(Problem):
    status = 503
    slug = "service-unavailable"


def problem_response(
    problem: Problem, instance: str | None = None, extra_headers: dict[str, str] | None = None
) -> JSONResponse:
    headers = dict(problem.headers)
    if extra_headers:
        headers.update(extra_headers)
    return JSONResponse(
        problem.to_dict(instance),
        status_code=problem.status_code,
        media_type=PROBLEM_JSON,
        headers=headers,
    )


def _field_errors(exc: RequestValidationError) -> list[dict[str, Any]]:
    """Field errors without the submitted input (it may hold secrets)."""
    errors: list[dict[str, Any]] = []
    for item in exc.errors():
        location = ".".join(str(part) for part in item.get("loc", ()))
        errors.append({"field": location, "message": str(item.get("msg", "invalid")), "code": item.get("type")})
    return errors


def install_problem_handlers(app: FastAPI) -> None:
    """Register the exception handlers that emit problem details."""

    @app.exception_handler(Problem)
    async def _problem_handler(request: Request, exc: Problem) -> JSONResponse:
        return problem_response(exc, request.url.path)

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        problem = UnprocessableEntity(
            "The request is not valid", code="validation_error", errors=_field_errors(exc)
        )
        return problem_response(problem, request.url.path)

    @app.exception_handler(StarletteHTTPException)
    async def _http_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        problem = Problem(
            str(exc.detail) if exc.detail and exc.detail != _title(exc.status_code) else None,
            status=exc.status_code,
            type_=TYPE_PREFIX + _title(exc.status_code).lower().replace(" ", "-"),
        )
        extra = dict(exc.headers) if exc.headers else None
        return problem_response(problem, request.url.path, extra)

    @app.exception_handler(Exception)
    async def _unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        log.error(
            "unhandled_exception",
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            exc_info=exc,
        )
        return problem_response(Problem(status=500, title="Internal Server Error"), request.url.path)
