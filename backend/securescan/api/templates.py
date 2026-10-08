"""Report templates (Admin): list, download the default, upload, preview, choose the default.

A template is a zip of HTML, CSS and brand files. It is code, so an upload is validated (only
``.html``, ``.css``, ``.svg``, ``.png``, ``.ttf`` and ``.otf`` files, 20 MB at most, no scripts or
double-underscore names), test-rendered in a sandboxed child process with a sample snapshot, and
refused when the render fails. Analysts may list templates so they can pick one when generating.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, File, Form, Request, Response, UploadFile
from pydantic import BaseModel
from sqlalchemy import select

from securescan.api.pagination import CursorPage, PageDep, paginate
from securescan.api.problems import Conflict, NotFound, PayloadTooLarge, UnprocessableEntity
from securescan.api.schemas import ORMModel
from securescan.auth.roles import AdminUser, AnalystUser
from securescan.config import get_settings
from securescan.db.models.artifacts import Artifact
from securescan.db.models.enums import ReportKind
from securescan.db.models.templates import ReportTemplate
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain import reports as report_service
from securescan.domain.audit import record_audit
from securescan.logging import get_logger
from securescan.reports import renderer
from securescan.reports import template_package as package
from securescan.storage.artifacts import StorageError, read_bytes

log = get_logger(__name__)

router = APIRouter(tags=["templates"])

PREVIEW_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; img-src data:; style-src 'unsafe-inline'",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "private, no-store",
}


class TemplateOut(ORMModel):
    id: uuid.UUID
    name: str
    version: int
    builtin: bool
    default_for_application: bool
    default_for_vendor: bool
    entry_file: str
    sha256: str | None
    validated_at: datetime | None
    validation_error: str | None
    active: bool
    created_by_id: uuid.UUID | None
    created_at: datetime


class DefaultIn(BaseModel):
    kind: ReportKind


class TemplateUpdate(BaseModel):
    active: bool


def _zip_response(data: bytes, filename: str) -> Response:
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
        },
    )


@router.get("/templates", response_model=CursorPage[TemplateOut], summary="List report templates")
async def list_templates(
    db: DbSession, user: AnalystUser, page: PageDep, include_inactive: bool = False
) -> CursorPage[TemplateOut]:
    await report_service.ensure_builtin_template(db)
    await db.commit()
    stmt = select(ReportTemplate)
    if not include_inactive:
        stmt = stmt.where(ReportTemplate.active.is_(True))
    key = [ReportTemplate.created_at, ReportTemplate.id]
    result = await paginate(db, stmt, key=key, params=page)
    return CursorPage(
        items=[TemplateOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor
    )


@router.get("/templates/default/download", summary="Download the default template as a zip")
async def download_default_template(
    request: Request, db: DbSession, user: AdminUser
) -> Response:
    """The shipped SonaComstar template (HTML, CSS, brand files): a starting point for a new one."""
    data = await asyncio.to_thread(package.zip_directory, renderer.DEFAULT_TEMPLATE_DIR)
    await record_audit(
        db, user, "template.download", "template", "default", {"builtin": True}, request
    )
    await db.commit()
    return _zip_response(data, "default-sonacomstar-template.zip")


@router.get("/templates/{template_id}", response_model=TemplateOut, summary="Get a template")
async def get_template(template_id: uuid.UUID, db: DbSession, user: AnalystUser) -> TemplateOut:
    return TemplateOut.model_validate(await get_or_404(db, ReportTemplate, template_id, "Template"))


@router.get("/templates/{template_id}/download", summary="Download a template as a zip")
async def download_template(
    template_id: uuid.UUID, request: Request, db: DbSession, user: AdminUser
) -> Response:
    template = await get_or_404(db, ReportTemplate, template_id, "Template")
    artifact = None
    if template.zip_artifact_id:
        artifact = await db.get(Artifact, template.zip_artifact_id)
    if artifact is None:
        raise NotFound("The template file does not exist", code="template.file_missing")
    try:
        data = await read_bytes(artifact)
    except StorageError as exc:
        raise NotFound(
            "The template file is missing from storage", code="template.file_missing"
        ) from exc
    await record_audit(
        db,
        user,
        "template.download",
        "template",
        template.id,
        {"name": template.name, "version": template.version},
        request,
    )
    await db.commit()
    return _zip_response(data, f"{template.name}-v{template.version}.zip".replace(" ", "-"))


@router.post("/templates", response_model=TemplateOut, status_code=201, summary="Upload a template")
async def upload_template(
    request: Request,
    db: DbSession,
    user: AdminUser,
    name: Annotated[str, Form(min_length=1, max_length=200)],
    file: Annotated[UploadFile, File(description="Zip with template.html at its top level")],
) -> TemplateOut:
    """Validate and test-render a template zip; it is stored as a new version of ``name``."""
    clean = " ".join(name.split())
    if not clean:
        raise UnprocessableEntity("The template needs a name", code="template.name_required")
    if clean.lower() == renderer.DEFAULT_TEMPLATE_NAME.lower():
        raise Conflict("That name belongs to the built-in template", code="template.reserved_name")
    limit = min(get_settings().report_template_max_bytes, package.MAX_ZIP_BYTES)
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise PayloadTooLarge("The template zip is larger than 20 MB", code="template.too_large")
    try:
        template = await report_service.install_template(
            db, name=clean, data=data, created_by_id=user.id
        )
    except UnprocessableEntity as exc:
        await record_audit(
            db,
            user,
            "template.upload_rejected",
            "template",
            None,
            {"name": clean, "reason": exc.detail, "size_bytes": len(data)},
            request,
        )
        await db.commit()
        raise
    await record_audit(
        db,
        user,
        "template.upload",
        "template",
        template.id,
        {"name": template.name, "version": template.version, "sha256": template.sha256},
        request,
    )
    await db.commit()
    return TemplateOut.model_validate(template)


@router.post("/templates/{template_id}/preview", summary="Render a template with sample data")
async def preview_template(
    template_id: uuid.UUID,
    request: Request,
    db: DbSession,
    user: AdminUser,
    kind: ReportKind = ReportKind.APPLICATION,
) -> Response:
    """HTML of the template rendered with the sample snapshot, served under the report CSP."""
    template = await get_or_404(db, ReportTemplate, template_id, "Template")
    try:
        html = await report_service.preview_html(template, kind)
    except (renderer.RenderError, report_service.ReportError) as exc:
        raise UnprocessableEntity(
            f"The template could not be rendered: {exc}", code="template.preview_failed"
        ) from exc
    await record_audit(
        db,
        user,
        "template.preview",
        "template",
        template.id,
        {"name": template.name, "version": template.version, "kind": kind.value},
        request,
    )
    await db.commit()
    return Response(
        content=html, media_type="text/html; charset=utf-8", headers=dict(PREVIEW_HEADERS)
    )


@router.post(
    "/templates/{template_id}/default",
    response_model=TemplateOut,
    summary="Make a template the default of a report kind",
)
async def set_default(
    template_id: uuid.UUID, body: DefaultIn, request: Request, db: DbSession, user: AdminUser
) -> TemplateOut:
    template = await get_or_404(db, ReportTemplate, template_id, "Template")
    await report_service.set_default_template(db, template, body.kind)
    await record_audit(
        db,
        user,
        "template.set_default",
        "template",
        template.id,
        {"name": template.name, "version": template.version, "kind": body.kind.value},
        request,
    )
    await db.commit()
    return TemplateOut.model_validate(template)


@router.patch(
    "/templates/{template_id}", response_model=TemplateOut, summary="Turn a template on or off"
)
async def update_template(
    template_id: uuid.UUID, body: TemplateUpdate, request: Request, db: DbSession, user: AdminUser
) -> TemplateOut:
    template = await get_or_404(db, ReportTemplate, template_id, "Template")
    if not body.active and (template.default_for_application or template.default_for_vendor):
        raise Conflict(
            "Choose another default template before turning this one off",
            code="template.is_default",
        )
    template.active = body.active
    await record_audit(
        db,
        user,
        "template.update",
        "template",
        template.id,
        {"name": template.name, "version": template.version, "active": body.active},
        request,
    )
    await db.commit()
    return TemplateOut.model_validate(template)
