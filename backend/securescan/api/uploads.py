"""Chunked, resumable uploads. The protocol is described in ``securescan/domain/uploads.py``."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from securescan.api.problems import PayloadTooLarge
from securescan.api.schemas import ORMModel
from securescan.auth.roles import AnalystUser
from securescan.config import get_settings
from securescan.db.models.artifacts import Upload
from securescan.db.models.enums import UploadState
from securescan.db.repositories.common import get_or_404
from securescan.db.session import DbSession
from securescan.domain import uploads as upload_service
from securescan.domain.audit import record_audit

router = APIRouter(tags=["uploads"])


class UploadCreate(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(gt=0, description="Total size of the file")
    content_type: str | None = Field(default=None, max_length=255)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")


class UploadOut(ORMModel):
    id: uuid.UUID
    filename: str
    size_bytes: int
    received_bytes: int
    chunk_bytes: int
    state: UploadState
    sha256: str | None
    artifact_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None


class UploadCompleted(BaseModel):
    upload_id: uuid.UUID
    artifact_id: uuid.UUID
    sha256: str
    size_bytes: int
    storage_key: str


@router.post("/uploads", response_model=UploadOut, status_code=201, summary="Start a chunked upload")
async def create_upload(
    body: UploadCreate, request: Request, db: DbSession, user: AnalystUser
) -> UploadOut:
    row = await upload_service.create_upload(
        db,
        filename=body.filename,
        size_bytes=body.size_bytes,
        content_type=body.content_type,
        sha256=body.sha256,
        user_id=user.id,
    )
    await record_audit(
        db, user, "upload.create", "upload", row.id,
        {"filename": row.filename, "size_bytes": row.size_bytes}, request,
    )  # fmt: skip
    await db.commit()
    return UploadOut.model_validate(row)


@router.get("/uploads/{upload_id}", response_model=UploadOut, summary="Upload status (resume offset)")
async def get_upload(upload_id: uuid.UUID, db: DbSession, user: AnalystUser) -> UploadOut:
    return UploadOut.model_validate(await get_or_404(db, Upload, upload_id, "Upload"))


@router.patch("/uploads/{upload_id}", response_model=UploadOut, summary="Send one chunk")
async def patch_upload(
    upload_id: uuid.UUID, request: Request, db: DbSession, user: AnalystUser
) -> UploadOut:
    """Body: the raw chunk. Header: ``Content-Range: bytes <start>-<end>/<total>`` (end inclusive)."""
    rng = upload_service.parse_content_range(request.headers.get("content-range"))
    limit = get_settings().upload_max_chunk_bytes
    buffer = bytearray()
    async for part in request.stream():
        buffer.extend(part)
        if len(buffer) > limit:
            raise PayloadTooLarge(f"Chunks are limited to {limit} bytes", code="upload.chunk_too_large")
    row = await upload_service.append_chunk(db, upload_id, rng, bytes(buffer))
    await db.commit()
    return UploadOut.model_validate(row)


@router.post(
    "/uploads/{upload_id}/complete", response_model=UploadCompleted, summary="Finish an upload"
)
async def complete_upload(
    upload_id: uuid.UUID, request: Request, db: DbSession, user: AnalystUser
) -> UploadCompleted:
    artifact = await upload_service.complete_upload(db, upload_id, user.id)
    await record_audit(
        db, user, "upload.complete", "upload", upload_id,
        {"artifact_id": str(artifact.id), "sha256": artifact.sha256, "size_bytes": artifact.size_bytes},
        request,
    )  # fmt: skip
    await db.commit()
    return UploadCompleted(
        upload_id=upload_id,
        artifact_id=artifact.id,
        sha256=artifact.sha256,
        size_bytes=artifact.size_bytes,
        storage_key=artifact.storage_key,
    )


@router.delete("/uploads/{upload_id}", status_code=204, summary="Abort an upload")
async def abort_upload(
    upload_id: uuid.UUID, request: Request, db: DbSession, user: AnalystUser
) -> Response:
    await upload_service.abort_upload(db, upload_id)
    await record_audit(db, user, "upload.abort", "upload", upload_id, None, request)
    await db.commit()
    return Response(status_code=204)
