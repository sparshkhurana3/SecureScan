"""Chunked, resumable uploads (zip sources, image tarballs, vendor authorization documents).

Protocol (see ``securescan/api/uploads.py``):

1. ``POST /uploads`` with ``{filename, size_bytes, sha256?}`` returns the upload id and chunk size.
2. ``PATCH /uploads/{id}`` with ``Content-Range: bytes <start>-<end>/<total>`` and the raw chunk as the
   body, in order. A chunk that does not start at ``received_bytes`` is refused with 409 and the
   header ``Upload-Offset`` so the client can resume.
3. ``POST /uploads/{id}/complete`` verifies the size, computes the SHA-256, compares it to the one
   announced (when given) and moves the file to ``uploads/<yyyy>/<mm>/<id>``, creating the Artifact.
"""

from __future__ import annotations

import asyncio
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.api.problems import BadRequest, Conflict, NotFound, PayloadTooLarge, UnprocessableEntity
from securescan.config import get_settings
from securescan.db.models.artifacts import Artifact, Upload
from securescan.db.models.enums import ArtifactKind, UploadState
from securescan.storage.artifacts import (
    resolve_key,
    safe_filename,
    save_file,
    sha256_file,
)
from securescan.util import new_id, utcnow

_RANGE = re.compile(r"^bytes (\d+)-(\d+)/(\d+)$")
PARTIAL_PREFIX = "uploads/.partial"


@dataclass(frozen=True)
class ContentRange:
    start: int
    end: int  # inclusive
    total: int

    @property
    def length(self) -> int:
        return self.end - self.start + 1


def parse_content_range(value: str | None) -> ContentRange:
    """Parse ``bytes <start>-<end>/<total>`` (end inclusive)."""
    match = _RANGE.match((value or "").strip())
    if match is None:
        raise BadRequest(
            "Send a Content-Range header like 'bytes 0-1048575/104857600'",
            code="upload.invalid_content_range",
        )
    start, end, total = (int(g) for g in match.groups())
    if end < start or end >= total:
        raise BadRequest("The Content-Range is inconsistent", code="upload.invalid_content_range")
    return ContentRange(start, end, total)


def partial_key(upload_id: uuid.UUID) -> str:
    return f"{PARTIAL_PREFIX}/{upload_id}"


def _write_chunk(path: Path, start: int, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o775)
    mode = "r+b" if path.exists() else "wb"
    with path.open(mode) as fh:
        fh.seek(start)
        fh.write(data)
        fh.truncate(start + len(data))  # drops bytes of an earlier attempt that was never recorded


async def create_upload(
    db: AsyncSession,
    *,
    filename: str,
    size_bytes: int,
    content_type: str | None,
    sha256: str | None,
    user_id: uuid.UUID,
) -> Upload:
    settings = get_settings()
    if size_bytes <= 0:
        raise UnprocessableEntity("The upload size must be greater than zero", code="upload.empty")
    if size_bytes > settings.upload_max_bytes:
        raise PayloadTooLarge(
            f"Uploads are limited to {settings.upload_max_bytes} bytes", code="upload.too_large"
        )
    upload_id = new_id()
    row = Upload(
        id=upload_id,
        filename=safe_filename(filename, "upload"),
        content_type=content_type,
        size_bytes=size_bytes,
        received_bytes=0,
        chunk_bytes=settings.upload_chunk_bytes,
        state=UploadState.RECEIVING,
        sha256_expected=sha256.lower() if sha256 else None,
        partial_key=partial_key(upload_id),
        created_by_id=user_id,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(row)
    await db.flush()
    return row


async def _locked_upload(db: AsyncSession, upload_id: uuid.UUID) -> Upload:
    row = await db.scalar(select(Upload).where(Upload.id == upload_id).with_for_update())
    if row is None:
        raise NotFound("Upload not found", code="upload.not_found")
    return row


def check_chunk(upload: Upload, rng: ContentRange, body_length: int) -> None:
    """Validate a chunk against the upload's state (pure; raises problems)."""
    settings = get_settings()
    if upload.state != UploadState.RECEIVING:
        raise Conflict("This upload is no longer receiving data", code="upload.not_receiving")
    if rng.total != upload.size_bytes:
        raise BadRequest("The total in Content-Range differs from the announced size", code="upload.size_mismatch")
    if body_length != rng.length:
        raise BadRequest("The body length does not match Content-Range", code="upload.length_mismatch")
    if body_length > settings.upload_max_chunk_bytes:
        raise PayloadTooLarge(
            f"Chunks are limited to {settings.upload_max_chunk_bytes} bytes", code="upload.chunk_too_large"
        )
    if rng.start != upload.received_bytes:
        raise Conflict(
            f"Expected the next chunk at offset {upload.received_bytes}",
            code="upload.wrong_offset",
            headers={"Upload-Offset": str(upload.received_bytes)},
            offset=upload.received_bytes,
        )


async def append_chunk(db: AsyncSession, upload_id: uuid.UUID, rng: ContentRange, data: bytes) -> Upload:
    """Append one chunk (the row is locked so concurrent retries cannot interleave)."""
    row = await _locked_upload(db, upload_id)
    check_chunk(row, rng, len(data))
    await asyncio.to_thread(_write_chunk, resolve_key(row.partial_key), rng.start, data)
    row.received_bytes = rng.end + 1
    row.updated_at = utcnow()
    await db.flush()
    return row


async def complete_upload(db: AsyncSession, upload_id: uuid.UUID, user_id: uuid.UUID) -> Artifact:
    """Finish an upload: verify size and checksum, store the file, create the Artifact."""
    row = await _locked_upload(db, upload_id)
    if row.state == UploadState.COMPLETE and row.artifact_id is not None:
        existing = await db.get(Artifact, row.artifact_id)
        if existing is not None:
            return existing
    if row.state != UploadState.RECEIVING:
        raise Conflict("This upload is no longer receiving data", code="upload.not_receiving")
    if row.received_bytes != row.size_bytes:
        raise Conflict(
            f"Only {row.received_bytes} of {row.size_bytes} bytes were received",
            code="upload.incomplete",
            headers={"Upload-Offset": str(row.received_bytes)},
            offset=row.received_bytes,
        )
    partial = resolve_key(row.partial_key)
    digest, size = await asyncio.to_thread(sha256_file, partial)
    if size != row.size_bytes:
        raise Conflict("The stored size differs from the announced size", code="upload.size_mismatch")
    if row.sha256_expected and row.sha256_expected != digest:
        row.state = UploadState.ABORTED
        row.updated_at = utcnow()
        await asyncio.to_thread(partial.unlink, True)
        await db.commit()
        raise UnprocessableEntity(
            "The SHA-256 of the received file differs from the announced one; upload it again",
            code="upload.checksum_mismatch",
        )
    now = utcnow()
    artifact_id = new_id()
    artifact = await save_file(
        db,
        kind=ArtifactKind.UPLOAD,
        source=partial,
        filename=row.filename,
        content_type=row.content_type,
        key=f"uploads/{now:%Y}/{now:%m}/{artifact_id}",
        move=True,
        artifact_id=artifact_id,
        created_by_id=user_id,
    )
    row.state = UploadState.COMPLETE
    row.sha256 = digest
    row.artifact_id = artifact.id
    row.completed_at = now
    row.updated_at = now
    await db.flush()
    return artifact


async def abort_upload(db: AsyncSession, upload_id: uuid.UUID) -> Upload:
    row = await _locked_upload(db, upload_id)
    if row.state == UploadState.COMPLETE:
        raise Conflict("The upload is already complete", code="upload.already_complete")
    row.state = UploadState.ABORTED
    row.updated_at = utcnow()
    await asyncio.to_thread(_unlink, resolve_key(row.partial_key))
    await db.flush()
    return row


def _unlink(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


async def gc_stale_uploads(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Abort uploads that received nothing for ``upload_stale_hours`` and delete their partial files."""
    settings = get_settings()
    cutoff = (now or utcnow()) - timedelta(hours=settings.upload_stale_hours)
    rows = (
        await db.scalars(
            select(Upload).where(Upload.state == UploadState.RECEIVING, Upload.updated_at < cutoff)
        )
    ).all()
    for row in rows:
        row.state = UploadState.ABORTED
        row.updated_at = utcnow()
        await asyncio.to_thread(_unlink, resolve_key(row.partial_key))
    await db.flush()
    return len(rows)
