"""Artifact volume layout and storage API.

Files live under ``SECURESCAN_ARTIFACTS_ROOT``. Every file has an ``Artifact`` row with its
``storage_key`` (path relative to the root), SHA-256 and size. Nothing is deleted automatically.

Default key layout (``default_key``):

* uploads:      ``uploads/<yyyy>/<mm>/<id>``
* raw reports:  ``scans/<scan id>/<job id>/<filename>``  (also SBOMs and logs of a job)
* report files: ``reports/<report id or owner id>/<filename>``
* templates:    ``templates/<id>/<filename>``

Usage (inside a transaction; the functions ``add`` and ``flush`` but never commit)::

    artifact = await save_bytes(session, kind=ArtifactKind.RAW_REPORT, data=raw,
                                filename="semgrep.json", scan_id=scan.id, job_id=job.id)
    path = artifact_path(artifact)            # pathlib.Path, safe under the root
    data = await read_bytes(artifact)
    with open_artifact(artifact) as fh: ...   # binary read handle
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import IO, Any

from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import get_settings
from securescan.db.models.artifacts import Artifact
from securescan.db.models.enums import ArtifactKind
from securescan.util import new_id, utcnow

CHUNK = 1024 * 1024
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class StorageError(Exception):
    """A storage key is unsafe or a file is missing."""


def artifacts_root() -> Path:
    return Path(get_settings().artifacts_root)


def safe_filename(name: str | None, fallback: str = "file") -> str:
    """Reduce a client-supplied file name to a harmless one (no path, no odd characters)."""
    base = os.path.basename((name or "").replace("\\", "/")).strip(". ")
    cleaned = _SAFE_NAME.sub("_", base)[:150].strip("._")
    return cleaned or fallback


def validate_key(key: str) -> str:
    """Reject keys that could leave the artifacts root."""
    if not key or key.startswith("/") or "\\" in key or "\x00" in key:
        raise StorageError(f"unsafe storage key {key!r}")
    parts = key.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise StorageError(f"unsafe storage key {key!r}")
    return key


def resolve_key(key: str, root: Path | None = None) -> Path:
    """Absolute path of a storage key; raises ``StorageError`` if it would escape the root."""
    base = (root or artifacts_root()).resolve()
    target = (base / validate_key(key)).resolve()
    if base != target and base not in target.parents:
        raise StorageError(f"storage key {key!r} escapes the artifacts root")
    return target


def artifact_path(artifact: Artifact) -> Path:
    return resolve_key(artifact.storage_key)


def default_key(
    kind: ArtifactKind,
    artifact_id: uuid.UUID,
    *,
    filename: str | None = None,
    scan_id: uuid.UUID | None = None,
    job_id: uuid.UUID | None = None,
    owner_id: uuid.UUID | None = None,
) -> str:
    name = safe_filename(filename, str(artifact_id))
    now = utcnow()
    if kind == ArtifactKind.UPLOAD:
        return f"uploads/{now:%Y}/{now:%m}/{artifact_id}"
    if scan_id is not None and kind in (ArtifactKind.RAW_REPORT, ArtifactKind.SBOM, ArtifactKind.LOG):
        return f"scans/{scan_id}/{job_id or 'scan'}/{name}"
    if kind in (ArtifactKind.REPORT_FILE, ArtifactKind.SNAPSHOT):
        return f"reports/{owner_id or artifact_id}/{name}"
    if kind == ArtifactKind.TEMPLATE:
        return f"templates/{owner_id or artifact_id}/{name}"
    return f"misc/{now:%Y}/{now:%m}/{artifact_id}-{name}"


def sha256_file(path: Path) -> tuple[str, int]:
    """SHA-256 hex digest and size of a file (blocking; call through ``asyncio.to_thread``)."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o775)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _place_file(source: Path, dest: Path, move: bool) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o775)
    tmp = dest.with_name(dest.name + ".tmp")
    if move:
        shutil.move(str(source), tmp)
    else:
        shutil.copyfile(source, tmp)
    os.replace(tmp, dest)


def _build_row(
    artifact_id: uuid.UUID,
    kind: ArtifactKind,
    key: str,
    *,
    filename: str | None,
    content_type: str | None,
    sha256: str,
    size: int,
    **links: Any,
) -> Artifact:
    return Artifact(
        id=artifact_id,
        kind=kind,
        storage_key=key,
        filename=safe_filename(filename, "") or None,
        content_type=content_type,
        sha256=sha256,
        size_bytes=size,
        created_at=utcnow(),
        **links,
    )


async def save_bytes(
    session: AsyncSession,
    *,
    kind: ArtifactKind,
    data: bytes,
    filename: str | None = None,
    content_type: str | None = None,
    key: str | None = None,
    scan_id: uuid.UUID | None = None,
    job_id: uuid.UUID | None = None,
    owner_type: str | None = None,
    owner_id: uuid.UUID | None = None,
    created_by_id: uuid.UUID | None = None,
) -> Artifact:
    """Write ``data`` under the artifacts root and add its ``Artifact`` row."""
    artifact_id = new_id()
    storage_key = key or default_key(
        kind, artifact_id, filename=filename, scan_id=scan_id, job_id=job_id, owner_id=owner_id
    )
    path = resolve_key(storage_key)
    await asyncio.to_thread(_write_bytes, path, data)
    row = _build_row(
        artifact_id, kind, storage_key,
        filename=filename, content_type=content_type,
        sha256=hashlib.sha256(data).hexdigest(), size=len(data),
        scan_id=scan_id, job_id=job_id, owner_type=owner_type, owner_id=owner_id,
        created_by_id=created_by_id,
    )  # fmt: skip
    session.add(row)
    await session.flush()
    return row


async def save_file(
    session: AsyncSession,
    *,
    kind: ArtifactKind,
    source: Path,
    filename: str | None = None,
    content_type: str | None = None,
    key: str | None = None,
    move: bool = False,
    scan_id: uuid.UUID | None = None,
    job_id: uuid.UUID | None = None,
    owner_type: str | None = None,
    owner_id: uuid.UUID | None = None,
    created_by_id: uuid.UUID | None = None,
    artifact_id: uuid.UUID | None = None,
) -> Artifact:
    """Store an existing file (copied, or moved when ``move=True``) and add its ``Artifact`` row."""
    new_artifact_id = artifact_id or new_id()
    storage_key = key or default_key(
        kind,
        new_artifact_id,
        filename=filename or source.name,
        scan_id=scan_id,
        job_id=job_id,
        owner_id=owner_id,
    )
    dest = resolve_key(storage_key)
    digest, size = await asyncio.to_thread(sha256_file, source)
    await asyncio.to_thread(_place_file, source, dest, move)
    row = _build_row(
        new_artifact_id, kind, storage_key,
        filename=filename or source.name, content_type=content_type,
        sha256=digest, size=size,
        scan_id=scan_id, job_id=job_id, owner_type=owner_type, owner_id=owner_id,
        created_by_id=created_by_id,
    )  # fmt: skip
    session.add(row)
    await session.flush()
    return row


def open_artifact(artifact: Artifact) -> IO[bytes]:
    """Open the stored file for binary reading."""
    path = artifact_path(artifact)
    if not path.is_file():
        raise StorageError(f"artifact file is missing: {artifact.storage_key}")
    return path.open("rb")


async def read_bytes(artifact: Artifact, *, max_bytes: int | None = None) -> bytes:
    """Read a whole stored file (use ``open_artifact`` for large files)."""

    def _read() -> bytes:
        with open_artifact(artifact) as fh:
            return fh.read() if max_bytes is None else fh.read(max_bytes)

    return await asyncio.to_thread(_read)


async def verify_artifact(artifact: Artifact) -> bool:
    """True when the file exists and still matches its recorded SHA-256."""
    path = artifact_path(artifact)
    if not path.is_file():
        return False
    digest, _ = await asyncio.to_thread(sha256_file, path)
    return digest == artifact.sha256
