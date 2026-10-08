from __future__ import annotations

import hashlib
import types
import uuid
from pathlib import Path

import pytest

from securescan.api.problems import BadRequest, Conflict, PayloadTooLarge, UnprocessableEntity
from securescan.db.models.enums import ArtifactKind, UploadState
from securescan.domain import uploads
from securescan.storage.artifacts import artifact_path, resolve_key
from tests.unit.conftest import FakeSession


def test_parse_content_range() -> None:
    rng = uploads.parse_content_range("bytes 0-1023/4096")
    assert (rng.start, rng.end, rng.total, rng.length) == (0, 1023, 4096, 1024)


@pytest.mark.parametrize(
    "value", [None, "", "0-10/20", "bytes 10-5/20", "bytes 0-20/20", "bytes */20", "bytes a-b/c"]
)
def test_parse_content_range_rejects_bad_values(value: str | None) -> None:
    with pytest.raises(BadRequest):
        uploads.parse_content_range(value)


def _upload(size: int = 100, received: int = 0) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        state=UploadState.RECEIVING, size_bytes=size, received_bytes=received
    )


def test_check_chunk_accepts_the_next_chunk() -> None:
    uploads.check_chunk(_upload(100, 0), uploads.ContentRange(0, 49, 100), 50)
    uploads.check_chunk(_upload(100, 50), uploads.ContentRange(50, 99, 100), 50)


def test_check_chunk_wrong_offset_reports_the_resume_offset() -> None:
    with pytest.raises(Conflict) as info:
        uploads.check_chunk(_upload(100, 50), uploads.ContentRange(0, 49, 100), 50)
    assert info.value.headers["Upload-Offset"] == "50"
    assert info.value.to_dict()["offset"] == 50


def test_check_chunk_length_and_total_must_match() -> None:
    with pytest.raises(BadRequest):
        uploads.check_chunk(_upload(100, 0), uploads.ContentRange(0, 49, 100), 40)
    with pytest.raises(BadRequest):
        uploads.check_chunk(_upload(100, 0), uploads.ContentRange(0, 49, 200), 50)


def test_check_chunk_refuses_finished_uploads() -> None:
    finished = _upload()
    finished.state = UploadState.COMPLETE
    with pytest.raises(Conflict):
        uploads.check_chunk(finished, uploads.ContentRange(0, 9, 100), 10)


def test_check_chunk_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_UPLOAD_MAX_CHUNK_BYTES", "10")
    from securescan.config import get_settings

    get_settings.cache_clear()
    with pytest.raises(PayloadTooLarge):
        uploads.check_chunk(_upload(100, 0), uploads.ContentRange(0, 19, 100), 20)


def test_write_chunk_overwrites_an_unrecorded_earlier_attempt(tmp_path: Path) -> None:
    target = tmp_path / "partial"
    uploads._write_chunk(target, 0, b"AAAA")
    uploads._write_chunk(target, 4, b"BBBBBBBB")  # a retry that was never recorded
    uploads._write_chunk(target, 4, b"CCCC")
    assert target.read_bytes() == b"AAAACCCC"


async def test_chunked_upload_end_to_end() -> None:
    payload = bytes(range(256)) * 40  # 10240 bytes
    digest = hashlib.sha256(payload).hexdigest()
    db = FakeSession()
    user_id = uuid.uuid4()
    upload = await uploads.create_upload(
        db,  # type: ignore[arg-type]
        filename="../../evil name.zip",
        size_bytes=len(payload),
        content_type="application/zip",
        sha256=digest,
        user_id=user_id,
    )
    assert upload.filename == "evil_name.zip"
    assert upload.state == UploadState.RECEIVING

    for start in range(0, len(payload), 4096):
        chunk = payload[start : start + 4096]
        rng = uploads.ContentRange(start, start + len(chunk) - 1, len(payload))
        await uploads.append_chunk(db, upload.id, rng, chunk)  # type: ignore[arg-type]
    assert upload.received_bytes == len(payload)

    artifact = await uploads.complete_upload(db, upload.id, user_id)  # type: ignore[arg-type]
    assert artifact.kind == ArtifactKind.UPLOAD
    assert artifact.sha256 == digest
    assert artifact.size_bytes == len(payload)
    assert artifact.storage_key.startswith("uploads/")
    assert artifact_path(artifact).read_bytes() == payload
    assert upload.state == UploadState.COMPLETE
    assert upload.artifact_id == artifact.id
    assert not resolve_key(upload.partial_key).exists()


async def test_complete_refuses_an_incomplete_upload() -> None:
    db = FakeSession()
    upload = await uploads.create_upload(
        db,  # type: ignore[arg-type]
        filename="a.zip",
        size_bytes=100,
        content_type=None,
        sha256=None,
        user_id=uuid.uuid4(),
    )
    await uploads.append_chunk(db, upload.id, uploads.ContentRange(0, 49, 100), b"x" * 50)  # type: ignore[arg-type]
    with pytest.raises(Conflict) as info:
        await uploads.complete_upload(db, upload.id, uuid.uuid4())  # type: ignore[arg-type]
    assert info.value.headers["Upload-Offset"] == "50"


async def test_complete_rejects_a_checksum_mismatch() -> None:
    db = FakeSession()
    upload = await uploads.create_upload(
        db,  # type: ignore[arg-type]
        filename="a.zip",
        size_bytes=4,
        content_type=None,
        sha256="0" * 64,
        user_id=uuid.uuid4(),
    )
    await uploads.append_chunk(db, upload.id, uploads.ContentRange(0, 3, 4), b"abcd")  # type: ignore[arg-type]
    with pytest.raises(UnprocessableEntity):
        await uploads.complete_upload(db, upload.id, uuid.uuid4())  # type: ignore[arg-type]
    assert upload.state == UploadState.ABORTED


async def test_create_upload_enforces_the_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_UPLOAD_MAX_BYTES", "1000")
    from securescan.config import get_settings

    get_settings.cache_clear()
    with pytest.raises(PayloadTooLarge):
        await uploads.create_upload(
            FakeSession(),  # type: ignore[arg-type]
            filename="big.zip",
            size_bytes=1001,
            content_type=None,
            sha256=None,
            user_id=uuid.uuid4(),
        )
    with pytest.raises(UnprocessableEntity):
        await uploads.create_upload(
            FakeSession(),  # type: ignore[arg-type]
            filename="empty.zip",
            size_bytes=0,
            content_type=None,
            sha256=None,
            user_id=uuid.uuid4(),
        )
