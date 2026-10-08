from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

import pytest

from securescan.db.models.enums import ArtifactKind
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.logging import scrub, scrub_processor, scrub_value
from securescan.storage.artifacts import (
    StorageError,
    artifact_path,
    default_key,
    read_bytes,
    resolve_key,
    safe_filename,
    save_bytes,
    save_file,
    validate_key,
    verify_artifact,
)
from tests.unit.conftest import FakeSession

# --------------------------------------------------------------------------- log scrubbing


@pytest.mark.parametrize(
    "secret",
    [
        "ghs_" + "A1b2C3d4E5" * 3,
        "ghp_" + "x" * 36,
        "github_pat_" + "Z9y8X7w6V5" * 4,
    ],
)
def test_github_tokens_are_scrubbed(secret: str) -> None:
    assert secret not in scrub(f"cloning with {secret} now")


def test_bearer_and_token_headers_are_scrubbed() -> None:
    text = scrub("Authorization: Bearer abcdefghijklmnop1234 and Token 0123456789abcdef0123456789")
    assert "abcdefghijklmnop1234" not in text
    assert "0123456789abcdef0123456789" not in text
    assert "Bearer [redacted]" in text


def test_private_keys_are_scrubbed() -> None:
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----"
    assert "abc" not in scrub(f"key: {key}")


def test_ordinary_text_is_unchanged() -> None:
    assert scrub("Token expired for user") == "Token expired for user"


def test_nested_values_and_sensitive_keys() -> None:
    cleaned = scrub_value({"password": "hunter2", "ok": "fine", "nested": ["Bearer " + "q" * 20]})
    assert cleaned["password"] == "[redacted]"
    assert cleaned["ok"] == "fine"
    assert "q" * 20 not in json.dumps(cleaned)


def test_processor_masks_sensitive_keys() -> None:
    event = scrub_processor(None, "info", {"event": "x", "api_key": "abc", "scan_id": "s1"})
    assert event["api_key"] == "[redacted]"
    assert event["scan_id"] == "s1"


# --------------------------------------------------------------------------- artifact storage


def test_unsafe_keys_are_rejected() -> None:
    for key in ("", "/etc/passwd", "../x", "a/../b", "a//b", "a\\b", "a/./b", "x\x00y"):
        with pytest.raises(StorageError):
            validate_key(key)
    assert validate_key("uploads/2026/10/abc") == "uploads/2026/10/abc"


def test_resolve_key_stays_under_the_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    assert resolve_key("a/b", root) == (root / "a" / "b").resolve()
    link = root / "escape"
    try:
        link.symlink_to(tmp_path)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(StorageError):
        resolve_key("escape/outside", root)


def test_safe_filename() -> None:
    assert safe_filename("../../etc/passwd") == "passwd"
    assert safe_filename("my report (final).pdf") == "my_report_final_.pdf"
    assert safe_filename("...") == "file"
    assert safe_filename(None, "x") == "x"


def test_default_keys() -> None:
    artifact_id, scan_id, job_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    assert default_key(ArtifactKind.UPLOAD, artifact_id).startswith("uploads/")
    assert (
        default_key(
            ArtifactKind.RAW_REPORT, artifact_id, filename="semgrep.json", scan_id=scan_id, job_id=job_id
        )
        == f"scans/{scan_id}/{job_id}/semgrep.json"
    )
    assert default_key(
        ArtifactKind.REPORT_FILE, artifact_id, filename="r.pdf", owner_id=scan_id
    ) == f"reports/{scan_id}/r.pdf"


async def test_save_bytes_records_hash_size_and_file() -> None:
    session = FakeSession()
    scan_id, job_id = uuid.uuid4(), uuid.uuid4()
    data = b'{"results": []}'
    artifact = await save_bytes(
        session,  # type: ignore[arg-type]
        kind=ArtifactKind.RAW_REPORT,
        data=data,
        filename="semgrep.json",
        scan_id=scan_id,
        job_id=job_id,
    )
    assert artifact.sha256 == hashlib.sha256(data).hexdigest()
    assert artifact.size_bytes == len(data)
    assert artifact.storage_key == f"scans/{scan_id}/{job_id}/semgrep.json"
    assert artifact_path(artifact).read_bytes() == data
    assert await read_bytes(artifact) == data
    assert await verify_artifact(artifact)
    artifact_path(artifact).write_bytes(b"changed")
    assert not await verify_artifact(artifact)
    assert session.added == [artifact]


async def test_save_file_copies_or_moves(tmp_path: Path) -> None:
    source = tmp_path / "report.xml"
    source.write_bytes(b"<x/>")
    session = FakeSession()
    copied = await save_file(
        session,  # type: ignore[arg-type]
        kind=ArtifactKind.SBOM,
        source=source,
        scan_id=uuid.uuid4(),
        job_id=uuid.uuid4(),
    )
    assert source.exists()
    assert artifact_path(copied).read_bytes() == b"<x/>"
    moved = await save_file(
        session,  # type: ignore[arg-type]
        kind=ArtifactKind.LOG,
        source=source,
        key="scans/s/j/job.log",
        move=True,
    )
    assert not source.exists()
    assert moved.storage_key == "scans/s/j/job.log"


# --------------------------------------------------------------------------- audit helper


async def test_record_audit_builds_an_event_and_scrubs_the_detail() -> None:
    session = FakeSession()
    user_id = uuid.uuid4()
    event = await record_audit(
        session,  # type: ignore[arg-type]
        user_id,
        "application.create",
        "application",
        uuid.uuid4(),
        {"name": "Billing", "token": "should-not-appear", "note": "Bearer " + "z" * 24},
    )
    assert session.added == [event]
    assert event.actor_id == user_id
    assert event.action == "application.create"
    assert event.detail["token"] == "[redacted]"
    assert "z" * 24 not in json.dumps(event.detail)
    assert event.detail["name"] == "Billing"


async def test_record_audit_system_and_object_actors() -> None:
    session = FakeSession()
    system = await record_audit(session, SYSTEM_ACTOR, "credential.expiring", "credential", "c1")  # type: ignore[arg-type]
    assert system.actor_id is None
    assert system.actor_label == "system"

    class Person:
        id = uuid.uuid4()
        email = "ada@example.com"

    person = await record_audit(session, Person(), "auth.login", "user", Person.id)  # type: ignore[arg-type]
    assert person.actor_id == Person.id
    assert person.actor_label == "ada@example.com"
