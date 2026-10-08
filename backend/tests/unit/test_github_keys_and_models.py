"""Deploy-key generation, App key validation, request models and small pure helpers."""

from __future__ import annotations

import base64
import hashlib
import struct
import types
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ValidationError

from securescan.api.credentials import VendorTokenIn, generate_deploy_key
from securescan.api.github import (
    RUNNING_MARKER,
    GitHubConnectionIn,
    _test_out,
    parse_repository_count,
)
from securescan.db.models.enums import CredentialKind
from securescan.db.models.github import GitHubConnection
from securescan.integrations.github.connection import github_hosts, validate_private_key
from securescan.jobs.credential_alerts import has_expired, is_unused_too_long
from securescan.jobs.github_poll import poll_due
from tests.unit.github_helpers import rsa_pair

UTC = timezone.utc


# --------------------------------------------------------------------------- deploy keys
def read_ssh_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    (length,) = struct.unpack(">I", blob[offset : offset + 4])
    return blob[offset + 4 : offset + 4 + length], offset + 4 + length


def test_deploy_key_public_line_is_openssh_ed25519() -> None:
    _private, public, fingerprint = generate_deploy_key("securescan-abc")
    parts = public.split(" ")
    assert parts[0] == "ssh-ed25519"
    assert parts[2] == "securescan-abc"
    blob = base64.b64decode(parts[1])
    key_type, offset = read_ssh_string(blob, 0)
    key_bytes, offset = read_ssh_string(blob, offset)
    assert key_type == b"ssh-ed25519"
    assert len(key_bytes) == 32
    assert offset == len(blob)
    expected = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    assert fingerprint == "SHA256:" + expected


def test_deploy_key_private_key_is_openssh_pem_and_matches_the_public_key() -> None:
    private, public, _fingerprint = generate_deploy_key("securescan-abc")
    assert private.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert private.rstrip().endswith("-----END OPENSSH PRIVATE KEY-----")
    loaded = serialization.load_ssh_private_key(private.encode("ascii"), password=None)
    derived = (
        loaded.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode("ascii")
    )
    assert derived == " ".join(public.split(" ")[:2])


def test_every_deploy_key_is_new() -> None:
    first = generate_deploy_key("a")
    second = generate_deploy_key("a")
    assert first[0] != second[0]
    assert first[1] != second[1]


def test_deploy_key_comment_is_sanitised() -> None:
    _private, public, _fp = generate_deploy_key("evil comment; rm -rf /\nnext")
    assert "\n" not in public
    assert len(public.split(" ")) == 3  # type, key, comment: no spaces survive


# --------------------------------------------------------------------------- App private keys
def test_valid_app_key_gives_a_sha256_fingerprint() -> None:
    private, _public = rsa_pair(0)
    fingerprint = validate_private_key(private)
    assert fingerprint.startswith("SHA256:")
    assert len(fingerprint) == len("SHA256:") + 44  # base64 of 32 bytes
    assert validate_private_key(private) == fingerprint  # stable


def test_fingerprint_is_sha256_of_the_der_public_key() -> None:
    private, public = rsa_pair(0)
    der = serialization.load_pem_public_key(public.encode("ascii")).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")
    assert validate_private_key(private) == expected


def test_garbage_is_not_a_private_key() -> None:
    with pytest.raises(ValueError, match="private key"):
        validate_private_key("hello")
    with pytest.raises(ValueError):
        validate_private_key("-----BEGIN PRIVATE KEY-----\nnot base64\n-----END PRIVATE KEY-----")


def test_non_rsa_keys_are_refused() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    with pytest.raises(ValueError, match="RSA"):
        validate_private_key(pem)


def test_password_protected_keys_are_refused() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"pw"),
    ).decode("ascii")
    with pytest.raises(ValueError, match="password"):
        validate_private_key(pem)


# --------------------------------------------------------------------------- request models
def connection_body(**changes: object) -> dict[str, object]:
    body: dict[str, object] = {"app_id": "123", "client_id": "Iv1.abc", "installation_id": "777"}
    body.update(changes)
    return body


def test_connection_defaults_are_the_documented_ones() -> None:
    model = GitHubConnectionIn(**connection_body())  # type: ignore[arg-type]
    assert model.api_base_url == "https://api.github.com"
    assert model.git_host == "github.com"
    assert model.api_version == "2026-03-10"
    assert model.active_key == 1
    assert model.enabled is True


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com",
        "https://user:pw@api.github.com",
        "https://api.github.com/?x=1",
        "ftp://api.github.com",
        "api.github.com",
        "https://",
    ],
)
def test_unsafe_api_urls_are_refused(url: str) -> None:
    with pytest.raises(ValidationError):
        GitHubConnectionIn(**connection_body(api_base_url=url))  # type: ignore[arg-type]


def test_api_url_trailing_slash_is_removed() -> None:
    model = GitHubConnectionIn(**connection_body(api_base_url="https://api.github.com/"))  # type: ignore[arg-type]
    assert model.api_base_url == "https://api.github.com"


def test_git_host_must_be_a_host_name() -> None:
    with pytest.raises(ValidationError):
        GitHubConnectionIn(**connection_body(git_host="github.com/evil"))  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        GitHubConnectionIn(**connection_body(installation_id="abc"))  # type: ignore[arg-type]


def test_private_keys_do_not_appear_in_the_repr() -> None:
    model = GitHubConnectionIn(**connection_body(private_key_1="-----BEGIN PRIVATE KEY-----secret"))  # type: ignore[arg-type]
    assert "secret" not in repr(model)
    assert "secret" not in model.model_dump_json()


def test_vendor_token_shape_is_checked_and_hidden() -> None:
    future = datetime.now(UTC) + timedelta(days=30)
    model = VendorTokenIn(
        target_id="3f1c1d56-0b7e-4c3e-9d0a-2b0f6f0f0f0f",  # type: ignore[arg-type]
        token="github_pat_" + "x" * 40,  # type: ignore[arg-type]
        expires_at=future,
    )
    assert "github_pat_" not in repr(model)
    with pytest.raises(ValidationError):
        VendorTokenIn(
            target_id="3f1c1d56-0b7e-4c3e-9d0a-2b0f6f0f0f0f",  # type: ignore[arg-type]
            token="too short",  # type: ignore[arg-type]
            expires_at=future,
        )
    with pytest.raises(ValidationError):
        VendorTokenIn(
            target_id="3f1c1d56-0b7e-4c3e-9d0a-2b0f6f0f0f0f",  # type: ignore[arg-type]
            token="a token with spaces in it, long enough",  # type: ignore[arg-type]
            expires_at=future,
        )


def test_vendor_token_needs_an_expiry() -> None:
    with pytest.raises(ValidationError):
        VendorTokenIn(  # type: ignore[call-arg]
            target_id="3f1c1d56-0b7e-4c3e-9d0a-2b0f6f0f0f0f",  # type: ignore[arg-type]
            token="github_pat_" + "x" * 40,  # type: ignore[arg-type]
        )


# --------------------------------------------------------------------------- test result mapping
def row(**values: object) -> types.SimpleNamespace:
    base = {"last_test_ok": None, "last_test_at": None, "last_test_message": None}
    base.update(values)
    return types.SimpleNamespace(**base)


def test_test_result_ok_reports_the_repository_count() -> None:
    now = datetime(2026, 10, 7, tzinfo=UTC)
    out = _test_out(  # type: ignore[arg-type]
        row(last_test_ok=True, last_test_at=now, last_test_message="Token minted, 42 repositories, ls-remote ok")
    )
    assert out.status == "ok"
    assert out.repositories == 42
    assert out.problems == []


def test_test_result_failed_lists_each_problem_on_its_own_line() -> None:
    now = datetime(2026, 10, 7, tzinfo=UTC)
    out = _test_out(  # type: ignore[arg-type]
        row(last_test_ok=False, last_test_at=now, last_test_message="first problem\nsecond problem")
    )
    assert out.status == "failed"
    assert out.problems == ["first problem", "second problem"]
    assert out.repositories is None


def test_test_result_running_and_untested() -> None:
    assert _test_out(row(last_test_message=RUNNING_MARKER)).status == "running"  # type: ignore[arg-type]
    assert "not been tested" in _test_out(row()).message  # type: ignore[arg-type]


def test_parse_repository_count() -> None:
    assert parse_repository_count("Token minted, 7 repositories, ls-remote ok") == 7
    assert parse_repository_count("something else") is None
    assert parse_repository_count(None) is None


# --------------------------------------------------------------------------- hosts
def test_github_hosts_for_github_com_include_codeload() -> None:
    connection = GitHubConnection(api_base_url="https://api.github.com", git_host="github.com")
    assert github_hosts(connection) == {"api.github.com", "github.com", "codeload.github.com"}


def test_github_hosts_for_another_installation() -> None:
    connection = GitHubConnection(
        api_base_url="https://api.sona.ghe.com", git_host="sona.ghe.com"
    )
    assert github_hosts(connection) == {"api.sona.ghe.com", "sona.ghe.com"}


# --------------------------------------------------------------------------- credential alerts
def test_expiry_check() -> None:
    now = datetime(2026, 10, 7, tzinfo=UTC)
    assert has_expired(now - timedelta(days=1), None, now)
    assert not has_expired(now + timedelta(days=1), None, now)
    assert not has_expired(None, None, now)
    assert not has_expired(now - timedelta(days=1), now - timedelta(hours=1), now)  # revoked


def test_unused_check_applies_to_vendor_access_only() -> None:
    now = datetime(2026, 10, 7, tzinfo=UTC)
    old = now - timedelta(days=400)
    assert is_unused_too_long(CredentialKind.DEPLOY_KEY, old, None, None, now)
    assert is_unused_too_long(CredentialKind.VENDOR_TOKEN, old, now - timedelta(days=340), None, now)
    assert not is_unused_too_long(CredentialKind.VENDOR_TOKEN, old, now - timedelta(days=10), None, now)
    assert not is_unused_too_long(CredentialKind.DEPLOY_KEY, now - timedelta(days=10), None, None, now)
    assert not is_unused_too_long(CredentialKind.NVD_KEY, old, None, None, now)
    assert not is_unused_too_long(CredentialKind.DEPLOY_KEY, old, None, now, now)  # revoked


# --------------------------------------------------------------------------- poll interval setting
def test_poll_due_respects_a_custom_interval() -> None:
    now = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
    assert poll_due(None, now - timedelta(minutes=1), now)
    assert poll_due(30, None, now)
    assert not poll_due(30, now - timedelta(minutes=10), now)
    assert poll_due(30, now - timedelta(minutes=29, seconds=30), now)  # slack for the clock
    assert poll_due(30, now - timedelta(minutes=45), now)
