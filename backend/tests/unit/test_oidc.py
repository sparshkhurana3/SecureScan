from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from securescan.auth.oidc import (
    LoginState,
    OidcError,
    identity_from_claims,
    new_login_state,
    safe_next_path,
    seal_login_state,
    unseal_login_state,
    verify_id_token,
)

ISSUER = "https://login.microsoftonline.com/tenant-id/v2.0"
CLIENT_ID = "client-123"


def _keys() -> tuple[bytes, dict[str, Any]]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    jwk = RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk["kid"] = "key-1"
    jwk["use"] = "sig"
    return pem, {"keys": [jwk]}


def _token(pem: bytes, **overrides: Any) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 600,
        "nonce": "nonce-1",
        "oid": "11111111-2222-3333-4444-555555555555",
        "name": "Ada Lovelace",
        "preferred_username": "ada@example.com",
        "roles": ["Analyst"],
    }
    claims.update(overrides)
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "key-1"})


def test_valid_id_token() -> None:
    pem, jwks = _keys()
    claims = verify_id_token(
        _token(pem), jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce="nonce-1"
    )
    assert claims["oid"].startswith("1111")


@pytest.mark.parametrize(
    "overrides",
    [{"aud": "someone-else"}, {"iss": "https://evil.example/"}, {"exp": 1}, {"nonce": "other"}],
)
def test_invalid_id_tokens_are_refused(overrides: dict[str, Any]) -> None:
    pem, jwks = _keys()
    with pytest.raises(OidcError):
        verify_id_token(
            _token(pem, **overrides), jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce="nonce-1"
        )


def test_token_signed_with_another_key_is_refused() -> None:
    other_pem, _ = _keys()
    _, jwks = _keys()
    with pytest.raises(OidcError):
        verify_id_token(
            _token(other_pem), jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce="nonce-1"
        )


def test_unsigned_or_symmetric_tokens_are_refused() -> None:
    _, jwks = _keys()
    forged = jwt.encode({"iss": ISSUER, "aud": CLIENT_ID}, "secret" * 8, algorithm="HS256")
    with pytest.raises(OidcError):
        verify_id_token(forged, jwks, issuer=ISSUER, client_id=CLIENT_ID, nonce="n")


def test_identity_from_entra_claims() -> None:
    identity = identity_from_claims(
        {
            "oid": "abc",
            "sub": "ignored",
            "name": "Ada",
            "preferred_username": "ada@example.com",
            "roles": ["Admin", "Analyst"],
        }
    )
    assert identity.oid == "abc"
    assert identity.email == "ada@example.com"
    assert identity.upn == "ada@example.com"
    assert identity.roles == ["Admin", "Analyst"]


def test_identity_from_mock_provider_claims() -> None:
    identity = identity_from_claims({"sub": "dev-user", "roles": ["Analyst"]})
    assert identity.oid == "dev-user"
    assert identity.email is None


def test_identity_without_roles_has_empty_roles() -> None:
    assert identity_from_claims({"oid": "x"}).roles == []
    assert identity_from_claims({"oid": "x", "roles": "Admin"}).roles == ["Admin"]


def test_identity_needs_a_subject() -> None:
    with pytest.raises(OidcError):
        identity_from_claims({"name": "nobody"})


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "/"),
        ("", "/"),
        ("/history?tool=semgrep", "/history?tool=semgrep"),
        ("//evil.example", "/"),
        ("https://evil.example", "/"),
        ("/\\evil", "/"),
        ("/ok\r\nSet-Cookie: x=y", "/"),
    ],
)
def test_safe_next_path(value: str | None, expected: str) -> None:
    assert safe_next_path(value) == expected


def test_login_state_round_trip(master_key: str) -> None:
    state = new_login_state("/sast")
    restored = unseal_login_state(seal_login_state(state))
    assert restored == state
    assert restored.next_path == "/sast"
    assert len({state.state, state.nonce, state.code_verifier}) == 3


def test_login_state_expires(master_key: str) -> None:
    sealed = seal_login_state(new_login_state(None))
    with pytest.raises(OidcError):
        unseal_login_state(sealed, now=time.time() + 3600)


def test_tampered_login_state_is_refused(master_key: str) -> None:
    sealed = seal_login_state(LoginState("s", "n", "v", "/"))
    with pytest.raises(OidcError):
        unseal_login_state(sealed[:-3] + "AAA")
    with pytest.raises(OidcError):
        unseal_login_state("garbage")
