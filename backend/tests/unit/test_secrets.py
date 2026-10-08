from __future__ import annotations

import pytest

from securescan.security.secrets import (
    KeyRing,
    SecretsError,
    decrypt_secret,
    derive_key,
    encrypt_secret,
    generate_master_key,
    key_id_for,
    reencrypt_secret,
)

KEY_A = "11" * 32
KEY_B = "22" * 32


def test_round_trip() -> None:
    ring = KeyRing.from_material(KEY_A)
    envelope = ring.encrypt(b"s3cret value", "credential:1")
    assert envelope.startswith("ss1:")
    assert "s3cret" not in envelope
    assert ring.decrypt(envelope, "credential:1") == b"s3cret value"


def test_encrypting_twice_gives_different_envelopes() -> None:
    ring = KeyRing.from_material(KEY_A)
    assert ring.encrypt(b"x") != ring.encrypt(b"x")


def test_wrong_context_fails() -> None:
    ring = KeyRing.from_material(KEY_A)
    envelope = ring.encrypt(b"x", "credential:1")
    with pytest.raises(SecretsError):
        ring.decrypt(envelope, "credential:2")


def test_tampered_ciphertext_fails() -> None:
    ring = KeyRing.from_material(KEY_A)
    prefix, kid, nonce, ciphertext = ring.encrypt(b"hello").split(":")
    flipped = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    with pytest.raises(SecretsError):
        ring.decrypt(":".join((prefix, kid, nonce, flipped)))


def test_garbage_is_not_an_envelope() -> None:
    ring = KeyRing.from_material(KEY_A)
    with pytest.raises(SecretsError):
        ring.decrypt("not-an-envelope")


def test_missing_master_key_is_an_error() -> None:
    ring = KeyRing.from_material("")
    with pytest.raises(SecretsError):
        ring.encrypt(b"x")


def test_unknown_key_id_fails() -> None:
    envelope = KeyRing.from_material(KEY_A).encrypt(b"x")
    with pytest.raises(SecretsError):
        KeyRing.from_material(KEY_B).decrypt(envelope)


def test_key_rotation_with_previous_key() -> None:
    old_ring = KeyRing.from_material(KEY_A)
    envelope = old_ring.encrypt(b"rotate me", "ctx")
    new_ring = KeyRing.from_material(KEY_B, previous=KEY_A)
    assert new_ring.decrypt(envelope, "ctx") == b"rotate me"
    assert new_ring.needs_rotation(envelope)
    fresh = new_ring.reencrypt(envelope, "ctx")
    assert not new_ring.needs_rotation(fresh)
    assert new_ring.key_id_of(fresh) == key_id_for(bytes.fromhex(KEY_B))
    assert KeyRing.from_material(KEY_B).decrypt(fresh, "ctx") == b"rotate me"


def test_derive_key_accepts_hex_and_passphrases() -> None:
    assert derive_key(KEY_A) == bytes.fromhex(KEY_A)
    stretched = derive_key("a long enough passphrase")
    assert len(stretched) == 32
    assert stretched == derive_key("a long enough passphrase")
    with pytest.raises(SecretsError):
        derive_key("short")


def test_generated_key_is_valid() -> None:
    key = generate_master_key()
    assert len(key) == 64
    assert len(derive_key(key)) == 32


def test_module_functions_use_the_configured_key(master_key: str) -> None:
    envelope = encrypt_secret("ghp_not_a_real_token", "credential:abc")
    assert decrypt_secret(envelope, "credential:abc") == "ghp_not_a_real_token"
    assert reencrypt_secret(envelope, "credential:abc") != envelope
