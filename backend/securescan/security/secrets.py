"""AES-256-GCM encryption for secrets stored in the database.

A stored secret is a text envelope::

    ss1:<key id>:<nonce, base64url>:<ciphertext+tag, base64url>

The key id (first 8 hex characters of a hash of the key) is stored with every ciphertext, so a
master key can be rotated: put the new key in ``SECURESCAN_MASTER_KEY`` and the old one in
``SECURESCAN_MASTER_KEY_PREVIOUS``; old envelopes still decrypt, new ones use the new key, and
``reencrypt_secret`` migrates an envelope. ``context`` (for example ``"credential:<id>"``) is
authenticated as additional data, so a ciphertext cannot be moved to another row undetected.

The master key is 32 random bytes written as 64 hex characters (``python scripts/dev.py secrets
init`` does this). Any other string of at least 16 characters is stretched with HKDF-SHA256.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from dataclasses import dataclass
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from securescan.config import get_settings

ENVELOPE_VERSION = "ss1"
_HEX_KEY = re.compile(r"^[0-9a-fA-F]{64}$")


class SecretsError(Exception):
    """The master key is missing or invalid, or an envelope cannot be decrypted."""


@dataclass(frozen=True)
class MasterKey:
    key_id: str
    key: bytes


def derive_key(material: str) -> bytes:
    """Turn the configured master key text into 32 key bytes."""
    text = material.strip()
    if _HEX_KEY.match(text):
        return bytes.fromhex(text)
    if len(text) == 44 and text.endswith("="):
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            raw = b""
        if len(raw) == 32:
            return raw
    if len(text) < 16:
        raise SecretsError("master key is too short (use 64 hex characters)")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"securescan-master-key-v1",
        info=b"aes-256-gcm",
    ).derive(text.encode("utf-8"))


def key_id_for(key: bytes) -> str:
    return hashlib.sha256(b"securescan-kid:" + key).hexdigest()[:8]


def make_master_key(material: str) -> MasterKey:
    key = derive_key(material)
    return MasterKey(key_id=key_id_for(key), key=key)


def generate_master_key() -> str:
    """A fresh master key as 64 hex characters."""
    return os.urandom(32).hex()


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _aad(context: str) -> bytes:
    return b"securescan:" + context.encode("utf-8")


class KeyRing:
    """The current master key plus any previous keys that may still decrypt old envelopes."""

    def __init__(self, current: MasterKey | None, previous: tuple[MasterKey, ...] = ()) -> None:
        self._current = current
        self._by_id = {k.key_id: k for k in previous}
        if current is not None:
            self._by_id[current.key_id] = current

    @classmethod
    def from_material(cls, current: str, previous: str = "") -> KeyRing:
        cur = make_master_key(current) if current.strip() else None
        prev = (make_master_key(previous),) if previous.strip() else ()
        return cls(cur, prev)

    @property
    def current_key_id(self) -> str:
        return self._require_current().key_id

    def _require_current(self) -> MasterKey:
        if self._current is None:
            raise SecretsError("no master key configured (SECURESCAN_MASTER_KEY_FILE)")
        return self._current

    def encrypt(self, plaintext: bytes, context: str = "") -> str:
        master = self._require_current()
        nonce = os.urandom(12)
        ciphertext = AESGCM(master.key).encrypt(nonce, plaintext, _aad(context))
        return ":".join((ENVELOPE_VERSION, master.key_id, _b64e(nonce), _b64e(ciphertext)))

    def decrypt(self, envelope: str, context: str = "") -> bytes:
        parts = envelope.split(":")
        if len(parts) != 4 or parts[0] != ENVELOPE_VERSION:
            raise SecretsError("not a SecureScan secret envelope")
        key = self._by_id.get(parts[1])
        if key is None:
            raise SecretsError(f"no master key with id {parts[1]} is configured")
        try:
            return AESGCM(key.key).decrypt(_b64d(parts[2]), _b64d(parts[3]), _aad(context))
        except (InvalidTag, binascii.Error, ValueError) as exc:
            raise SecretsError("secret cannot be decrypted (wrong key or context, or damaged)") from exc

    def key_id_of(self, envelope: str) -> str:
        parts = envelope.split(":")
        if len(parts) != 4 or parts[0] != ENVELOPE_VERSION:
            raise SecretsError("not a SecureScan secret envelope")
        return parts[1]

    def needs_rotation(self, envelope: str) -> bool:
        return self.key_id_of(envelope) != self.current_key_id

    def reencrypt(self, envelope: str, context: str = "") -> str:
        return self.encrypt(self.decrypt(envelope, context), context)


@lru_cache
def get_keyring() -> KeyRing:
    settings = get_settings()
    return KeyRing.from_material(settings.master_key, settings.master_key_previous)


def encrypt_secret(plaintext: str | bytes, context: str = "") -> str:
    """Encrypt with the current master key; returns the text envelope to store."""
    data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
    return get_keyring().encrypt(data, context)


def decrypt_secret(envelope: str, context: str = "") -> str:
    """Decrypt an envelope to text. ``context`` must equal the one used to encrypt."""
    return get_keyring().decrypt(envelope, context).decode("utf-8")


def decrypt_secret_bytes(envelope: str, context: str = "") -> bytes:
    return get_keyring().decrypt(envelope, context)


def reencrypt_secret(envelope: str, context: str = "") -> str:
    """Re-encrypt under the current key (key rotation)."""
    return get_keyring().reencrypt(envelope, context)


def current_key_id() -> str:
    return get_keyring().current_key_id
