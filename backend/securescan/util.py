"""Small shared helpers: UUIDv7 ids, UTC time, hashing."""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from datetime import datetime, timezone

UTC = timezone.utc


def utcnow() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as an aware UTC datetime (naive values are assumed to be UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _uuid7_fallback() -> uuid.UUID:
    """UUIDv7 (RFC 9562) for interpreters without ``uuid.uuid7`` (before Python 3.14)."""
    millis = time.time_ns() // 1_000_000
    raw = bytearray(millis.to_bytes(6, "big") + os.urandom(10))
    raw[6] = (raw[6] & 0x0F) | 0x70  # version 7
    raw[8] = (raw[8] & 0x3F) | 0x80  # variant 10
    return uuid.UUID(bytes=bytes(raw))


def new_id() -> uuid.UUID:
    """A new UUIDv7 primary key (time ordered)."""
    native = getattr(uuid, "uuid7", None)
    if native is not None:
        return native()  # type: ignore[no-any-return]
    return _uuid7_fallback()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
