"""Helpers shared by the GitHub tests: RSA keys, a fake clock and a recording logger."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_CACHE: dict[int, tuple[str, str]] = {}


def rsa_pair(index: int = 0) -> tuple[str, str]:
    """(private PEM, public PEM) of a 2048-bit RSA key; generated once per index per run."""
    if index not in _CACHE:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
        public = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode("ascii")
        )
        _CACHE[index] = (private, public)
    return _CACHE[index]


class FakeClock:
    """An epoch clock that ``FakeClock.sleep`` advances (so back-off waits cost no real time)."""

    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class RecordingLogger:
    """Stands in for a structlog logger and keeps every call so tests can search it."""

    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict[str, Any]]] = []

    def _record(self, level: str, event: str, **kwargs: Any) -> None:
        self.records.append((level, event, kwargs))

    def debug(self, event: str, **kwargs: Any) -> None:
        self._record("debug", event, **kwargs)

    def info(self, event: str, **kwargs: Any) -> None:
        self._record("info", event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._record("warning", event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._record("error", event, **kwargs)

    def text(self) -> str:
        return "\n".join("%s %s %r" % record for record in self.records)
