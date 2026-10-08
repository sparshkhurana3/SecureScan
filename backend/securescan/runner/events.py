"""Live progress of a scan: PostgreSQL ``LISTEN``/``NOTIFY`` plus a log file per job.

Choice (plan M3 task 2 asked to record it): the worker writes every log line to the job's log file under
the artifacts root *and* publishes it with ``pg_notify`` on the channel ``scan_<scan id without dashes>``.
The API's event stream (``GET /scans/{id}/events``) first sends a snapshot and the tail of each job log
(read from the file when the API can see the artifacts volume), then ``LISTEN``s. NOTIFY payloads are
limited to 8000 bytes, so log lines travel in batches of at most ``MAX_PAYLOAD`` bytes. Notifications are
a convenience: the stream also re-reads the database every few seconds, so a missed one only delays an
update. A line never carries a secret: ``scrub`` runs before anything is written or published.

Message shapes (JSON in the payload, ``event`` is also the SSE event name)::

    {"event": "state", "scan_id": ..., "job_id": ..., "tool": ..., "state": "running", "scan_state": ...}
    {"event": "log",   "scan_id": ..., "job_id": ..., "tool": ..., "lines": ["...", "..."]}
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from sqlalchemy import text

from securescan.db.engine import get_engine
from securescan.logging import get_logger, scrub
from securescan.storage.artifacts import resolve_key

log = get_logger(__name__)

MAX_PAYLOAD = 7000  # bytes of JSON per NOTIFY (the server limit is 8000)
FLUSH_INTERVAL = 0.5
MAX_LOG_FILE_BYTES = 64 * 1024 * 1024  # the file stops growing here; the tail stays in the artifact
LOG_NAME = "job.log"


def scan_channel(scan_id: uuid.UUID | str) -> str:
    """The NOTIFY channel of a scan (a plain identifier: lower-case letters, digits, underscore)."""
    return "scan_" + str(scan_id).replace("-", "").lower()


def job_log_key(scan_id: uuid.UUID, job_id: uuid.UUID) -> str:
    """Storage key (relative to the artifacts root) of a job's log file."""
    return f"scans/{scan_id}/{job_id}/{LOG_NAME}"


def job_log_path(scan_id: uuid.UUID, job_id: uuid.UUID) -> Path:
    return resolve_key(job_log_key(scan_id, job_id))


def encode_message(message: dict[str, Any]) -> str:
    return json.dumps(message, separators=(",", ":"), default=str)


async def notify(scan_id: uuid.UUID | str, message: dict[str, Any]) -> None:
    """Publish ``message`` on the scan's channel. Never raises: progress is best effort."""
    payload = encode_message(message)
    if len(payload.encode("utf-8")) > MAX_PAYLOAD + 900:
        payload = encode_message({k: v for k, v in message.items() if k != "lines"})
    try:
        async with get_engine().connect() as conn:
            await conn.execute(
                text("SELECT pg_notify(:channel, :payload)"),
                {"channel": scan_channel(scan_id), "payload": payload},
            )
            await conn.commit()
    except Exception as exc:  # noqa: BLE001 - a lost notification must never fail a scan
        log.warning("notify_failed", error=type(exc).__name__)


def batch_lines(lines: list[str], limit: int = MAX_PAYLOAD) -> list[list[str]]:
    """Group lines into batches whose JSON size stays under ``limit`` bytes."""
    batches: list[list[str]] = []
    current: list[str] = []
    size = 0
    for line in lines:
        cost = len(json.dumps(line).encode("utf-8")) + 1
        if cost > limit:
            line = line[: max(1, limit // 4)]
            cost = len(json.dumps(line).encode("utf-8")) + 1
        if current and size + cost > limit:
            batches.append(current)
            current, size = [], 0
        current.append(line)
        size += cost
    if current:
        batches.append(current)
    return batches


class JobLog:
    """Collects a job's log lines: scrubs them, appends to the log file, publishes them in batches."""

    def __init__(
        self,
        scan_id: uuid.UUID,
        job_id: uuid.UUID,
        tool: str,
        *,
        path: Path | None = None,
        publish: Callable[[uuid.UUID, dict[str, Any]], Awaitable[None]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.scan_id = scan_id
        self.job_id = job_id
        self.tool = tool
        self.path = path or job_log_path(scan_id, job_id)
        self._publish = publish or notify
        self._clock = clock
        self._pending: list[str] = []
        self._last_flush = clock()
        self._written = 0
        self._lock = asyncio.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o775)
        self._handle = open(self.path, "a", encoding="utf-8")  # noqa: SIM115 - closed in close()

    async def write(self, line: str) -> None:
        clean = scrub(line.rstrip("\r\n"))
        async with self._lock:
            if self._written < MAX_LOG_FILE_BYTES:
                data = clean + "\n"
                self._handle.write(data)
                self._handle.flush()
                self._written += len(data)
            self._pending.append(clean)
            if self._clock() - self._last_flush >= FLUSH_INTERVAL or sum(map(len, self._pending)) > MAX_PAYLOAD:
                await self._flush_locked()

    async def system(self, line: str) -> None:
        """A line produced by SecureScan itself (prefixed so it cannot be mistaken for tool output)."""
        await self.write(f"[securescan] {line}")

    async def flush(self) -> None:
        async with self._lock:
            await self._flush_locked()

    async def _flush_locked(self) -> None:
        pending, self._pending = self._pending, []
        self._last_flush = self._clock()
        for batch in batch_lines(pending):
            await self._publish(
                self.scan_id,
                {
                    "event": "log",
                    "scan_id": str(self.scan_id),
                    "job_id": str(self.job_id),
                    "tool": self.tool,
                    "lines": batch,
                },
            )

    async def close(self) -> None:
        await self.flush()
        try:
            self._handle.flush()
            os.fsync(self._handle.fileno())
        except OSError:
            pass
        self._handle.close()


def tail_lines(path: Path, max_lines: int = 200, max_bytes: int = 256 * 1024) -> list[str]:
    """The last ``max_lines`` lines of a log file (empty when the file does not exist)."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            data = handle.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[-max_lines:]


async def state_event(
    scan_id: uuid.UUID,
    job_id: uuid.UUID | None,
    tool: str | None,
    state: str,
    scan_state: str,
    extra: dict[str, Any] | None = None,
) -> None:
    """Publish a state change of a job (and the scan's state after it)."""
    message: dict[str, Any] = {
        "event": "state",
        "scan_id": str(scan_id),
        "job_id": str(job_id) if job_id else None,
        "tool": tool,
        "state": state,
        "scan_state": scan_state,
    }
    if extra:
        message.update(extra)
    await notify(scan_id, message)
