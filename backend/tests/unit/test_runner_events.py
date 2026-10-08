"""Live progress: channel names, NOTIFY batching, the job log file."""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

import pytest

from securescan.runner import events
from securescan.runner.events import (
    MAX_PAYLOAD,
    JobLog,
    batch_lines,
    encode_message,
    job_log_key,
    job_log_path,
    notify,
    scan_channel,
    state_event,
    tail_lines,
)

TOKEN = "ghs_" + "Z9y8X7w6" * 5


def test_channel_is_a_plain_identifier() -> None:
    scan_id = uuid.uuid4()
    channel = scan_channel(scan_id)
    assert channel == "scan_" + scan_id.hex and re.fullmatch(r"[a-z0-9_]+", channel)
    assert scan_channel(str(scan_id).upper()) == channel
    assert len(channel) < 63  # a PostgreSQL identifier limit


def test_log_paths_live_under_the_scan_and_job() -> None:
    scan_id, job_id = uuid.uuid4(), uuid.uuid4()
    assert job_log_key(scan_id, job_id) == f"scans/{scan_id}/{job_id}/job.log"
    assert job_log_path(scan_id, job_id).name == "job.log"
    assert job_log_path(scan_id, job_id).parent.name == str(job_id)


def test_batches_stay_under_the_payload_limit() -> None:
    lines = [f"line {i} " + "x" * 200 for i in range(200)] + ["y" * 20000]
    batches = batch_lines(lines)
    assert sum(len(b) for b in batches) == len(lines)
    for batch in batches:
        assert len(json.dumps(batch, separators=(",", ":")).encode("utf-8")) <= MAX_PAYLOAD + 2
    assert batches[0][0] == lines[0]
    assert batch_lines([]) == []
    assert batch_lines(["a", "b"]) == [["a", "b"]]


class FakeConn:
    def __init__(self) -> None:
        self.executed: list[tuple[str, dict[str, Any]]] = []
        self.committed = False

    async def __aenter__(self) -> FakeConn:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def execute(self, statement: Any, params: dict[str, Any]) -> None:
        self.executed.append((str(statement), params))

    async def commit(self) -> None:
        self.committed = True


class FakeEngine:
    def __init__(self) -> None:
        self.conn = FakeConn()

    def connect(self) -> FakeConn:
        return self.conn


async def test_notify_sends_pg_notify_on_the_scan_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = FakeEngine()
    monkeypatch.setattr(events, "get_engine", lambda: engine)
    scan_id = uuid.uuid4()
    await notify(scan_id, {"event": "log", "lines": ["a"]})
    statement, params = engine.conn.executed[0]
    assert "pg_notify" in statement and engine.conn.committed
    assert params["channel"] == scan_channel(scan_id)
    assert json.loads(params["payload"]) == {"event": "log", "lines": ["a"]}


async def test_notify_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> Any:
        raise RuntimeError("database down")

    monkeypatch.setattr(events, "get_engine", broken)
    await notify(uuid.uuid4(), {"event": "state"})  # must not raise


async def test_state_event_message_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[Any, dict[str, Any]]] = []

    async def capture(scan_id: Any, message: dict[str, Any]) -> None:
        sent.append((scan_id, message))

    monkeypatch.setattr(events, "notify", capture)
    scan_id, job_id = uuid.uuid4(), uuid.uuid4()
    await state_event(scan_id, job_id, "semgrep", "running", "running", {"reason": None})
    assert sent[0][1] == {
        "event": "state",
        "scan_id": str(scan_id),
        "job_id": str(job_id),
        "tool": "semgrep",
        "state": "running",
        "scan_state": "running",
        "reason": None,
    }
    await state_event(scan_id, None, None, "cancel_requested", "running")
    assert sent[1][1]["job_id"] is None


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


async def test_job_log_writes_the_file_and_publishes_batches(tmp_path: Path) -> None:
    published: list[dict[str, Any]] = []

    async def publish(scan_id: Any, message: dict[str, Any]) -> None:
        published.append(message)

    clock = Clock()
    scan_id, job_id = uuid.uuid4(), uuid.uuid4()
    log = JobLog(scan_id, job_id, "semgrep", path=tmp_path / "scan" / "job.log", publish=publish, clock=clock)
    await log.write("first")
    await log.write("second\r\n")
    assert published == []  # batched: nothing yet
    clock.now = 1.0
    await log.write("third")
    assert [m["lines"] for m in published] == [["first", "second", "third"]]
    assert published[0]["event"] == "log" and published[0]["tool"] == "semgrep"
    assert published[0]["scan_id"] == str(scan_id) and published[0]["job_id"] == str(job_id)
    await log.system("done")
    await log.close()
    assert published[-1]["lines"] == ["[securescan] done"]
    assert (tmp_path / "scan" / "job.log").read_text(encoding="utf-8") == "first\nsecond\nthird\n[securescan] done\n"


async def test_secrets_never_reach_the_file_or_the_stream(tmp_path: Path) -> None:
    published: list[dict[str, Any]] = []

    async def publish(scan_id: Any, message: dict[str, Any]) -> None:
        published.append(message)

    log = JobLog(uuid.uuid4(), uuid.uuid4(), "gitleaks", path=tmp_path / "job.log", publish=publish)
    await log.write(f"cloning with {TOKEN}")
    await log.write("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123")
    await log.close()
    text = (tmp_path / "job.log").read_text(encoding="utf-8")
    assert TOKEN not in text and "abcdefghijklmnopqrstuvwxyz0123" not in text
    assert TOKEN not in json.dumps(published)


async def test_a_huge_burst_is_flushed_before_the_payload_limit(tmp_path: Path) -> None:
    published: list[dict[str, Any]] = []

    async def publish(scan_id: Any, message: dict[str, Any]) -> None:
        published.append(message)

    log = JobLog(uuid.uuid4(), uuid.uuid4(), "semgrep", path=tmp_path / "job.log", publish=publish, clock=Clock())
    for i in range(100):
        await log.write(f"{i:03d} " + "z" * 500)
    await log.close()
    assert len(published) > 1
    assert sum(len(m["lines"]) for m in published) == 100
    for message in published:
        assert len(encode_message(message).encode("utf-8")) < 8000


def test_tail_lines(tmp_path: Path) -> None:
    path = tmp_path / "job.log"
    assert tail_lines(path) == []
    path.write_text("\n".join(f"line {i}" for i in range(1000)) + "\n", encoding="utf-8")
    assert tail_lines(path, max_lines=3) == ["line 997", "line 998", "line 999"]
    assert len(tail_lines(path, max_lines=5000, max_bytes=100)) < 20  # only the last bytes are read
