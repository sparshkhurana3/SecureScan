"""Stalled-job decisions, workspace garbage collection, the scan_job task registration, executor helpers."""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from securescan.config import get_settings
from securescan.db.models.enums import JobState
from securescan.jobs import hooks
from securescan.jobs.app import app, load_tasks
from securescan.jobs.scan_job import MAX_ATTEMPTS, is_last_attempt
from securescan.runner import recovery
from securescan.runner.executor import _Finish, describe_exit
from securescan.runner.recovery import decide_stalled, gc_workspaces, is_stale
from securescan.runner.workspace import Workspace, remove_tree, workspaces_root
from securescan.util import utcnow
from tests.unit.conftest import FakeSession


# --------------------------------------------------------------------------- decisions
def test_stalled_jobs_are_requeued_once_then_failed() -> None:
    assert decide_stalled(0) == JobState.QUEUED
    assert decide_stalled(1) == JobState.QUEUED
    assert decide_stalled(2) == JobState.FAILED
    assert decide_stalled(5) == JobState.FAILED
    assert MAX_ATTEMPTS == 2


def test_staleness() -> None:
    now = utcnow()
    assert is_stale(now - timedelta(seconds=400), now - timedelta(hours=1), now, 300)
    assert not is_stale(now - timedelta(seconds=10), now - timedelta(hours=1), now, 300)
    assert is_stale(None, now - timedelta(seconds=400), now, 300)  # no heartbeat: use the last update
    assert not is_stale(None, now - timedelta(seconds=5), now, 300)
    assert is_stale(now, now, now, 0)  # start-up: everything in flight is orphaned


def test_the_last_attempt_is_the_second() -> None:
    assert is_last_attempt(0) is False
    assert is_last_attempt(1) is True
    assert is_last_attempt(2) is True


# --------------------------------------------------------------------------- the task is registered
def test_scan_job_task_and_hooks_are_registered() -> None:
    load_tasks()
    assert "scan_job" in app.tasks
    task = app.tasks["scan_job"]
    assert task.queue == "scans"
    strategy = task.retry_strategy
    assert strategy is not None and strategy.max_attempts == 2
    assert hooks.has_periodic_hook("stalled_jobs") and hooks.has_periodic_hook("workspace_gc")


# --------------------------------------------------------------------------- executor helpers
def test_exit_descriptions() -> None:
    assert "exit code 2" in describe_exit(2, "a\nb\nlast line\n")
    assert "last line" in describe_exit(2, "a\nb\nlast line\n")
    assert "memory" in describe_exit(137, "")
    assert "exit code" in describe_exit(None, "")
    secret = "ghs_" + "Q1w2E3r4" * 5
    assert secret not in describe_exit(1, f"token {secret}")
    assert describe_exit(3, "") == "The tool failed with exit code 3."


def test_finish_signal_carries_its_state() -> None:
    signal = _Finish(JobState.FAILED, "because")
    assert signal.state == JobState.FAILED and signal.reason == "because" and signal.outputs == []
    assert not signal.skipped and "because" in str(signal)
    assert _Finish(JobState.COMPLETED, "n/a", skipped=True).skipped
    hash(signal)  # exceptions must stay hashable (a dataclass would break this)


# --------------------------------------------------------------------------- workspaces
def test_workspace_layout_and_modes() -> None:
    job_id = uuid.uuid4()
    ws = Workspace.create(job_id)
    assert ws.root == workspaces_root() / str(job_id)
    for directory in (ws.src, ws.out, ws.config):
        assert directory.is_dir()
    assert (ws.out.stat().st_mode & 0o777) == 0o777  # any scanner uid can write its reports
    assert (ws.src.stat().st_mode & 0o777) == 0o775 and (ws.config.stat().st_mode & 0o777) == 0o775
    (ws.src / "file.txt").write_text("x", encoding="utf-8")
    again = Workspace.create(job_id)  # a retried job starts clean
    assert not (again.src / "file.txt").exists()
    again.cleanup()
    assert not ws.root.exists()
    again.cleanup()  # idempotent


def test_remove_tree_copes_with_read_only_entries(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "ro.txt").write_text("x", encoding="utf-8")
    os.chmod(root / "sub" / "ro.txt", 0o444)
    os.chmod(root / "sub", 0o555)
    try:
        assert remove_tree(root) is True
    finally:
        if (root / "sub").exists():
            os.chmod(root / "sub", 0o755)
    assert not root.exists()
    assert remove_tree(tmp_path / "never-existed") is True


@asynccontextmanager
async def fake_scope() -> AsyncIterator[FakeSession]:
    yield FakeSession()  # every job id is unknown to the database


async def test_gc_removes_old_unowned_workspaces_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(recovery, "session_scope", fake_scope)
    root = workspaces_root()
    old, fresh = uuid.uuid4(), uuid.uuid4()
    for job_id in (old, fresh):
        Workspace.create(job_id)
    stranger = root / "not-a-job-id"
    stranger.mkdir()
    long_ago = time.time() - 30 * 3600
    for path in (root / str(old), stranger):
        os.utime(path, (long_ago, long_ago))
    removed = await gc_workspaces()
    assert removed == [str(old)]
    assert not (root / str(old)).exists()
    assert (root / str(fresh)).exists()  # younger than 24 hours
    assert stranger.exists()  # never delete what we did not create


async def test_gc_keeps_the_workspace_of_a_live_job(monkeypatch: pytest.MonkeyPatch) -> None:
    import types

    job_id = uuid.uuid4()
    Workspace.create(job_id)
    long_ago = time.time() - 30 * 3600
    os.utime(workspaces_root() / str(job_id), (long_ago, long_ago))
    live = types.SimpleNamespace(id=job_id, state=JobState.RUNNING, heartbeat_at=utcnow(), updated_at=utcnow())

    @asynccontextmanager
    async def scope() -> AsyncIterator[Any]:
        session = FakeSession(rows=[live])
        yield session

    monkeypatch.setattr(recovery, "session_scope", scope)
    assert await gc_workspaces() == []
    assert (workspaces_root() / str(job_id)).exists()
    live.heartbeat_at = utcnow() - timedelta(hours=2)  # the worker died: now it is an orphan
    assert await gc_workspaces() == [str(job_id)]


async def test_gc_without_a_workspaces_directory() -> None:
    assert not workspaces_root().exists()
    assert await gc_workspaces() == []
    assert get_settings().workspace_max_age_hours == 24
