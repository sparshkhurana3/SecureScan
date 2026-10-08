"""Shared builders for the DAST tests (no database, no Docker, no network)."""

from __future__ import annotations

import types
import uuid
from pathlib import Path
from typing import Any

import pytest

from securescan.config import Settings, get_settings
from securescan.db.models.enums import AppType, TargetEnvironment, TargetKind
from securescan.runner import dast_egress
from securescan.runner.tools.base import ToolContext
from tests.unit.conftest import FakeSession
from tests.unit.runner_helpers import make_ctx

SQUID_IMAGE = "ubuntu/squid@sha256:" + "b" * 64
CIDRS = "10.0.0.0/8"


def make_target(**overrides: Any) -> Any:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "name": "Shop (UAT)",
        "kind": TargetKind.URL,
        "locator": "http://10.20.30.40:8080/",
        "environment": TargetEnvironment.UAT,
        "login_profile_id": None,
        "host_approved": False,
        "scope_includes": [],
        "scope_excludes": [],
        "blackout_windows": [],
        "api_spec_type": None,
        "api_spec_locator": None,
        "api_spec_artifact_id": None,
        "rate_limit_rps": None,
        "vendor_authorization_artifact_id": None,
        "vendor_authorized_from": None,
        "vendor_authorized_until": None,
        "vendor_contact": None,
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def make_application(kind: AppType = AppType.INTERNAL, hosting: str | None = None) -> Any:
    return types.SimpleNamespace(id=uuid.uuid4(), type=kind, hosting=hosting)


class FakeLauncher:
    """Just enough of the Launcher for the proxy lifecycle (no Docker)."""

    def __init__(self, *, running: bool = True, exits: bool = False) -> None:
        self.created: list[Any] = []
        self.started: list[str] = []
        self.removed: list[str] = []
        self.running = running
        self.exits = exits
        self.listed: list[str] = []
        self.infos: dict[str, dict[str, Any]] = {}

    async def create(self, spec: Any) -> str:
        self.created.append(spec)
        cid = "c" * 63 + str(len(self.created))
        self.infos[spec.name] = {
            "Id": cid,
            "Name": "/" + spec.name,
            "Config": {"Labels": dict(spec.labels)},
            "State": {"Running": self.running, "Status": "exited" if self.exits else "running", "ExitCode": 1},
        }
        self.infos[cid] = self.infos[spec.name]
        return cid

    async def start(self, cid: str) -> None:
        self.started.append(cid)

    async def inspect(self, name: str) -> dict[str, Any] | None:
        return self.infos.get(name)

    async def remove(self, cid: str, force: bool = True) -> None:
        self.removed.append(cid)
        info = self.infos.pop(cid, None)
        if info is not None:
            self.infos.pop(str(info["Name"]).lstrip("/"), None)

    async def list_by_label(self, label: str) -> list[str]:
        return list(self.listed)


class Scheduled:
    """Records the watchers a prepare started (they are not run in unit tests)."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, Any, float]] = []

    def __call__(self, job_id: Any, handle: Any, max_seconds: float) -> None:
        self.calls.append((job_id, handle, max_seconds))


def prepared_ctx(
    tool: str,
    mode: str,
    monkeypatch: pytest.MonkeyPatch,
    *,
    target: Any | None = None,
    application: Any | None = None,
    session: FakeSession | None = None,
    options: dict[str, Any] | None = None,
    launcher: FakeLauncher | None = None,
    cidrs: str = CIDRS,
    extra_env: dict[str, str] | None = None,
) -> tuple[ToolContext, FakeLauncher, Scheduled]:
    """A ToolContext for ``prepare``: allowlisted CIDRs, a squid image, a fake launcher, no watcher task."""
    monkeypatch.setenv("SECURESCAN_DAST_ALLOWED_CIDRS", cidrs)
    monkeypatch.setenv("SECURESCAN_EGRESS_IMAGE", SQUID_IMAGE)
    for key, value in (extra_env or {}).items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    fake = launcher or FakeLauncher()
    scheduled = Scheduled()
    monkeypatch.setattr("securescan.runner.launcher.get_launcher", lambda: fake)
    monkeypatch.setattr(dast_egress, "schedule_cleanup", scheduled)
    monkeypatch.setattr(dast_egress, "READY_SETTLE_SECONDS", 0.0)
    ctx = make_ctx(tool, kind=TargetKind.URL, options=dict(options or {}), settings=Settings())
    ctx.scan.mode = mode  # type: ignore[attr-defined]
    ctx.target = target if target is not None else make_target()
    ctx.application = application
    ctx.session = session if session is not None else FakeSession()
    return ctx, fake, scheduled


def work_dir(ctx: ToolContext) -> Path:
    return Path(ctx.workspace.root)
