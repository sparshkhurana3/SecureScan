"""Dependency-Check: command, network and secrets, the no-disclosure mode, the first-update block, exit code 14."""

from __future__ import annotations

import os
import types
from pathlib import Path
from typing import Any

import pytest

from securescan.config import Settings, get_settings
from securescan.db.models.enums import AppType
from securescan.runner.specs import ContainerResult
from securescan.runner.tools import dependency_check as odc_module
from securescan.runner.tools import get_builder
from securescan.runner.tools.base import ToolPreparationError
from securescan.runner.tools.dependency_check import (
    DependencyCheckBuilder,
    central_enabled,
    no_disclosure,
    render_properties,
    write_properties,
)
from tests.unit.m8_helpers import PROXY, ctx_for, host_path_of

BUILDER = DependencyCheckBuilder()
KEY = "0a1b2c3d-4e5f-6789-abcd-ef0123456789"


def flag_value(command: list[str], flag: str) -> str:
    return command[command.index(flag) + 1]


def prepared(app_type: AppType = AppType.INTERNAL, options: dict[str, Any] | None = None, proxy: str = PROXY) -> Any:
    ctx = ctx_for("dependency-check", app_type=app_type, options=options)
    ctx.extra_values["project_key"] = "shop-main"
    if central_enabled(ctx) and proxy:
        ctx.extra_values["egress_proxy_url"] = proxy
    return ctx


def test_registered() -> None:
    assert get_builder("dependency-check") is odc_module.BUILDER


# --------------------------------------------------------------------------- the command
def test_scan_command_with_maven_central_goes_through_the_proxy() -> None:
    command = BUILDER.build_command(prepared())
    assert command[:2] == ["--scan", "/src"]
    for expected in ("--noupdate", "--disableVersionCheck", "--disableOssIndex", "--disableNodeAudit", "--disableYarnAudit", "--disablePnpmAudit"):
        assert expected in command, expected
    assert command.count("--format") == 2 and {"XML", "HTML"} <= set(command)
    assert flag_value(command, "--out") == "/out" and flag_value(command, "--project") == "shop-main"
    assert flag_value(command, "--data") == "/usr/share/dependency-check/data"
    assert flag_value(command, "--propertyfile") == "/config/odc.properties"
    assert flag_value(command, "--proxyserver") == "securescan-egress" and flag_value(command, "--proxyport") == "3128"
    assert "--disableCentral" not in command and "--nvdApiKey" not in command


def test_no_disclosure_turns_central_off_and_needs_no_proxy() -> None:
    ctx = prepared(options={"no_disclosure": True})
    command = BUILDER.build_command(ctx)
    assert "--disableCentral" in command and "--proxyserver" not in command and "--proxyport" not in command


def test_vendor_applications_default_to_no_disclosure() -> None:
    assert no_disclosure(ctx_for("dependency-check", app_type=AppType.VENDOR)) is True
    assert no_disclosure(ctx_for("dependency-check", app_type=AppType.INTERNAL)) is False
    assert no_disclosure(ctx_for("dependency-check", app_type=AppType.VENDOR, options={"no_disclosure": False})) is False
    assert no_disclosure(ctx_for("dependency-check", app_type=AppType.INTERNAL, options={"no_disclosure": True})) is True
    assert central_enabled(ctx_for("dependency-check", app_type=AppType.VENDOR)) is False


def test_a_proxy_that_is_not_there_in_dev_means_no_proxy_flags() -> None:
    command = BUILDER.build_command(prepared(proxy=""))
    assert "--proxyserver" not in command and "--disableCentral" not in command


# --------------------------------------------------------------------------- network, mounts and secrets
def test_container_with_central_joins_only_the_egress_client_network() -> None:
    ctx = prepared()
    spec = BUILDER.container_spec(ctx)
    assert spec.network == ctx.settings.network_backend and spec.extra_networks == []
    assert spec.read_only_rootfs is True and spec.user == "1000:1000"
    data = host_path_of(spec, "/usr/share/dependency-check/data")
    assert data == Path(get_settings().content_root) / "odc-data" and data.is_dir()
    assert [ro for _s, target, ro in spec.binds if target == "/usr/share/dependency-check/data"] == [False]
    assert host_path_of(spec, "/config") == ctx.workspace.config
    assert [ro for _s, target, ro in spec.binds if target == "/src"] == [True]


def test_the_egress_network_can_be_overridden(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_EGRESS_CLIENT_NETWORK", "securescan_dast")
    ctx = ctx_for("dependency-check", settings=Settings())
    ctx.extra_values["project_key"] = "p"
    assert BUILDER.container_spec(ctx).network == "securescan_dast"


def test_container_without_disclosure_has_no_network_at_all() -> None:
    spec = BUILDER.container_spec(prepared(AppType.VENDOR))
    assert spec.network == "none" and spec.extra_networks == []


def test_the_data_mount_can_be_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_ODC_DATA_READ_ONLY", "true")
    ctx = ctx_for("dependency-check", settings=Settings())
    ctx.extra_values["project_key"] = "p"
    spec = BUILDER.container_spec(ctx)
    assert [ro for _s, target, ro in spec.binds if target == "/usr/share/dependency-check/data"] == [True]


def test_the_nvd_key_is_never_in_a_scan_container_or_its_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_NVD_API_KEY", KEY)
    ctx = ctx_for("dependency-check", settings=Settings())
    ctx.extra_values["project_key"] = "p"
    spec = BUILDER.container_spec(ctx)
    written = write_properties(ctx.workspace.config)
    haystack = " ".join([*spec.command, *spec.env.keys(), *spec.env.values(), written.read_text(encoding="utf-8")]).lower()
    assert KEY not in haystack and "nvd" not in haystack and "api.key" not in haystack


def test_the_update_properties_file_carries_the_key_with_mode_0600(tmp_path: Path) -> None:
    path = write_properties(tmp_path, KEY)
    assert f"nvd.api.key={KEY}" in path.read_text(encoding="utf-8")
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    assert "nvd.api.key" not in render_properties(None)
    for bad in ("short", "has space in it", "line\nbreak=1", "x" * 300):
        with pytest.raises(ValueError):
            render_properties(bad)
    rewritten = write_properties(tmp_path)  # replaced, not appended to
    assert KEY not in rewritten.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- exit codes
def test_exit_code_14_is_a_partial_result() -> None:
    ctx = prepared()
    assert BUILDER.classify_exit(ctx, 0) == "completed"
    assert BUILDER.classify_exit(ctx, 14) == "completed_partial"
    for code in (1, 2, 3, 15, 137, None):
        assert BUILDER.classify_exit(ctx, code) == "failed", code


async def test_post_run_notes_a_partial_result() -> None:
    ctx = prepared()
    await BUILDER.post_run(ctx, ContainerResult("c", 14, False, ""))
    assert any("partial" in note for note in ctx.coverage_notes)
    clean = prepared()
    await BUILDER.post_run(clean, ContainerResult("c", 0, False, ""))
    assert clean.coverage_notes == []


# --------------------------------------------------------------------------- prepare
async def test_scans_are_blocked_until_the_first_update_succeeded(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.jobs import scanner_health
    from tests.unit.conftest import FakeSession

    async def none(_session: Any) -> dict[str, Any]:
        return {}

    monkeypatch.setattr(scanner_health, "active_versions", none)
    ctx = ctx_for("dependency-check")
    ctx.session = FakeSession()  # type: ignore[assignment]
    with pytest.raises(ToolPreparationError) as info:
        await BUILDER.prepare(ctx)
    assert info.value.code == "odc.data_missing" and "first vulnerability data download" in str(info.value)


async def test_prepare_with_central_holds_the_egress_proxy_and_writes_a_key_free_properties_file(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.jobs import scanner_health
    from tests.unit.conftest import FakeSession

    async def installed(_session: Any) -> dict[str, Any]:
        return {"nvd_data": types.SimpleNamespace(version="nvd-20261007")}

    held: list[tuple[str, list[str], float]] = []
    released: list[str] = []

    async def hold(key: str, hosts: Any, seconds: float) -> str:
        held.append((key, sorted(hosts), seconds))
        return PROXY

    async def release(key: str) -> None:
        released.append(key)

    monkeypatch.setattr(scanner_health, "active_versions", installed)
    monkeypatch.setattr(odc_module, "hold_egress", hold)
    monkeypatch.setattr(odc_module, "release_egress", release)
    ctx = ctx_for("dependency-check", options={"timeout_minutes": 10})
    ctx.session = FakeSession()  # type: ignore[assignment]
    await BUILDER.prepare(ctx)
    assert held == [(f"odc:{ctx.job.id}", ["repo1.maven.org", "search.maven.org"], 10 * 60 + 300.0)]
    assert ctx.extra_values["egress_proxy_url"] == PROXY and ctx.extra_values["project_key"] == "shop-main"
    assert ctx.content_versions == {"nvd_data": "nvd-20261007"}
    properties = (ctx.workspace.config / "odc.properties").read_text(encoding="utf-8")
    assert "api.key" not in properties
    command = BUILDER.build_command(ctx)
    assert flag_value(command, "--proxyserver") == "securescan-egress"
    await BUILDER.post_run(ctx, ContainerResult("c", 0, False, ""))
    assert released == [f"odc:{ctx.job.id}"], "the proxy lease ends with the job"


async def test_prepare_without_disclosure_never_touches_the_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.jobs import scanner_health
    from tests.unit.conftest import FakeSession

    async def installed(_session: Any) -> dict[str, Any]:
        return {"nvd_data": types.SimpleNamespace(version="nvd-1")}

    async def hold(*_a: Any, **_k: Any) -> str:
        raise AssertionError("the proxy must not be used")

    monkeypatch.setattr(scanner_health, "active_versions", installed)
    monkeypatch.setattr(odc_module, "hold_egress", hold)
    ctx = ctx_for("dependency-check", app_type=AppType.VENDOR)
    ctx.session = FakeSession()  # type: ignore[assignment]
    await BUILDER.prepare(ctx)
    assert any("Maven Central" in note for note in ctx.coverage_notes)
    assert BUILDER.container_spec(ctx).network == "none"
