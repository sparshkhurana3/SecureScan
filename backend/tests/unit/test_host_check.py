"""The worker's host check: parsing, evaluation, reading the container's view, enforcement, backup status."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from securescan.config import get_settings
from securescan.observability.metrics import BACKUP_LAST_SUCCESS
from securescan.runner import host_check
from securescan.runner.host_check import (
    HostCheckError,
    HostFacts,
    Thresholds,
    docker_ping_url,
    enforce_host_check,
    evaluate,
    host_check_mode,
    parse_api_version,
    parse_backup_status,
    parse_controllers,
    parse_int_file,
    parse_server_header,
    read_cgroup,
    read_docker,
    refresh_backup_gauge,
)

GOOD = HostFacts(
    cgroup_v2=True,
    cgroup_controllers=frozenset({"cpuset", "cpu", "io", "memory", "pids"}),
    max_map_count=524288,
    file_max=262144,
    docker_version=(29, 0, 1),
    docker_api=(1, 52),
)


def names(checks: list[Any]) -> list[str]:
    return [c.name for c in checks]


# --------------------------------------------------------------------------- parsing
def test_parse_int_file() -> None:
    assert parse_int_file("524288\n") == 524288
    assert parse_int_file("  65530 \n") == 65530
    assert parse_int_file("") is None and parse_int_file(None) is None and parse_int_file("max") is None


def test_parse_controllers() -> None:
    assert parse_controllers("cpuset cpu io memory pids\n") == {"cpuset", "cpu", "io", "memory", "pids"}
    assert parse_controllers(None) == set()


def test_parse_server_header_and_api_version() -> None:
    assert parse_server_header("Docker/29.0.1 (linux)") == (29, 0, 1)
    assert parse_server_header("Docker/28.3 (linux)") == (28, 3, 0)
    assert parse_server_header("nginx") is None and parse_server_header(None) is None
    assert parse_api_version("1.52") == (1, 52)
    assert parse_api_version("1.52.1") is None and parse_api_version(None) is None


def test_docker_ping_url() -> None:
    assert docker_ping_url("tcp://socket-proxy:2375") == "http://socket-proxy:2375/_ping"
    assert docker_ping_url("https://proxy:2376") == "https://proxy:2376/_ping"
    assert docker_ping_url("unix:///var/run/docker.sock") is None
    assert docker_ping_url("") is None


# --------------------------------------------------------------------------- evaluating
def test_a_good_host_passes_every_check() -> None:
    result = evaluate(GOOD)
    assert result.ok and result.warnings == [] and result.blocking_failures == []
    assert {"cgroup_v2", "cgroup_controllers", "vm.max_map_count", "fs.file-max", "docker_api", "docker_engine"} <= set(names(result.checks))
    assert result.to_dict()["ok"] is True


def test_cgroup_v1_blocks() -> None:
    result = evaluate(HostFacts(cgroup_v2=False, max_map_count=524288, file_max=131072, docker_api=(1, 52), docker_version=(29, 0, 0)))
    assert not result.ok and names(result.blocking_failures) == ["cgroup_v2"]


def test_missing_memory_or_pids_controller_blocks_but_missing_cpu_only_warns() -> None:
    no_pids = HostFacts(**{**GOOD.__dict__, "cgroup_controllers": frozenset({"cpu", "memory"})})
    result = evaluate(no_pids)
    assert names(result.blocking_failures) == ["cgroup_controllers"] and "pids" in result.blocking_failures[0].detail
    no_cpu = HostFacts(**{**GOOD.__dict__, "cgroup_controllers": frozenset({"memory", "pids"})})
    result = evaluate(no_cpu)
    assert result.ok and names(result.warnings) == ["cgroup_controllers"]


def test_low_kernel_limits_block_with_the_remedy() -> None:
    result = evaluate(HostFacts(**{**GOOD.__dict__, "max_map_count": 65530, "file_max": 1000}))
    assert names(result.blocking_failures) == ["vm.max_map_count", "fs.file-max"]
    assert "sysctl.d/99-securescan.conf" in result.blocking_failures[0].detail


def test_the_thresholds_come_from_the_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_HOST_MIN_MAX_MAP_COUNT", "100")
    monkeypatch.setenv("SECURESCAN_HOST_MIN_DOCKER_API", "1.50")
    get_settings.cache_clear()
    limits = Thresholds.from_settings(get_settings())
    assert limits.max_map_count == 100 and limits.docker_api == (1, 50)
    assert evaluate(HostFacts(**{**GOOD.__dict__, "max_map_count": 200, "docker_api": (1, 49)}), limits).blocking_failures[0].name == "docker_api"


def test_an_old_docker_api_blocks_and_an_old_engine_only_warns() -> None:
    too_old = evaluate(HostFacts(**{**GOOD.__dict__, "docker_api": (1, 43), "docker_version": (24, 0, 0)}))
    assert names(too_old.blocking_failures) == ["docker_api"]
    older = evaluate(HostFacts(**{**GOOD.__dict__, "docker_api": (1, 47), "docker_version": (27, 3, 1)}))
    assert older.ok and names(older.warnings) == ["docker_engine"]


def test_values_that_could_not_be_read_are_warnings_never_passes() -> None:
    result = evaluate(HostFacts())
    assert result.ok  # nothing is known to be wrong...
    assert {"cgroup_v2", "vm.max_map_count", "fs.file-max", "docker_version"} <= set(names(result.warnings))  # ...and nothing is claimed


# --------------------------------------------------------------------------- reading the container's view
def test_read_cgroup_v2_and_v1_and_unknown(tmp_path: Path) -> None:
    v2 = tmp_path / "v2"
    v2.mkdir()
    (v2 / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
    assert read_cgroup(v2) == (True, frozenset({"cpu", "memory", "pids"}))
    v1 = tmp_path / "v1"
    (v1 / "memory").mkdir(parents=True)
    assert read_cgroup(v1) == (False, None)
    assert read_cgroup(tmp_path / "nothing") == (None, None)


async def test_read_docker_takes_the_versions_from_the_ping_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, headers={"Server": "Docker/29.0.1 (linux)", "Api-Version": "1.52"}, text="OK")

    monkeypatch.setenv("SECURESCAN_DOCKER_HOST", "tcp://socket-proxy:2375")
    get_settings.cache_clear()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert await read_docker(get_settings(), http=client) == ((29, 0, 1), (1, 52))
    assert seen == ["http://socket-proxy:2375/_ping"]


async def test_read_docker_retries_then_gives_up(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        raise httpx.ConnectError("refused", request=request)

    monkeypatch.setenv("SECURESCAN_DOCKER_HOST", "tcp://socket-proxy:2375")
    get_settings.cache_clear()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert await read_docker(get_settings(), http=client, attempts=3, delay=0.0) == (None, None)
    assert calls["n"] == 3


async def test_read_docker_without_a_tcp_host_reads_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_DOCKER_HOST", "unix:///var/run/docker.sock")
    get_settings.cache_clear()
    assert await read_docker(get_settings()) == (None, None)


# --------------------------------------------------------------------------- enforcement
def test_the_mode_follows_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    assert host_check_mode() == "enforce"  # production by default
    monkeypatch.setenv("SECURESCAN_ENV", "dev")
    get_settings.cache_clear()
    assert host_check_mode() == "warn"
    monkeypatch.setenv("SECURESCAN_HOST_CHECK", "off")
    get_settings.cache_clear()
    assert host_check_mode() == "off"
    monkeypatch.setenv("SECURESCAN_HOST_CHECK", "enforce")
    get_settings.cache_clear()
    assert host_check_mode() == "enforce"


async def test_enforcement_raises_on_a_blocking_failure_and_sets_the_gauge(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = evaluate(HostFacts(**{**GOOD.__dict__, "cgroup_v2": False}))

    async def fake_run(settings: Any = None) -> Any:
        return bad

    monkeypatch.setattr(host_check, "run_host_check", fake_run)
    with pytest.raises(HostCheckError, match="cgroup v1"):
        await enforce_host_check(get_settings())
    assert host_check.HOST_CHECK_OK._value.get() == 0  # type: ignore[attr-defined]

    monkeypatch.setenv("SECURESCAN_HOST_CHECK", "warn")
    get_settings.cache_clear()
    result = await enforce_host_check(get_settings())  # only logs
    assert result is bad


async def test_enforcement_passes_a_good_host_and_off_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run(settings: Any = None) -> Any:
        return evaluate(GOOD)

    monkeypatch.setattr(host_check, "run_host_check", fake_run)
    result = await enforce_host_check(get_settings())
    assert result is not None and result.ok and host_check.HOST_CHECK_OK._value.get() == 1  # type: ignore[attr-defined]
    monkeypatch.setenv("SECURESCAN_HOST_CHECK", "off")
    get_settings.cache_clear()
    assert await enforce_host_check(get_settings()) is None


# --------------------------------------------------------------------------- backup status
def test_parse_backup_status() -> None:
    status = parse_backup_status(json.dumps({"last_success": 1760000000, "set": "securescan-backup-x", "size_bytes": 12, "offsite": True}))
    assert status is not None and status.last_success == 1760000000.0 and status.set_name == "securescan-backup-x"
    assert status.size_bytes == 12 and status.offsite is True
    assert parse_backup_status('{"last_success": 5.5}') is not None
    for bad in (None, "", "not json", "[]", '{"last_success": 0}', '{"last_success": "x"}', '{"last_success": true}', "{}"):
        assert parse_backup_status(bad) is None


def test_refresh_backup_gauge_reads_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "status.json"
    monkeypatch.setenv("SECURESCAN_BACKUP_STATUS_FILE", str(path))
    get_settings.cache_clear()
    assert refresh_backup_gauge() is None  # no file: the gauge keeps its value
    path.write_text('{"last_success": 1760000123}', encoding="utf-8")
    status = refresh_backup_gauge()
    assert status is not None and BACKUP_LAST_SUCCESS._value.get() == 1760000123.0  # type: ignore[attr-defined]
