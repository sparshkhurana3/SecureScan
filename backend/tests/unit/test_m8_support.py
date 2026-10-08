"""The shared helpers of the M8 builders: container specs from catalogue entries, the egress hold, small utilities."""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from securescan.config import Settings
from securescan.runner.egress import EgressError
from securescan.runner.tools import _support
from securescan.runner.tools._support import (
    content_dir,
    egress_network,
    hold_egress,
    proxy_env,
    proxy_host_port,
    release_egress,
    skip_job,
    slug,
    spec_from_entry,
    write_private_file,
)
from tests.unit.m8_helpers import DIGEST
from tests.unit.runner_helpers import real_catalogue

IMAGE = f"quay.io/skopeo/stable@{DIGEST}"


def test_slug() -> None:
    assert slug("My App (v2)!") == "my-app-v2" and slug("a" * 100, 10) == "a" * 10
    assert slug("---") == "x" and slug("") == "x" and slug("\u00dcn\u00efcode name") == "n-code-name"


def test_content_directories_are_created_open_to_the_scanner_uid() -> None:
    root = Path(Settings().content_root)
    directory = content_dir(Settings(), "grype-db")
    assert directory == root / "grype-db" and directory.is_dir()
    if os.name != "nt":
        assert directory.stat().st_mode & 0o777 == 0o777
    assert content_dir(Settings()) == root, "the root itself is only created"
    for bad in ("../x", "a/b", ".hidden", "", "x y"):
        with pytest.raises(ValueError):
            content_dir(Settings(), bad)


def test_the_egress_network_is_the_backend_unless_overridden(monkeypatch: pytest.MonkeyPatch) -> None:
    assert egress_network(Settings()) == "securescan_backend"
    monkeypatch.setenv("SECURESCAN_EGRESS_CLIENT_NETWORK", "securescan_dast")
    assert egress_network(Settings()) == "securescan_dast"


def test_proxy_helpers() -> None:
    assert proxy_host_port("http://securescan-egress:3128") == ("securescan-egress", 3128)
    assert proxy_host_port("http://proxy.example") == ("proxy.example", 3128)
    assert proxy_host_port("") is None and proxy_host_port("not a url") is None
    env = proxy_env("http://securescan-egress:3128")
    assert env["HTTPS_PROXY"] == env["http_proxy"] == "http://securescan-egress:3128" and "localhost" in env["NO_PROXY"]
    assert proxy_env("") == {}


def test_private_files_are_exclusive_and_mode_0600(tmp_path: Path) -> None:
    path = write_private_file(tmp_path, "auth.json", '{"a": 1}')
    assert path.read_text(encoding="utf-8") == '{"a": 1}'
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    replaced = write_private_file(tmp_path, "auth.json", "new")
    assert replaced.read_text(encoding="utf-8") == "new"
    for bad in ("../x", "a/b", ""):
        with pytest.raises(ValueError):
            write_private_file(tmp_path, bad, "x")


def test_a_spec_from_a_catalogue_entry_takes_everything_from_the_entry() -> None:
    entry = real_catalogue()["skopeo"]
    spec = spec_from_entry(
        entry,
        IMAGE,
        name="securescan-job-1-skopeo",
        binds=[("/data/out", "/out", False)],
        env={"HTTPS_PROXY": "http://p:3128"},
        network="securescan_backend",
        labels={"securescan.job_id": "1"},
        command=entry.render_command({"target_url": "docker://ghcr.io/o/a:1"}),
    )
    assert spec.image == IMAGE and spec.user == "1000:1000" and spec.read_only_rootfs is True
    assert spec.command[:3] == ["copy", "--retry-times", "2"] and spec.command[3] == "docker://ghcr.io/o/a:1"
    assert spec.env == {"HOME": "/tmp", "TMPDIR": "/out/tmp", "HTTPS_PROXY": "http://p:3128"}
    assert spec.mem_limit == "2g" and spec.nano_cpus == 2_000_000_000 and spec.pids_limit == 256
    assert spec.tmpfs == {"/tmp": "rw,size=256m,mode=1777"} and spec.entrypoint is None
    assert spec.labels["securescan.managed"] == "true" and spec.labels["securescan.tool"] == "skopeo"
    assert spec.labels["securescan.job_id"] == "1" and spec.network == "securescan_backend"
    cleared = spec_from_entry(real_catalogue()["semgrep"], IMAGE, name="x")
    assert cleared.entrypoint == [""], "an entry that clears the entrypoint keeps doing so"
    assert cleared.user == "1000:1000"


def test_a_spec_can_override_the_users_of_the_entry_and_the_tmpfs() -> None:
    entry = real_catalogue()["sonarqube-server"]
    spec = spec_from_entry(entry, IMAGE, name="sonarqube", tmpfs={"/tmp": "rw,exec,size=1m"}, user="root")
    assert spec.user == "0" and spec.tmpfs["/tmp"] == "rw,exec,size=1m" and "/opt/sonarqube/temp" in spec.tmpfs


async def test_skip_job_ends_the_job_as_skipped() -> None:
    from securescan.db.models.enums import JobState
    from securescan.runner.executor import _Finish

    with pytest.raises(_Finish) as info:
        skip_job("no compiled classes found")
    assert info.value.skipped is True and info.value.state == JobState.COMPLETED and info.value.reason == "no compiled classes found"


# --------------------------------------------------------------------------- the egress hold
class Leases:
    def __init__(self) -> None:
        self.opened: list[list[str]] = []
        self.closed = 0
        self.fail: Exception | None = None

    def __call__(self, hosts: Any) -> Any:
        leases = self

        @asynccontextmanager
        async def lease() -> Any:
            if leases.fail is not None:
                raise leases.fail
            leases.opened.append(sorted(hosts))
            try:
                yield "http://securescan-egress:3128"
            finally:
                leases.closed += 1

        return lease()


@pytest.fixture
def leases(monkeypatch: pytest.MonkeyPatch) -> Leases:
    from securescan.runner import egress

    fake = Leases()
    monkeypatch.setattr(egress, "egress_lease", fake)
    yield fake
    _support._HOLDS.clear()


async def test_the_hold_keeps_a_lease_open_until_it_is_released(leases: Leases) -> None:
    url = await hold_egress("job-1", ["search.maven.org", "repo1.maven.org"], 3600)
    assert url == "http://securescan-egress:3128"
    assert leases.opened == [["repo1.maven.org", "search.maven.org"]] and leases.closed == 0
    await asyncio.sleep(0)
    assert leases.closed == 0, "still held"
    await release_egress("job-1")
    assert leases.closed == 1
    await release_egress("job-1")  # releasing twice is harmless
    assert leases.closed == 1


async def test_the_hold_ends_by_itself_after_its_time_limit(leases: Leases) -> None:
    await hold_egress("job-2", ["h.example"], 0.05)
    await asyncio.sleep(0.3)
    assert leases.closed == 1


async def test_holding_again_for_the_same_job_replaces_the_hold(leases: Leases) -> None:
    await hold_egress("job-3", ["a.example"], 3600)
    await hold_egress("job-3", ["a.example"], 3600)
    assert len(leases.opened) == 2 and leases.closed == 1
    await release_egress("job-3")
    assert leases.closed == 2


async def test_a_proxy_that_cannot_start_is_an_error_for_the_caller(leases: Leases) -> None:
    leases.fail = EgressError("The egress proxy did not become ready in 30 seconds.")
    with pytest.raises(EgressError):
        await hold_egress("job-4", ["a.example"], 60)
    assert "job-4" not in _support._HOLDS
