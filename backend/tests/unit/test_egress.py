"""The shared egress proxy: configuration, start, allowlist changes, leases and the idle stop."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from securescan.config import Settings
from securescan.runner.egress import (
    EGRESS_NAME,
    LABEL_HOSTS,
    EgressError,
    EgressManager,
    allow_hash,
    normalise_hosts,
    render_squid_conf,
    resolve_egress_image,
)
from tests.unit.github_helpers import FakeClock

IMAGE = "ubuntu/squid@sha256:" + "ab" * 32


class FakeLauncher:
    """The few Launcher methods the manager uses, backed by a dict."""

    def __init__(self) -> None:
        self.containers: dict[str, dict[str, Any]] = {}
        self.specs: list[Any] = []
        self.removed: list[str] = []
        self.stopped: list[str] = []
        self._counter = 0

    async def inspect(self, ref: str) -> dict[str, Any] | None:
        for name, info in self.containers.items():
            if ref in (name, info["Id"]):
                return info
        return None

    async def create(self, spec: Any) -> str:
        self._counter += 1
        container_id = "container-%d" % self._counter
        self.specs.append(spec)
        self.containers[spec.name] = {
            "Id": container_id,
            "State": {"Running": False},
            "Config": {"Labels": dict(spec.labels)},
        }
        return container_id

    async def start(self, container_id: str) -> None:
        for info in self.containers.values():
            if info["Id"] == container_id:
                info["State"]["Running"] = True

    async def stop(self, container_id: str, timeout: int = 10) -> None:
        self.stopped.append(container_id)
        for info in self.containers.values():
            if info["Id"] == container_id:
                info["State"]["Running"] = False

    async def remove(self, container_id: str, force: bool = True) -> None:
        self.removed.append(container_id)
        for name in [n for n, i in self.containers.items() if container_id in (n, i["Id"])]:
            del self.containers[name]


async def ready(_host: str, _port: int) -> bool:
    return True


async def pinned_image() -> str:
    return IMAGE


def make_manager(
    tmp_path: Path, launcher: FakeLauncher, clock: FakeClock | None = None, **settings: Any
) -> EgressManager:
    clock = clock or FakeClock()
    values: dict[str, Any] = {"data_root": str(tmp_path), "egress_enabled": True}
    values.update(settings)
    return EgressManager(
        launcher_factory=lambda: launcher,
        settings=Settings(**values),
        clock=clock,
        sleep=clock.sleep,
        probe=ready,
        image_resolver=pinned_image,
    )


# --------------------------------------------------------------------------- configuration
def test_hosts_are_normalised_and_deduplicated() -> None:
    assert normalise_hosts(["GitHub.com", "api.github.com.", " github.com ", ""]) == [
        "api.github.com",
        "github.com",
    ]


@pytest.mark.parametrize(
    "host",
    ["evil.com\nhttp_access allow all", "a b", "*.github.com", "github.com:443", "../x", "a..b", "-x.com"],
)
def test_hosts_that_could_inject_configuration_are_refused(host: str) -> None:
    with pytest.raises(EgressError):
        normalise_hosts([host])


def test_squid_configuration_allows_only_the_listed_hosts() -> None:
    conf = render_squid_conf({"github.com", "api.github.com"})
    assert "acl allowed_hosts dstdomain api.github.com github.com" in conf
    access = [line for line in conf.splitlines() if line.startswith("http_access")]
    assert access == [
        "http_access deny !Safe_ports",
        "http_access deny CONNECT !SSL_ports",
        "http_access allow allowed_hosts",
        "http_access deny all",
    ]
    assert "cache deny all" in conf
    assert "http_port 3128" in conf


def test_an_empty_allowlist_is_refused() -> None:
    with pytest.raises(EgressError):
        render_squid_conf([])


def test_allow_hash_does_not_depend_on_order() -> None:
    assert allow_hash(["b", "a"]) == allow_hash(["a", "b"])
    assert allow_hash(["a"]) != allow_hash(["a", "b"])


async def test_the_image_must_be_pinned_by_digest_outside_dev() -> None:
    with pytest.raises(EgressError, match="digest"):
        await resolve_egress_image(Settings(env="production", egress_image="ubuntu/squid:latest"))
    assert await resolve_egress_image(Settings(env="production", egress_image=IMAGE)) == IMAGE
    assert await resolve_egress_image(Settings(env="dev", egress_image="ubuntu/squid:6")) == (
        "ubuntu/squid:6"
    )


# --------------------------------------------------------------------------- starting the proxy
async def test_first_use_starts_the_proxy_with_the_requested_hosts(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    manager = make_manager(tmp_path, launcher)
    url = await manager.ensure({"github.com", "api.github.com"})
    assert url == "http://securescan-egress:3128"
    (spec,) = launcher.specs
    assert spec.name == EGRESS_NAME
    assert spec.image == IMAGE
    assert spec.network == "securescan_backend"
    assert spec.extra_networks == ["securescan_egress"]
    assert spec.labels[LABEL_HOSTS] == "api.github.com,github.com"
    assert spec.read_only_rootfs is True
    assert spec.user == "13:13"
    ((source, target, read_only),) = spec.binds
    assert target == "/etc/squid/securescan.conf" and read_only is True
    assert Path(source).parent == tmp_path / "egress"
    assert "dstdomain api.github.com github.com" in Path(source).read_text(encoding="ascii")
    assert launcher.containers[EGRESS_NAME]["State"]["Running"] is True


async def test_a_second_request_for_hosts_already_allowed_reuses_the_container(
    tmp_path: Path,
) -> None:
    launcher = FakeLauncher()
    manager = make_manager(tmp_path, launcher)
    await manager.ensure({"github.com", "api.github.com"})
    await manager.ensure({"github.com"})
    assert len(launcher.specs) == 1
    assert launcher.removed == []


async def test_a_new_host_recreates_the_proxy_with_the_union(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    manager = make_manager(tmp_path, launcher)
    await manager.ensure({"github.com"})
    await manager.ensure({"repo1.maven.org"})
    assert len(launcher.specs) == 2
    assert launcher.removed == ["container-1"]
    assert launcher.specs[1].labels[LABEL_HOSTS] == "github.com,repo1.maven.org"
    configs = sorted(p.name for p in (tmp_path / "egress").glob("squid-*.conf"))
    assert len(configs) == 1  # the superseded configuration file is removed


async def test_a_stopped_container_is_replaced(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    manager = make_manager(tmp_path, launcher)
    await manager.ensure({"github.com"})
    launcher.containers[EGRESS_NAME]["State"]["Running"] = False
    await manager.ensure({"github.com"})
    assert len(launcher.specs) == 2
    assert launcher.containers[EGRESS_NAME]["State"]["Running"] is True


async def test_a_proxy_that_never_answers_is_removed_and_reported(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    clock = FakeClock()

    async def dead(_host: str, _port: int) -> bool:
        return False

    manager = EgressManager(
        launcher_factory=lambda: launcher,
        settings=Settings(data_root=str(tmp_path), egress_enabled=True),
        clock=clock,
        sleep=clock.sleep,
        probe=dead,
        image_resolver=pinned_image,
    )
    with pytest.raises(EgressError, match="did not become ready"):
        await manager.ensure({"github.com"})
    assert launcher.containers == {}


async def test_egress_can_be_switched_off_for_development(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    manager = make_manager(tmp_path, launcher, egress_enabled=False)
    assert await manager.ensure({"github.com"}) == ""
    assert launcher.specs == []
    assert await manager.stop_if_idle() is False


async def test_bad_host_names_never_reach_docker(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    manager = make_manager(tmp_path, launcher)
    with pytest.raises(EgressError):
        await manager.ensure({"github.com\nhttp_access allow all"})
    assert launcher.specs == []


# --------------------------------------------------------------------------- idle stop and leases
async def test_the_proxy_stops_after_the_idle_period(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    clock = FakeClock()
    manager = make_manager(tmp_path, launcher, clock, egress_idle_minutes=5)
    await manager.ensure({"github.com"})
    clock.now += 4 * 60
    assert await manager.stop_if_idle() is False
    assert EGRESS_NAME in launcher.containers
    clock.now += 2 * 60
    assert await manager.stop_if_idle() is True
    assert launcher.containers == {}
    assert launcher.stopped == ["container-1"]
    assert await manager.stop_if_idle() is False  # nothing left to stop


async def test_use_resets_the_idle_clock(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    clock = FakeClock()
    manager = make_manager(tmp_path, launcher, clock, egress_idle_minutes=5)
    await manager.ensure({"github.com"})
    clock.now += 4 * 60
    await manager.ensure({"github.com"})
    clock.now += 4 * 60
    assert await manager.stop_if_idle() is False  # only 4 minutes since the last use


async def test_a_lease_keeps_the_proxy_alive_and_ends_the_idle_clock_on_exit(
    tmp_path: Path,
) -> None:
    launcher = FakeLauncher()
    clock = FakeClock()
    manager = make_manager(tmp_path, launcher, clock, egress_idle_minutes=5)
    async with manager.lease({"github.com"}) as url:
        assert url == "http://securescan-egress:3128"
        assert manager.active_leases == 1
        clock.now += 30 * 60
        assert await manager.stop_if_idle() is False  # a long job holds the proxy open
    assert manager.active_leases == 0
    clock.now += 4 * 60
    assert await manager.stop_if_idle() is False  # the idle period starts when the lease ends
    clock.now += 2 * 60
    assert await manager.stop_if_idle() is True


async def test_a_failed_start_releases_the_lease(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    manager = make_manager(tmp_path, launcher)
    with pytest.raises(EgressError):
        async with manager.lease({"not a host"}):
            pass
    assert manager.active_leases == 0


async def test_reconcile_reports_the_real_state(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    manager = make_manager(tmp_path, launcher)
    assert await manager.reconcile() is False
    await manager.ensure({"github.com"})
    assert await manager.reconcile() is True
