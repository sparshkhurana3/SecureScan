"""The SonarQube server container: specification, start on demand, idle stop (with a fake Docker and a fake server)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from securescan.config import Settings
from securescan.integrations.sonarqube.client import SonarNotReady
from securescan.jobs import sonarqube_lifecycle as lifecycle
from securescan.jobs.sonarqube_lifecycle import (
    build_server_spec,
    container_image,
    container_running,
    ensure_running,
    exec_tmpfs,
    idle_for,
    read_last_used,
    server_environment,
    stop_if_idle,
    touch_last_used,
)
from securescan.observability import metrics
from securescan.runner.specs import ContainerSpec
from tests.unit.runner_helpers import real_catalogue

IMAGE = "sonarqube@sha256:" + "a" * 64
OTHER = "sonarqube@sha256:" + "b" * 64


def settings(monkeypatch: pytest.MonkeyPatch | None = None, **env: str) -> Settings:
    if monkeypatch is not None:
        for key, value in env.items():
            monkeypatch.setenv("SECURESCAN_" + key.upper(), value)
    return Settings()


# --------------------------------------------------------------------------- the specification
def test_the_server_specification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = settings(monkeypatch, sonarqube_db_password="dbpw-123456")
    ca = tmp_path / "db-ca.crt"
    ca.write_text("CA")
    spec = build_server_spec(cfg, real_catalogue()["sonarqube-server"], IMAGE, ca_file=ca)
    assert spec.name == "sonarqube" and spec.image == IMAGE and spec.user == "1000:0"
    assert spec.network == cfg.network_sonarqube and spec.extra_networks == [cfg.network_backend]
    assert spec.stop_timeout == 300, "ElasticSearch needs the long grace period to shut down"
    assert spec.ulimits == {"nofile": (131072, 131072), "nproc": (8192, 8192)}
    assert spec.volumes == [
        ("securescan_sonarqube_data", "/opt/sonarqube/data", False),
        ("securescan_sonarqube_extensions", "/opt/sonarqube/extensions", False),
        ("securescan_sonarqube_logs", "/opt/sonarqube/logs", False),
    ]
    assert spec.binds == [(str(ca), "/opt/sonarqube/conf/db-ca.crt", True)]
    assert spec.env["SONAR_JDBC_URL"] == cfg.sonarqube_jdbc_url and "sslmode=verify-full" in spec.env["SONAR_JDBC_URL"]
    assert spec.env["SONAR_JDBC_USERNAME"] == "sonarqube" and spec.env["SONAR_JDBC_PASSWORD"] == "dbpw-123456"
    assert spec.env["SONAR_TELEMETRY_ENABLE"] == "false"
    assert spec.command == ["/opt/sonarqube/docker/sonar.sh"] and spec.entrypoint is None
    assert spec.read_only_rootfs is True
    assert spec.labels["securescan.role"] == "sonarqube"
    for path, options in spec.tmpfs.items():
        assert "exec" in options.split(",") and path in ("/opt/sonarqube/temp", "/tmp")
    assert spec.mem_limit == "4g" and spec.pids_limit == 2048


def test_the_password_is_left_out_when_none_is_configured_and_read_only_can_be_switched_off(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = settings(monkeypatch, sonarqube_read_only_rootfs="false")
    spec = build_server_spec(cfg, real_catalogue()["sonarqube-server"], IMAGE)
    assert "SONAR_JDBC_PASSWORD" not in spec.env and spec.read_only_rootfs is False and spec.binds == []
    assert server_environment(cfg).keys() == {"SONAR_JDBC_URL", "SONAR_JDBC_USERNAME"}


def test_exec_tmpfs_options() -> None:
    options = exec_tmpfs(real_catalogue()["sonarqube-server"])
    assert options["/opt/sonarqube/temp"] == "rw,exec,size=2g,uid=1000,gid=0,mode=0770"
    assert options["/tmp"].startswith("rw,exec,size=256m")


def test_container_helpers() -> None:
    assert container_running({"State": {"Running": True}}) and not container_running({"State": {"Running": False}})
    assert not container_running(None) and container_image({"Config": {"Image": IMAGE}}) == IMAGE and container_image(None) == ""
    assert idle_for(None, None, 100.0) is None
    assert idle_for(40.0, 10.0, 100.0) == 60.0 and idle_for(None, 70.0, 100.0) == 30.0 and idle_for(200.0, None, 100.0) == 0.0


def test_the_last_used_marker(tmp_path: Path) -> None:
    cfg = Settings()
    assert read_last_used(cfg) is None
    touch_last_used(cfg, 1234.5)
    assert read_last_used(cfg) == 1234.5
    touch_last_used(cfg)
    assert read_last_used(cfg) > 1234.5


# --------------------------------------------------------------------------- starting
class FakeDocker:
    """The launcher methods the lifecycle uses, over a dict of containers."""

    def __init__(self, info: dict[str, Any] | None = None) -> None:
        self.info = info
        self.calls: list[tuple[str, Any]] = []

    async def inspect(self, name: str) -> dict[str, Any] | None:
        self.calls.append(("inspect", name))
        return self.info

    async def create(self, spec: ContainerSpec) -> str:
        self.calls.append(("create", spec.image))
        self.info = {"Id": "new-id", "State": {"Running": False}, "Config": {"Image": spec.image}}
        return "new-id"

    async def start(self, cid: str) -> None:
        self.calls.append(("start", cid))
        assert self.info is not None
        self.info["State"]["Running"] = True

    async def remove(self, cid: str, force: bool = True) -> None:
        self.calls.append(("remove", cid))
        self.info = None

    async def stop(self, cid: str, timeout: int = 10) -> None:
        self.calls.append(("stop", (cid, timeout)))
        assert self.info is not None
        self.info["State"]["Running"] = False

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


class FakeSonar:
    def __init__(self, result: float | Exception = 12.0) -> None:
        self.result = result
        self.closed = False
        self.timeouts: list[float] = []

    async def wait_until_up(self, timeout_s: float, interval_s: float = 3.0) -> float:
        self.timeouts.append(timeout_s)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    async def aclose(self) -> None:
        self.closed = True


def spec_loader(image: str = IMAGE) -> Any:
    async def load(cfg: Settings) -> ContainerSpec:
        return ContainerSpec(image=image, command=["x"], name=cfg.sonarqube_container)

    return load


@pytest.fixture(autouse=True)
def no_first_time_setup(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    async def not_needed(_cfg: Any = None, **_kw: Any) -> bool:
        calls.append("needs_initialisation")
        return False

    monkeypatch.setattr(lifecycle, "needs_initialisation", not_needed)
    return calls


async def test_a_missing_container_is_created_from_the_catalogue_and_started() -> None:
    docker, sonar = FakeDocker(None), FakeSonar(42.0)
    clock = iter([100.0, 160.0, 160.0])
    result = await ensure_running(
        launcher=docker, client_factory=lambda cfg: sonar, spec_loader=spec_loader(), clock=lambda: next(clock)
    )
    assert docker.names() == ["inspect", "create", "start"]
    assert result.started is True and result.seconds_to_up == 42.0 and sonar.closed
    assert sonar.timeouts == [600.0], "the plan's ten minutes"
    assert metrics.SONARQUBE_START_SECONDS._value.get() == 60.0  # type: ignore[attr-defined]
    assert read_last_used(Settings()) is not None


async def test_a_stopped_container_is_just_started() -> None:
    docker = FakeDocker({"Id": "abc", "State": {"Running": False}, "Config": {"Image": IMAGE}})
    result = await ensure_running(launcher=docker, client_factory=lambda cfg: FakeSonar(), spec_loader=spec_loader())
    assert docker.names() == ["inspect", "start"] and docker.calls[1] == ("start", "abc") and result.started


async def test_a_stopped_container_of_an_older_image_is_recreated_keeping_its_volumes() -> None:
    docker = FakeDocker({"Id": "abc", "State": {"Running": False}, "Config": {"Image": OTHER}})
    await ensure_running(launcher=docker, client_factory=lambda cfg: FakeSonar(), spec_loader=spec_loader(IMAGE))
    assert docker.names() == ["inspect", "remove", "create", "start"]
    assert docker.calls[2] == ("create", IMAGE)


async def test_a_running_container_is_left_alone_and_only_waited_for() -> None:
    docker = FakeDocker({"Id": "abc", "State": {"Running": True}, "Config": {"Image": OTHER}})
    result = await ensure_running(launcher=docker, client_factory=lambda cfg: FakeSonar(1.0), spec_loader=spec_loader())
    assert docker.names() == ["inspect"] and result.started is False and result.seconds_to_up == 1.0


async def test_a_server_that_never_comes_up_raises_and_closes_the_client() -> None:
    docker = FakeDocker({"Id": "abc", "State": {"Running": True}, "Config": {"Image": IMAGE}})
    sonar = FakeSonar(SonarNotReady("did not become ready"))
    with pytest.raises(SonarNotReady):
        await ensure_running(launcher=docker, client_factory=lambda cfg: sonar, spec_loader=spec_loader())
    assert sonar.closed


async def test_the_first_time_setup_runs_inside_ensure_running(monkeypatch: pytest.MonkeyPatch) -> None:
    ran: list[str] = []

    async def needed(_cfg: Any = None, **_kw: Any) -> bool:
        return True

    async def initialise(_session: Any, _cfg: Any = None, **_kw: Any) -> list[str]:
        ran.append("initialise")
        return ["changed the SonarQube admin password"]

    class Scope:
        async def __aenter__(self) -> object:
            return object()

        async def __aexit__(self, *_a: object) -> None:
            return None

    monkeypatch.setattr(lifecycle, "needs_initialisation", needed)
    monkeypatch.setattr(lifecycle, "initialise", initialise)
    monkeypatch.setattr(lifecycle, "session_scope", lambda: Scope())
    docker = FakeDocker({"Id": "abc", "State": {"Running": True}, "Config": {"Image": IMAGE}})
    result = await ensure_running(launcher=docker, client_factory=lambda cfg: FakeSonar(), spec_loader=spec_loader())
    assert ran == ["initialise"] and result.initialised == ["changed the SonarQube admin password"]


# --------------------------------------------------------------------------- stopping when idle
def activity(busy: bool, finished: float | None) -> Any:
    async def check(_cfg: Settings) -> tuple[bool, float | None]:
        return busy, finished

    return check


def running_docker() -> FakeDocker:
    return FakeDocker({"Id": "abc", "State": {"Running": True}, "Config": {"Image": IMAGE}})


async def test_the_server_is_stopped_after_fifteen_idle_minutes() -> None:
    docker = running_docker()
    now = 10_000.0
    stopped = await stop_if_idle(launcher=docker, activity=activity(False, now - 16 * 60), now=lambda: now)
    assert stopped is True and docker.calls[-1] == ("stop", ("abc", 300))


async def test_it_keeps_running_while_a_job_is_queued_or_running() -> None:
    docker = running_docker()
    now = 10_000.0
    assert await stop_if_idle(launcher=docker, activity=activity(True, now - 3600), now=lambda: now) is False
    assert "stop" not in docker.names()
    assert read_last_used(Settings()) is not None, "a busy check counts as use"


async def test_it_keeps_running_within_the_idle_window() -> None:
    docker = running_docker()
    now = 10_000.0
    assert await stop_if_idle(launcher=docker, activity=activity(False, now - 14 * 60), now=lambda: now) is False
    touch_last_used(Settings(), now - 60)  # a start a minute ago
    assert await stop_if_idle(launcher=docker, activity=activity(False, now - 3600), now=lambda: now) is False
    assert "stop" not in docker.names()


async def test_the_marker_file_counts_as_use() -> None:
    docker = running_docker()
    now = 10_000.0
    touch_last_used(Settings(), now - 20 * 60)
    assert await stop_if_idle(launcher=docker, activity=activity(False, None), now=lambda: now) is True


async def test_a_server_without_any_trace_of_use_starts_its_idle_period() -> None:
    docker = running_docker()
    now = 10_000.0
    assert await stop_if_idle(launcher=docker, activity=activity(False, None), now=lambda: now) is False
    assert read_last_used(Settings()) == now


async def test_a_stopped_or_missing_server_is_not_stopped_again() -> None:
    for info in (None, {"Id": "abc", "State": {"Running": False}}):
        docker = FakeDocker(info)
        assert await stop_if_idle(launcher=docker, activity=activity(False, 0.0)) is False
        assert docker.names() == ["inspect"]


async def test_the_idle_minutes_are_a_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = settings(monkeypatch, sonarqube_idle_minutes="1")
    docker = running_docker()
    now = 10_000.0
    assert await stop_if_idle(settings=cfg, launcher=docker, activity=activity(False, now - 90), now=lambda: now) is True


async def test_the_periodic_hook_swallows_docker_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(**_kw: Any) -> bool:
        raise RuntimeError("docker is away")

    monkeypatch.setattr(lifecycle, "stop_if_idle", boom)
    await lifecycle.stop_idle_sonarqube(int(time.time()))  # must not raise


def test_the_hook_is_registered_under_the_planned_name() -> None:
    from securescan.jobs.hooks import has_periodic_hook

    assert has_periodic_hook("sonarqube_idle_stop")

