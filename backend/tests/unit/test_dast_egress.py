"""The per-job DAST proxy: generated squid.conf, container specification, lifecycle, access log summary."""

from __future__ import annotations

import asyncio
import types
import uuid
from pathlib import Path
from typing import Any

import pytest

from securescan.config import Settings
from securescan.db.models.enums import JobState, TargetKind
from securescan.domain.dast_rules import ALWAYS_BLOCKED, HostInfo
from securescan.runner import dast_egress
from securescan.runner.dast_egress import (
    CONF_NAME,
    DastProxyError,
    ProxyHandle,
    allowed_destinations,
    build_proxy_spec,
    proxy_name,
    proxy_url,
    read_access_log,
    release_proxy,
    render_squid_conf,
    schedule_cleanup,
    stop_proxy,
    summarise_access_log,
    sweep_stale_proxies,
    wait_until_running,
    watch_and_remove,
)
from securescan.runner.launcher import build_create_body
from securescan.runner.sources import SourceRequest, acquire_source

IMAGE = "ubuntu/squid@sha256:" + "b" * 64
JOB = uuid.UUID("11111111-2222-3333-4444-555555555555")


def host(name: str, port: int = 80, scheme: str = "http") -> HostInfo:
    return HostInfo(scheme=scheme, host=name, port=port)


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


@pytest.fixture(autouse=True)
def fast_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dast_egress, "READY_SETTLE_SECONDS", 0.0)


# --------------------------------------------------------------------------- squid.conf
def conf_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line and not line.startswith("#")]


def test_squid_conf_allows_only_the_target_host_and_port() -> None:
    text = render_squid_conf([host("shop.uat.example", 8443, "https")], name="securescan-dast-proxy-x")
    lines = conf_lines(text)
    assert "acl dast_names dstdomain shop.uat.example" in lines
    assert "acl dast_ports port 8443" in lines
    allows = [line for line in lines if line.startswith("http_access allow")]
    assert allows == ["http_access allow dast_names dast_ports"]
    assert lines[lines.index("http_access deny all") - 1].startswith("http_access allow")  # deny all comes last
    assert [line for line in lines if line.startswith("http_access")][-1] == "http_access deny all"
    assert "acl dast_ips" not in text and "allow all" not in text and "localnet" not in text
    assert "http_port 3128" in lines and "visible_hostname securescan-dast-proxy-x" in lines
    assert "cache deny all" in lines and "access_log stdio:/var/log/squid/access.log" in lines


def test_squid_conf_with_api_spec_host_ip_literals_and_ports() -> None:
    text = render_squid_conf(
        [host("shop.uat.example", 443, "https"), host("specs.example", 80), host("10.20.30.40", 8080), host("2001:db8::5", 8443, "https")],
        name="p",
    )
    lines = conf_lines(text)
    assert "acl dast_names dstdomain shop.uat.example specs.example" in lines
    assert "acl dast_ips dst 10.20.30.40 2001:db8::5" in lines
    assert "acl dast_ports port 80 443 8080 8443" in lines
    assert [line for line in lines if line.startswith("http_access allow")] == [
        "http_access allow dast_names dast_ports",
        "http_access allow dast_ips dast_ports",
    ]
    assert allowed_destinations([host("Shop.UAT.example."), host("10.1.1.1")]) == {"shop.uat.example", "10.1.1.1"}


def test_squid_conf_never_forwards_into_blocked_ranges() -> None:
    lines = conf_lines(render_squid_conf([host("shop.uat.example", 80), host("10.0.0.1", 80)], name="p"))
    blocked = next(line for line in lines if line.startswith("acl blocked_dst"))
    for network in ALWAYS_BLOCKED:
        assert str(network) in blocked
    assert "169.254.0.0/16" in blocked and "127.0.0.0/8" in blocked
    first_allow = next(i for i, line in enumerate(lines) if line.startswith("http_access allow"))
    assert lines.index("http_access deny dast_names blocked_dst") < first_allow  # refused before it is allowed
    assert lines.index("http_access deny dast_ips blocked_dst") < first_allow
    assert lines.index("http_access deny !dast_ports") < first_allow


@pytest.mark.parametrize("bad", ["", "bad host", "evil.example/../x", "a..b", "-start.example", "x" * 300, "*.example.com"])
def test_squid_conf_refuses_unusable_hosts(bad: str) -> None:
    with pytest.raises(DastProxyError):
        render_squid_conf([host(bad)], name="p")


def test_squid_conf_refuses_bad_ports_and_no_hosts() -> None:
    with pytest.raises(DastProxyError):
        render_squid_conf([host("a.example", 0)], name="p")
    with pytest.raises(DastProxyError):
        render_squid_conf([host("a.example", 70000)], name="p")
    with pytest.raises(DastProxyError):
        render_squid_conf([], name="p")


def test_names_and_urls() -> None:
    name = proxy_name(JOB)
    assert name == "securescan-dast-proxy-11111111-2222-3333-4444-555555555555"
    assert name.startswith("securescan-")  # what the socket proxy allowlist accepts
    assert proxy_url(name) == f"http://{name}:3128"


# --------------------------------------------------------------------------- the container
def spec_for(settings: Settings | None = None, directory: Path = Path("/var/lib/securescan/workspaces/j/proxy")) -> Any:
    return build_proxy_spec(
        image=IMAGE, name=proxy_name(JOB), token="tok", job_id=JOB, scan_id=uuid.UUID(int=7),
        directory=directory, hosts=["shop.uat.example"], settings=settings or Settings(),
    )  # fmt: skip


def test_the_proxy_joins_dast_and_egress_and_the_request_body_lists_both() -> None:
    settings = Settings()
    spec = spec_for(settings)
    assert spec.network == settings.network_dast and spec.extra_networks == [settings.network_egress]
    body = build_create_body(spec, host_path=lambda p: p)
    assert set(body["NetworkingConfig"]["EndpointsConfig"]) == {settings.network_dast, settings.network_egress}
    host_config = body["HostConfig"]
    assert host_config["NetworkMode"] == settings.network_dast
    assert host_config["CapDrop"] == ["ALL"] and host_config["SecurityOpt"] == ["no-new-privileges"]
    assert host_config["ReadonlyRootfs"] is True and host_config["Privileged"] is False
    assert body["Entrypoint"] == ["/usr/sbin/squid"] and body["User"] == "13:13"
    assert body["Cmd"] == ["-N", "-f", "/etc/squid/securescan.conf"]
    binds = host_config["Binds"]
    assert "/var/lib/securescan/workspaces/j/proxy/squid.conf:/etc/squid/securescan.conf:ro" in binds
    assert "/var/lib/securescan/workspaces/j/proxy/logs:/var/log/squid:rw" in binds
    assert body["Labels"]["securescan.role"] == "dast-proxy" and body["Labels"]["securescan.job_id"] == str(JOB)
    assert body["Labels"]["securescan.dast.token"] == "tok"
    assert "@sha256:" in body["Image"]


def test_the_scanner_network_is_not_the_proxys() -> None:
    from securescan.runner.tools.base import docker_network

    settings = Settings()
    assert docker_network(settings, "dast") == settings.network_dast  # the scanner: dast only
    assert docker_network(settings, "dast") != settings.network_egress


# --------------------------------------------------------------------------- start, stop, sweep
async def test_start_proxy_writes_the_config_and_starts_the_container(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    handle = await dast_egress.start_proxy(
        job_id=JOB, scan_id=uuid.UUID(int=7), workspace_root=tmp_path,
        hosts=[host("shop.uat.example", 443, "https")], settings=Settings(), launcher=launcher, image=IMAGE,
    )  # fmt: skip
    conf = (tmp_path / "proxy" / CONF_NAME).read_text(encoding="ascii")
    assert "acl dast_names dstdomain shop.uat.example" in conf and "port 443" in conf
    assert (tmp_path / "proxy" / "logs").is_dir()
    assert handle.name == proxy_name(JOB) and handle.url == proxy_url(handle.name)
    assert handle.hosts == ["shop.uat.example"] and handle.ports == [443]
    assert len(launcher.created) == 1 and launcher.started and launcher.created[0].image == IMAGE
    assert launcher.created[0].labels["securescan.dast.token"] == handle.token
    assert await stop_proxy(handle.name, token="wrong", launcher=launcher) is False  # another attempt's proxy
    assert await stop_proxy(handle.name, token=handle.token, launcher=launcher) is True
    assert await stop_proxy(handle.name, token=handle.token, launcher=launcher) is False  # already gone


async def test_a_proxy_that_exits_is_removed_and_reported(tmp_path: Path) -> None:
    launcher = FakeLauncher(running=False, exits=True)
    with pytest.raises(DastProxyError, match="stopped right after it started"):
        await dast_egress.start_proxy(
            job_id=JOB, scan_id=JOB, workspace_root=tmp_path, hosts=[host("a.example")],
            settings=Settings(), launcher=launcher, image=IMAGE,
        )  # fmt: skip
    assert launcher.removed, "the failed proxy must not be left behind"


async def test_a_proxy_that_never_runs_times_out(tmp_path: Path) -> None:
    launcher = FakeLauncher(running=False, exits=False)
    clock_value = [0.0]

    async def fast_sleep(seconds: float) -> None:
        clock_value[0] += 5.0

    with pytest.raises(DastProxyError, match="did not stay up"):
        await wait_until_running(
            launcher, "x", 20.0, sleep=fast_sleep, clock=lambda: clock_value[0]
        )
    launcher.infos["x"] = {"State": {"Running": True}}
    await wait_until_running(launcher, "x", 20.0, settle=0.0, sleep=fast_sleep, clock=lambda: clock_value[0])


async def test_the_proxy_must_stay_up_for_the_settle_time() -> None:
    launcher = FakeLauncher()
    launcher.infos["x"] = {"State": {"Running": True}}
    clock_value = [0.0]

    async def tick(seconds: float) -> None:
        clock_value[0] += 1.0

    await wait_until_running(launcher, "x", 30.0, settle=3.0, sleep=tick, clock=lambda: clock_value[0])
    assert clock_value[0] >= 3.0


async def test_stale_proxies_are_swept_but_the_kept_one_stays() -> None:
    launcher = FakeLauncher()
    launcher.infos["old"] = {"Id": "old", "Name": "/securescan-dast-proxy-old", "State": {}}
    launcher.infos["keep"] = {"Id": "keep", "Name": "/securescan-dast-proxy-keep", "State": {}}
    launcher.listed = ["old", "keep"]
    assert await sweep_stale_proxies(keep="securescan-dast-proxy-keep", launcher=launcher) == 1
    assert launcher.removed == ["old"]
    launcher.listed = ["missing"]
    assert await sweep_stale_proxies(launcher=launcher) == 1  # an id that vanished is still counted once removed


async def test_cleanup_never_raises() -> None:
    class Broken(FakeLauncher):
        async def inspect(self, name: str) -> Any:
            raise RuntimeError("docker is gone")

        async def list_by_label(self, label: str) -> list[str]:
            raise RuntimeError("docker is gone")

    assert await stop_proxy("x", launcher=Broken()) is False
    assert await sweep_stale_proxies(launcher=Broken()) == 0


# --------------------------------------------------------------------------- the watcher
def handle_for(tmp_path: Path, token: str = "tok") -> ProxyHandle:
    return ProxyHandle(
        name=proxy_name(JOB), token=token, container_id="c1", url=proxy_url(proxy_name(JOB)),
        hosts=["a.example"], ports=[80], directory=tmp_path / "proxy",
    )  # fmt: skip


async def test_the_watcher_removes_the_proxy_when_the_job_is_final(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    handle = handle_for(tmp_path)
    launcher.infos[handle.name] = {"Id": "c1", "Name": "/" + handle.name, "Config": {"Labels": {"securescan.dast.token": "tok"}}, "State": {}}
    states = iter([JobState.PREPARING, JobState.RUNNING, JobState.RUNNING, JobState.FAILED])
    clock_value = [0.0]

    async def state_of(job_id: uuid.UUID) -> JobState | None:
        return next(states)

    async def sleep(seconds: float) -> None:
        clock_value[0] += seconds

    await watch_and_remove(JOB, handle, 3600.0, poll=5.0, state_of=state_of, sleep=sleep, clock=lambda: clock_value[0], launcher=launcher)
    assert launcher.removed == ["c1"] and clock_value[0] == 20.0


@pytest.mark.parametrize("final", [JobState.COMPLETED, JobState.CANCELLED, JobState.TIMED_OUT, JobState.QUEUED, None])
async def test_the_watcher_stops_for_every_end_of_a_job(tmp_path: Path, final: JobState | None) -> None:
    launcher = FakeLauncher()
    handle = handle_for(tmp_path)
    launcher.infos[handle.name] = {"Id": "c1", "Name": "/" + handle.name, "Config": {"Labels": {"securescan.dast.token": "tok"}}, "State": {}}

    async def state_of(job_id: uuid.UUID) -> JobState | None:
        return final

    async def sleep(seconds: float) -> None:
        return None

    await watch_and_remove(JOB, handle, 100.0, state_of=state_of, sleep=sleep, launcher=launcher)
    assert launcher.removed == ["c1"]


async def test_the_watcher_gives_up_after_the_deadline_and_survives_database_errors(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    handle = handle_for(tmp_path)
    launcher.infos[handle.name] = {"Id": "c1", "Name": "/" + handle.name, "Config": {"Labels": {"securescan.dast.token": "tok"}}, "State": {}}
    clock_value = [0.0]
    calls = [0]

    async def state_of(job_id: uuid.UUID) -> JobState | None:
        calls[0] += 1
        raise RuntimeError("database is down")

    async def sleep(seconds: float) -> None:
        clock_value[0] += seconds

    await watch_and_remove(JOB, handle, 30.0, poll=10.0, state_of=state_of, sleep=sleep, clock=lambda: clock_value[0], launcher=launcher)
    assert calls[0] == 3 and launcher.removed == ["c1"]  # still removed at the deadline


async def test_a_new_attempts_proxy_survives_the_old_watcher(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    old = handle_for(tmp_path, token="old")
    launcher.infos[old.name] = {"Id": "c2", "Name": "/" + old.name, "Config": {"Labels": {"securescan.dast.token": "new"}}, "State": {}}

    async def state_of(job_id: uuid.UUID) -> JobState | None:
        return JobState.QUEUED

    async def sleep(seconds: float) -> None:
        return None

    await watch_and_remove(JOB, old, 10.0, state_of=state_of, sleep=sleep, launcher=launcher)
    assert launcher.removed == []  # the container with the same name now belongs to another attempt


async def test_schedule_cleanup_replaces_the_previous_watcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[str] = []

    async def fake_watch(job_id: uuid.UUID, handle: ProxyHandle, max_seconds: float, **kwargs: Any) -> None:
        started.append(handle.token)
        await asyncio.sleep(3600)

    monkeypatch.setattr(dast_egress, "watch_and_remove", fake_watch)
    first = schedule_cleanup(JOB, handle_for(tmp_path, "one"), 10.0)
    await asyncio.sleep(0)
    second = schedule_cleanup(JOB, handle_for(tmp_path, "two"), 10.0)
    await asyncio.sleep(0)
    assert started == ["one", "two"]
    await asyncio.gather(first, return_exceptions=True)
    assert first.cancelled() and not second.done()
    assert dast_egress._WATCHERS[str(JOB)] is second  # noqa: SLF001
    launcher = FakeLauncher()
    await release_proxy(JOB, None, launcher=launcher)  # stops the watcher, nothing to remove
    await asyncio.gather(second, return_exceptions=True)
    assert second.cancelled() and str(JOB) not in dast_egress._WATCHERS  # noqa: SLF001
    assert launcher.removed == []


# --------------------------------------------------------------------------- the access log
SAMPLE_LOG = "\n".join(
    [
        "1700000000.100    120 172.20.0.5 TCP_MISS/200 5120 GET http://shop.uat.example:8080/index.html - HIER_DIRECT/10.20.30.40 text/html",
        "1700000000.200     80 172.20.0.5 TCP_MISS/404 310 GET http://shop.uat.example:8080/nope - HIER_DIRECT/10.20.30.40 text/html",
        "1700000001.000   5000 172.20.0.5 TCP_TUNNEL/200 9000 CONNECT shop.uat.example:443 - HIER_DIRECT/10.20.30.40 -",
        "1700000002.000      0 172.20.0.5 TCP_DENIED/403 3900 GET http://example.com/ - HIER_NONE/- text/html",
        "1700000003.000      0 172.20.0.5 TCP_DENIED/403 3900 CONNECT example.com:443 - HIER_NONE/- text/html",
        "1700000004.000      0 172.20.0.5 TCP_DENIED/403 3900 GET http://169.254.169.254/latest/meta-data/ - HIER_NONE/- text/html",
        "garbage line",
        "",
    ]
)


def test_the_access_log_summary_shows_only_the_allowed_host() -> None:
    summary = summarise_access_log(SAMPLE_LOG, ["shop.uat.example"])
    assert summary.requests == 6 and summary.denied == 3
    assert summary.by_host == {"shop.uat.example": 3}
    assert summary.denied_hosts == {"example.com": 2, "169.254.169.254": 1}
    assert summary.unexpected_hosts == []
    note = summary.note()
    assert "3 requests to shop.uat.example (3)" in note and "3 requests were refused" in note and "WARNING" not in note


def test_a_served_request_to_another_host_is_a_warning() -> None:
    log = "1700000000.1 10 1.1.1.1 TCP_MISS/200 10 GET http://other.example/x - HIER_DIRECT/1.2.3.4 -"
    summary = summarise_access_log(log, ["shop.uat.example"])
    assert summary.unexpected_hosts == ["other.example"]
    assert "WARNING" in summary.note() and "other.example" in summary.note()
    assert summarise_access_log("", ["a"]).note().startswith("Scan proxy: 0 requests to none.")
    ipv6 = summarise_access_log("1 1 c TCP_MISS/200 1 GET http://[2001:db8::5]:8443/x - HIER_DIRECT/x -", ["2001:db8::5"])
    assert ipv6.by_host == {"2001:db8::5": 1} and ipv6.unexpected_hosts == []


def test_read_access_log(tmp_path: Path) -> None:
    handle = handle_for(tmp_path)
    assert read_access_log(handle) == ""
    (tmp_path / "proxy" / "logs").mkdir(parents=True)
    handle.access_log_path.write_text(SAMPLE_LOG, encoding="utf-8")
    assert "TCP_DENIED" in read_access_log(handle)


# --------------------------------------------------------------------------- the url source
async def test_a_url_target_needs_no_source() -> None:
    request = SourceRequest(
        session=None, scan=None, version=None, application=None,  # type: ignore[arg-type]
        target=types.SimpleNamespace(kind=TargetKind.URL, locator="http://x/"),  # type: ignore[arg-type]
        workspace=None, settings=Settings(), log=None, claim_commit=None,  # type: ignore[arg-type]
    )  # fmt: skip
    info = await acquire_source(request)
    assert info.kind == "url" and info.is_git is False
