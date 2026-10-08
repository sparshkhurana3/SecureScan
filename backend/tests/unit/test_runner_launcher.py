"""Launcher: spec to Engine API request (hardening), host-path mapping, run, timeout, cancel, errors."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from securescan.runner.launcher import (
    Launcher,
    LauncherConfigError,
    LauncherError,
    PathMapper,
    build_create_body,
    map_docker_error,
)
from securescan.runner.specs import ContainerSpec, parse_size
from tests.unit.runner_helpers import DIGEST

DATA_HOST = "/var/lib/docker/volumes/securescan_data/_data"
CONTENT_HOST = "/var/lib/docker/volumes/securescan_content/_data"
CID = "c" * 64


def identity(path: str) -> str:
    return path


def make_spec(**overrides: Any) -> ContainerSpec:
    values: dict[str, Any] = {
        "image": f"example/demo@{DIGEST}",
        "command": ["demo", "scan", "/src"],
        "name": "securescan-job-1",
        "user": "1000:1000",
        "env": {"HOME": "/tmp", "A": "b"},  # noqa: S108
        "binds": [("/host/src", "/src", True), ("/host/out", "/out", False)],
        "tmpfs": {"/tmp": "rw,size=64m,mode=1777"},  # noqa: S108
        "network": "none",
        "labels": {"securescan.job_id": "1"},
        "mem_limit": "512m",
        "nano_cpus": 1_500_000_000,
        "pids_limit": 128,
        "entrypoint": [""],
        "stop_timeout": 10,
    }
    values.update(overrides)
    return ContainerSpec(**values)


# --------------------------------------------------------------------------- spec to HostConfig
def test_body_is_hardened_and_follows_the_spec() -> None:
    body = build_create_body(make_spec(), identity)
    host = body["HostConfig"]
    assert body["Image"] == f"example/demo@{DIGEST}"
    assert body["Cmd"] == ["demo", "scan", "/src"]
    assert body["Entrypoint"] == [""]
    assert body["User"] == "1000:1000"
    assert body["Env"] == ["HOME=/tmp", "A=b"]
    assert body["Labels"] == {"securescan.job_id": "1"}
    assert body["StopTimeout"] == 10
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"] and "CapAdd" not in host
    assert host["SecurityOpt"] == ["no-new-privileges"]
    assert host["Privileged"] is False and host["AutoRemove"] is False
    assert host["NetworkMode"] == "none" and "NetworkingConfig" not in body
    assert host["Binds"] == ["/host/src:/src:ro", "/host/out:/out:rw"]
    assert host["Tmpfs"] == {"/tmp": "rw,size=64m,mode=1777"}  # noqa: S108
    assert host["Memory"] == 512 * 1024**2 == host["MemorySwap"]
    assert host["NanoCpus"] == 1_500_000_000 and host["PidsLimit"] == 128
    assert host["RestartPolicy"] == {"Name": "no"}
    assert not {"PidMode", "IpcMode", "UsernsMode", "Devices", "VolumesFrom", "Mounts"} & set(host)


def test_hardening_cannot_be_switched_off_by_the_spec() -> None:
    spec = make_spec(read_only_rootfs=False)
    body = build_create_body(spec, identity)
    assert body["HostConfig"]["CapDrop"] == ["ALL"]  # always
    assert body["HostConfig"]["SecurityOpt"] == ["no-new-privileges"]
    assert body["HostConfig"]["Privileged"] is False
    assert body["HostConfig"]["ReadonlyRootfs"] is False  # the one knob the spec owns (catalogue: always True)


def test_optional_fields_are_left_out() -> None:
    body = build_create_body(ContainerSpec(image=f"x/y@{DIGEST}", command=["a"]), identity)
    host = body["HostConfig"]
    for key in ("Memory", "NanoCpus", "PidsLimit", "Tmpfs", "Binds", "ShmSize", "Ulimits"):
        assert key not in host
    assert "User" not in body and "Entrypoint" not in body and "StopTimeout" not in body


def test_named_networks_get_an_endpoint_each() -> None:
    spec = make_spec(network="securescan_backend", extra_networks=["securescan_egress"])
    body = build_create_body(spec, identity)
    assert body["HostConfig"]["NetworkMode"] == "securescan_backend"
    assert body["NetworkingConfig"] == {"EndpointsConfig": {"securescan_backend": {}, "securescan_egress": {}}}


def test_no_network_cannot_have_extra_networks() -> None:
    with pytest.raises(LauncherConfigError):
        build_create_body(make_spec(network="none", extra_networks=["x"]), identity)


def test_ulimits_shm_and_volumes() -> None:
    spec = make_spec(ulimits={"nofile": (1024, 2048)}, shm_size="256m", volumes=[("securescan_grype_db", "/db", True)])
    body = build_create_body(spec, identity)
    host = body["HostConfig"]
    assert host["Ulimits"] == [{"Name": "nofile", "Soft": 1024, "Hard": 2048}]
    assert host["ShmSize"] == 256 * 1024**2
    assert "securescan_grype_db:/db:ro" in host["Binds"]


@pytest.mark.parametrize("image", ["example/demo", "example/demo:latest", "", "a b", "localhost:5000/demo"])
def test_unpinned_images_are_refused(image: str) -> None:
    with pytest.raises(LauncherConfigError):
        build_create_body(make_spec(image=image), identity)


def test_exact_tags_and_digests_are_accepted() -> None:
    build_create_body(make_spec(image="example/demo:1.2.3"), identity)
    build_create_body(make_spec(image="localhost:5000/demo:2"), identity)
    build_create_body(make_spec(image=f"ghcr.io/x/y:v1@{DIGEST}"), identity)


@pytest.mark.parametrize(
    "bind",
    [
        ("/host/a:b", "/src", True),
        ("/host/a", "/s:rc", True),
        ("relative/path", "/src", True),
        ("/host/../etc", "/src", True),
        ("/host/a", "/src/../x", True),
        ("/host/a\n", "/src", True),
    ],
)
def test_unsafe_binds_are_refused(bind: tuple[str, str, bool]) -> None:
    with pytest.raises(LauncherConfigError):
        build_create_body(make_spec(binds=[bind]), identity)


def test_unsafe_names_and_empty_commands_are_refused() -> None:
    with pytest.raises(LauncherConfigError):
        build_create_body(make_spec(name="bad name;rm"), identity)
    with pytest.raises(LauncherConfigError):
        build_create_body(make_spec(command=[]), identity)
    with pytest.raises(LauncherConfigError):
        build_create_body(make_spec(volumes=[("../x", "/db", True)]), identity)


def test_binds_go_through_the_host_path_mapping() -> None:
    mapper = PathMapper([("/var/lib/securescan", DATA_HOST)])
    spec = make_spec(binds=[("/var/lib/securescan/workspaces/j/src", "/src", True)])
    body = build_create_body(spec, mapper.to_host)
    assert body["HostConfig"]["Binds"] == [f"{DATA_HOST}/workspaces/j/src:/src:ro"]


def test_parse_size() -> None:
    assert parse_size("512m") == 512 * 1024**2
    assert parse_size("4g") == 4 * 1024**3
    assert parse_size("1048576") == 1048576
    assert parse_size("1.5g") == int(1.5 * 1024**3)
    for bad in ("", "abc", "-1m", "1x"):
        with pytest.raises(ValueError):
            parse_size(bad)


# --------------------------------------------------------------------------- path mapping
def test_path_mapper_uses_the_longest_prefix() -> None:
    mapper = PathMapper(
        [("/var/lib/securescan", DATA_HOST), ("/var/lib/securescan/content", CONTENT_HOST)]
    )
    assert mapper.to_host("/var/lib/securescan/workspaces/j/src") == f"{DATA_HOST}/workspaces/j/src"
    assert mapper.to_host("/var/lib/securescan/content/semgrep/rules-x") == f"{CONTENT_HOST}/semgrep/rules-x"
    assert mapper.to_host("/var/lib/securescan") == DATA_HOST
    assert mapper.to_host("/var/lib/securescanX/y") == "/var/lib/securescanX/y"  # not a prefix match
    assert mapper.to_host("/etc/other") == "/etc/other"  # an absolute daemon path stays as it is
    assert not PathMapper()
    assert PathMapper([("/a", "/b")])


# --------------------------------------------------------------------------- a fake Docker API
class ReadTimeout(Exception):
    pass


class NotFound(Exception):
    explanation = "No such container"
    status_code = 404


NotFound.__module__ = "docker.errors"


class ApiError(Exception):
    def __init__(self, status: int, explanation: str = "") -> None:
        super().__init__(explanation)
        self.status_code = status
        self.explanation = explanation


ApiError.__name__ = "APIError"
ApiError.__module__ = "docker.errors"


class FakeApi:
    def __init__(
        self,
        *,
        exit_code: int = 0,
        log_chunks: list[bytes] | None = None,
        hang: bool = False,
        create_error: Exception | None = None,
    ) -> None:
        self.exit_code = exit_code
        self.log_chunks = log_chunks if log_chunks is not None else [b"hello\n", b"world\n"]
        self.hang = hang
        self.create_error = create_error
        self.calls: list[tuple[str, Any]] = []
        self.bodies: list[tuple[dict[str, Any], str | None]] = []
        self.existing: set[str] = set()
        self.ended = False

    def _note(self, name: str, *args: Any) -> None:
        self.calls.append((name, args))

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]

    def ping(self) -> bool:
        return True

    def inspect_volume(self, name: str) -> dict[str, str]:
        self._note("inspect_volume", name)
        if name == "securescan_content":
            return {"Mountpoint": CONTENT_HOST}
        return {"Mountpoint": DATA_HOST}

    def create_container_from_config(self, body: dict[str, Any], name: str | None = None) -> dict[str, str]:
        self._note("create", name)
        if self.create_error is not None:
            raise self.create_error
        self.bodies.append((body, name))
        self.existing.add(CID)
        if name:
            self.existing.add(name)
        return {"Id": CID}

    def start(self, cid: str) -> None:
        self._note("start", cid)

    def wait(self, cid: str, timeout: float | None = None) -> dict[str, int]:
        self._note("wait", cid)
        if self.hang and not self.ended:
            raise ReadTimeout("Read timed out")
        return {"StatusCode": 137 if self.hang else self.exit_code}

    def logs(self, cid: str, **kwargs: Any) -> Any:
        self._note("logs", cid)
        return iter(self.log_chunks)

    def stop(self, cid: str, timeout: int = 10) -> None:
        self._note("stop", cid)
        self.ended = True

    def kill(self, cid: str) -> None:
        self._note("kill", cid)
        self.ended = True

    def remove_container(self, cid: str, v: bool = False, link: bool = False, force: bool = False) -> None:
        self._note("remove", cid, force)
        if cid not in self.existing:
            raise NotFound()
        self.existing.discard(cid)

    def inspect_container(self, ident: str) -> dict[str, Any]:
        self._note("inspect", ident)
        if ident not in self.existing:
            raise NotFound()
        return {"Id": CID, "State": {"Running": False}}

    def containers(self, **kwargs: Any) -> list[dict[str, str]]:
        self._note("containers", kwargs.get("filters"))
        return [{"Id": CID}, {"Id": "d" * 64}]


def make_launcher(api: FakeApi, **kwargs: Any) -> Launcher:
    return Launcher(
        api,
        data_root="/var/lib/securescan",
        content_root="/var/lib/securescan/content",
        **kwargs,
    )


# --------------------------------------------------------------------------- run
async def test_run_creates_starts_streams_waits_and_removes() -> None:
    api = FakeApi(exit_code=2, log_chunks=[b"line1\nli", b"ne2\n", b"tail"])
    launcher = make_launcher(api)
    seen: list[str] = []
    created: list[str] = []

    async def sink(line: str) -> None:
        seen.append(line)

    async def on_created(cid: str) -> None:
        created.append(cid)

    spec = make_spec(
        binds=[
            ("/var/lib/securescan/workspaces/j/src", "/src", True),
            ("/var/lib/securescan/content/semgrep/rules-abc", "/rules", True),
        ]
    )
    result = await launcher.run(spec, 30, sink, on_created=on_created)

    assert (result.exit_code, result.timed_out, result.cancelled) == (2, False, False)
    assert result.container_id == CID and created == [CID]
    assert seen == ["line1", "line2", "tail"]
    assert result.logs == "line1\nline2\ntail"
    body, name = api.bodies[0]
    assert name == "securescan-job-1"
    assert body["HostConfig"]["Binds"] == [
        f"{DATA_HOST}/workspaces/j/src:/src:ro",
        f"{CONTENT_HOST}/semgrep/rules-abc:/rules:ro",
    ]
    order = api.names()
    assert order.index("create") < order.index("start") < order.index("wait")
    assert order[-1] == "remove"
    assert ("remove", (CID, True)) in api.calls  # removed with force at the end
    assert ("remove", ("securescan-job-1", True)) in api.calls  # a stale container of the same name goes first
    assert order.index("create") > order.index("remove")  # ... before create
    assert api.calls[0][0] == "inspect_volume"


async def test_a_timeout_kills_the_container_and_reports_it() -> None:
    api = FakeApi(hang=True)
    launcher = make_launcher(api, data_host_root=DATA_HOST)
    result = await launcher.run(make_spec(), 0.05)
    assert result.timed_out is True and result.cancelled is False
    assert result.exit_code == 137
    assert "kill" in api.names() and "stop" not in api.names()
    assert api.calls[-1] == ("remove", (CID, True))


async def test_cancel_stops_the_container() -> None:
    api = FakeApi(hang=True)
    launcher = make_launcher(api, data_host_root=DATA_HOST)
    cancel = asyncio.Event()
    cancel.set()
    result = await launcher.run(make_spec(), 60, cancel=cancel)
    assert result.cancelled is True and result.timed_out is False
    assert "stop" in api.names() and "kill" not in api.names()
    assert ("remove", (CID, True)) in api.calls


async def test_the_container_is_removed_even_when_a_callback_fails() -> None:
    api = FakeApi()
    launcher = make_launcher(api, data_host_root=DATA_HOST)

    async def broken(cid: str) -> None:
        raise RuntimeError("database is down")

    with pytest.raises(RuntimeError):
        await launcher.run(make_spec(), 5, on_created=broken)
    assert "start" not in api.names()
    assert ("remove", (CID, True)) in api.calls


async def test_wait_returns_the_exit_code_or_none_on_timeout() -> None:
    launcher = make_launcher(FakeApi(exit_code=7), data_host_root=DATA_HOST)
    assert await launcher.wait(CID, 5) == 7
    hanging = make_launcher(FakeApi(hang=True), data_host_root=DATA_HOST)
    assert await hanging.wait(CID, 0.01) is None
    event = asyncio.Event()
    event.set()
    assert await hanging.wait(CID, None, event) is None


# --------------------------------------------------------------------------- roots
async def test_roots_are_read_from_the_volumes_once() -> None:
    api = FakeApi()
    launcher = make_launcher(api)
    with pytest.raises(LauncherError):
        launcher.host_path("/var/lib/securescan/workspaces/j")  # before ensure_roots
    await launcher.ensure_roots()
    await launcher.ensure_roots()
    assert api.names().count("inspect_volume") == 2  # data and content, once
    assert launcher.host_path("/var/lib/securescan/workspaces/j") == f"{DATA_HOST}/workspaces/j"
    assert launcher.host_path("/var/lib/securescan/content/x") == f"{CONTENT_HOST}/x"


def test_explicit_host_root_needs_no_docker_call() -> None:
    api = FakeApi()
    launcher = Launcher(api, data_root="/var/lib/securescan", data_host_root="/mnt/data")
    assert launcher.host_path("/var/lib/securescan/a") == "/mnt/data/a"
    assert api.calls == []


# --------------------------------------------------------------------------- other calls
async def test_inspect_remove_and_list() -> None:
    api = FakeApi()
    launcher = make_launcher(api, data_host_root=DATA_HOST)
    assert await launcher.inspect("missing") is None
    api.existing.add("securescan-egress")
    info = await launcher.inspect("securescan-egress")
    assert info is not None and info["Id"] == CID
    await launcher.remove("missing")  # a missing container is not an error
    await launcher.stop("missing")
    await launcher.kill("missing")
    assert await launcher.list_by_label("securescan.job_id") == [CID, "d" * 64]
    assert ("containers", ({"label": ["securescan.job_id"]},)) in api.calls
    assert await launcher.ping() is True


async def test_stream_logs_splits_long_lines_and_keeps_the_tail() -> None:
    api = FakeApi(log_chunks=[b"x" * 20000 + b"\n", b"done"])
    launcher = make_launcher(api, data_host_root=DATA_HOST)
    lines: list[str] = []

    async def sink(line: str) -> None:
        lines.append(line)

    await launcher.stream_logs(CID, sink)
    assert [len(line) for line in lines] == [8000, 8000, 4000, 4]
    assert lines[-1] == "done"


# --------------------------------------------------------------------------- error mapping
async def test_docker_errors_become_launcher_errors() -> None:
    forbidden = make_launcher(FakeApi(create_error=ApiError(403, "denied by the proxy")), data_host_root=DATA_HOST)
    with pytest.raises(LauncherConfigError, match="refused"):
        await forbidden.create(make_spec())
    broken = make_launcher(FakeApi(create_error=ApiError(500, "boom")), data_host_root=DATA_HOST)
    with pytest.raises(LauncherError):
        await broken.create(make_spec())
    unreachable = make_launcher(FakeApi(create_error=ConnectionError("no route")), data_host_root=DATA_HOST)
    with pytest.raises(LauncherError):
        await unreachable.create(make_spec())


def test_missing_image_is_a_configuration_error() -> None:
    class ImageNotFound(NotFound):
        explanation = "No such image: example/demo"

    ImageNotFound.__module__ = "docker.errors"
    mapped = map_docker_error(ImageNotFound())
    assert isinstance(mapped, LauncherConfigError) and "pre-pull" in str(mapped)


def test_launcher_error_classes_are_distinct() -> None:
    assert not issubclass(LauncherConfigError, LauncherError)
    assert not issubclass(LauncherError, LauncherConfigError)
