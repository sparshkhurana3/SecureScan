#!/usr/bin/env python3
"""Spike S2: assert allow and deny behaviour of the socket proxy (re-run in M9 after any allowlist change).

Runs inside the `client` container against a proxy started with the ENFORCING allowlist (run.sh enforce):

    python /spike/test_allowlist.py          # prints PASS/FAIL per test, exit 1 on the first run with failures

It is also collectable by pytest (plain functions, no fixtures) when `docker` and `httpx` are installed:

    DOCKER_HOST=tcp://socket-proxy:2375 python -m pytest -q spikes/s2/test_allowlist.py

Two kinds of check
  * plain HTTP with httpx: a denied request must return 403 from the proxy; an allowed request must NOT return 403
    (Docker's own answer is 200, 404 for a container that does not exist, ...).
  * the Docker SDK: the worker's complete lifecycle (scenario.run_lifecycle) must work, and bind-mount attempts outside
    the allowed host path must be refused with 403 by the proxy (SP_ALLOWBINDMOUNTFROM).
Probes (functions starting with probe_) only print what the proxy does for requests it cannot filter, e.g. a
privileged container. They never fail the run; copy the output into docs/spikes/s2-socket-proxy.md.

Environment: DOCKER_HOST (tcp://socket-proxy:2375), S2_IMAGE, S2_VOLUME, S2_SONAR_NAME, S2_NET_A, S2_NET_B.
"""

from __future__ import annotations

import socket
import sys
import traceback
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import docker  # noqa: E402
import httpx  # noqa: E402
import scenario  # noqa: E402
from docker.errors import APIError  # noqa: E402
from docker.types import Mount  # noqa: E402

DOCKER_HOST = scenario.DOCKER_HOST
BASE = DOCKER_HOST.replace("tcp://", "http://")
FAKE_ID = "0" * 64
SONAR = scenario.SONAR_NAME


def _api_version() -> str:
    client = scenario.make_client("auto")
    return str(client.version()["ApiVersion"])


API = "/v" + _api_version()


def status(method: str, path: str, versioned: bool = True) -> Tuple[int, str]:
    url = BASE + (API if versioned else "") + path
    with httpx.Client(timeout=30, follow_redirects=False) as client:
        response = client.request(method, url)
    return response.status_code, response.text[:120].replace("\n", " ")


def raw_status(method: str, target: str) -> int:
    """Send a request line exactly as given (no URL normalisation) and return the status code, 0 if no answer."""
    host, port = BASE.replace("http://", "").split(":")
    with socket.create_connection((host, int(port)), timeout=15) as sock:
        sock.sendall(("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (method, target, host)).encode("ascii"))
        data = b""
        while b"\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    line = data.split(b"\r\n", 1)[0].decode("ascii", "replace")
    parts = line.split(" ")
    return int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0


def assert_denied(method: str, path: str, versioned: bool = True) -> None:
    code, body = status(method, path, versioned)
    assert code == 403, "%s %s should be denied (403) but returned %d %s" % (method, path, code, body)


def assert_allowed(method: str, path: str, versioned: bool = True) -> int:
    code, body = status(method, path, versioned)
    assert code != 403, "%s %s should be allowed but the proxy returned 403 %s" % (method, path, body)
    return code


# ------------------------------------------------------------------ allowed (plain HTTP)
def test_allowed_ping() -> None:
    assert assert_allowed("GET", "/_ping") == 200


def test_allowed_version() -> None:
    assert assert_allowed("GET", "/version") == 200


def test_allowed_volume_inspect() -> None:
    assert assert_allowed("GET", "/volumes/%s" % scenario.VOLUME) == 200


def test_allowed_sonarqube_inspect_start_stop_by_name() -> None:
    # The container does not exist here, so Docker answers 404; a 403 would mean the proxy blocked the path.
    assert assert_allowed("GET", "/containers/%s/json" % SONAR) in (200, 404)
    assert assert_allowed("POST", "/containers/%s/start" % SONAR) in (204, 304, 404)
    assert assert_allowed("POST", "/containers/%s/stop" % SONAR) in (204, 304, 404)


def test_allowed_job_container_verbs_by_id() -> None:
    for method, verb in (("GET", "json"), ("GET", "logs"), ("POST", "start"), ("POST", "stop"), ("POST", "kill"),
                         ("POST", "wait")):
        assert assert_allowed(method, "/containers/%s/%s" % (FAKE_ID, verb)) in (404, 409, 200, 204, 304)
    assert assert_allowed("DELETE", "/containers/%s" % FAKE_ID) in (404, 204)


# ------------------------------------------------------------------ denied (plain HTTP)
def test_denied_exec() -> None:
    assert_denied("POST", "/containers/%s/exec" % FAKE_ID)
    assert_denied("POST", "/containers/%s/exec" % SONAR)
    assert_denied("POST", "/exec/%s/start" % FAKE_ID)


def test_denied_container_listing() -> None:
    assert_denied("GET", "/containers/json")
    assert_denied("GET", "/containers/json?all=1")


def test_denied_network_image_volume_creation() -> None:
    assert_denied("POST", "/networks/create")
    assert_denied("POST", "/images/create?fromImage=busybox&tag=1.37")
    assert_denied("POST", "/volumes/create")
    assert_denied("POST", "/build")


def test_denied_listing_and_system_calls() -> None:
    for method, path in (
        ("GET", "/images/json"), ("GET", "/info"), ("GET", "/events"), ("GET", "/system/df"), ("GET", "/plugins"),
        ("GET", "/networks"), ("GET", "/volumes"), ("GET", "/swarm"), ("POST", "/swarm/init"), ("POST", "/auth"),
        ("POST", "/containers/prune"), ("POST", "/volumes/prune"), ("POST", "/images/prune"),
    ):
        assert_denied(method, path)


def test_denied_removal_of_non_container_objects() -> None:
    assert_denied("DELETE", "/volumes/%s" % scenario.VOLUME)
    assert_denied("DELETE", "/networks/%s" % scenario.NET_A)
    assert_denied("DELETE", "/images/busybox")


def test_denied_other_container_verbs() -> None:
    for method, verb in (("POST", "restart"), ("POST", "rename"), ("POST", "update"), ("POST", "pause"),
                         ("POST", "unpause"), ("POST", "attach"), ("GET", "top"), ("GET", "changes"),
                         ("GET", "archive"), ("PUT", "archive"), ("GET", "export"), ("GET", "stats")):
        assert_denied(method, "/containers/%s/%s" % (FAKE_ID, verb))


def test_denied_container_by_other_name() -> None:
    # The allowlist names exactly one container by name (the SonarQube server); everything else goes by 64-hex id.
    assert_denied("GET", "/containers/some-other-name/json")
    assert_denied("POST", "/containers/some-other-name/start")


def test_denied_wrong_method_on_allowed_path() -> None:
    assert_denied("PUT", "/containers/create")
    assert_denied("DELETE", "/containers/create")
    assert_denied("GET", "/containers/create")
    assert_denied("POST", "/_ping")


def test_path_tricks_do_not_reach_docker() -> None:
    """Dot segments and encoded slashes must not turn an allowed prefix into a denied call."""
    targets = [
        "%s/containers/%s/start/../exec" % (API, FAKE_ID),
        "%s/containers/%s/start%%2f..%%2fexec" % (API, FAKE_ID),
        "%s/containers/%s/start/%%2e%%2e/exec" % (API, FAKE_ID),
        "%s//containers/%s/exec" % (API, FAKE_ID),
        "%s/containers/%s/exec?x=/start" % (API, FAKE_ID),
        "%s/containers/%s/start?/../exec" % (API, FAKE_ID),
    ]
    for target in targets:
        code = raw_status("POST", target)
        # 301/307 (path cleaned, then denied on follow-up), 400, 403 or 404 are all fine; anything 2xx is not.
        assert code not in (200, 201, 204), "path trick %r reached Docker: HTTP %d" % (target, code)


# ------------------------------------------------------------------ Docker SDK
def test_sdk_lifecycle_works_completely() -> None:
    client = scenario.make_client()
    rec = scenario.Recorder()
    rec.attach(client)
    info = scenario.run_lifecycle(client, rec)
    assert info["exit"]["StatusCode"] == 0, "job container exited with %r" % (info["exit"],)
    assert "hello-from-job" in str(info["logs"]), "job log did not come back through the proxy"
    assert not [c for c in rec.calls if c["status"] == 403], "a 403 occurred: %r" % [c for c in rec.calls if c["status"] == 403]


def test_sdk_lifecycle_works_with_auto_version() -> None:
    client = scenario.make_client("auto")
    rec = scenario.Recorder()
    rec.attach(client)
    scenario.run_lifecycle(client, rec)
    assert not [c for c in rec.calls if c["status"] == 403]


def test_named_volume_mount_is_allowed() -> None:
    """Named volumes (grype_db, odc_data, content, ...) are not host bind mounts and must pass the bind filter."""
    client = scenario.make_client()
    api = client.api
    cid = None
    try:
        host_config = api.create_host_config(
            mounts=[Mount(target="/content", source=scenario.VOLUME, type="volume", read_only=True)],
            network_mode="none", cap_drop=["ALL"],
        )
        cid = api.create_container(scenario.IMAGE, command=["true"], host_config=host_config)["Id"]
        legacy = api.create_host_config(binds=["%s:/legacy:ro" % scenario.VOLUME], network_mode="none")
        cid2 = api.create_container(scenario.IMAGE, command=["true"], host_config=legacy)["Id"]
        scenario.remove_quietly(client, cid2)
    finally:
        if cid:
            scenario.remove_quietly(client, cid)


def _expect_create_refused(host_config_kwargs: dict, what: str) -> None:
    client = scenario.make_client()
    api = client.api
    try:
        host_config = api.create_host_config(network_mode="none", **host_config_kwargs)
        created = api.create_container(scenario.IMAGE, command=["true"], host_config=host_config)
    except APIError as exc:
        assert exc.response is not None and exc.response.status_code == 403, \
            "%s: expected 403 from the proxy, got %s" % (what, exc)
        return
    scenario.remove_quietly(client, created["Id"])
    raise AssertionError("%s: the container was created (the proxy let a forbidden bind mount through)" % what)


def test_bind_mount_outside_allowed_path_is_refused() -> None:
    _expect_create_refused({"binds": ["/etc:/mnt:ro"]}, "legacy bind from /etc")


def test_bind_mount_of_docker_socket_is_refused() -> None:
    _expect_create_refused({"binds": ["/var/run/docker.sock:/var/run/docker.sock"]}, "bind of the Docker socket")


def test_modern_bind_mount_outside_allowed_path_is_refused() -> None:
    _expect_create_refused(
        {"mounts": [Mount(target="/mnt", source="/etc", type="bind", read_only=True)]}, "Mounts[] bind from /etc"
    )


def test_bind_mount_dotdot_escape_is_refused() -> None:
    client = scenario.make_client()
    root = scenario.volume_mountpoint(client)
    _expect_create_refused({"binds": ["%s/../../../../etc:/mnt:ro" % root]}, "bind with .. escaping the allowed root")


def test_volumes_from_is_refused() -> None:
    _expect_create_refused({"volumes_from": ["some-container"]}, "VolumesFrom")


# ------------------------------------------------------------------ probes (informational)
def probe_privileged_container() -> str:
    """HostConfig.Privileged is not something the proxy filters. Records what happens."""
    return _probe_create({"privileged": True}, "Privileged=true")


def probe_host_network() -> str:
    client = scenario.make_client()
    try:
        host_config = client.api.create_host_config(network_mode="host")
        created = client.api.create_container(scenario.IMAGE, command=["true"], host_config=host_config)
    except APIError as exc:
        return "refused: %s" % (exc.response.status_code if exc.response is not None else exc)
    scenario.remove_quietly(client, created["Id"])
    return "ALLOWED (the proxy does not look at NetworkMode)"


def probe_cap_add() -> str:
    return _probe_create({"cap_add": ["SYS_ADMIN"]}, "CapAdd SYS_ADMIN")


def _probe_create(kwargs: dict, what: str) -> str:
    client = scenario.make_client()
    try:
        host_config = client.api.create_host_config(network_mode="none", **kwargs)
        created = client.api.create_container(scenario.IMAGE, command=["true"], host_config=host_config)
    except APIError as exc:
        return "%s refused: HTTP %s" % (what, exc.response.status_code if exc.response is not None else exc)
    scenario.remove_quietly(client, created["Id"])
    return "%s ALLOWED: the proxy does not filter this field; the worker must build specs only from the catalogue" % what


def probe_unversioned_paths() -> str:
    out = []
    for method, path in (("GET", "/_ping"), ("GET", "/version"), ("POST", "/containers/create")):
        out.append("%s %s unversioned -> %d" % (method, path, status(method, path, versioned=False)[0]))
    return "; ".join(out)


def probe_head_ping() -> str:
    return "HEAD /_ping -> %d (Traefik-style health probes need -allowHEAD=/_ping; the worker does not)" % status("HEAD", "/_ping")[0]


TESTS = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
PROBES = [(n, f) for n, f in sorted(globals().items()) if n.startswith("probe_") and callable(f)]


def main() -> int:
    print("Proxy: %s  API version in use for plain requests: %s  image: %s" % (BASE, API, scenario.IMAGE))
    failures = []  # type: List[str]
    for name, func in TESTS:
        try:
            func()
            print("PASS  %s" % name)
        except AssertionError as exc:
            failures.append(name)
            print("FAIL  %s: %s" % (name, exc))
        except Exception as exc:
            failures.append(name)
            print("ERROR %s: %s: %s" % (name, type(exc).__name__, exc))
            traceback.print_exc()
    print("\nProbes (informational, never fail the run):")
    for name, func in PROBES:
        try:
            print("PROBE %s: %s" % (name, func()))
        except Exception as exc:
            print("PROBE %s: error %s: %s" % (name, type(exc).__name__, exc))
    print("\n%d test(s), %d failure(s)" % (len(TESTS), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
