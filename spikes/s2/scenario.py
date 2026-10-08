"""The Docker SDK call sequence the SecureScan worker will make, shared by derive_paths.py and test_allowlist.py.

Runs inside the `client` container of spikes/s2/docker-compose.yml (python:3.14-slim-trixie with the `docker`
and `httpx` packages installed). Only the Docker SDK for Python is needed.

Every request the SDK makes is recorded through a `requests` response hook (method, path, query, status), which
is more exact than parsing log lines; urllib3's DEBUG logging is switched on as well so the raw lines appear in
the output ("SDK debug logging").
"""

from __future__ import annotations

import logging
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import docker

NET_A = os.environ.get("S2_NET_A", "s2-net-a")
NET_B = os.environ.get("S2_NET_B", "s2-net-b")
VOLUME = os.environ.get("S2_VOLUME", "securescan_data")
IMAGE = os.environ.get("S2_IMAGE", "busybox:1.37")
SONAR_NAME = os.environ.get("S2_SONAR_NAME", "sonarqube")
WORKSPACE = os.environ.get("S2_WORKSPACE", "s2job")
DOCKER_HOST = os.environ.get("DOCKER_HOST", "tcp://socket-proxy:2375")


def enable_sdk_debug_logging() -> None:
    """Show the HTTP request lines urllib3 sends for the SDK (`"POST /v1.44/containers/create HTTP/1.1" 201`)."""
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s", stream=sys.stdout)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.DEBUG)
    logging.getLogger("docker").setLevel(logging.DEBUG)


class Recorder:
    """Collects (step, method, path, query, status) for every HTTP call the SDK makes."""

    def __init__(self) -> None:
        self.step = "init"
        self.calls = []  # type: List[Dict[str, Any]]

    def attach(self, client: "docker.DockerClient") -> None:
        client.api.hooks["response"].append(self._hook)

    def _hook(self, response: Any, *args: Any, **kwargs: Any) -> Any:
        parts = urlsplit(response.request.url)
        self.calls.append(
            {
                "step": self.step,
                "method": response.request.method,
                "path": parts.path,
                "query": parts.query,
                "status": response.status_code,
            }
        )
        return response


def make_client(version: Optional[str] = None) -> "docker.DockerClient":
    """The worker's client. ``version=None`` uses the SDK's fixed default API version; "auto" asks the daemon."""
    if version is None:
        return docker.DockerClient(base_url=DOCKER_HOST, timeout=60)
    return docker.DockerClient(base_url=DOCKER_HOST, version=version, timeout=60)


def volume_mountpoint(client: "docker.DockerClient") -> str:
    return str(client.volumes.get(VOLUME).attrs["Mountpoint"])


def create_job_container(
    client: "docker.DockerClient", host_root: str, command: List[str], name: str, network_names: Tuple[str, ...],
    binds_extra: Optional[List[str]] = None,
) -> str:
    """create_container with the M3 HostConfig and a NetworkingConfig listing several networks."""
    api = client.api
    binds = [
        "%s/workspaces/%s/src:/src:ro" % (host_root, WORKSPACE),
        "%s/workspaces/%s/out:/out:rw" % (host_root, WORKSPACE),
    ] + list(binds_extra or [])
    host_config = api.create_host_config(
        binds=binds,
        network_mode=network_names[0],
        cap_drop=["ALL"],
        security_opt=["no-new-privileges"],
        read_only=True,
        pids_limit=64,
        mem_limit="128m",
        nano_cpus=500000000,
        tmpfs={"/tmp": "rw,size=16m"},
    )
    networking = api.create_networking_config({n: api.create_endpoint_config() for n in network_names})
    created = api.create_container(
        IMAGE,
        command=command,
        name=name,
        user="1000:1000",
        labels={"securescan.job_id": "s2"},
        host_config=host_config,
        networking_config=networking,
    )
    return str(created["Id"])


def remove_quietly(client: "docker.DockerClient", ident: str) -> None:
    try:
        client.api.remove_container(ident, force=True, v=True)
    except Exception:  # cleanup only
        pass


def run_lifecycle(client: "docker.DockerClient", rec: Recorder) -> Dict[str, Any]:
    """Every call of the worker's container lifecycle; raises on the first failing call."""
    api = client.api
    info = {}  # type: Dict[str, Any]
    suffix = uuid.uuid4().hex[:8]
    job_name = "s2-job-" + suffix
    created_ids = []  # type: List[str]
    try:
        rec.step = "ping"
        client.ping()
        rec.step = "version"
        info["api_version"] = client.version().get("ApiVersion")

        rec.step = "volume mountpoint (GET /volumes/<name>)"
        host_root = volume_mountpoint(client)
        info["host_root"] = host_root

        rec.step = "create job container (two networks, binds, tmpfs, hardening)"
        cid = create_job_container(
            client, host_root, ["sh", "-c", "echo hello-from-job; ls /src >/dev/null; echo data > /out/probe.txt"],
            job_name, (NET_A, NET_B),
        )
        created_ids.append(cid)
        info["job_id"] = cid

        rec.step = "start job container"
        api.start(cid)
        rec.step = "wait job container"
        info["exit"] = api.wait(cid, timeout=60)
        rec.step = "logs (not streaming)"
        info["logs"] = api.logs(cid, stdout=True, stderr=True).decode("utf-8", "replace")
        rec.step = "logs (stream, follow)"
        for _ in api.logs(cid, stdout=True, stderr=True, stream=True, follow=True):
            pass
        rec.step = "inspect job container"
        api.inspect_container(cid)

        rec.step = "kill a running container"
        kid = create_job_container(client, host_root, ["sleep", "300"], "s2-kill-" + suffix, (NET_A,))
        created_ids.append(kid)
        api.start(kid)
        api.kill(kid)
        api.wait(kid, timeout=30)

        rec.step = "stop a running container (graceful)"
        sid = create_job_container(client, host_root, ["sleep", "300"], "s2-stop-" + suffix, (NET_A,))
        created_ids.append(sid)
        api.start(sid)
        api.stop(sid, timeout=2)

        rec.step = "remove (force, with volumes)"
        for ident in list(created_ids):
            api.remove_container(ident, force=True, v=True)
        created_ids.clear()

        # SonarQube lifecycle by NAME, the way jobs/sonarqube_lifecycle.py will do it.
        rec.step = "sonarqube: create by name (catalogue spec)"
        son_id = create_job_container(client, host_root, ["sleep", "300"], SONAR_NAME, (NET_A, NET_B))
        created_ids.append(son_id)
        rec.step = "sonarqube: inspect by name (GET /containers/<name>/json)"
        api.inspect_container(SONAR_NAME)
        rec.step = "sonarqube: start by name (POST /containers/<name>/start)"
        api.start(SONAR_NAME)
        rec.step = "sonarqube: stop by name (POST /containers/<name>/stop)"
        api.stop(SONAR_NAME, timeout=2)
        rec.step = "sonarqube: start again after stop (warm start)"
        api.start(SONAR_NAME)
        rec.step = "sonarqube: stop again"
        api.stop(SONAR_NAME, timeout=2)
        rec.step = "sonarqube: remove"
        api.remove_container(SONAR_NAME, force=True, v=True)
        created_ids.clear()
        time.sleep(0.2)
        return info
    finally:
        rec.step = "cleanup"
        for ident in created_ids:
            remove_quietly(client, ident)
