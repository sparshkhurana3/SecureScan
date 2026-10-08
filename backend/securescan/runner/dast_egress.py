"""The per-job DAST egress proxy: one squid container per web-scan job, removed with the job.

Why a proxy of its own (plan M9 task 2, design "DAST safety controls"): the scanner container sits on the
``dast`` network, which is ``internal: true`` and has no route out. The only way out is a squid container
that is attached to ``dast`` *and* ``egress`` and whose generated ``squid.conf`` allows exactly the hosts of
this job (the target, and the API specification host) on exactly their ports. A scan cannot reach any
other address, whatever its plan or its templates say. The worker creates the container with
``NetworkingConfig.EndpointsConfig`` listing both networks (``ContainerSpec.network`` plus
``extra_networks``); the socket proxy needs no network permission because both networks exist already.

The proxy is not shared. DAST jobs run one at a time (Procrastinate ``lock: dast``), so no job can use the
proxy of another. Its name is ``securescan-dast-proxy-<job id>`` (the socket proxy allows names that start
with ``securescan-``). Its access log goes to a directory of the job's workspace so that it can be summarised
into the coverage notes and stored with the job ("the squid access log shows only the target's host").

Lifecycle, without a hook in the executor: ``start_proxy`` runs in the tool builder's ``prepare``; a
background watcher (``schedule_cleanup``) removes the proxy as soon as the job is final, queued again or
too old, whichever way the job ended; ``post_run`` removes it at once on the normal path; the next DAST job
removes whatever is left over (``sweep_stale_proxies``). Leftovers survive only a worker crash until then.

This module also registers the ``url`` source handler: a web target has nothing to fetch, the job only
needs a workspace.
"""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import select

from securescan.config import Settings
from securescan.db.models.enums import JOB_TERMINAL_STATES, JobState
from securescan.db.models.jobs import ScanJob
from securescan.db.session import session_scope
from securescan.domain.dast_rules import ALWAYS_BLOCKED, HostInfo, normalise_address
from securescan.logging import get_logger
from securescan.runner.egress import SQUID_UID, EgressError, resolve_egress_image
from securescan.runner.sources import SourceInfo, SourceRequest, register_source_handler
from securescan.runner.specs import ContainerSpec

log = get_logger(__name__)

PROXY_PORT = 3128
PROXY_PREFIX = "securescan-dast-proxy-"
LABEL_ROLE = "securescan.role"
LABEL_MANAGED = "securescan.managed"
LABEL_JOB = "securescan.job_id"
LABEL_SCAN = "securescan.scan_id"
LABEL_TOKEN = "securescan.dast.token"
LABEL_HOSTS = "securescan.dast.hosts"
ROLE_VALUE = "dast-proxy"
PROXY_DIR = "proxy"
LOG_DIR = "logs"
CONF_NAME = "squid.conf"
ACCESS_LOG = "access.log"
MAX_LOG_READ_BYTES = 2 * 1024 * 1024
WATCH_POLL_SECONDS = 5.0
READY_SETTLE_SECONDS = 2.0

_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")

Sleep = Callable[[float], Awaitable[None]]


class DastProxyError(Exception):
    """The job's proxy could not be configured or started (message is plain language)."""


# --------------------------------------------------------------------------- names and configuration
def proxy_name(job_id: uuid.UUID | str) -> str:
    return PROXY_PREFIX + str(job_id)


def proxy_url(name: str) -> str:
    return "http://%s:%d" % (name, PROXY_PORT)


def _split_hosts(hosts: Iterable[HostInfo]) -> tuple[list[str], list[str], list[int]]:
    names: list[str] = []
    addresses: list[str] = []
    ports: list[int] = []
    for info in hosts:
        host = info.host.strip().lower().rstrip(".")
        literal = normalise_address(host)
        if literal is not None:
            if str(literal) not in addresses:
                addresses.append(str(literal))
        else:
            if not _NAME_RE.match(host) or ".." in host:
                raise DastProxyError("'%s' is not a valid host name for the scan proxy." % host[:80])
            if host not in names:
                names.append(host)
        if not 0 < int(info.port) < 65536:
            raise DastProxyError("The port %s is not valid." % info.port)
        if int(info.port) not in ports:
            ports.append(int(info.port))
    if not names and not addresses:
        raise DastProxyError("The scan proxy needs at least one host.")
    return sorted(names), sorted(addresses), sorted(ports)


def render_squid_conf(hosts: Iterable[HostInfo], *, name: str) -> str:
    """The squid configuration of one job: only ``hosts`` on their ports, nothing else.

    Host names are matched exactly (``dstdomain``); address literals with ``dst``. A destination that
    resolves into a never-scanned range (loopback, link-local and cloud metadata, multicast) is refused even
    when its name is allowed, so a DNS answer cannot turn the proxy against this machine. DNS is only
    consulted for allowed names (the ACLs are evaluated left to right).
    """
    names, addresses, ports = _split_hosts(hosts)
    blocked = " ".join(str(net) for net in ALWAYS_BLOCKED)
    lines = [
        "# Generated by SecureScan for one DAST job. Do not edit.",
        "http_port %d" % PROXY_PORT,
        "visible_hostname %s" % name,
        "acl dast_ports port %s" % " ".join(str(p) for p in ports),
        "acl blocked_dst dst %s" % blocked,
    ]
    if names:
        lines.append("acl dast_names dstdomain %s" % " ".join(names))
    if addresses:
        lines.append("acl dast_ips dst %s" % " ".join(addresses))
    lines.append("http_access deny !dast_ports")
    if names:
        lines.append("http_access deny dast_names blocked_dst")
    if addresses:
        lines.append("http_access deny dast_ips blocked_dst")
    if names:
        lines.append("http_access allow dast_names dast_ports")
    if addresses:
        lines.append("http_access allow dast_ips dast_ports")
    lines += [
        "http_access deny all",
        "cache deny all",
        "umask 022",
        "buffered_logs off",
        "logfile_rotate 0",
        "access_log stdio:/var/log/squid/%s" % ACCESS_LOG,
        "cache_log /var/log/squid/cache.log",
        "debug_options ALL,1",
        "pid_filename none",
        "coredump_dir /tmp",
        "forwarded_for delete",
        "via off",
        "dns_v4_first on",
        "shutdown_lifetime 1 seconds",
        "",
    ]
    return "\n".join(lines)


def allowed_destinations(hosts: Iterable[HostInfo]) -> set[str]:
    """The host names and addresses the generated configuration allows (lower case)."""
    names, addresses, _ports = _split_hosts(hosts)
    return set(names) | set(addresses)


@dataclass
class ProxyHandle:
    name: str
    token: str
    container_id: str
    url: str
    hosts: list[str]
    ports: list[int]
    directory: Path  # <workspace>/proxy
    started_at: float = field(default_factory=time.time)

    @property
    def access_log_path(self) -> Path:
        return self.directory / LOG_DIR / ACCESS_LOG


def build_proxy_spec(
    *,
    image: str,
    name: str,
    token: str,
    job_id: uuid.UUID | str,
    scan_id: uuid.UUID | str,
    directory: Path,
    hosts: Sequence[str],
    settings: Settings,
) -> ContainerSpec:
    """The squid container: ``dast`` as its network and ``egress`` as the second one."""
    return ContainerSpec(
        image=image,
        name=name,
        user=SQUID_UID,
        entrypoint=["/usr/sbin/squid"],
        command=["-N", "-f", "/etc/squid/securescan.conf"],
        binds=[
            (str(directory / CONF_NAME), "/etc/squid/securescan.conf", True),
            (str(directory / LOG_DIR), "/var/log/squid", False),
        ],
        tmpfs={"/tmp": "size=16m,mode=1777"},  # noqa: S108 - container-internal tmpfs
        network=settings.network_dast,
        extra_networks=[settings.network_egress],
        labels={
            LABEL_MANAGED: "true",
            LABEL_ROLE: ROLE_VALUE,
            LABEL_JOB: str(job_id),
            LABEL_SCAN: str(scan_id),
            LABEL_TOKEN: token,
            LABEL_HOSTS: ",".join(hosts)[:500],
        },
        mem_limit="512m",
        nano_cpus=1_000_000_000,
        pids_limit=256,
        read_only_rootfs=True,
        stop_timeout=5,
    )


def _write_proxy_files(directory: Path, conf: str) -> None:
    """Create ``<workspace>/proxy`` with the configuration (0644) and a world-writable log directory."""
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o755)
    logs = directory / LOG_DIR
    logs.mkdir(exist_ok=True)
    os.chmod(logs, 0o777)  # squid runs as uid 13 and writes its logs here
    path = directory / CONF_NAME
    path.write_text(conf, encoding="ascii")
    os.chmod(path, 0o644)


# --------------------------------------------------------------------------- lifecycle
def _launcher(launcher: Any | None) -> Any:
    if launcher is not None:
        return launcher
    from securescan.runner.launcher import get_launcher

    return get_launcher()


async def wait_until_running(
    launcher: Any,
    name: str,
    seconds: float,
    *,
    settle: float | None = None,
    sleep: Sleep = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    """Return when the container has stayed ``Running`` for ``settle`` seconds; else ``DastProxyError``.

    The worker is not attached to the ``dast`` network, so it cannot connect to the proxy to test it; a
    squid that has parsed its configuration and keeps running is listening.
    """
    wanted = READY_SETTLE_SECONDS if settle is None else settle
    deadline = clock() + seconds
    running_since: float | None = None
    while True:
        info = await launcher.inspect(name)
        state = (info or {}).get("State") or {}
        if state.get("Running"):
            if running_since is None:
                running_since = clock()
            if clock() - running_since >= wanted:
                return
        else:
            running_since = None
            if info is not None and str(state.get("Status", "")).lower() in ("exited", "dead"):
                raise DastProxyError(
                    "The scan proxy stopped right after it started (exit code %s). The squid image or the "
                    "generated configuration was refused." % state.get("ExitCode", "?")
                )
        if clock() >= deadline:
            raise DastProxyError(
                "The scan proxy did not stay up for %d seconds. Check that the 'dast' and 'egress' "
                "networks exist and that the squid image can start." % int(seconds)
            )
        await sleep(0.5)


async def stop_proxy(name: str, *, token: str | None = None, launcher: Any | None = None) -> bool:
    """Remove the proxy container. With ``token`` only a container that carries it is removed (a retried
    job's new proxy has the same name). Never raises; True when something was removed."""
    try:
        client = _launcher(launcher)
        info = await client.inspect(name)
        if info is None:
            return False
        if token is not None:
            labels = (info.get("Config") or {}).get("Labels") or {}
            if str(labels.get(LABEL_TOKEN, "")) != token:
                return False
        await client.remove(str(info.get("Id") or name), force=True)
        return True
    except Exception as exc:  # noqa: BLE001 - cleanup must not hide the job's own result
        log.warning("dast_proxy_remove_failed", name=name, error=type(exc).__name__)
        return False


async def sweep_stale_proxies(*, keep: str | None = None, launcher: Any | None = None) -> int:
    """Remove every DAST proxy except ``keep``. Safe because only one DAST job runs at a time."""
    client = _launcher(launcher)
    removed = 0
    try:
        ids = await client.list_by_label("%s=%s" % (LABEL_ROLE, ROLE_VALUE))
    except Exception as exc:  # noqa: BLE001 - a failed sweep must not block a scan
        log.warning("dast_proxy_sweep_failed", error=type(exc).__name__)
        return 0
    for container_id in ids:
        try:
            info = await client.inspect(container_id)
            name = str((info or {}).get("Name", "")).lstrip("/")
            if keep is not None and name == keep:
                continue
            await client.remove(container_id, force=True)
            removed += 1
        except Exception as exc:  # noqa: BLE001
            log.warning("dast_proxy_sweep_item_failed", error=type(exc).__name__)
    if removed:
        log.info("dast_proxies_swept", count=removed)
    return removed


async def start_proxy(
    *,
    job_id: uuid.UUID | str,
    scan_id: uuid.UUID | str,
    workspace_root: Path,
    hosts: Sequence[HostInfo],
    settings: Settings,
    launcher: Any | None = None,
    image: str | None = None,
    sleep: Sleep = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> ProxyHandle:
    """Write the job's ``squid.conf`` and start its proxy; returns when it is up."""
    name = proxy_name(job_id)
    client = _launcher(launcher)
    names, addresses, ports = _split_hosts(hosts)
    allowed = names + addresses
    conf = render_squid_conf(hosts, name=name)
    directory = workspace_root / PROXY_DIR
    await asyncio.to_thread(_write_proxy_files, directory, conf)
    squid_image = image or await resolve_egress_image(settings)
    await sweep_stale_proxies(keep=None, launcher=client)  # one DAST job at a time: anything left is stale
    token = secrets.token_hex(8)
    spec = build_proxy_spec(
        image=squid_image,
        name=name,
        token=token,
        job_id=job_id,
        scan_id=scan_id,
        directory=directory,
        hosts=allowed,
        settings=settings,
    )
    container_id = await client.create(spec)
    try:
        await client.start(container_id)
        await wait_until_running(
            client, name, float(settings.dast_proxy_ready_seconds), sleep=sleep, clock=clock
        )
    except BaseException:
        await stop_proxy(name, token=token, launcher=client)
        raise
    log.info("dast_proxy_started", name=name, hosts=allowed, ports=ports)
    return ProxyHandle(
        name=name,
        token=token,
        container_id=container_id,
        url=proxy_url(name),
        hosts=allowed,
        ports=ports,
        directory=directory,
    )


# --------------------------------------------------------------------------- watcher
_WATCHERS: dict[str, asyncio.Task[None]] = {}
_DONE_STATES = frozenset(JOB_TERMINAL_STATES) | {JobState.QUEUED}


async def _job_state(job_id: uuid.UUID) -> JobState | None:
    async with session_scope() as db:
        return await db.scalar(select(ScanJob.state).where(ScanJob.id == job_id))


async def watch_and_remove(
    job_id: uuid.UUID,
    handle: ProxyHandle,
    max_seconds: float,
    *,
    poll: float = WATCH_POLL_SECONDS,
    state_of: Callable[[uuid.UUID], Awaitable[JobState | None]] = _job_state,
    sleep: Sleep = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
    launcher: Any | None = None,
) -> None:
    """Remove the proxy when the job is final (or queued again, or ``max_seconds`` have passed)."""
    deadline = clock() + max_seconds
    while clock() < deadline:
        await sleep(poll)
        try:
            state = await state_of(job_id)
        except Exception as exc:  # noqa: BLE001 - a database blip must not leave the proxy running
            log.warning("dast_proxy_watch_failed", error=type(exc).__name__)
            continue
        if state is None or state in _DONE_STATES:
            break
    await stop_proxy(handle.name, token=handle.token, launcher=launcher)


def schedule_cleanup(job_id: uuid.UUID, handle: ProxyHandle, max_seconds: float) -> asyncio.Task[None]:
    """Start the watcher for a job's proxy (replacing the watcher of an earlier attempt)."""
    key = str(job_id)
    previous = _WATCHERS.pop(key, None)
    if previous is not None and not previous.done():
        previous.cancel()
    task = asyncio.get_running_loop().create_task(watch_and_remove(job_id, handle, max_seconds))
    _WATCHERS[key] = task

    def _forget(done: asyncio.Task[None]) -> None:
        if _WATCHERS.get(key) is done:
            _WATCHERS.pop(key, None)

    task.add_done_callback(_forget)
    return task


async def release_proxy(job_id: uuid.UUID | str, handle: ProxyHandle | None, launcher: Any | None = None) -> None:
    """Remove the job's proxy now and stop its watcher."""
    task = _WATCHERS.pop(str(job_id), None)
    if task is not None and not task.done():
        task.cancel()
    if handle is not None:
        await stop_proxy(handle.name, token=handle.token, launcher=launcher)


# --------------------------------------------------------------------------- what a builder calls
async def prepare_job_network(
    ctx: Any, *, tool: str, timeout_s: float, launcher: Any | None = None
) -> tuple[ProxyHandle, list[HostInfo]]:
    """The common start of a web-scan job: ask the rules again, then start the job's proxy.

    Raises ``ToolPreparationError`` (plain message, stable code) when the rules now forbid the scan (the
    scan waited in the queue past its authorization window, into a blackout window or past an allowlist
    change) or when the proxy cannot start. On success a watcher removes the proxy whenever the job ends.
    """
    from securescan.api.problems import Problem
    from securescan.domain.dast_rules import check_job_allowed, resolve_hosts, target_hosts
    from securescan.runner.tools.base import ToolPreparationError

    target = ctx.target
    if target is None:
        raise ToolPreparationError("This scan has no target.", code="scan.no_target")
    try:
        hosts = target_hosts(target)
    except ValueError as exc:
        raise ToolPreparationError(str(exc), code="target.invalid_url") from exc
    resolved = await resolve_hosts([h.host for h in hosts])
    try:
        check_job_allowed(
            target, ctx.application, tool=tool, mode=ctx.scan.mode, resolved=resolved
        )
    except Problem as exc:
        raise ToolPreparationError(
            str(exc.detail or exc), code=str(exc.code or "dast.not_allowed")
        ) from exc
    try:
        handle = await start_proxy(
            job_id=ctx.job.id,
            scan_id=ctx.scan.id,
            workspace_root=ctx.workspace.root,
            hosts=hosts,
            settings=ctx.settings,
            launcher=launcher,
        )
    except (DastProxyError, EgressError) as exc:  # EgressError: the squid image is not configured or not pinned
        raise ToolPreparationError(str(exc), code="dast.proxy_failed") from exc
    schedule_cleanup(ctx.job.id, handle, max_seconds=timeout_s + 900.0)
    return handle, hosts


# --------------------------------------------------------------------------- the access log
@dataclass
class ProxySummary:
    requests: int = 0
    denied: int = 0
    by_host: dict[str, int] = field(default_factory=dict)
    denied_hosts: dict[str, int] = field(default_factory=dict)
    unexpected_hosts: list[str] = field(default_factory=list)  # served although not on the allowlist

    def note(self) -> str:
        hosts = ", ".join("%s (%d)" % (h, n) for h, n in sorted(self.by_host.items())) or "none"
        text = "Scan proxy: %d requests to %s." % (self.requests - self.denied, hosts)
        if self.denied:
            blocked = ", ".join("%s (%d)" % (h, n) for h, n in sorted(self.denied_hosts.items()))
            text += " %d requests were refused (%s)." % (self.denied, blocked)
        if self.unexpected_hosts:
            text += " WARNING: traffic to hosts outside the allowlist: %s." % ", ".join(self.unexpected_hosts)
        return text


def _host_of_log_url(url: str) -> str:
    """Host of a squid access-log URL: ``http://host:port/path``, ``host:port`` (CONNECT) or a bare name."""
    text = url.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    if text.startswith("["):  # IPv6 literal
        return text[1:].split("]", 1)[0].lower()
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text.lower().rstrip(".")


def summarise_access_log(text: str, allowed: Iterable[str]) -> ProxySummary:
    """Count requests per host from squid's native access log format.

    A line looks like ``<time> <elapsed> <client> <result>/<status> <bytes> <method> <url> <user>
    <hierarchy>/<peer> <type>``. ``TCP_DENIED`` results (or status 403 from the proxy itself) are counted as
    refused; any other result for a host that is not allowlisted would be a hole in the configuration and is
    reported as unexpected.
    """
    allowed_set = {a.lower() for a in allowed}
    summary = ProxySummary()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 7 or "/" not in fields[3]:
            continue
        result, _, status = fields[3].partition("/")
        host = _host_of_log_url(fields[6])
        if not host:
            continue
        summary.requests += 1
        if result.endswith("DENIED") or result == "NONE_NONE":
            summary.denied += 1
            summary.denied_hosts[host] = summary.denied_hosts.get(host, 0) + 1
            continue
        summary.by_host[host] = summary.by_host.get(host, 0) + 1
        if host not in allowed_set and host not in summary.unexpected_hosts:
            summary.unexpected_hosts.append(host)
    return summary


def read_access_log(handle: ProxyHandle) -> str:
    """The last ``MAX_LOG_READ_BYTES`` of the proxy's access log ('' when there is none)."""
    path = handle.access_log_path
    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            if size > MAX_LOG_READ_BYTES:
                stream.seek(size - MAX_LOG_READ_BYTES)
            return stream.read().decode("utf-8", "replace")
    except OSError:
        return ""


async def finish_job_proxy(
    ctx: Any,
    handle: ProxyHandle,
    *,
    extra_files: Sequence[tuple[Path, str, str]] = (),
    launcher: Any | None = None,
) -> ProxySummary:
    """End of a web-scan job: summarise the proxy's access log into the coverage notes, store it (and
    ``extra_files``: ``(path, artifact file name, content type)``) as log artifacts, remove the proxy.

    A removed proxy takes its log with it, so this runs first. Only the normal path gets here (the executor
    calls ``post_run`` for finished tools); on every other path the watcher removes the proxy.
    """
    from securescan.db.models.enums import ArtifactKind
    from securescan.storage.artifacts import save_file

    summary = ProxySummary()
    try:
        summary = summarise_access_log(read_access_log(handle), handle.hosts)
        ctx.coverage_notes.append(summary.note())
        if summary.unexpected_hosts:
            log.warning("dast_proxy_unexpected_hosts", hosts=summary.unexpected_hosts)
        session = getattr(ctx, "session", None)
        if session is not None:
            files = list(extra_files)
            files.append((handle.access_log_path, "dast-proxy-access.log", "text/plain"))
            for path, name, content_type in files:
                if path.is_file():
                    await save_file(
                        session,
                        kind=ArtifactKind.LOG,
                        source=path,
                        filename=name,
                        content_type=content_type,
                        scan_id=ctx.scan.id,
                        job_id=ctx.job.id,
                    )
    finally:
        await release_proxy(ctx.job.id, handle, launcher=launcher)
    return summary


# --------------------------------------------------------------------------- the url source
async def acquire_url(request: SourceRequest) -> SourceInfo:
    """A web target has nothing to fetch; the job gets its (empty) workspace."""
    return SourceInfo(kind="url", is_git=False, description="web target (nothing to fetch)")


register_source_handler("url", acquire_url)
