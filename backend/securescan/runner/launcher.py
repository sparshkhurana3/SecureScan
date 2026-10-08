"""The Docker launcher: the only code in SecureScan that talks to the Docker Engine API.

It uses the Docker SDK's low-level ``APIClient`` against ``SECURESCAN_DOCKER_HOST`` (the socket proxy,
``tcp://socket-proxy:2375``), always with an explicit API version (the SDK would otherwise send an
unversioned ``GET /version`` first). The SDK is synchronous, so every call runs in a worker thread.

Container specifications are built elsewhere (catalogue, tool builders); the launcher only translates a
``ContainerSpec`` into the Engine API request body (``build_create_body``), adding the hardening that is
not negotiable: all capabilities dropped, ``no-new-privileges``, not privileged, no swap, no restart.

Bind sources: the worker sees the ``securescan_data`` volume at ``/var/lib/securescan`` but the daemon
needs the path on the host. ``ensure_roots`` reads ``GET /volumes/securescan_data`` (``Mountpoint``)
unless ``SECURESCAN_DATA_HOST_ROOT`` is set, and does the same for ``securescan_content`` (a separate
volume mounted below the data root in the worker). ``host_path`` maps a worker path with the longest
matching prefix; a path outside every known root is taken to be an absolute daemon path already.

Requests the proxy must allow (see ``deploy/socket-proxy/args.env``): ``POST /containers/create``,
``POST /containers/<id|name>/{start,stop,kill,wait}``, ``GET /containers/<id|name>/{json,logs}``,
``DELETE /containers/<id|name>``, ``GET /containers/json``, ``GET /volumes/<name>``, ``GET /_ping``.
No network is ever created, no image is ever pulled.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable
from functools import lru_cache
from typing import Any

from securescan.config import Settings, get_settings
from securescan.logging import get_logger, scrub
from securescan.runner.specs import LOG_TAIL_BYTES, ContainerResult, ContainerSpec, parse_size

log = get_logger(__name__)

LogSink = Callable[[str], Awaitable[None]]
WAIT_SLICE_SECONDS = 10
MAX_LINE_CHARS = 8000
_NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_BIND_BAD = re.compile(r"[:\x00\n]")


class LauncherError(Exception):
    """Docker could not be reached or failed in a way that a retry may fix (infrastructure)."""


class LauncherConfigError(Exception):
    """The request can never succeed as it is: missing image, refused by the proxy, bad spec."""


# --------------------------------------------------------------------------- request translation
def _check_image(image: str) -> None:
    if not image or any(ch.isspace() for ch in image):
        raise LauncherConfigError("container image is empty or contains whitespace")
    if "@sha256:" in image:
        return
    tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else ""
    if not tag or tag == "latest":
        raise LauncherConfigError(f"image {image!r} must be pinned by digest or an exact tag, never latest")


def _bind_string(source: str, target: str, read_only: bool, *, volume: bool = False) -> str:
    """``source:target:ro|rw``; ``source`` is an absolute daemon path or (``volume=True``) a volume name."""
    if _BIND_BAD.search(source) or _BIND_BAD.search(target):
        raise LauncherConfigError("bind paths cannot contain ':' or control characters")
    if (not volume and not source.startswith("/")) or not target.startswith("/"):
        raise LauncherConfigError("bind paths must be absolute")
    if ".." in source.split("/") or ".." in target.split("/"):
        raise LauncherConfigError("bind paths cannot contain '..'")
    return f"{source}:{target}:{'ro' if read_only else 'rw'}"


def build_create_body(spec: ContainerSpec, host_path: Callable[[str], str]) -> dict[str, Any]:
    """The JSON body of ``POST /containers/create`` for ``spec``. Pure; unit-tested."""
    _check_image(spec.image)
    if not spec.command:
        raise LauncherConfigError("container command is empty")
    if spec.name is not None and not _NAME_OK.match(spec.name):
        raise LauncherConfigError(f"unsafe container name {spec.name!r}")

    binds = [_bind_string(host_path(src), target, ro) for src, target, ro in spec.binds]
    for volume, target, ro in spec.volumes:
        if not _NAME_OK.match(volume):
            raise LauncherConfigError(f"unsafe volume name {volume!r}")
        binds.append(_bind_string(volume, target, ro, volume=True))

    host_config: dict[str, Any] = {
        "NetworkMode": spec.network,
        "ReadonlyRootfs": bool(spec.read_only_rootfs),
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges"],
        "Privileged": False,
        "AutoRemove": False,
        "RestartPolicy": {"Name": "no"},
        "LogConfig": {"Type": "json-file", "Config": {"max-size": "20m", "max-file": "2"}},
    }
    if binds:
        host_config["Binds"] = binds
    if spec.mem_limit:
        memory = parse_size(spec.mem_limit)
        host_config["Memory"] = memory
        host_config["MemorySwap"] = memory  # no swap
    if spec.nano_cpus:
        host_config["NanoCpus"] = int(spec.nano_cpus)
    if spec.pids_limit:
        host_config["PidsLimit"] = int(spec.pids_limit)
    if spec.tmpfs:
        host_config["Tmpfs"] = dict(spec.tmpfs)
    if spec.shm_size:
        host_config["ShmSize"] = parse_size(spec.shm_size)
    if spec.ulimits:
        host_config["Ulimits"] = [
            {"Name": name, "Soft": soft, "Hard": hard} for name, (soft, hard) in spec.ulimits.items()
        ]

    body: dict[str, Any] = {
        "Image": spec.image,
        "Cmd": list(spec.command),
        "Env": [f"{key}={value}" for key, value in spec.env.items()],
        "Labels": dict(spec.labels),
        "HostConfig": host_config,
        "AttachStdin": False,
        "AttachStdout": False,
        "AttachStderr": False,
        "Tty": False,
        "OpenStdin": False,
    }
    if spec.user:
        body["User"] = spec.user
    if spec.entrypoint is not None:
        body["Entrypoint"] = list(spec.entrypoint)
    if spec.stop_timeout is not None:
        body["StopTimeout"] = int(spec.stop_timeout)

    networks = [spec.network, *spec.extra_networks]
    if spec.network == "none":
        if spec.extra_networks:
            raise LauncherConfigError("a container without network cannot join extra networks")
    else:
        body["NetworkingConfig"] = {"EndpointsConfig": {name: {} for name in networks}}
    return body


# --------------------------------------------------------------------------- path mapping
class PathMapper:
    """Maps worker paths to daemon paths with the longest matching prefix."""

    def __init__(self, mappings: list[tuple[str, str]] | None = None) -> None:
        self._mappings: list[tuple[str, str]] = []
        for worker, host in mappings or []:
            self.add(worker, host)

    def add(self, worker_root: str, host_root: str) -> None:
        self._mappings.append((worker_root.rstrip("/") or "/", host_root.rstrip("/") or "/"))
        self._mappings.sort(key=lambda pair: len(pair[0]), reverse=True)

    def __bool__(self) -> bool:
        return bool(self._mappings)

    def to_host(self, path: str) -> str:
        for worker, host in self._mappings:
            if path == worker:
                return host
            if path.startswith(worker + "/"):
                return host + path[len(worker) :]
        return path


# --------------------------------------------------------------------------- the launcher
class _LogTail:
    """The last ``LOG_TAIL_BYTES`` of the output, kept as lines."""

    def __init__(self, limit: int = LOG_TAIL_BYTES) -> None:
        self._limit = limit
        self._lines: deque[str] = deque()
        self._size = 0

    def add(self, line: str) -> None:
        self._lines.append(line)
        self._size += len(line) + 1
        while self._size > self._limit and len(self._lines) > 1:
            self._size -= len(self._lines.popleft()) + 1

    def text(self) -> str:
        return "\n".join(self._lines)


class Launcher:
    """Create, run, watch and remove containers. ``api`` is a ``docker.APIClient`` (or a test double)."""

    def __init__(
        self,
        api: Any,
        *,
        data_root: str = "/var/lib/securescan",
        data_host_root: str = "",
        data_volume: str = "securescan_data",
        content_root: str = "",
        content_host_root: str = "",
        content_volume: str = "securescan_content",
    ) -> None:
        self.api = api
        self._data_root = data_root
        self._data_volume = data_volume
        self._content_root = content_root
        self._content_volume = content_volume
        self._mapper = PathMapper()
        self._roots_ready = False
        self._lock = asyncio.Lock()
        self._data_host_root = data_host_root
        self._content_host_root = content_host_root
        if data_host_root:
            self._mapper.add(data_root, data_host_root)
        if content_root and content_host_root:
            self._mapper.add(content_root, content_host_root)

    # ------------------------------------------------------------------ plumbing
    async def _call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            return await asyncio.to_thread(func, *args, **kwargs)
        except Exception as exc:
            raise map_docker_error(exc) from exc

    async def _call_wait(self, cid: str, slice_s: float) -> Any:
        """``POST /containers/<id>/wait`` for one slice; a read timeout is not an error."""
        try:
            return await asyncio.to_thread(self.api.wait, cid, slice_s)
        except Exception as exc:
            if _is_read_timeout(exc):
                raise _WaitTimeout(str(exc)) from exc
            raise map_docker_error(exc) from exc

    async def ping(self) -> bool:
        return bool(await self._call(self.api.ping))

    async def ensure_roots(self) -> None:
        """Learn the daemon-side directories of the data and content volumes (once)."""
        if self._roots_ready:
            return
        async with self._lock:
            if self._roots_ready:
                return
            if not self._data_host_root:
                self._mapper.add(self._data_root, await self._mountpoint(self._data_volume))
            if self._content_root and not self._content_host_root:
                try:
                    content = await self._mountpoint(self._content_volume)
                except LauncherConfigError:
                    log.info("content_volume_not_found", volume=self._content_volume)
                else:
                    self._mapper.add(self._content_root, content)
            self._roots_ready = True

    async def _mountpoint(self, volume: str) -> str:
        info = await self._call(self.api.inspect_volume, volume)
        mountpoint = str((info or {}).get("Mountpoint") or "")
        if not mountpoint.startswith("/"):
            raise LauncherConfigError(f"volume {volume} has no usable Mountpoint")
        return mountpoint

    def host_path(self, worker_path: str) -> str:
        """Daemon-side path for a path under DATA_ROOT (or the content root) as the worker sees it."""
        if not self._roots_ready and not self._mapper:
            raise LauncherError("the launcher has not read the data volume yet (call ensure_roots)")
        return self._mapper.to_host(str(worker_path))

    # ------------------------------------------------------------------ container lifecycle
    async def create(self, spec: ContainerSpec) -> str:
        await self.ensure_roots()
        body = build_create_body(spec, self.host_path)
        if spec.name:
            await self.remove(spec.name, force=True)  # a leftover of a failed earlier attempt
        created = await self._call(self.api.create_container_from_config, body, spec.name)
        container_id = str((created or {}).get("Id") or "")
        if not container_id:
            raise LauncherError("Docker did not return a container id")
        log.info("container_created", container_id=container_id[:12], image=spec.image, name=spec.name)
        return container_id

    async def start(self, cid: str) -> None:
        await self._call(self.api.start, cid)

    async def wait(
        self, cid: str, timeout_s: float | None, cancel: asyncio.Event | None = None
    ) -> int | None:
        """Exit code, or None when ``timeout_s`` elapsed (or ``cancel`` was set) first."""
        started = time.monotonic()
        while True:
            if cancel is not None and cancel.is_set():
                return None
            remaining = None if timeout_s is None else timeout_s - (time.monotonic() - started)
            if remaining is not None and remaining <= 0:
                return None
            slice_s = WAIT_SLICE_SECONDS if remaining is None else max(1.0, min(WAIT_SLICE_SECONDS, remaining))
            try:
                result = await self._call_wait(cid, slice_s)
            except _WaitTimeout:
                continue
            code = (result or {}).get("StatusCode")
            return int(code) if code is not None else None

    async def stream_logs(self, cid: str, sink: LogSink) -> None:
        """Feed every output line of the container to ``sink`` until the stream ends."""
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[bytes | BaseException | None] = asyncio.Queue()

        def pump() -> None:
            try:
                stream = self.api.logs(cid, stdout=True, stderr=True, stream=True, follow=True)
                for chunk in stream:
                    loop.call_soon_threadsafe(queue.put_nowait, bytes(chunk))
            except Exception as exc:  # reported through the queue, never raised in the thread
                loop.call_soon_threadsafe(queue.put_nowait, exc)
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        thread_future = loop.run_in_executor(None, pump)
        pending = ""
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                if isinstance(item, BaseException):
                    log.warning("log_stream_error", error=scrub(str(item))[:200])
                    break
                pending += item.decode("utf-8", "replace")
                lines = pending.split("\n")
                pending = lines.pop()
                for line in lines:
                    for piece in _split_line(line.rstrip("\r")):
                        await sink(piece)
                if len(pending) > MAX_LINE_CHARS:
                    for piece in _split_line(pending):
                        await sink(piece)
                    pending = ""
            if pending:
                await sink(pending.rstrip("\r"))
        finally:
            if not thread_future.done():
                thread_future.cancel()

    async def stop(self, cid: str, timeout: int = 10) -> None:
        await self._call_ignoring(self.api.stop, cid, timeout, statuses=(304, 404, 409))

    async def kill(self, cid: str) -> None:
        await self._call_ignoring(self.api.kill, cid, statuses=(404, 409))

    async def remove(self, cid: str, force: bool = True) -> None:
        await self._call_ignoring(
            self.api.remove_container, cid, v=True, force=force, statuses=(404, 409)
        )

    async def inspect(self, cid_or_name: str) -> dict[str, Any] | None:
        """The container's inspect document, or None when it does not exist."""
        try:
            info = await self._call(self.api.inspect_container, cid_or_name)
        except _NotFound:
            return None
        return dict(info) if info else None

    async def list_by_label(self, label: str) -> list[str]:
        """Ids of all containers (any state) with the label (``key`` or ``key=value``)."""
        rows = await self._call(self.api.containers, all=True, filters={"label": [label]}, quiet=False)
        return [str(row["Id"]) for row in rows or [] if row.get("Id")]

    async def _call_ignoring(
        self, func: Callable[..., Any], *args: Any, statuses: tuple[int, ...], **kwargs: Any
    ) -> None:
        try:
            await self._call(func, *args, **kwargs)
        except _NotFound:
            return
        except _StatusError as exc:
            if exc.status in statuses:
                return
            raise LauncherError(str(exc)) from exc

    # ------------------------------------------------------------------ the whole run
    async def run(
        self,
        spec: ContainerSpec,
        timeout_s: float | None,
        on_log: LogSink | None = None,
        *,
        on_created: Callable[[str], Awaitable[None]] | None = None,
        cancel: asyncio.Event | None = None,
    ) -> ContainerResult:
        """Create, start, stream, wait (kill on timeout, stop on cancel) and remove a container."""
        tail = _LogTail()

        async def sink(line: str) -> None:
            tail.add(line)
            if on_log is not None:
                await on_log(line)

        cid = await self.create(spec)
        timed_out = False
        cancelled = False
        exit_code: int | None = None
        log_task: asyncio.Task[None] | None = None
        try:
            if on_created is not None:
                await on_created(cid)
            await self.start(cid)
            log_task = asyncio.create_task(self.stream_logs(cid, sink))
            exit_code = await self.wait(cid, timeout_s, cancel)
            if exit_code is None:
                cancelled = bool(cancel is not None and cancel.is_set())
                timed_out = not cancelled
                if cancelled:
                    await self.stop(cid, timeout=10)
                else:
                    await self.kill(cid)
                exit_code = await self.wait(cid, 30)
            await _drain(log_task)
        finally:
            if log_task is not None and not log_task.done():
                log_task.cancel()
            await asyncio.shield(self.remove(cid, force=True))
        return ContainerResult(
            container_id=cid,
            exit_code=exit_code,
            timed_out=timed_out,
            logs=tail.text(),
            cancelled=cancelled,
        )


async def _drain(task: asyncio.Task[None]) -> None:
    try:
        await asyncio.wait_for(task, timeout=15)
    except Exception as exc:  # the logs are best effort
        log.warning("log_drain_incomplete", error=type(exc).__name__)


def _split_line(line: str) -> list[str]:
    if len(line) <= MAX_LINE_CHARS:
        return [line]
    return [line[i : i + MAX_LINE_CHARS] for i in range(0, len(line), MAX_LINE_CHARS)]


# --------------------------------------------------------------------------- error mapping
class _NotFound(Exception):
    """Internal: the container or volume does not exist (HTTP 404)."""


class _StatusError(Exception):
    """Internal: Docker answered with an error status that the caller may tolerate."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class _WaitTimeout(Exception):
    """Internal: one slice of ``wait`` elapsed without the container exiting."""


def _is_read_timeout(exc: BaseException) -> bool:
    name = type(exc).__name__
    return name in ("ReadTimeout", "ReadTimeoutError", "Timeout") or "Read timed out" in str(exc)


def map_docker_error(exc: Exception) -> Exception:
    """Translate SDK and HTTP-library exceptions into the launcher's own."""
    if isinstance(exc, (LauncherError, LauncherConfigError, _NotFound, _StatusError, _WaitTimeout)):
        return exc
    name = type(exc).__name__
    module = type(exc).__module__
    status = getattr(exc, "status_code", None) or getattr(
        getattr(exc, "response", None), "status_code", None
    )
    explanation = str(getattr(exc, "explanation", "") or exc)
    if module.startswith("docker") and name in ("NotFound", "ImageNotFound"):
        if "No such image" in explanation or name == "ImageNotFound":
            return LauncherConfigError(
                f"the scanner image is not present on this host (pre-pull it): {explanation[:200]}"
            )
        return _NotFound(explanation)
    if module.startswith("docker") and name in ("APIError", "ContainerError", "BuildError"):
        code = int(status) if isinstance(status, int) else 0
        if code == 404:
            return _NotFound(explanation)
        if code in (400, 401, 403):
            return LauncherConfigError(f"Docker refused the request ({code}): {explanation[:300]}")
        if code in (304, 409):
            return _StatusError(code, explanation[:300])
        return LauncherError(f"Docker API error {code}: {explanation[:300]}")
    return LauncherError(f"{name}: {scrub(str(exc))[:300]}")


# --------------------------------------------------------------------------- factory
def make_api_client(settings: Settings | None = None) -> Any:
    """A ``docker.APIClient`` for the configured (proxy) endpoint with an explicit API version."""
    import docker  # imported here so that modules importing the launcher stay light

    cfg = settings or get_settings()
    return docker.APIClient(base_url=cfg.docker_host, version=cfg.docker_api_version, timeout=60)


@lru_cache
def get_launcher() -> Launcher:
    settings = get_settings()
    return Launcher(
        make_api_client(settings),
        data_root=settings.data_root,
        data_host_root=settings.data_host_root,
        data_volume=settings.data_volume,
        content_root=settings.content_root,
        content_volume=settings.content_volume,
    )


def reset_launcher_cache() -> None:
    get_launcher.cache_clear()
