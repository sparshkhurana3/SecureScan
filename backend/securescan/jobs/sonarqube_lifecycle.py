"""The on-demand SonarQube server: create, start, wait for ``UP``, set up, and stop when idle (plan M8 task 5).

The server is not a Compose service. Its catalogue entry is ``sonarqube-server``
(``scanners/catalogue.d/sonarqube-server.yaml``); this module adds what the entry cannot say (networks, named
volumes, ulimits, database settings, the stop grace period) and drives the container through the launcher:

* ``ensure_running()`` is called by the SonarQube builder's ``prepare``. It inspects the container: missing
  (404) means create from the catalogue and start, stopped means start (re-created first when the pinned image
  changed), running means nothing. It then waits for ``GET /api/system/status`` to say ``UP`` (10 minutes at
  most, ``securescan_sonarqube_start_seconds`` records the last start) and, while the admin password is still the
  default, runs the first-time setup of ``securescan.integrations.sonarqube.init``.
* ``stop_if_idle()`` is the ``sonarqube_idle_stop`` periodic task (every 5 minutes): it stops the container
  (graceful, up to 300 s, the data stays on the named volumes) when no SonarQube job is queued or running and
  nothing used the server for ``sonarqube_idle_minutes`` (15). "Used" is the later of the last job's finish and
  the marker file ``<data root>/sonarqube/last_used`` that ``ensure_running`` touches.

One asyncio lock serialises start and stop (a single worker process, as for the egress proxy).

The server's database password goes into the container environment (``SONAR_JDBC_PASSWORD``), as the plan
says; it is readable with ``docker inspect`` by root on the host only (the socket proxy forbids it to everyone
else). Everything marked unverified in the catalogue entry is confirmed by spike S3.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from securescan.config import Settings, get_settings
from securescan.db.models.enums import JobState
from securescan.db.models.jobs import ScanJob
from securescan.db.session import session_scope
from securescan.integrations.sonarqube.client import SonarQubeClient
from securescan.integrations.sonarqube.init import initialise, needs_initialisation
from securescan.jobs.hooks import periodic_hook
from securescan.logging import get_logger
from securescan.observability.metrics import SONARQUBE_START_SECONDS
from securescan.runner.catalogue import (
    CatalogueEntry,
    ResolvedImage,
    get_entry,
    resolve_image_with_override,
)
from securescan.runner.specs import ContainerSpec
from securescan.runner.tools._support import spec_from_entry
from securescan.runner.tools.base import LABEL_MANAGED
from securescan.util import ensure_utc

log = get_logger(__name__)

SERVER_TOOL = "sonarqube-server"
SCANNER_TOOL = "sonarqube"
LABEL_ROLE = "securescan.role"
ROLE_VALUE = "sonarqube"
STOP_TIMEOUT_SECONDS = 300
DATA_PATH = "/opt/sonarqube/data"
EXTENSIONS_PATH = "/opt/sonarqube/extensions"
LOGS_PATH = "/opt/sonarqube/logs"
CA_TARGET = "/opt/sonarqube/conf/db-ca.crt"
ACTIVE_JOB_STATES = (JobState.QUEUED, JobState.PREPARING, JobState.RUNNING)

_LOCK = asyncio.Lock()


# --------------------------------------------------------------------------- pure parts
def state_dir(settings: Settings) -> Path:
    return Path(settings.data_root) / "sonarqube"


def read_last_used(settings: Settings) -> float | None:
    try:
        return float((state_dir(settings) / "last_used").read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def touch_last_used(settings: Settings, moment: float | None = None) -> None:
    directory = state_dir(settings)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "last_used").write_text(str(moment if moment is not None else time.time()), encoding="ascii")
    except OSError as exc:
        log.warning("sonarqube_state_write_failed", error=type(exc).__name__)


def prepare_ca_file(settings: Settings) -> Path | None:
    """Copy the database CA certificate next to the server's state (a bind source the daemon may mount)."""
    source = Path(settings.sonarqube_db_ca_file) if settings.sonarqube_db_ca_file else None
    if source is None or not source.is_file():
        log.warning("sonarqube_db_ca_missing", path=str(source) if source else "")
        return None
    directory = state_dir(settings)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o755)
    target = directory / "db-ca.crt"
    shutil.copyfile(source, target)
    os.chmod(target, 0o644)
    return target


def server_environment(settings: Settings) -> dict[str, str]:
    """Database connection of the server (the password is the one secret value in the environment)."""
    env = {
        "SONAR_JDBC_URL": settings.sonarqube_jdbc_url,
        "SONAR_JDBC_USERNAME": settings.sonarqube_db_user,
    }
    if settings.sonarqube_db_password:
        env["SONAR_JDBC_PASSWORD"] = settings.sonarqube_db_password
    return env


def exec_tmpfs(entry: CatalogueEntry, user: str = "1000:0") -> dict[str, str]:
    """The entry's tmpfs mounts with the ``exec`` option (Elasticsearch loads native libraries from there)."""
    uid, _, gid = user.partition(":")
    return {
        t.path: f"rw,exec,size={t.size},uid={uid or '1000'},gid={gid or '0'},mode=0770" for t in entry.tmpfs
    }


def build_server_spec(
    settings: Settings,
    entry: CatalogueEntry,
    image: ResolvedImage | str,
    *,
    ca_file: Path | None = None,
) -> ContainerSpec:
    """The container specification of the server. Pure; unit-tested."""
    binds: list[tuple[str, str, bool]] = []
    if ca_file is not None:
        binds.append((str(ca_file), CA_TARGET, True))
    spec = spec_from_entry(
        entry,
        image,
        name=settings.sonarqube_container,
        binds=binds,
        volumes=[
            (settings.sonarqube_volume_data, DATA_PATH, False),
            (settings.sonarqube_volume_extensions, EXTENSIONS_PATH, False),
            (settings.sonarqube_volume_logs, LOGS_PATH, False),
        ],
        env=server_environment(settings),
        network=settings.network_sonarqube,
        extra_networks=[settings.network_backend],
        labels={LABEL_ROLE: ROLE_VALUE, LABEL_MANAGED: "true"},
        tmpfs=exec_tmpfs(entry, entry.user),
        read_only_rootfs=settings.sonarqube_read_only_rootfs,
        stop_timeout=STOP_TIMEOUT_SECONDS,
        command=entry.render_command(),
    )
    spec.ulimits = {"nofile": (131072, 131072), "nproc": (8192, 8192)}
    return spec


def container_running(info: dict[str, Any] | None) -> bool:
    return bool(info and (info.get("State") or {}).get("Running"))


def container_image(info: dict[str, Any] | None) -> str:
    return str(((info or {}).get("Config") or {}).get("Image") or "")


def idle_for(last_used: float | None, last_finished: float | None, now: float) -> float | None:
    """Seconds since SonarQube was last used; None when there is no sign of use at all."""
    moments = [m for m in (last_used, last_finished) if m is not None]
    if not moments:
        return None
    return max(0.0, now - max(moments))


# --------------------------------------------------------------------------- the lifecycle
@dataclass
class EnsureResult:
    started: bool  # the container was created or started by this call
    seconds_to_up: float  # time the status wait took
    initialised: list[str]  # changes the first-time setup made


async def _load_spec(settings: Settings, entry: CatalogueEntry | None = None) -> ContainerSpec:
    chosen = entry or get_entry(SERVER_TOOL)
    async with session_scope() as db:
        image = await resolve_image_with_override(db, chosen, settings)
    ca_file = await asyncio.to_thread(prepare_ca_file, settings)
    return build_server_spec(settings, chosen, image, ca_file=ca_file)


async def ensure_running(
    *,
    settings: Settings | None = None,
    launcher: Any = None,
    client_factory: Callable[[Settings], SonarQubeClient] | None = None,
    spec_loader: Callable[[Settings], Awaitable[ContainerSpec]] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> EnsureResult:
    """Make sure the server runs, is ``UP`` and is set up. Raises ``LauncherError`` (Docker) or
    ``SonarError`` (the server did not come up)."""
    cfg = settings or get_settings()
    docker = launcher or _get_launcher()
    make_client = client_factory or (lambda s: SonarQubeClient(s.sonarqube_url))
    load = spec_loader or _load_spec
    async with _LOCK:
        started_at = clock()
        started = False
        info = await docker.inspect(cfg.sonarqube_container)
        if info is None:
            spec = await load(cfg)
            log.info("sonarqube_create", image=spec.image)
            container_id = await docker.create(spec)
            await docker.start(container_id)
            started = True
        elif not container_running(info):
            container_id = str(info.get("Id") or cfg.sonarqube_container)
            spec = await load(cfg)
            if container_image(info) and container_image(info) != spec.image:
                log.info("sonarqube_recreate", old=container_image(info), new=spec.image)
                await docker.remove(container_id, force=True)
                container_id = await docker.create(spec)
            await docker.start(container_id)
            started = True
        touch_last_used(cfg)
        client = make_client(cfg)
        try:
            waited = await client.wait_until_up(float(cfg.sonarqube_start_timeout_seconds))
        finally:
            await client.aclose()
        if started:
            SONARQUBE_START_SECONDS.set(clock() - started_at)
            log.info("sonarqube_up", seconds=round(clock() - started_at, 1))
        changes: list[str] = []
        if await needs_initialisation(cfg):
            async with session_scope() as db:
                changes = await initialise(db, cfg)
        touch_last_used(cfg)
        return EnsureResult(started=started, seconds_to_up=waited, initialised=changes)


def _get_launcher() -> Any:
    from securescan.runner.launcher import get_launcher

    return get_launcher()


async def _job_activity(settings: Settings) -> tuple[bool, float | None]:
    """``(a SonarQube job is queued or running, finish time of the latest SonarQube job)``."""
    async with session_scope() as db:
        busy = await db.scalar(
            select(func.count())
            .select_from(ScanJob)
            .where(ScanJob.tool == SCANNER_TOOL, ScanJob.state.in_(ACTIVE_JOB_STATES))
        )
        finished = await db.scalar(
            select(func.max(ScanJob.finished_at)).where(ScanJob.tool == SCANNER_TOOL)
        )
    return bool(busy), (ensure_utc(finished).timestamp() if finished is not None else None)


async def stop_if_idle(
    *,
    settings: Settings | None = None,
    launcher: Any = None,
    activity: Callable[[Settings], Awaitable[tuple[bool, float | None]]] | None = None,
    now: Callable[[], float] = time.time,
) -> bool:
    """Stop the server when it has been idle for ``sonarqube_idle_minutes``. True when it was stopped."""
    cfg = settings or get_settings()
    docker = launcher or _get_launcher()
    check = activity or _job_activity
    async with _LOCK:
        info = await docker.inspect(cfg.sonarqube_container)
        if not container_running(info):
            return False
        busy, last_finished = await check(cfg)
        if busy:
            touch_last_used(cfg)
            return False
        moment = now()
        idle = idle_for(read_last_used(cfg), last_finished, moment)
        if idle is None:
            touch_last_used(cfg, moment)  # running without any trace of use: start the idle period now
            return False
        if idle < cfg.sonarqube_idle_minutes * 60:
            return False
        assert info is not None  # noqa: S101 - container_running said so
        container_id = str(info.get("Id") or cfg.sonarqube_container)
        log.info("sonarqube_idle_stop", idle_seconds=int(idle))
        await docker.stop(container_id, timeout=STOP_TIMEOUT_SECONDS)
        return True


@periodic_hook("sonarqube_idle_stop")
async def stop_idle_sonarqube(timestamp: int) -> None:
    """Periodic task (every 5 minutes): stop the SonarQube server after 15 idle minutes."""
    try:
        stopped = await stop_if_idle()
    except Exception as exc:  # noqa: BLE001 - Docker may be briefly unreachable; the next run retries
        log.warning("sonarqube_idle_stop_failed", error=type(exc).__name__)
        return
    if stopped:
        log.info("sonarqube_stopped_idle")
