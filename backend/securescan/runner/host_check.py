"""Checks of the machine the worker runs on: cgroup v2 and the Docker version.

``scripts/check_host.sh`` checks the host from the outside (it can run ``docker info`` and read
``sysctl``). This module checks what the worker can see from inside its container, at start-up
(``securescan/jobs/host_startup.py``):

* cgroup v2 with the ``memory`` and ``pids`` controllers: without them the CPU, memory and PID limits
  of the scanner containers are not enforced. The container's own view (``/sys/fs/cgroup``) shows the
  host's cgroup version.
* The Docker Engine version from the headers of ``GET /_ping`` (the socket proxy allows it): the API
  version must be one the launcher speaks, and the install guide asks for Engine 29 or later.

Result: a list of checks, each ``blocking`` or a warning. With ``SECURESCAN_HOST_CHECK=enforce`` (the
default in production) a failed blocking check stops the worker at start, so no scan runs on a host
that cannot enforce its limits; ``warn`` (the default in dev and test) only logs; ``off`` skips it.
The parsing and the evaluation are pure functions with unit tests.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from prometheus_client import Gauge

from securescan.config import Settings, get_settings
from securescan.logging import get_logger
from securescan.observability.metrics import BACKUP_LAST_SUCCESS, REGISTRY

log = get_logger(__name__)

HOST_CHECK_OK = Gauge(
    "securescan_host_check_ok",
    "1 when every blocking host check passed at worker start, 0 otherwise",
    registry=REGISTRY,
)

REQUIRED_CONTROLLERS = ("memory", "pids")
RECOMMENDED_CONTROLLERS = ("cpu",)
_SERVER = re.compile(r"Docker/(\d+)\.(\d+)(?:\.(\d+))?", re.IGNORECASE)
_API = re.compile(r"^(\d+)\.(\d+)$")


class HostCheckError(RuntimeError):
    """A blocking host check failed and enforcement is on."""


# ================================================================================ parsing (pure)


def parse_controllers(text: str | None) -> set[str]:
    """``cpuset cpu io memory pids`` -> a set (``/sys/fs/cgroup/cgroup.controllers``)."""
    return set((text or "").split())


def parse_server_header(value: str | None) -> tuple[int, int, int] | None:
    """``Docker/29.0.1 (linux)`` -> ``(29, 0, 1)``."""
    match = _SERVER.search(value or "")
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def parse_api_version(value: str | None) -> tuple[int, int] | None:
    match = _API.match((value or "").strip())
    return (int(match.group(1)), int(match.group(2))) if match else None


# ================================================================================ evaluating (pure)


@dataclass(frozen=True)
class HostFacts:
    """What was read. ``None`` means "could not be read"."""

    cgroup_v2: bool | None = None
    cgroup_controllers: frozenset[str] | None = None
    docker_version: tuple[int, int, int] | None = None
    docker_api: tuple[int, int] | None = None


@dataclass(frozen=True)
class Thresholds:
    docker_major: int = 29
    docker_api: tuple[int, int] = (1, 44)

    @classmethod
    def from_settings(cls, settings: Settings) -> Thresholds:
        api = parse_api_version(settings.host_min_docker_api) or (1, 44)
        return cls(
            docker_major=settings.host_min_docker_major,
            docker_api=api,
        )


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    blocking: bool
    detail: str


@dataclass
class HostCheckResult:
    checks: list[Check] = field(default_factory=list)

    @property
    def blocking_failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.blocking]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and not c.blocking]

    @property
    def ok(self) -> bool:
        return not self.blocking_failures

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checks": [
                {"name": c.name, "ok": c.ok, "blocking": c.blocking, "detail": c.detail} for c in self.checks
            ],
        }


def _version_text(parts: tuple[int, ...]) -> str:
    return ".".join(str(p) for p in parts)


def evaluate(facts: HostFacts, limits: Thresholds | None = None) -> HostCheckResult:
    """Turn the facts into checks. A value that could not be read is a warning, never a pass."""
    t = limits or Thresholds()
    result = HostCheckResult()
    add = result.checks.append

    if facts.cgroup_v2 is None:
        add(Check("cgroup_v2", False, False, "Could not tell which cgroup version the host uses."))
    elif facts.cgroup_v2:
        add(Check("cgroup_v2", True, True, "cgroup v2 in use."))
    else:
        add(
            Check(
                "cgroup_v2", False, True,
                "The host uses cgroup v1: container memory, CPU and PID limits are not enforced reliably. "
                "Boot with systemd.unified_cgroup_hierarchy=1 (Ubuntu 24.04 does by default).",
            )  # fmt: skip
        )
    if facts.cgroup_v2:
        controllers = facts.cgroup_controllers
        if controllers is None:
            add(Check("cgroup_controllers", False, False, "Could not read the available cgroup controllers."))
        else:
            missing = [c for c in REQUIRED_CONTROLLERS if c not in controllers]
            lacking = [c for c in RECOMMENDED_CONTROLLERS if c not in controllers]
            if missing:
                add(
                    Check(
                        "cgroup_controllers", False, True,
                        "The cgroup controllers %s are not available to containers, so their limits are not enforced."
                        % ", ".join(missing),
                    )  # fmt: skip
                )
            elif lacking:
                add(
                    Check(
                        "cgroup_controllers", False, False,
                        "The cgroup controller %s is not available: CPU limits are not enforced." % ", ".join(lacking),
                    )  # fmt: skip
                )
            else:
                add(Check("cgroup_controllers", True, True, "memory, pids and cpu controllers available."))

    if facts.docker_api is None and facts.docker_version is None:
        add(Check("docker_version", False, False, "Could not read the Docker Engine version through the socket proxy."))
    else:
        if facts.docker_api is not None and facts.docker_api < t.docker_api:
            add(
                Check(
                    "docker_api", False, True,
                    "Docker API %d.%d is older than the %d.%d the launcher needs; upgrade Docker Engine."
                    % (facts.docker_api + t.docker_api),
                )  # fmt: skip
            )
        elif facts.docker_api is not None:
            add(Check("docker_api", True, True, "Docker API %d.%d." % facts.docker_api))
        if facts.docker_version is not None:
            if facts.docker_version[0] < t.docker_major:
                add(
                    Check(
                        "docker_engine", False, False,
                        "Docker Engine %s is older than %d, the version this release was written for."
                        % (_version_text(facts.docker_version), t.docker_major),
                    )  # fmt: skip
                )
            else:
                add(Check("docker_engine", True, False, "Docker Engine %s." % _version_text(facts.docker_version)))
    return result


# ================================================================================ reading the host


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def read_cgroup(root: Path = Path("/sys/fs/cgroup")) -> tuple[bool | None, frozenset[str] | None]:
    """``(is_v2, controllers)`` from the container's view of ``/sys/fs/cgroup``."""
    controllers = _read(root / "cgroup.controllers")
    if controllers is not None:
        return True, frozenset(parse_controllers(controllers))
    if (root / "memory").exists() or (root / "cpu").exists():
        return False, None
    return None, None


def docker_ping_url(docker_host: str) -> str | None:
    """``tcp://socket-proxy:2375`` -> ``http://socket-proxy:2375/_ping``; unix sockets are not supported here."""
    parts = urlsplit(docker_host)
    if parts.scheme not in ("tcp", "http", "https") or not parts.netloc:
        return None
    scheme = "https" if parts.scheme == "https" else "http"
    return "%s://%s/_ping" % (scheme, parts.netloc)


async def read_docker(
    settings: Settings, *, http: httpx.AsyncClient | None = None, attempts: int = 3, delay: float = 1.0
) -> tuple[tuple[int, int, int] | None, tuple[int, int] | None]:
    """``(engine version, api version)`` from the headers of ``GET /_ping``; ``(None, None)`` when unreachable."""
    url = docker_ping_url(settings.docker_host)
    if url is None:
        return None, None
    client = http or httpx.AsyncClient(timeout=5.0, trust_env=False)
    try:
        for attempt in range(attempts):
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                if attempt + 1 < attempts:
                    await asyncio.sleep(delay)
                continue
            return (
                parse_server_header(response.headers.get("Server")),
                parse_api_version(response.headers.get("Api-Version")),
            )
    finally:
        if http is None:
            await client.aclose()
    return None, None


async def collect_facts(settings: Settings | None = None) -> HostFacts:
    cfg = settings or get_settings()
    v2, controllers = read_cgroup()
    engine, api = await read_docker(cfg)
    return HostFacts(
        cgroup_v2=v2,
        cgroup_controllers=controllers,
        docker_version=engine,
        docker_api=api,
    )


async def run_host_check(settings: Settings | None = None) -> HostCheckResult:
    cfg = settings or get_settings()
    return evaluate(await collect_facts(cfg), Thresholds.from_settings(cfg))


def host_check_mode(settings: Settings | None = None) -> str:
    """``enforce``, ``warn`` or ``off`` (``auto`` means enforce in production, warn in dev and test)."""
    cfg = settings or get_settings()
    value = cfg.host_check.strip().lower()
    if value in ("enforce", "warn", "off"):
        return value
    return "warn" if cfg.is_dev else "enforce"


async def enforce_host_check(settings: Settings | None = None) -> HostCheckResult | None:
    """Run the check, log every result, set the gauge and raise ``HostCheckError`` when enforcing."""
    cfg = settings or get_settings()
    mode = host_check_mode(cfg)
    if mode == "off":
        log.info("host_check_off")
        return None
    result = await run_host_check(cfg)
    for check in result.checks:
        if check.ok:
            log.info("host_check", check=check.name, detail=check.detail)
        else:
            log.warning("host_check_failed", check=check.name, blocking=check.blocking, detail=check.detail)
    HOST_CHECK_OK.set(1 if result.ok else 0)
    if not result.ok and mode == "enforce":
        problems = "; ".join(c.detail for c in result.blocking_failures)
        log.critical("host_check_blocking", mode=mode, problems=problems)
        raise HostCheckError(
            "The host does not meet the requirements, so the worker will not start scans: %s "
            "(set SECURESCAN_HOST_CHECK=warn only to diagnose)" % problems
        )
    return result


# ================================================================================ backup status


@dataclass(frozen=True)
class BackupStatus:
    last_success: float  # Unix time
    set_name: str | None = None
    size_bytes: int | None = None
    offsite: bool | None = None


def parse_backup_status(text: str | None) -> BackupStatus | None:
    """The JSON file ``scripts/backup.sh`` writes after a backup that was also copied off the machine."""
    if not text:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    stamp = data.get("last_success")
    if isinstance(stamp, bool) or not isinstance(stamp, (int, float)) or stamp <= 0:
        return None
    size = data.get("size_bytes")
    return BackupStatus(
        last_success=float(stamp),
        set_name=str(data["set"]) if data.get("set") else None,
        size_bytes=int(size) if isinstance(size, int) and not isinstance(size, bool) else None,
        offsite=data.get("offsite") if isinstance(data.get("offsite"), bool) else None,
    )


def refresh_backup_gauge(settings: Settings | None = None) -> BackupStatus | None:
    """Set ``securescan_backup_last_success_timestamp`` from the status file (no change when absent)."""
    cfg = settings or get_settings()
    status = parse_backup_status(_read(Path(cfg.backup_status_file)))
    if status is not None:
        BACKUP_LAST_SUCCESS.set(status.last_success)
    return status
