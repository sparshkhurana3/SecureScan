"""Container specification and result: the data the launcher consumes and returns.

A ``ContainerSpec`` is built only from the scanner catalogue (see ``runner/catalogue.py`` and
``runner/tools/base.py``), never from user input. The launcher translates it into the Docker Engine
API body (``runner/launcher.py::build_create_body``) and always adds the hardening that is not
negotiable: all capabilities dropped, ``no-new-privileges``, never privileged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_SIZE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?)b?\s*$", re.IGNORECASE)
_UNITS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_size(text: str) -> int:
    """Bytes of a size such as ``512m``, ``4g`` or ``1048576`` (binary multiples). ValueError otherwise."""
    match = _SIZE.match(str(text))
    if match is None:
        raise ValueError(f"not a size: {text!r}")
    return int(float(match.group(1)) * _UNITS[match.group(2).lower()])



@dataclass
class ContainerSpec:
    image: str
    command: list[str]
    name: str | None = None
    user: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    # (path under DATA_ROOT as seen by the worker OR an absolute daemon path, container path, read_only)
    binds: list[tuple[str, str, bool]] = field(default_factory=list)
    # container path -> mount options, for example "size=512m"
    tmpfs: dict[str, str] = field(default_factory=dict)
    network: str = "none"
    extra_networks: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    mem_limit: str | None = None
    nano_cpus: int | None = None
    pids_limit: int | None = None
    read_only_rootfs: bool = True
    shm_size: str | None = None
    stop_timeout: int | None = None
    # None: keep the image entrypoint. [""] clears it (the command is then the whole argv).
    entrypoint: list[str] | None = None
    ulimits: dict[str, tuple[int, int]] = field(default_factory=dict)
    # (named volume, container path, read_only)
    volumes: list[tuple[str, str, bool]] = field(default_factory=list)


@dataclass
class ContainerResult:
    container_id: str
    exit_code: int | None
    timed_out: bool
    logs: str  # last 2 MB of combined output
    cancelled: bool = False


LOG_TAIL_BYTES = 2 * 1024 * 1024
"""How much of a container's output ``ContainerResult.logs`` keeps."""
