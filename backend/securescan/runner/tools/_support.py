"""Helpers shared by the M8 tool builders, the image source handler, the updaters and SonarQube.

This module is not a tool builder (its name starts with an underscore, so the registry skips it).

* ``spec_from_entry``: a ``ContainerSpec`` from a catalogue entry for the containers that are not scan jobs
  (updaters, image intake, the SonarQube server, regression runs). Everything about the container comes from
  the entry; the caller supplies only bind sources, networks and values the entry cannot know.
* ``skip_job``: end a job as "skipped, with a coverage note" from inside ``prepare`` (the executor decides
  applicability before the source exists, so the tools that depend on the source's content must skip later).
* small path, network and naming helpers.
"""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit

from securescan.config import Settings
from securescan.runner.catalogue import CatalogueEntry, Limits, ResolvedImage
from securescan.runner.specs import ContainerSpec
from securescan.runner.tools.base import LABEL_MANAGED, LABEL_TOOL, normalise_user

_NON_SLUG = re.compile(r"[^a-z0-9]+")
_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
DEFAULT_PROXY_PORT = 3128


def slug(text: str, max_length: int = 60) -> str:
    """Lower-case letters, digits and single dashes; never empty."""
    cleaned = _NON_SLUG.sub("-", (text or "").lower()).strip("-")
    return cleaned[:max_length].strip("-") or "x"


def skip_job(reason: str) -> NoReturn:
    """End the running job as completed-but-skipped with ``reason`` as its coverage note.

    The executor (``runner/executor.py``) raises its private ``_Finish`` for this inside
    ``_build_context``; ``prepare`` runs inside the same ``try`` block, so raising it from a builder's
    ``prepare`` has the same effect. Imported lazily because the executor imports the tool registry.
    """
    from securescan.db.models.enums import JobState
    from securescan.runner.executor import _Finish

    raise _Finish(JobState.COMPLETED, reason, skipped=True)


def content_dir(settings: Settings, *parts: str, mode: int = 0o777) -> Path:
    """A directory below the content root, created when missing and opened to the scanner uid.

    The worker (uid 1000) owns it; ``mode`` is applied explicitly because ``mkdir`` honours the umask.
    ``parts`` are plain names (no separators, no ``..``).
    """
    path = Path(settings.content_root)
    for part in parts:
        if not _PART.match(part) or ".." in part:
            raise ValueError(f"unsafe directory name {part!r}")
        path = path / part
    path.mkdir(parents=True, exist_ok=True)
    if parts:  # the content root itself keeps the mode the image gave it
        os.chmod(path, mode)
    return path


def egress_network(settings: Settings) -> str:
    """The Docker network of containers that reach the internet through the shared egress proxy."""
    return settings.egress_client_network or settings.network_backend


def proxy_host_port(proxy_url: str) -> tuple[str, int] | None:
    """``(host, port)`` of a proxy URL such as ``http://securescan-egress:3128``; None for an empty URL."""
    if not proxy_url:
        return None
    parts = urlsplit(proxy_url)
    if not parts.hostname:
        return None
    return parts.hostname, parts.port or DEFAULT_PROXY_PORT


def proxy_env(proxy_url: str) -> dict[str, str]:
    """``HTTP(S)_PROXY`` variables (both spellings) for tools that honour them; empty without a proxy."""
    if not proxy_url:
        return {}
    return {
        "HTTPS_PROXY": proxy_url,
        "HTTP_PROXY": proxy_url,
        "https_proxy": proxy_url,
        "http_proxy": proxy_url,
        "NO_PROXY": "localhost,127.0.0.1",
        "no_proxy": "localhost,127.0.0.1",
    }


_HOLDS: dict[str, asyncio.Task[None]] = {}


async def hold_egress(key: str, hosts: Iterable[str], seconds: float) -> str:
    """Keep the shared egress proxy alive for a container that runs after ``prepare`` returns.

    A lease (``runner/egress.py``) only protects a ``with`` block, but a scan container runs later and
    longer than that. This starts a task that holds a lease for at most ``seconds`` and returns the proxy
    URL ("" when egress is disabled). ``release_egress(key)`` ends it early; the time limit makes sure a
    job that never reaches its end (worker crash aside) cannot keep the proxy running forever.
    """
    from securescan.runner.egress import egress_lease

    await release_egress(key)
    ready: asyncio.Future[str] = asyncio.get_running_loop().create_future()
    wanted = list(hosts)

    async def hold() -> None:
        try:
            async with egress_lease(wanted) as url:
                if not ready.done():
                    ready.set_result(url)
                await asyncio.sleep(seconds)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - reported to the waiting caller
            if not ready.done():
                ready.set_exception(exc)

    task = asyncio.create_task(hold())
    _HOLDS[key] = task
    try:
        return await ready
    except BaseException:
        await release_egress(key)
        raise


async def release_egress(key: str) -> None:
    task = _HOLDS.pop(key, None)
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):  # noqa: BLE001 - nothing to report
        pass


def write_private_file(directory: Path, name: str, content: str) -> Path:
    """Write ``content`` to ``directory/name`` with mode 0600 (created exclusively, never world-readable).

    The file belongs to the worker's uid, which is also the uid of the scanner container that reads it.
    An existing file of that name is replaced.
    """
    if not _PART.match(name):
        raise ValueError(f"unsafe file name {name!r}")
    path = directory / name
    if path.exists() or path.is_symlink():
        path.unlink()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def spec_from_entry(
    entry: CatalogueEntry,
    image: ResolvedImage | str,
    *,
    name: str,
    binds: Sequence[tuple[str, str, bool]] = (),
    volumes: Sequence[tuple[str, str, bool]] = (),
    env: Mapping[str, str] | None = None,
    network: str = "none",
    extra_networks: Sequence[str] = (),
    labels: Mapping[str, str] | None = None,
    command: Sequence[str] | None = None,
    tmpfs: Mapping[str, str] | None = None,
    limits: Limits | None = None,
    read_only_rootfs: bool = True,
    stop_timeout: int = 10,
    shm_size: str | None = None,
    user: str | None = None,
) -> ContainerSpec:
    """A ``ContainerSpec`` for a container that is not a scan job, from its catalogue entry.

    ``binds`` are ``(path, container path, read_only)`` with paths under the data or content root (or an
    absolute daemon path). ``tmpfs`` entries replace the entry's options for the same path.
    """
    reference = image.reference if isinstance(image, ResolvedImage) else str(image)
    limit = limits or entry.limits
    merged_env = dict(entry.env)
    merged_env.update(env or {})
    merged_tmpfs = {t.path: t.options() for t in entry.tmpfs}
    merged_tmpfs.update(tmpfs or {})
    merged_labels = {LABEL_MANAGED: "true", LABEL_TOOL: entry.tool}
    merged_labels.update(labels or {})
    argv = list(command) if command is not None else entry.render_command()
    return ContainerSpec(
        image=reference,
        command=argv,
        name=name,
        user=normalise_user(user or entry.user),
        env=merged_env,
        binds=list(binds),
        tmpfs=merged_tmpfs,
        network=network,
        extra_networks=list(extra_networks),
        labels=merged_labels,
        mem_limit=limit.memory,
        nano_cpus=limit.nano_cpus,
        pids_limit=limit.pids,
        read_only_rootfs=read_only_rootfs,
        shm_size=shm_size,
        stop_timeout=stop_timeout,
        entrypoint=list(entry.entrypoint) if entry.entrypoint is not None else None,
        volumes=list(volumes),
    )
