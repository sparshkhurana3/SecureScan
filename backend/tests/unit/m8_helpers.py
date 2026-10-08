"""Shared builders for the M8 tests: class files, image archives, a fake launcher, a context with an application."""

from __future__ import annotations

import io
import json
import struct
import tarfile
import types
import uuid
from collections.abc import Awaitable, Callable, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from securescan.db.models.enums import AppType, TargetKind
from securescan.runner.specs import ContainerResult, ContainerSpec
from securescan.runner.tools.base import ToolContext
from tests.unit.runner_helpers import DIGEST, make_ctx

PROXY = "http://securescan-egress:3128"


# --------------------------------------------------------------------------- Java class files
def make_class_file(name: str) -> bytes:
    """A minimal ``.class`` header: a constant pool that names ``name`` as this class (and ``Object`` as super)."""

    def utf8(text: str) -> bytes:
        raw = text.encode()
        return b"\x01" + struct.pack(">H", len(raw)) + raw

    pool = utf8(name) + b"\x07" + struct.pack(">H", 1) + utf8("java/lang/Object") + b"\x07" + struct.pack(">H", 3)
    pool += b"\x05" + struct.pack(">q", 5)  # a long takes two constant pool slots
    return b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 61, 7) + pool + struct.pack(">HHH", 0x21, 2, 4)


# --------------------------------------------------------------------------- image archives
Entry = tuple[Any, ...]


def add_entry(archive: tarfile.TarFile, name: str, data: bytes = b"", kind: bytes = tarfile.REGTYPE, mode: int = 0o644, link: str = "") -> None:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = mode
    info.linkname = link
    if kind == tarfile.REGTYPE:
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    else:
        archive.addfile(info)


def layer_tar(entries: list[Entry]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for entry in entries:
            add_entry(archive, *entry)
    return buffer.getvalue()


def docker_archive(path: Path, layers: list[bytes], image_id: str = "abc123", tags: list[str] | None = None) -> Path:
    """A ``docker save`` style archive: ``manifest.json`` and ``layerN/layer.tar``."""
    with tarfile.open(path, "w") as outer:
        names = []
        for index, data in enumerate(layers):
            name = f"layer{index}/layer.tar"
            names.append(name)
            info = tarfile.TarInfo(name)
            info.size = len(data)
            outer.addfile(info, io.BytesIO(data))
        manifest = json.dumps([{"Config": f"{image_id}.json", "RepoTags": tags or ["demo:1"], "Layers": names}]).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        outer.addfile(info, io.BytesIO(manifest))
    return path


def can_symlink(directory: Path) -> bool:
    probe = directory / "probe-link"
    try:
        probe.symlink_to("target")
    except (OSError, NotImplementedError):
        return False
    probe.unlink()
    return True


# --------------------------------------------------------------------------- fakes
@asynccontextmanager
async def fake_lease(url: str = PROXY) -> Any:
    yield url


def lease_factory(url: str = PROXY, seen: list[Any] | None = None) -> Callable[..., Any]:
    """A stand-in for ``egress_lease`` that records the hosts it was asked for."""

    def lease(hosts: Any) -> Any:
        if seen is not None:
            seen.append(sorted(hosts))
        return fake_lease(url)

    return lease


class FakeLauncher:
    """Runs a callback instead of Docker. ``on_run(spec)`` may write files and returns the exit code."""

    def __init__(self, on_run: Callable[[ContainerSpec], int | Awaitable[int]] | None = None, logs: str = "") -> None:
        self.on_run = on_run
        self.logs = logs
        self.specs: list[ContainerSpec] = []
        self.timeouts: list[float | None] = []

    async def run(self, spec: ContainerSpec, timeout_s: float | None, on_log: Any = None, **_kw: Any) -> ContainerResult:
        self.specs.append(spec)
        self.timeouts.append(timeout_s)
        code: Any = 0
        if self.on_run is not None:
            code = self.on_run(spec)
            if hasattr(code, "__await__"):
                code = await code
        return ContainerResult(container_id="c" * 12, exit_code=int(code), timed_out=False, logs=self.logs)


def host_path_of(spec: ContainerSpec, container_path: str) -> Path:
    """The host directory bound at ``container_path`` in ``spec``."""
    for source, target, _ro in spec.binds:
        if target == container_path:
            return Path(source)
    raise AssertionError(f"nothing is bound at {container_path}: {spec.binds}")


# --------------------------------------------------------------------------- contexts
def ctx_for(
    tool: str,
    *,
    app_type: AppType = AppType.INTERNAL,
    kind: TargetKind = TargetKind.ZIP,
    options: dict[str, Any] | None = None,
    **kwargs: Any,
) -> ToolContext:
    """``make_ctx`` plus an application and a version, as the builders that name the project need them."""
    ctx = make_ctx(tool, kind=kind, options=options, **kwargs)
    ctx.application = types.SimpleNamespace(name="Shop", type=app_type)  # type: ignore[assignment]
    ctx.version = types.SimpleNamespace(id=uuid.uuid4(), label="main", sonar_project_key=None)  # type: ignore[assignment]
    return ctx


def put_file(root: Path, relative: str, data: bytes = b"x") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def set_pin(monkeypatch: pytest.MonkeyPatch, lock: str, image: str) -> str:
    """``SECURESCAN_IMAGE_<lock>=<image>@sha256:...`` so that catalogue lookups resolve without a lock file."""
    reference = f"{image}@{DIGEST}"
    monkeypatch.setenv(f"SECURESCAN_IMAGE_{lock}", reference)
    return reference


def walk_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path
