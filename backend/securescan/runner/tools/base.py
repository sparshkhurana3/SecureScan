"""The tool builder framework.

A *tool builder* knows how to prepare a workspace for one tool, which optional switches to append and
how to read the tool's exit code. It never parses findings. Everything about the container itself comes
from the catalogue entry (``runner/catalogue.py``); ``DefaultToolBuilder`` turns an entry plus a
``ToolContext`` into a ``ContainerSpec``, so most tools only override ``prepare`` and the optional-switch
hooks. A builder module exposes ``BUILDER`` and is registered automatically (``runner/tools/__init__.py``).

Call order in ``runner/executor.py``: ``applicable`` -> ``prepare`` -> ``container_spec`` (which calls
``build_command``) -> container run -> ``classify_exit`` -> output validation -> ``post_run``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import Settings
from securescan.db.models.applications import Application
from securescan.db.models.jobs import ScanJob
from securescan.db.models.scans import Scan
from securescan.db.models.targets import Target
from securescan.db.models.versions import ApplicationVersion
from securescan.runner.catalogue import CatalogueEntry, Limits, ResolvedImage, resolve_image
from securescan.runner.sources.base import SourceInfo
from securescan.runner.specs import ContainerResult, ContainerSpec
from securescan.runner.workspace import Workspace

JobOutcome = Literal["completed", "completed_partial", "failed"]

LABEL_JOB = "securescan.job_id"
LABEL_SCAN = "securescan.scan_id"
LABEL_TOOL = "securescan.tool"
LABEL_MANAGED = "securescan.managed"
LIMIT_KEYS = ("cpus", "memory", "pids")


class ToolPreparationError(Exception):
    """Preparing a job failed for a reason the user can act on (message is plain language)."""

    def __init__(self, message: str, code: str = "tool.prepare_failed") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class ToolContext:
    job: ScanJob
    scan: Scan
    version: ApplicationVersion
    target: Target | None
    workspace: Workspace
    entry: CatalogueEntry
    settings: Settings
    session: AsyncSession | None = None  # valid only inside the call it is passed to
    options: dict[str, Any] = field(default_factory=dict)  # per-job options (profile and request)
    application: Application | None = None
    source: SourceInfo | None = None
    image: ResolvedImage | None = None
    scanners_dir: Path | None = None
    # filled by the builder, persisted by the executor
    applied_exclusions: list[dict[str, Any]] = field(default_factory=list)
    content_versions: dict[str, str] = field(default_factory=dict)
    coverage_notes: list[str] = field(default_factory=list)
    tool_version: str | None = None
    extra_values: dict[str, str] = field(default_factory=dict)  # {target_url}, {project_key}


class ToolBuilder(Protocol):
    tool: str

    def applicable(self, ctx: ToolContext) -> tuple[bool, str]: ...

    async def prepare(self, ctx: ToolContext) -> None: ...

    def build_command(self, ctx: ToolContext) -> list[str]: ...

    def container_spec(self, ctx: ToolContext) -> ContainerSpec: ...

    async def post_run(self, ctx: ToolContext, result: ContainerResult) -> None: ...

    def classify_exit(self, ctx: ToolContext, exit_code: int | None) -> JobOutcome: ...


def normalise_user(user: str) -> str:
    """``root`` becomes ``0``; a uid or ``uid:gid`` stays as it is."""
    return ":".join("0" if part == "root" else part for part in user.split(":"))


def docker_network(settings: Settings, logical: str) -> str:
    if logical == "none":
        return "none"
    if logical == "sonarqube":
        return settings.network_sonarqube
    if logical == "dast":
        return settings.network_dast
    raise ToolPreparationError(f"unknown network {logical!r} in the catalogue")


def container_name(job_id: Any) -> str:
    return f"securescan-job-{job_id}"


def insert_before_target(command: list[str], extras: list[str], target: str | None) -> list[str]:
    """Insert optional switches before the final positional target (the ``src`` path), else at the end."""
    if not extras:
        return list(command)
    result = list(command)
    if target is not None and result and result[-1] == target:
        result[-1:-1] = extras
    else:
        result.extend(extras)
    return result


def remove_ignore_files(root: Path, names: tuple[str, ...], depth: int = 1) -> list[str]:
    """Delete files called one of ``names`` at the top of ``root`` and ``depth`` levels below it.

    Used so that a vendor's own ignore file cannot hide findings. Returns the removed paths relative to
    ``root``. A symbolic link is removed, never followed.
    """
    removed: list[str] = []
    directories = [root]
    if depth >= 1:
        try:
            directories.extend(
                sorted(
                    p
                    for p in root.iterdir()
                    if p.is_dir() and not p.is_symlink() and p.name != ".git"
                )
            )
        except OSError:
            pass
    for directory in directories:
        for name in names:
            path = directory / name
            if path.is_symlink() or path.is_file():
                try:
                    path.unlink()
                except OSError:
                    continue
                removed.append(str(path.relative_to(root)))
    return removed


class DefaultToolBuilder:
    """Builds the container specification from the catalogue entry; subclasses add tool knowledge."""

    tool: str = ""

    # ------------------------------------------------------------------ hooks for subclasses
    def applicable(self, ctx: ToolContext) -> tuple[bool, str]:
        if ctx.target is not None and ctx.target.kind.value not in ctx.entry.target_kinds:
            return False, f"{self.tool} does not scan {ctx.target.kind.value} targets."
        return True, ""

    async def prepare(self, ctx: ToolContext) -> None:
        """Put tool-specific files in the workspace; record exclusions and content versions."""
        return None

    def optional_args(self, ctx: ToolContext) -> list[tuple[str, str | None]]:
        """Switches to append, as ``(flag, value)``; each must be on the entry's allowlist."""
        return []

    def content_path(self, ctx: ToolContext) -> Path | None:
        """Host path of the ``content`` mount (rules, templates, databases) or None."""
        return None

    def extra_env(self, ctx: ToolContext) -> dict[str, str]:
        return {}

    async def post_run(self, ctx: ToolContext, result: ContainerResult) -> None:
        return None

    # ------------------------------------------------------------------ the generic parts
    def placeholder_values(self, ctx: ToolContext) -> dict[str, str]:
        return dict(ctx.extra_values)

    def build_command(self, ctx: ToolContext) -> list[str]:
        command = ctx.entry.render_command(self.placeholder_values(ctx))
        extras = ctx.entry.render_optional_args(self.optional_args(ctx))
        src = ctx.entry.mount_target("src") if ctx.entry.mount("src") is not None else None
        return insert_before_target(command, extras, src)

    def limits(self, ctx: ToolContext) -> Limits:
        """Catalogue limits, with the profile's per-job overrides (``options["limits"]``) applied."""
        merged: dict[str, Any] = {
            "cpus": ctx.entry.limits.cpus,
            "memory": ctx.entry.limits.memory,
            "pids": ctx.entry.limits.pids,
        }
        override = ctx.options.get("limits")
        if isinstance(override, dict):
            for key in LIMIT_KEYS:
                if override.get(key) is not None:
                    merged[key] = override[key]
        return Limits(cpus=float(merged["cpus"]), memory=str(merged["memory"]), pids=int(merged["pids"]))

    def timeout_seconds(self, ctx: ToolContext) -> float:
        override = ctx.options.get("timeout_minutes")
        if isinstance(override, (int, float)) and not isinstance(override, bool) and override > 0:
            return float(override) * 60.0
        return ctx.entry.timeout_seconds

    def container_spec(self, ctx: ToolContext) -> ContainerSpec:
        entry = ctx.entry
        image = ctx.image or resolve_image(entry, settings=ctx.settings)
        host_dirs: dict[str, Path | None] = {
            "src": ctx.workspace.src,
            "out": ctx.workspace.out,
            "config": ctx.workspace.config,
            "content": self.content_path(ctx),
        }
        binds: list[tuple[str, str, bool]] = []
        for mount in entry.mounts:
            path = host_dirs.get(mount.name)
            if path is None:
                raise ToolPreparationError(
                    f"{self.tool}: nothing is available for the {mount.name} mount "
                    "(for example the rules or templates are not installed yet)",
                    code="tool.content_missing",
                )
            binds.append((str(path), mount.target, mount.read_only))
        limits = self.limits(ctx)
        env = dict(entry.env)
        env.update(self.extra_env(ctx))
        labels = {
            LABEL_MANAGED: "true",
            LABEL_JOB: str(ctx.job.id),
            LABEL_SCAN: str(ctx.scan.id),
            LABEL_TOOL: self.tool,
        }
        return ContainerSpec(
            image=image.reference,
            command=self.build_command(ctx),
            name=container_name(ctx.job.id),
            user=normalise_user(entry.user),
            env=env,
            binds=binds,
            tmpfs={t.path: t.options() for t in entry.tmpfs},
            network=docker_network(ctx.settings, entry.network),
            labels=labels,
            mem_limit=limits.memory,
            nano_cpus=limits.nano_cpus,
            pids_limit=limits.pids,
            read_only_rootfs=True,
            stop_timeout=10,
            entrypoint=list(entry.entrypoint) if entry.entrypoint is not None else None,
        )

    def classify_exit(self, ctx: ToolContext, exit_code: int | None) -> JobOutcome:
        return ctx.entry.outcome_for(exit_code)
