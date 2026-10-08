"""OWASP Dependency-Check: command builder (no parsing of findings), plan M8 task 3.

* Scans run with ``--noupdate`` against the NVD data in ``<content root>/odc-data`` (written by the daily
  updater, ``jobs/updaters.py``); they are blocked until the first update succeeded (an active ``nvd_data``
  content version) and wait while an update rewrites the data.
* ``--propertyfile /config/odc.properties`` is written into the job's ``config`` directory. For scans it carries
  **no secret**: the NVD API key goes only into the properties file of the update container (``render_properties``
  is shared with the updater), never on a command line and never into a scan container.
* Maven Central (file hash lookups at ``search.maven.org``) is on by default and reached only through the egress
  proxy (``--proxyserver``/``--proxyport``; the container joins the egress client network). The
  "no third-party disclosure" mode (``options.no_disclosure``, default on for vendor applications, see
  ``scanners/profiles/dependency-check.yaml``) adds ``--disableCentral`` and keeps the container without any
  network. Sonatype OSS Index and the npm, Yarn and pnpm audits are always off (catalogue command).
* Exit code 14 maps to ``completed_partial`` (the report is imported and flagged partial).
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Any

from securescan.db.models.enums import ContentFeed
from securescan.runner.profiles import ProfileError, load_tool_settings, string_list
from securescan.runner.specs import ContainerResult, ContainerSpec
from securescan.runner.tools._support import (
    content_dir,
    egress_network,
    hold_egress,
    proxy_host_port,
    release_egress,
    slug,
)
from securescan.runner.tools.base import (
    DefaultToolBuilder,
    JobOutcome,
    ToolContext,
    ToolPreparationError,
)

CENTRAL_HOSTS = ("search.maven.org", "repo1.maven.org")
DATA_DIRECTORY = "odc-data"
DATA_TARGET = "/usr/share/dependency-check/data"
PROPERTIES_NAME = "odc.properties"
UPDATE_WAIT_SECONDS = 1800.0
EGRESS_GRACE_SECONDS = 300.0
_KEY_OK = re.compile(r"^[A-Za-z0-9._-]{8,200}$")


# --------------------------------------------------------------------------- pure helpers
def render_properties(nvd_api_key: str | None = None) -> str:
    """The content of ``odc.properties``. Only the update container gets a key (``nvd.api.key``)."""
    lines = [
        "# Written by SecureScan for one container. Do not edit.",
        f"data.directory={DATA_TARGET}",
    ]
    if nvd_api_key:
        if not _KEY_OK.match(nvd_api_key):
            raise ValueError("the NVD API key has an unexpected format")
        lines.append(f"nvd.api.key={nvd_api_key}")
    return "\n".join(lines) + "\n"


def write_properties(directory: Path, nvd_api_key: str | None = None) -> Path:
    """Write ``odc.properties``: 0600 when it holds a key, 0644 otherwise (same uid as the container)."""
    path = directory / PROPERTIES_NAME
    if path.exists() or path.is_symlink():
        path.unlink()
    mode = 0o600 if nvd_api_key else 0o644
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(render_properties(nvd_api_key))
    return path


def tool_settings(ctx: ToolContext) -> dict[str, Any]:
    try:
        return load_tool_settings("dependency-check", ctx.scanners_dir)
    except ProfileError as exc:
        raise ToolPreparationError(str(exc), code="odc.settings_invalid") from exc


def no_disclosure(ctx: ToolContext) -> bool:
    """The job's mode: an explicit ``options.no_disclosure`` wins, else the application type decides."""
    explicit = ctx.options.get("no_disclosure")
    if isinstance(explicit, bool):
        return explicit
    raw = tool_settings(ctx).get("no_disclosure_for_application_types")
    try:
        types = ["vendor"] if raw is None else string_list(raw, "no_disclosure_for_application_types")
    except ProfileError as exc:
        raise ToolPreparationError(str(exc), code="odc.settings_invalid") from exc
    kind = getattr(getattr(ctx.application, "type", None), "value", None)
    return bool(kind) and kind in types


def central_enabled(ctx: ToolContext) -> bool:
    analyzers = tool_settings(ctx).get("analyzers")
    configured = True
    if isinstance(analyzers, dict) and analyzers.get("central") is False:
        configured = False
    return configured and not no_disclosure(ctx)


def project_name(ctx: ToolContext) -> str:
    application = getattr(ctx.application, "name", None) or "application"
    label = getattr(ctx.version, "label", None) or "version"
    return slug(f"{application}-{label}", 120)


class DependencyCheckBuilder(DefaultToolBuilder):
    tool = "dependency-check"

    def egress_key(self, ctx: ToolContext) -> str:
        return f"odc:{ctx.job.id}"

    # ------------------------------------------------------------------ prepare
    async def prepare(self, ctx: ToolContext) -> None:
        from securescan.jobs.scanner_health import active_versions, wait_feed_idle

        if ctx.session is None:
            raise ToolPreparationError("internal: no database session in prepare", code="tool.no_session")
        row = (await active_versions(ctx.session)).get(ContentFeed.NVD_DATA.value)
        if row is None:
            raise ToolPreparationError(
                "Dependency-Check is waiting for its first vulnerability data download. The download "
                "takes 20 minutes or more and needs the NVD API key (Settings, Content); an Admin can "
                "start it there. Scan again when it has finished.",
                code="odc.data_missing",
            )
        if not await wait_feed_idle(ContentFeed.NVD_DATA, UPDATE_WAIT_SECONDS):
            raise ToolPreparationError(
                "The Dependency-Check data is being updated and the update did not finish in time. "
                "Scan again later.",
                code="odc.update_running",
            )
        ctx.content_versions["nvd_data"] = row.version
        content_dir(ctx.settings, DATA_DIRECTORY)
        write_properties(ctx.workspace.config)  # no key: scans never receive the NVD API key
        ctx.extra_values["project_key"] = project_name(ctx)
        if central_enabled(ctx):
            seconds = self.timeout_seconds(ctx) + EGRESS_GRACE_SECONDS
            proxy_url = await hold_egress(self.egress_key(ctx), CENTRAL_HOSTS, seconds)
            ctx.extra_values["egress_proxy_url"] = proxy_url
        else:
            ctx.coverage_notes.append(
                "Dependency-Check ran without the Maven Central lookup (no third-party disclosure), so "
                "JAR files without manifests are identified less reliably."
            )
        for pattern in self.exclude_patterns(ctx):
            ctx.applied_exclusions.append({"kind": "pattern", "value": pattern, "source": "dependency-check settings"})
        ctx.tool_version = ctx.image.tag if ctx.image is not None else None

    def exclude_patterns(self, ctx: ToolContext) -> list[str]:
        try:
            patterns = string_list(tool_settings(ctx).get("exclude"), "dependency-check settings: exclude")
        except ProfileError as exc:
            raise ToolPreparationError(str(exc), code="odc.settings_invalid") from exc
        return list(dict.fromkeys(patterns))

    # ------------------------------------------------------------------ command and container
    def optional_args(self, ctx: ToolContext) -> list[tuple[str, str | None]]:
        requested: list[tuple[str, str | None]] = []
        if central_enabled(ctx):
            endpoint = proxy_host_port(ctx.extra_values.get("egress_proxy_url", ""))
            if endpoint is not None:
                requested += [("--proxyserver", endpoint[0]), ("--proxyport", str(endpoint[1]))]
        else:
            requested.append(("--disableCentral", None))
        requested += [("--exclude", pattern) for pattern in self.exclude_patterns(ctx)]
        return requested

    def content_path(self, ctx: ToolContext) -> Path | None:
        return content_dir(ctx.settings, DATA_DIRECTORY)

    def container_spec(self, ctx: ToolContext) -> ContainerSpec:
        spec = super().container_spec(ctx)
        read_only = ctx.settings.odc_data_read_only
        spec.binds = [(path, target, read_only if target == DATA_TARGET else ro) for path, target, ro in spec.binds]
        if central_enabled(ctx):
            spec.network = egress_network(ctx.settings)
        return spec

    # ------------------------------------------------------------------ the end of the run
    def classify_exit(self, ctx: ToolContext, exit_code: int | None) -> JobOutcome:
        self._release_later(ctx)
        return super().classify_exit(ctx, exit_code)

    def _release_later(self, ctx: ToolContext) -> None:
        try:
            asyncio.get_running_loop().create_task(release_egress(self.egress_key(ctx)))
        except RuntimeError:  # no running loop (a unit test): the time limit of the hold applies
            return

    async def post_run(self, ctx: ToolContext, result: ContainerResult) -> None:
        await release_egress(self.egress_key(ctx))
        if result.exit_code == 14:
            ctx.coverage_notes.append(
                "Dependency-Check finished with exit code 14: part of its analysis could not run, so the "
                "result is partial."
            )


BUILDER = DependencyCheckBuilder()
