"""Nuclei: command builder for UAT web targets (no parsing, no findings).

The fixed flags are in ``scanners/catalogue.d/nuclei.yaml`` (``-duc -ni -dut -nc -ud <templates> -etags ...
-severity ... -r <resolvers> -rd Authorization,Cookie -json-export``). This builder adds:

* the templates: the *resolved* dated directory behind ``<content>/nuclei-templates`` is mounted read-only at
  ``/content/nuclei-templates``, so every job records which template version it used;
* the proxy and the rate: ``-proxy http://<job proxy>:3128``, ``-rl`` and ``-c`` from the target's rate cap
  (default 50 requests per second, plan M9 task 4) through the catalogue's ``optional_args``;
* the resolver list in ``/config/resolvers.txt``;
* UAT only: a production target is refused here again, whatever created the job.

Nuclei exits 0 when it ran, with or without results. A clean run may export no file at all; the builder
then writes an empty JSON array so that the job still has a report to import (DefectDojo reads it as
"no findings") instead of failing a clean scan.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import yaml

from securescan.domain.dast_rules import effective_rate
from securescan.runner.catalogue import find_scanners_dir
from securescan.runner.dast_egress import (
    PROXY_PORT,
    finish_job_proxy,
    prepare_job_network,
    release_proxy,
)
from securescan.runner.specs import ContainerResult
from securescan.runner.tools.base import (
    DefaultToolBuilder,
    JobOutcome,
    ToolContext,
    ToolPreparationError,
)
from securescan.runner.tools.zap import STATE_KEY, DastState, state_of
from securescan.runner.workspace import make_world_readable

TOOL = "nuclei"
REPORT = "nuclei.json"
RESOLVERS = "resolvers.txt"
SETTINGS_FILE = "nuclei-uat.yaml"
DEFAULT_RPS = 50
DEFAULT_CONCURRENCY = 10
TEMPLATES_LINK = "nuclei-templates"
UAT_MODES = frozenset({"full", "api", "nuclei"})


def resolve_templates_dir(content_root: Path, link: str = TEMPLATES_LINK) -> Path:
    """The real directory behind the templates symlink; it must lie inside the content root."""
    candidate = content_root / link
    if candidate.exists():
        root = content_root.resolve()
        real = candidate.resolve()
        if real != root and root not in real.parents:
            raise ToolPreparationError(
                "The Nuclei templates link points outside the content volume.", code="nuclei.templates_invalid"
            )
        if real.is_dir() and any(real.iterdir()):
            return real
    raise ToolPreparationError(
        "The Nuclei templates are not installed yet. Run the template update (Settings, Content) or wait "
        "for the weekly update, then start the scan again.",
        code="nuclei.templates_missing",
    )


def load_settings(scanners_dir: Path | None) -> dict[str, Any]:
    """``scanners/profiles/nuclei-uat.yaml`` (defaults for the rate and concurrency); {} when absent."""
    if scanners_dir is None:
        return {}
    path = scanners_dir / "profiles" / SETTINGS_FILE
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def _positive(value: Any, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return default
    return value


def rate_flags(rps: int, concurrency: int) -> list[tuple[str, str | None]]:
    """``-rl`` and ``-c``: the concurrency never exceeds the rate (a rate of 2 with 10 workers would burst)."""
    return [("-rl", str(max(1, rps))), ("-c", str(max(1, min(concurrency, rps))))]


class NucleiBuilder(DefaultToolBuilder):
    tool = TOOL

    # ------------------------------------------------------------------ preparation
    async def prepare(self, ctx: ToolContext) -> None:
        target = ctx.target
        if target is None:
            raise ToolPreparationError("This scan has no target.", code="scan.no_target")
        environment = getattr(target.environment, "value", target.environment)
        if environment != "uat" or ctx.scan.mode not in UAT_MODES:
            raise ToolPreparationError(
                "Nuclei runs on UAT targets only. Production targets accept the ZAP baseline scan only.",
                code="dast.production_baseline_only",
            )
        scanners = ctx.scanners_dir or find_scanners_dir(ctx.settings)
        defaults = load_settings(scanners)
        link = str(defaults.get("templates_link") or TEMPLATES_LINK)
        if "/" in link or "\\" in link or ".." in link:
            link = TEMPLATES_LINK
        templates = resolve_templates_dir(Path(ctx.settings.content_root), link)
        self._install_resolvers(ctx, scanners)
        rps = effective_rate(target, _positive(defaults.get("default_rps"), DEFAULT_RPS), ctx.settings)
        concurrency = _positive(defaults.get("default_concurrency"), DEFAULT_CONCURRENCY)
        proxy, _hosts = await prepare_job_network(
            ctx, tool=TOOL, timeout_s=float(self.timeout_seconds(ctx))
        )
        ctx.options[STATE_KEY] = DastState(proxy=proxy)
        ctx.options["_nuclei_rate"] = (rps, concurrency)
        ctx.extra_values["target_url"] = str(target.locator).strip()
        ctx.extra_values["templates_dir"] = str(templates)
        ctx.content_versions["nuclei_templates"] = templates.name
        ctx.tool_version = ctx.image.tag if ctx.image is not None else None
        ctx.coverage_notes.append(
            "Nuclei ran with the template set %s at about %d requests per second, without the login profile "
            "and without out-of-band callbacks." % (templates.name, rps)
        )
        ctx.applied_exclusions.append(
            {
                "kind": "template_tags",
                "value": "dos, fuzz, bruteforce, local, txt-service, intrusive",
                "source": "scanner catalogue",
            }
        )

    @staticmethod
    def _install_resolvers(ctx: ToolContext, scanners: Path | None) -> None:
        source = (scanners / "dast" / "templates" / RESOLVERS) if scanners is not None else None
        if source is None or not source.is_file():
            raise ToolPreparationError(
                "The resolver list scanners/dast/templates/resolvers.txt is missing.", code="nuclei.resolvers_missing"
            )
        shutil.copyfile(source, ctx.workspace.config / RESOLVERS)
        make_world_readable(ctx.workspace.config)

    # ------------------------------------------------------------------ command
    def optional_args(self, ctx: ToolContext) -> list[tuple[str, str | None]]:
        state = state_of(ctx)
        if state is None:
            raise ToolPreparationError("The scan proxy is not ready.", code="dast.proxy_failed")
        rate = ctx.options.get("_nuclei_rate")
        rps, concurrency = rate if isinstance(rate, tuple) else (DEFAULT_RPS, DEFAULT_CONCURRENCY)
        return [("-proxy", "http://%s:%d" % (state.proxy.name, PROXY_PORT)), *rate_flags(rps, concurrency)]

    def content_path(self, ctx: ToolContext) -> Path | None:
        value = ctx.extra_values.get("templates_dir")
        return Path(value) if value else None

    # ------------------------------------------------------------------ after the run
    def classify_exit(self, ctx: ToolContext, exit_code: int | None) -> JobOutcome:
        outcome = super().classify_exit(ctx, exit_code)
        if outcome == "completed":
            ensure_report(ctx.workspace.out / REPORT)
        return outcome

    async def post_run(self, ctx: ToolContext, result: ContainerResult) -> None:
        state = state_of(ctx)
        if state is not None:
            await finish_job_proxy(ctx, state.proxy)

    async def cleanup(self, ctx: ToolContext) -> None:
        state = state_of(ctx)
        if state is not None:
            await release_proxy(ctx.job.id, state.proxy)


def ensure_report(path: Path) -> bool:
    """Write ``[]`` when a successful run left no (or an empty) report. True when it wrote the file."""
    try:
        if path.is_symlink():
            return False  # never write through a link the container may have planted
        if path.exists() and path.stat().st_size > 0:
            return False
        path.write_text("[]\n", encoding="utf-8")
        path.chmod(0o644)
    except OSError:
        return False
    return True


BUILDER = NucleiBuilder()
