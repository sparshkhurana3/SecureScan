"""Syft then Grype as one job (plan M8 task 2): command builder, no parsing of findings.

Shape of the job ``syft-grype``:

1. ``prepare`` checks that a Grype database is installed (an active ``grype_db`` content version), then runs the
   Syft container itself (catalogue entry ``syft``, no network) to write ``sbom.syft.json`` and
   ``sbom.cdx.json`` into the job's ``out`` directory. For an image target Syft reads the image archive that the
   image source left in the ``config`` directory (``docker-archive:/config/image.tar``); otherwise it reads the
   source tree (``dir:/src``).
2. The executor then runs the Grype container (entry ``syft-grype``, no network) against the Syft SBOM with
   the database from ``<content root>/grype-db`` and ``GRYPE_DB_AUTO_UPDATE=false``,
   ``GRYPE_DB_VALIDATE_AGE=true``: a database older than ``SECURESCAN_GRYPE_DB_MAX_AGE`` (120 h) makes Grype fail
   instead of reporting against old data. ``classify_exit`` turns that failure into a plain-language reason.
3. ``post_run`` stores the two SBOMs as artifacts of kind ``sbom`` (the report counts components from them and
   links them). Only ``grype.json`` goes to DefectDojo (scan type ``Anchore Grype``).

Scan containers never download anything: the database is written by the daily updater (``jobs/updaters.py``).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

from securescan.db.models.enums import ArtifactKind, ContentFeed
from securescan.logging import get_logger, scrub
from securescan.runner.catalogue import (
    CatalogueEntry,
    get_entry,
    resolve_image,
    resolve_image_with_override,
)
from securescan.runner.events import job_log_path, tail_lines
from securescan.runner.launcher import get_launcher
from securescan.runner.specs import ContainerResult, ContainerSpec
from securescan.runner.tools._support import content_dir, spec_from_entry
from securescan.runner.tools.base import (
    LABEL_JOB,
    LABEL_SCAN,
    DefaultToolBuilder,
    JobOutcome,
    ToolContext,
    ToolPreparationError,
)
from securescan.runner.validate import validate_outputs
from securescan.storage.artifacts import save_file

log = get_logger(__name__)

SYFT_TOOL = "syft"
IMAGE_ARCHIVE = "image.tar"
GRYPE_DB_DIRECTORY = "grype-db"
GRYPE_DB_TARGET = "/content/grype-db"
SBOM_FILES = (
    ("sbom.syft.json", "application/json"),
    ("sbom.cdx.json", "application/vnd.cyclonedx+json"),
)
SYFT_TMPFS_IMAGE = "1536m"  # charged to the 2560m memory limit: an image that does not fit fails the Syft stage
SYFT_TMPFS_DIRECTORY = "512m"
STALE_MARKERS = ("max allowed", "too old", "older than", "was built", "is stale")
MISSING_MARKERS = (
    "grype db update",
    "vulnerability database not found",
    "failed to load vulnerability db",
    "no vulnerability database",
)
_DURATION = re.compile(r"^\s*(\d+)\s*h\s*$")


# --------------------------------------------------------------------------- pure helpers
def is_image_source(ctx: ToolContext) -> bool:
    if ctx.source is not None:
        return ctx.source.kind == "image"
    return ctx.target is not None and ctx.target.kind.value == "image"


def syft_command(entry: CatalogueEntry, image: bool) -> list[str]:
    """The Syft arguments: the catalogue command, with the input replaced by the image archive for images."""
    command = entry.render_command()
    if not image:
        return command
    source = f"dir:{entry.mount_target('src')}"
    archive = f"docker-archive:{entry.mount_target('config')}/{IMAGE_ARCHIVE}"
    if source not in command:
        raise ToolPreparationError("The Syft catalogue command has no dir: input to replace.", code="syft.command")
    return [archive if part == source else part for part in command]


def humanise_age(value: str) -> str:
    """``120h`` as "5 days"; anything else is shown as written."""
    match = _DURATION.match(value)
    if match is None:
        return value
    hours = int(match.group(1))
    if hours >= 48 and hours % 24 == 0:
        return f"{hours // 24} days"
    return f"{hours} hours"


def explain_grype_failure(lines: Sequence[str], max_age: str) -> str | None:
    """A plain-language reason when Grype's output shows a stale or missing database, else None."""
    text = "\n".join(lines).lower()
    if "database" not in text and " db" not in text:
        return None
    if any(marker in text for marker in STALE_MARKERS):
        return (
            f"The vulnerability database is older than the allowed {humanise_age(max_age)}, so the scan "
            "was stopped instead of reporting against old data. The daily database update has probably "
            "failed: check the Grype database age under Settings, Scanner health, start an update there, "
            "then scan again."
        )
    if any(marker in text for marker in MISSING_MARKERS):
        return (
            "Grype could not load its vulnerability database. The database is downloaded by the daily "
            "update: start an update under Settings, Content, wait for it to finish, then scan again."
        )
    return None


class SyftGrypeBuilder(DefaultToolBuilder):
    tool = "syft-grype"

    # ------------------------------------------------------------------ prepare: database check, then Syft
    async def prepare(self, ctx: ToolContext) -> None:
        from securescan.jobs.scanner_health import active_versions

        if ctx.session is None:
            raise ToolPreparationError("internal: no database session in prepare", code="tool.no_session")
        versions = await active_versions(ctx.session)
        row = versions.get(ContentFeed.GRYPE_DB.value)
        if row is None:
            raise ToolPreparationError(
                "The Grype vulnerability database has not been downloaded yet. It is fetched by the daily "
                "update (07:30 UTC) and at start-up; an Admin can start it under Settings, Content. "
                "Scan again when it has finished.",
                code="grype.db_missing",
            )
        ctx.content_versions["grype_db"] = row.version
        content_dir(ctx.settings, GRYPE_DB_DIRECTORY)
        await self.run_syft(ctx)
        grype_tag = ctx.image.tag if ctx.image is not None and ctx.image.tag else "grype"
        syft_entry = get_entry(SYFT_TOOL)
        ctx.tool_version = f"syft {syft_entry.image.tag or ''} + grype {grype_tag}".replace("  ", " ").strip()
        ctx.coverage_notes.append(
            "Syft and Grype see only what is declared in manifests and lock files (images: what the package "
            "databases and files of the image show)."
        )

    def syft_spec(self, ctx: ToolContext, entry: CatalogueEntry, image: str) -> ContainerSpec:
        """The Syft container: source, out and config mounted, no network, a tmpfs sized for the input."""
        as_image = is_image_source(ctx)
        archive = ctx.workspace.config / IMAGE_ARCHIVE
        if as_image and not archive.is_file():
            raise ToolPreparationError(
                "The image archive is missing from the workspace; the image could not be read.",
                code="syft.archive_missing",
            )
        tmpfs_size = SYFT_TMPFS_IMAGE if as_image else SYFT_TMPFS_DIRECTORY
        return spec_from_entry(
            entry,
            image,
            name=f"securescan-job-{ctx.job.id}-syft",
            binds=[
                (str(ctx.workspace.src), entry.mount_target("src"), True),
                (str(ctx.workspace.out), entry.mount_target("out"), False),
                (str(ctx.workspace.config), entry.mount_target("config"), True),
            ],
            network="none",
            labels={LABEL_JOB: str(ctx.job.id), LABEL_SCAN: str(ctx.scan.id)},
            command=syft_command(entry, as_image),
            tmpfs={"/tmp": f"rw,size={tmpfs_size},mode=1777"},
        )

    async def run_syft(self, ctx: ToolContext) -> None:
        entry = get_entry(SYFT_TOOL)
        if ctx.session is not None:
            image = await resolve_image_with_override(ctx.session, entry, ctx.settings, ctx.options)
        else:
            image = resolve_image(entry, settings=ctx.settings)
        spec = self.syft_spec(ctx, entry, image.reference)
        timeout_s = entry.timeout_seconds
        result = await get_launcher().run(spec, timeout_s)
        self.check_syft_result(result, entry, ctx, timeout_s)

    def check_syft_result(
        self, result: ContainerResult, entry: CatalogueEntry, ctx: ToolContext, timeout_s: float
    ) -> None:
        if result.timed_out:
            raise ToolPreparationError(
                f"Syft did not finish within {int(timeout_s // 60)} minutes and was stopped.", code="syft.timeout"
            )
        if result.exit_code != 0:
            last = next((ln.strip() for ln in reversed(result.logs.splitlines()) if ln.strip()), "")
            suffix = f" Last output: {scrub(last)[:300]}" if last else ""
            raise ToolPreparationError(
                f"Syft failed (exit code {result.exit_code}) while reading the code.{suffix}", code="syft.failed"
            )
        validation = validate_outputs(entry, ctx.workspace.out)
        if not validation.ok:
            raise ToolPreparationError(f"Syft produced no usable SBOM: {validation.reason()}", code="syft.no_sbom")

    # ------------------------------------------------------------------ the Grype container
    def content_path(self, ctx: ToolContext) -> Path | None:
        return content_dir(ctx.settings, GRYPE_DB_DIRECTORY)

    def extra_env(self, ctx: ToolContext) -> dict[str, str]:
        return {"GRYPE_DB_MAX_ALLOWED_BUILT_AGE": ctx.settings.grype_db_max_age}

    def container_spec(self, ctx: ToolContext) -> ContainerSpec:
        spec = super().container_spec(ctx)
        read_only = ctx.settings.grype_db_read_only
        spec.binds = [
            (path, target, read_only if target == GRYPE_DB_TARGET else ro) for path, target, ro in spec.binds
        ]
        return spec

    def classify_exit(self, ctx: ToolContext, exit_code: int | None) -> JobOutcome:
        outcome = super().classify_exit(ctx, exit_code)
        if outcome == "failed" and ctx.scan is not None:
            try:
                lines = tail_lines(job_log_path(ctx.scan.id, ctx.job.id), 80)
            except Exception:  # noqa: BLE001 - the explanation is a bonus; the generic reason still applies
                lines = []
            reason = explain_grype_failure(lines, ctx.settings.grype_db_max_age)
            if reason is not None:
                raise ToolPreparationError(reason, code="grype.stale_database")
        return outcome

    # ------------------------------------------------------------------ after a good run
    async def post_run(self, ctx: ToolContext, result: ContainerResult) -> None:
        if ctx.session is None:
            raise ToolPreparationError("internal: no database session in post_run", code="tool.no_session")
        for name, content_type in SBOM_FILES:
            path = ctx.workspace.out / name
            if not path.is_file():
                continue
            await save_file(
                ctx.session,
                kind=ArtifactKind.SBOM,
                source=path,
                filename=name,
                content_type=content_type,
                scan_id=ctx.scan.id,
                job_id=ctx.job.id,
            )


BUILDER = SyftGrypeBuilder()

# The image source handler must be registered before the executor acquires an image target's source; the tool
# registry imports this module first (get_builder runs before acquire_source), so register it here.
from securescan.runner.sources.image import register_image_source  # noqa: E402

register_image_source()
