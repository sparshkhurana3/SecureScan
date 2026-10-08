"""SonarQube scanner: command builder and post-run export (no parsing of findings), plan M8 task 5.

The job, step by step:

1. ``prepare`` decides applicability from the source (images without application source and C#-only sources are
   skipped with a coverage note), starts the on-demand server (``jobs/sonarqube_lifecycle.ensure_running``, which
   also runs the first-time setup), creates the project when it does not exist and mints a **project analysis token
   that expires after one day**; that token is the only credential of the scanner container (``SONAR_TOKEN`` in its
   environment, never on the command line).
2. The executor runs ``sonar-scanner`` on the internal ``sonarqube`` network with the source at ``/usr/src``.
3. ``post_run`` reads ``report-task.txt``, waits for the compute-engine task, reads the quality gate and the
   measures, pages the issues API into ``sonarqube-issues.zip`` (``SonarQubeClient.export_issues``), stores the
   zip as the raw report and puts the quality gate and measures into the job's ``options`` (where the report's
   code-quality section reads them). The analysis token is revoked.

Java without compiled classes: SonarQube analyses the sources with reduced precision. The job says so in its
coverage note ("analysed without bytecode, reduced precision"). When ``SECURESCAN_SONARQUBE_EMPTY_BINARIES_FALLBACK``
is on (the pinned build refuses a missing ``sonar.java.binaries``, spike S3) an empty directory is passed instead.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import update

from securescan.db.models.enums import ArtifactKind
from securescan.db.models.jobs import ScanJob
from securescan.db.models.versions import ApplicationVersion
from securescan.integrations.sonarqube.client import (
    SonarError,
    SonarQubeClient,
    read_report_task,
    tomorrow,
)
from securescan.integrations.sonarqube.init import stored_service_token
from securescan.logging import get_logger
from securescan.runner.catalogue import contained_path
from securescan.runner.specs import ContainerResult, ContainerSpec
from securescan.runner.tools._support import skip_job, slug
from securescan.runner.tools.base import DefaultToolBuilder, ToolContext, ToolPreparationError
from securescan.runner.tools.spotbugs import discover_java
from securescan.storage.artifacts import save_file
from securescan.util import utcnow

log = get_logger(__name__)

TOKEN_KEY = "sonar_token"
TOKEN_NAME_KEY = "sonar_token_name"
ISSUES_ZIP = "sonarqube-issues.zip"
EMPTY_CLASSES = "empty-classes"
SCANNER_WORK = ".scannerwork"
JAVA_SUFFIXES = (".java",)
WEB_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".html", ".htm", ".css", ".scss")
PYTHON_SUFFIXES = (".py",)
CSHARP_SUFFIXES = (".cs", ".csproj", ".sln", ".vb")
SKIPPED_DIRECTORIES = frozenset(
    {".git", "node_modules", "bower_components", "vendor", "__pycache__", "site-packages", "dist-packages", ".venv", "venv", "dist", "build", "target"}
)  # fmt: skip
# Parts of an image filesystem that are the operating system, not the application.
IMAGE_SYSTEM_PREFIXES = (
    "rootfs/usr/lib", "rootfs/usr/share", "rootfs/usr/bin", "rootfs/usr/sbin", "rootfs/usr/include",
    "rootfs/usr/libexec", "rootfs/usr/local/lib", "rootfs/usr/local/share", "rootfs/usr/local/bin",
    "rootfs/lib", "rootfs/lib64", "rootfs/bin", "rootfs/sbin", "rootfs/var/lib", "rootfs/var/cache",
    "rootfs/etc", "rootfs/proc", "rootfs/sys", "rootfs/dev", "rootfs/opt/java", "rootfs/opt/openjdk",
)  # fmt: skip
IMAGE_EXCLUSIONS = ",".join(f"{prefix}/**" for prefix in IMAGE_SYSTEM_PREFIXES)
MAX_WALK_ENTRIES = 400_000


@dataclass
class LanguageSummary:
    java: int = 0
    web: int = 0
    python: int = 0
    csharp: int = 0
    walked: int = 0

    @property
    def analysable(self) -> int:
        return self.java + self.web + self.python


def scan_languages(root: Path, *, image: bool = False) -> LanguageSummary:
    """Count source files by language family below ``root`` (never following links, bounded)."""
    summary = LanguageSummary()
    base = str(root)
    for current, dirs, files in os.walk(root, followlinks=False):
        relative = os.path.relpath(current, base).replace(os.sep, "/")
        relative = "" if relative == "." else relative
        kept = []
        for name in sorted(dirs):
            child = f"{relative}/{name}" if relative else name
            if name in SKIPPED_DIRECTORIES or os.path.islink(os.path.join(current, name)):
                continue
            if image and any(child == prefix or child.startswith(prefix + "/") for prefix in IMAGE_SYSTEM_PREFIXES):
                continue
            kept.append(name)
        dirs[:] = kept
        for name in files:
            summary.walked += 1
            lowered = name.lower()
            if lowered.endswith(JAVA_SUFFIXES):
                summary.java += 1
            elif lowered.endswith(WEB_SUFFIXES) and not lowered.endswith(".min.js"):
                summary.web += 1
            elif lowered.endswith(PYTHON_SUFFIXES):
                summary.python += 1
            elif lowered.endswith(CSHARP_SUFFIXES):
                summary.csharp += 1
        if summary.walked > MAX_WALK_ENTRIES:
            break
    return summary


def decide(summary: LanguageSummary, *, image: bool) -> str | None:
    """None to run, else the reason to skip (a coverage note)."""
    if summary.analysable == 0:
        if summary.csharp > 0:
            return "C# needs the .NET scanner and a build; SonarQube Community Build's command-line scanner cannot analyse it."
        if image:
            return "the image holds no application source that SonarQube analyses (the dependency scanners cover images)."
        return "no source files of a language SonarQube Community Build analyses (Java, JavaScript, TypeScript, Python, HTML, CSS) were found."
    return None


def project_key_for(application_name: str, version_label: str, version_id: Any) -> str:
    """``ss-<application>-<version>-<id>``: letters, digits and dashes, unique per version."""
    suffix = str(version_id).replace("-", "")[:8]
    return f"ss-{slug(application_name, 60)}-{slug(version_label, 60)}-{suffix}"


def merge_options(existing: dict[str, Any] | None, quality_gate: dict[str, Any], measures: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    """The job options after the export: the quality gate and measures where the report reads them."""
    merged: dict[str, Any] = dict(existing or {})
    merged["quality_gate"] = quality_gate
    merged["measures"] = {k: v for k, v in measures.items() if v is not None}
    merged["sonarqube"] = {**(merged.get("sonarqube") if isinstance(merged.get("sonarqube"), dict) else {}), **extra}
    return merged


class SonarQubeBuilder(DefaultToolBuilder):
    tool = "sonarqube"

    # ------------------------------------------------------------------ prepare
    async def prepare(self, ctx: ToolContext) -> None:
        from securescan.jobs.sonarqube_lifecycle import ensure_running

        if ctx.session is None:
            raise ToolPreparationError("internal: no database session in prepare", code="tool.no_session")
        image = ctx.source is not None and ctx.source.kind == "image"
        summary = await asyncio.to_thread(scan_languages, ctx.workspace.src, image=image)
        reason = decide(summary, image=image)
        if reason is not None:
            skip_job(reason)
        if summary.csharp > 0:
            ctx.coverage_notes.append("C# files were not analysed: that needs the .NET scanner and a build.")
        await self.prepare_java(ctx, summary)

        try:
            await ensure_running(settings=ctx.settings)
        except SonarError as exc:
            raise ToolPreparationError(
                f"The SonarQube server did not become ready: {exc} Check the sonarqube container's log on the host.",
                code="sonarqube.not_ready",
            ) from exc
        service_token = await stored_service_token(ctx.session)
        if not service_token:
            raise ToolPreparationError(
                "SonarQube is running but has not been set up: its service token is missing. Check "
                "SECURESCAN_SONARQUBE_ADMIN_PASSWORD_FILE and run 'python -m securescan sonar-init'.",
                code="sonarqube.not_initialised",
            )
        application_name = getattr(ctx.application, "name", None) or "application"
        label = getattr(ctx.version, "label", None) or "version"
        key = ctx.version.sonar_project_key or project_key_for(application_name, label, ctx.version.id)
        token_name = f"ss-{str(ctx.job.id).replace('-', '')[:24]}"
        try:
            async with SonarQubeClient(ctx.settings.sonarqube_url, token=service_token) as client:
                await client.ensure_project(key, f"{application_name} / {label}")
                analysis_token = await client.generate_token(
                    token_name,
                    "PROJECT_ANALYSIS_TOKEN",
                    project_key=key,
                    expiration_date=tomorrow(),
                )
        except SonarError as exc:
            raise ToolPreparationError(
                f"SonarQube refused to prepare the project: {exc}", code="sonarqube.project_failed"
            ) from exc
        if ctx.version.sonar_project_key != key:
            await ctx.session.execute(
                update(ApplicationVersion).where(ApplicationVersion.id == ctx.version.id).values(sonar_project_key=key)
            )
        ctx.extra_values["project_key"] = key
        ctx.extra_values[TOKEN_KEY] = analysis_token
        ctx.extra_values[TOKEN_NAME_KEY] = token_name
        ctx.tool_version = ctx.image.tag if ctx.image is not None else None

    async def prepare_java(self, ctx: ToolContext, summary: LanguageSummary) -> None:
        """Class directories and JARs of the source for ``sonar.java.binaries``; the empty-binaries fallback."""
        if summary.java == 0:
            return
        found = await asyncio.to_thread(discover_java, ctx.workspace.src)
        binaries = [*found.class_dirs, *found.archives]
        if binaries:
            ctx.options["sonar_binaries"] = binaries
            return
        ctx.coverage_notes.append(
            "Java sources were analysed without bytecode (no compiled classes found), with reduced precision."
        )
        if ctx.settings.sonarqube_empty_binaries_fallback:
            directory = ctx.workspace.out / EMPTY_CLASSES
            directory.mkdir(exist_ok=True)
            os.chmod(directory, 0o777)
            ctx.options["sonar_binaries_out"] = [EMPTY_CLASSES]

    # ------------------------------------------------------------------ command and container
    def build_command(self, ctx: ToolContext) -> list[str]:
        command = super().build_command(ctx)
        src_root = ctx.entry.mount_target("src")
        out_root = ctx.entry.mount_target("out")
        binaries: list[str] = []
        for relative in ctx.options.get("sonar_binaries", []) or []:
            binaries.append(contained_path("." if relative in ("", ".") else str(relative), src_root))
        for relative in ctx.options.get("sonar_binaries_out", []) or []:
            binaries.append(contained_path(str(relative), out_root))
        if binaries:
            command.append("-Dsonar.java.binaries=" + ",".join(binaries))
        if ctx.source is not None and ctx.source.kind == "image":
            command.append("-Dsonar.exclusions=" + IMAGE_EXCLUSIONS)
        return command

    def extra_env(self, ctx: ToolContext) -> dict[str, str]:
        token = ctx.extra_values.get(TOKEN_KEY)
        if not token:
            raise ToolPreparationError("SonarQube was not prepared: no analysis token.", code="sonarqube.no_token")
        return {"SONAR_TOKEN": token}

    def container_spec(self, ctx: ToolContext) -> ContainerSpec:
        spec = super().container_spec(ctx)
        # S3: the scanner may need to run files it extracts below /tmp; keep nosuid and nodev, allow exec.
        for path, options in list(spec.tmpfs.items()):
            if path == "/tmp" and "exec" not in options.split(","):  # noqa: S108 - container-internal tmpfs
                spec.tmpfs[path] = options.replace("rw,", "rw,exec,", 1)
        return spec

    # ------------------------------------------------------------------ after the scanner ended well
    async def post_run(self, ctx: ToolContext, result: ContainerResult) -> None:
        if ctx.session is None:
            raise ToolPreparationError("internal: no database session in post_run", code="tool.no_session")
        service_token = await stored_service_token(ctx.session)
        if not service_token:
            raise ToolPreparationError("SonarQube's service token is missing.", code="sonarqube.not_initialised")
        report = ctx.workspace.out / SCANNER_WORK / "report-task.txt"
        if not report.is_file():
            raise ToolPreparationError(
                "The SonarQube scanner did not write report-task.txt, so the analysis cannot be followed.",
                code="sonarqube.no_report_task",
            )
        task_file = read_report_task(report.read_text(encoding="utf-8", errors="replace"))
        task_id = task_file.get("ceTaskId")
        key = task_file.get("projectKey") or ctx.extra_values.get("project_key")
        if not task_id or not key:
            raise ToolPreparationError("report-task.txt has no task id or project key.", code="sonarqube.bad_report_task")
        target = ctx.workspace.out / ISSUES_ZIP
        try:
            async with SonarQubeClient(ctx.settings.sonarqube_url, token=service_token) as client:
                task = await client.wait_for_ce_task(task_id, float(ctx.settings.sonarqube_ce_timeout_seconds))
                if str(task.get("status")) != "SUCCESS":
                    message = str(task.get("errorMessage") or task.get("status"))[:200]
                    raise ToolPreparationError(
                        f"SonarQube could not process the analysis ({message}).", code="sonarqube.ce_failed"
                    )
                analysis_id = str(task.get("analysisId") or "") or None
                gate = await client.quality_gate(key, analysis_id)
                measures = await client.measures(key)
                export = await client.export_issues(key, target)
                token_name = ctx.extra_values.get(TOKEN_NAME_KEY)
                if token_name:
                    try:
                        await client.revoke_token(token_name)
                    except SonarError:
                        log.warning("sonarqube_token_revoke_failed")
        except SonarError as exc:
            raise ToolPreparationError(
                f"Reading the SonarQube results failed: {exc}", code="sonarqube.export_failed"
            ) from exc
        await save_file(
            ctx.session,
            kind=ArtifactKind.RAW_REPORT,
            source=target,
            filename=ISSUES_ZIP,
            content_type="application/zip",
            scan_id=ctx.scan.id,
            job_id=ctx.job.id,
        )
        extra = {
            "project_key": key,
            "ce_task_id": task_id,
            "analysis_id": analysis_id,
            "issues_total": export.total,
            "issues_exported": export.exported,
            "issue_pages": export.files,
            "export_split_by": export.splits,
            "export_truncated": export.truncated,
        }
        options = merge_options(ctx.job.options, gate, dict(measures), extra)
        await ctx.session.execute(
            update(ScanJob).where(ScanJob.id == ctx.job.id).values(options=options, updated_at=utcnow())
        )
        if export.truncated:
            ctx.coverage_notes.append(
                f"SonarQube reported {export.total} issues; the export holds {export.exported} "
                "(the API limit of 10 000 per query was reached)."
            )


BUILDER = SonarQubeBuilder()
