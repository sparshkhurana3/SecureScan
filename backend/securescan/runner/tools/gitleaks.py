"""Gitleaks: command builder (no parsing, no findings).

* repositories (``github_repo``, ``vendor_repo``) are scanned with ``gitleaks git`` (full history);
  zip uploads and image filesystems with ``gitleaks dir`` and the same flags (plan M3 task 1);
* SecureScan's own rule file ``scanners/gitleaks.toml`` is copied into the job's ``config`` directory and
  passed with ``--config``, so a vendor's ``.gitleaks.toml`` cannot switch rules off;
* a ``.gitleaksignore`` in the scanned source is removed and the removal is recorded;
* ``--redact`` and ``--ignore-gitleaks-allow`` are part of the catalogue command: secret values never
  reach the report, and inline ``gitleaks:allow`` comments are ignored.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from securescan.runner.tools.base import (
    DefaultToolBuilder,
    ToolContext,
    ToolPreparationError,
    remove_ignore_files,
)

CONFIG_NAME = "gitleaks.toml"
GIT_TARGET_KINDS = ("github_repo", "vendor_repo")


def is_git_source(ctx: ToolContext) -> bool:
    """History mode for repositories; file mode for zips and image filesystems."""
    if ctx.source is not None:
        return ctx.source.is_git
    return ctx.target is not None and ctx.target.kind.value in GIT_TARGET_KINDS


class GitleaksBuilder(DefaultToolBuilder):
    tool = "gitleaks"

    async def prepare(self, ctx: ToolContext) -> None:
        removed = remove_ignore_files(ctx.workspace.src, (".gitleaksignore",))
        for path in removed:
            ctx.applied_exclusions.append(
                {
                    "kind": "source_file_removed",
                    "value": path,
                    "note": "the scanned code's own ignore file was not honoured",
                }
            )
        ctx.coverage_notes.extend(
            f"{path} was removed before the scan so that it cannot hide secrets." for path in removed
        )
        source = self._config_source(ctx)
        destination = ctx.workspace.config / CONFIG_NAME
        shutil.copyfile(source, destination)
        destination.chmod(0o644)
        ctx.tool_version = ctx.image.tag if ctx.image is not None else None

    def _config_source(self, ctx: ToolContext) -> Path:
        base = ctx.scanners_dir
        if base is not None and (base / CONFIG_NAME).is_file():
            return base / CONFIG_NAME
        raise ToolPreparationError(
            "SecureScan's Gitleaks rule file (scanners/gitleaks.toml) was not found.",
            code="gitleaks.config_missing",
        )

    def build_command(self, ctx: ToolContext) -> list[str]:
        command = super().build_command(ctx)
        if not is_git_source(ctx):
            if len(command) < 2 or command[1] != "git":
                raise ToolPreparationError("The Gitleaks catalogue command must start with 'gitleaks git'.")
            command[1] = "dir"
        return command


BUILDER = GitleaksBuilder()
