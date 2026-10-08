"""Semgrep: command builder (no parsing, no findings).

Command and limits come from the catalogue. What this builder adds:

* mounts the *resolved* rules directory (``<content>/semgrep/rules`` is a symlink to ``rules-<commit>``)
  at the fixed container path, so rule ids and finding titles do not change with the commit; the
  directory name is recorded as the job's content version;
* ``--exclude <pattern>`` switches from ``scanners/profiles/semgrep.yaml`` plus the job options;
* removes a ``.semgrepignore`` found in the scanned source so that the owner of the code cannot hide
  files from the scan, and records the removal, the exclusion patterns and Semgrep's built-in skips as
  "applied exclusions" (reports state them).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from securescan.runner.profiles import ProfileError, load_tool_settings, string_list
from securescan.runner.tools.base import (
    DefaultToolBuilder,
    ToolContext,
    ToolPreparationError,
    remove_ignore_files,
)

# Semgrep skips these on its own (its default ignore list and size limit); stated in every report.
BUILTIN_SKIPS = ("tests/", "vendor/", "node_modules/", "build/", "dist/", "*.min.js", "files larger than 1 MB")
RULE_DIRECTORY_NAMES = ("semgrep/rules", "semgrep-rules")


def resolve_rules_dir(content_root: Path) -> Path:
    """The real directory behind the rules symlink, which must lie inside the content root."""
    root = content_root.resolve()
    for name in RULE_DIRECTORY_NAMES:
        candidate = content_root / name
        if not candidate.exists():
            continue
        real = candidate.resolve()
        if root != real and root not in real.parents:
            raise ToolPreparationError(
                "The Semgrep rules link points outside the content volume.", code="semgrep.rules_invalid"
            )
        if real.is_dir() and any(real.iterdir()):
            return real
    raise ToolPreparationError(
        "The Semgrep rules are not installed yet. Run the rules update (Settings, Content) "
        "or wait for the weekly update, then start the scan again.",
        code="semgrep.rules_missing",
    )


def rules_version(rules_dir: Path) -> str:
    """``rules-<commit>`` (the directory name), or the commit in a ``<name>.commit`` file next to it."""
    name = rules_dir.name
    if name.startswith("rules-"):
        return name
    marker = rules_dir.parent / f"{name}.commit"
    if marker.is_file():
        commit = marker.read_text(encoding="utf-8", errors="replace").strip()
        if commit:
            return f"rules-{commit[:40]}"
    return name


class SemgrepBuilder(DefaultToolBuilder):
    tool = "semgrep"

    # ------------------------------------------------------------------ preparation
    async def prepare(self, ctx: ToolContext) -> None:
        removed = remove_ignore_files(ctx.workspace.src, (".semgrepignore",))
        for path in removed:
            ctx.applied_exclusions.append(
                {"kind": "source_file_removed", "value": path, "note": "the scanned code's own ignore file was not honoured"}
            )
        ctx.coverage_notes.extend(
            f"{path} was removed before the scan so that it cannot hide files." for path in removed
        )
        rules = resolve_rules_dir(Path(ctx.settings.content_root))
        ctx.content_versions["semgrep_rules"] = rules_version(rules)
        ctx.extra_values["rules_dir"] = str(rules)
        patterns = self.exclude_patterns(ctx)
        for pattern in patterns:
            ctx.applied_exclusions.append({"kind": "pattern", "value": pattern, "source": "semgrep settings"})
        for skip in BUILTIN_SKIPS:
            ctx.applied_exclusions.append({"kind": "builtin", "value": skip, "source": "semgrep"})
        ctx.tool_version = ctx.image.tag if ctx.image is not None else None

    def exclude_patterns(self, ctx: ToolContext) -> list[str]:
        """Patterns from ``scanners/profiles/semgrep.yaml`` plus ``options["exclude"]``, de-duplicated."""
        try:
            settings: dict[str, Any] = load_tool_settings("semgrep", ctx.scanners_dir)
            patterns = string_list(settings.get("exclude"), "semgrep settings: exclude")
            patterns += string_list(ctx.options.get("exclude"), "job option exclude")
        except ProfileError as exc:
            raise ToolPreparationError(str(exc), code="semgrep.settings_invalid") from exc
        seen: list[str] = []
        for pattern in patterns:
            if pattern not in seen:
                seen.append(pattern)
        return seen

    # ------------------------------------------------------------------ command
    def optional_args(self, ctx: ToolContext) -> list[tuple[str, str | None]]:
        return [("--exclude", pattern) for pattern in self.exclude_patterns(ctx)]

    def content_path(self, ctx: ToolContext) -> Path | None:
        value = ctx.extra_values.get("rules_dir")
        return Path(value) if value else None


BUILDER = SemgrepBuilder()
