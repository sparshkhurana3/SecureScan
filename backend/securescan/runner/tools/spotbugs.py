"""SpotBugs with Find Security Bugs: command builder and Java artifact discovery (no parsing of findings).

SpotBugs analyses compiled classes. ``prepare`` walks the source (a repository, a zip, or an image filesystem
under ``src/rootfs``) and collects

* the files to analyse: JAR, WAR and EAR files outside library directories, and class directories (the package
  root of a tree of ``.class`` files, found by reading the class name from one class file);
* the libraries (JARs in ``lib``, ``libs``, ``WEB-INF/lib`` ...), which go to ``-auxclasspath`` so that
  SpotBugs can resolve what the analysed code calls without reporting on it.

Nothing found: the job is skipped with the coverage note "no compiled classes found" (``skip_job``). All paths
reach the command line only after ``contained_path`` proved that they lie under ``/src``; nothing comes from
user input except the file names inside the scanned source, and those are checked.

The same discovery serves the SonarQube builder (``sonar.java.binaries``).
"""

from __future__ import annotations

import asyncio
import os
import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from securescan.runner.catalogue import contained_path
from securescan.runner.tools._support import skip_job
from securescan.runner.tools.base import DefaultToolBuilder, ToolContext, ToolPreparationError

ARCHIVE_SUFFIXES = (".jar", ".war", ".ear")
SKIP_ARCHIVE_SUFFIXES = ("-sources.jar", "-javadoc.jar", "-tests.jar", "-test.jar", "-test-sources.jar")
SKIPPED_DIRECTORIES = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", ".gradle", ".m2", ".idea", "__pycache__", "site-packages",
        "dist-packages", ".venv", "venv", "jvm", "jdk", "jre",
    }
)  # fmt: skip
SKIPPED_PREFIXES = ("openjdk", "jdk-", "jre-", "java-1", "java-2", "temurin", "zulu", "corretto")
LIBRARY_DIRECTORIES = frozenset(
    {"lib", "libs", "library", "libraries", "dependencies", "deps", "vendor", "third_party", "third-party", "3rdparty"}
)
TEST_DIRECTORIES = frozenset({"test", "tests", "test-classes", "it-classes"})
MAX_TARGETS = 100
MAX_LIBRARIES = 400
MAX_ENTRIES = 600_000
MAX_AUX_LENGTH = 2000
CLASS_HEADER_BYTES = 128 * 1024


@dataclass
class JavaDiscovery:
    """Paths relative to the directory that was walked (POSIX separators)."""

    archives: list[str] = field(default_factory=list)
    class_dirs: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def targets(self) -> list[str]:
        return [*self.archives, *self.class_dirs]

    def as_options(self) -> dict[str, Any]:
        return {
            "archives": list(self.archives),
            "class_dirs": list(self.class_dirs),
            "libraries": list(self.libraries),
            "truncated": self.truncated,
        }


# --------------------------------------------------------------------------- class file names
_FIXED_ENTRY_SIZES = {3: 4, 4: 4, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}


def parse_class_name(data: bytes) -> str | None:
    """The internal name (``com/example/App``) of the class in a ``.class`` file header, or None.

    Reads the constant pool only; it needs the beginning of the file (see ``CLASS_HEADER_BYTES``).
    """
    try:
        if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
            return None
        count = int.from_bytes(data[8:10], "big")
        position = 10
        utf8: dict[int, str] = {}
        classes: dict[int, int] = {}
        index = 1
        while index < count:
            tag = data[position]
            position += 1
            if tag == 1:
                length = int.from_bytes(data[position : position + 2], "big")
                position += 2
                if position + length > len(data):
                    return None
                utf8[index] = data[position : position + length].decode("utf-8", "replace")
                position += length
            elif tag == 7:
                classes[index] = int.from_bytes(data[position : position + 2], "big")
                position += 2
            elif tag in (5, 6):
                position += 8
                index += 1  # long and double take two slots
            elif tag in _FIXED_ENTRY_SIZES:
                position += _FIXED_ENTRY_SIZES[tag]
            else:
                return None
            index += 1
        this_class = int.from_bytes(data[position + 2 : position + 4], "big")
        name_index = classes.get(this_class)
        return utf8.get(name_index) if name_index is not None else None
    except IndexError:
        return None


def class_root(class_file: Path) -> Path | None:
    """The directory that holds the package tree of ``class_file`` (``target/classes`` for
    ``target/classes/com/example/App.class``), from the class name inside the file."""
    try:
        with class_file.open("rb") as handle:
            name = parse_class_name(handle.read(CLASS_HEADER_BYTES))
    except OSError:
        return None
    if not name or ".." in name or name.startswith("/"):
        return None
    package = name.split("/")[:-1]
    directory = class_file.parent
    if not package:
        return directory
    parts = directory.parts
    if len(parts) < len(package) or list(parts[len(parts) - len(package) :]) != package:
        return None
    return Path(*parts[: len(parts) - len(package)]) if len(parts) > len(package) else None


# --------------------------------------------------------------------------- discovery
def skipped_directory(name: str) -> bool:
    lowered = name.lower()
    return lowered in SKIPPED_DIRECTORIES or lowered.startswith(SKIPPED_PREFIXES)


def safe_name(relative: str) -> bool:
    """False for paths with a backslash or control characters (they never reach a command line)."""
    return "\\" not in relative and not any(ord(ch) < 32 or ord(ch) == 127 for ch in relative)


def is_library(relative: str) -> bool:
    """A JAR below a library directory is a dependency, not the application (Gradle's ``build/libs`` is not)."""
    parts = relative.lower().split("/")[:-1]
    if not parts:
        return False
    if "web-inf" in parts or "boot-inf" in parts:
        return parts[-1] in LIBRARY_DIRECTORIES
    if parts[-1] == "libs" and len(parts) >= 2 and parts[-2] == "build":
        return False
    return parts[-1] in LIBRARY_DIRECTORIES


def discover_java(root: Path, *, max_targets: int = MAX_TARGETS) -> JavaDiscovery:
    """Walk ``root`` (never following links) and collect Java artifacts. Deterministic order."""
    found = JavaDiscovery()
    class_samples: dict[str, Path] = {}
    visited = 0
    base = str(root)
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not skipped_directory(d) and not os.path.islink(os.path.join(current, d)))
        visited += len(files)
        if visited > MAX_ENTRIES:
            found.truncated = True
            break
        relative_dir = os.path.relpath(current, base).replace(os.sep, "/")
        relative_dir = "" if relative_dir == "." else relative_dir
        for name in sorted(files):
            lowered = name.lower()
            path = os.path.join(current, name)
            if os.path.islink(path):
                continue
            relative = f"{relative_dir}/{name}" if relative_dir else name
            if not safe_name(relative):
                continue
            if lowered.endswith(".class"):
                class_samples.setdefault(relative_dir, Path(path))
            elif lowered.endswith(ARCHIVE_SUFFIXES) and not lowered.endswith(SKIP_ARCHIVE_SUFFIXES):
                try:
                    if os.path.getsize(path) == 0:
                        continue
                except OSError:
                    continue
                if is_library(relative):
                    if len(found.libraries) < MAX_LIBRARIES:
                        found.libraries.append(relative)
                    else:
                        found.truncated = True
                elif len(found.archives) < max_targets:
                    found.archives.append(relative)
                else:
                    found.truncated = True
    roots: list[str] = []
    for sample in class_samples.values():
        top = class_root(sample)
        if top is None:
            continue
        try:
            relative_root = os.path.relpath(str(top), base).replace(os.sep, "/")
        except ValueError:
            continue
        if relative_root == ".":
            relative_root = ""
        if relative_root.startswith("..") or not safe_name(relative_root):
            continue
        if any(part in TEST_DIRECTORIES for part in relative_root.lower().split("/")):
            continue
        if relative_root not in roots:
            roots.append(relative_root)
    archive_parents = {posixpath.dirname(a) for a in found.archives}
    for relative_root in sorted(roots):
        # The class directory beside a JAR built from it (target/classes and target/app.jar) would double the findings.
        if posixpath.dirname(relative_root) in archive_parents and relative_root:
            continue
        if len(found.class_dirs) < max_targets:
            found.class_dirs.append(relative_root or ".")
        else:
            found.truncated = True
    found.archives.sort()
    return found


# --------------------------------------------------------------------------- the builder
class SpotBugsBuilder(DefaultToolBuilder):
    tool = "spotbugs"

    async def prepare(self, ctx: ToolContext) -> None:
        found = await asyncio.to_thread(discover_java, ctx.workspace.src)
        if not found.targets:
            skip_job(
                "no compiled classes found: SpotBugs analyses JAR, WAR and EAR files and class directories, "
                "and the source holds none. Compiling the project is part of the later build-based analysis."
            )
        ctx.options["java_discovery"] = found.as_options()
        note = (
            f"SpotBugs analysed {len(found.archives)} archive(s) and {len(found.class_dirs)} class "
            f"director{'y' if len(found.class_dirs) == 1 else 'ies'}"
            + (f" with {len(found.libraries)} librar{'y' if len(found.libraries) == 1 else 'ies'} on the class path." if found.libraries else ".")
        )
        if found.truncated:
            note += " The list was cut at the limit; further files were not analysed."
        ctx.coverage_notes.append(note)
        ctx.tool_version = ctx.image.tag if ctx.image is not None else None

    def discovery(self, ctx: ToolContext) -> dict[str, Any]:
        value = ctx.options.get("java_discovery")
        if not isinstance(value, dict):
            raise ToolPreparationError("SpotBugs was not prepared: no discovery result.", code="spotbugs.not_prepared")
        return value

    def container_path(self, ctx: ToolContext, relative: str) -> str:
        """``/src/<relative>`` after the containment check."""
        return contained_path("." if relative in ("", ".") else relative, ctx.entry.mount_target("src"))

    def auxclasspath(self, ctx: ToolContext, libraries: list[str]) -> tuple[str, int]:
        """The ``-auxclasspath`` value (at most ``MAX_AUX_LENGTH`` characters) and the number of libraries left out."""
        chosen: list[str] = []
        length = 0
        for relative in libraries:
            path = self.container_path(ctx, relative)
            if ":" in path:
                continue  # a class path separator inside a file name cannot be expressed
            extra = len(path) + (1 if chosen else 0)
            if length + extra > MAX_AUX_LENGTH:
                break
            chosen.append(path)
            length += extra
        return ":".join(chosen), len(libraries) - len(chosen)

    def build_command(self, ctx: ToolContext) -> list[str]:
        found = self.discovery(ctx)
        command = ctx.entry.render_command(self.placeholder_values(ctx))
        requested: list[tuple[str, str | None]] = []
        aux, left_out = self.auxclasspath(ctx, [str(x) for x in found.get("libraries", [])])
        if aux:
            requested.append(("-auxclasspath", aux))
        if left_out > 0:
            note = f"{left_out} librar{'y was' if left_out == 1 else 'ies were'} left off the class path (length limit)."
            if note not in ctx.coverage_notes:
                ctx.coverage_notes.append(note)
        targets = [
            self.container_path(ctx, str(t))
            for t in [*found.get("archives", []), *found.get("class_dirs", [])]
        ]
        if not targets:
            raise ToolPreparationError("SpotBugs has nothing to analyse.", code="spotbugs.no_targets")
        return [*command, *ctx.entry.render_optional_args(requested), *targets]


BUILDER = SpotBugsBuilder()
