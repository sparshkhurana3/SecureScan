"""The scanner catalogue: the only source of container specifications.

``scanners/catalogue.yaml`` (merged with ``scanners/catalogue.d/*.yaml``) lists every tool the
platform may run. Everything about a container comes from here: image, user, network, mounts, tmpfs,
limits, command template and the allowlist of optional switches. Nothing is built from user input.

File format::

    schema_version: 1
    scanners:
      - tool: semgrep
        image: {name: semgrep/semgrep, tag: 1.179.0-nonroot, lock: SEMGREP}
        user: "1000:1000"
        network: none                    # none | sonarqube | dast
        mounts:                          # name in {src, out, config, content}
          - {name: src, target: /src, read_only: true}
        tmpfs: [{path: /tmp, size: 512m}]
        limits: {cpus: 2, memory: 4g, pids: 256}
        timeout_minutes: 60
        max_parallel: 2
        command: ["semgrep", "scan", "--config", "{content}", "{src}"]
        optional_args:
          - {flag: --exclude, value: pattern, repeatable: true}
        outputs:
          - {file: semgrep.json, max_mb: 90, format: json}
        exit_codes: {"0": completed, ">=2": failed, default: failed}
        defectdojo_scan_type: Semgrep JSON Report
        defectdojo_file: semgrep.json

Placeholders allowed in ``command``: ``{src}``, ``{out}``, ``{config}``, ``{content}`` (the container
path of that mount) and ``{target_url}``, ``{project_key}`` (supplied by the tool builder).

Image pinning: the digest comes from (1) an approved ``ImageVersion`` row (``image_override``),
(2) the variable ``SECURESCAN_IMAGE_<lock>`` (``name@sha256:...``, written by Compose from
``deploy/images.env``), (3) ``digest`` in the entry, (4) ``deploy/images.lock.yaml``. An unpinned
image is refused outside dev and test; ``latest`` is refused everywhere.
"""

from __future__ import annotations

import hmac
import os
import posixpath
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import Settings, get_settings
from securescan.runner.specs import parse_size

Outcome = Literal["completed", "completed_partial", "failed"]
OUTCOMES = ("completed", "completed_partial", "failed")
MOUNT_NAMES = ("src", "out", "config", "content")
PLACEHOLDERS = frozenset({"src", "out", "config", "content", "target_url", "project_key"})
NETWORKS = ("none", "sonarqube", "dast")
IMAGE_ENV_PREFIX = "SECURESCAN_IMAGE_"

_BRACES = re.compile(r"\{([^{}]*)\}")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_USER = re.compile(r"^([0-9]{1,10}|root)(:([0-9]{1,10}|root))?$")
_TOOL = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_EXIT_KEY = re.compile(r"^([0-9]{1,3}|>=[0-9]{1,3}|default)$")
_FLAG = re.compile(r"^--?[A-Za-z][A-Za-z0-9-]*$")
_LOCK_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


class CatalogueError(Exception):
    """The catalogue (or a request to render from it) is invalid."""


class OptionalArgError(CatalogueError):
    """An optional switch is not on the entry's allowlist or its value is not acceptable."""


class ImageRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    tag: str | None = None
    digest: str | None = None
    lock: str | None = None  # name in deploy/images.lock.yaml, also the SECURESCAN_IMAGE_<lock> variable

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not value or any(ch.isspace() for ch in value) or "@" in value or ":" in value.rsplit("/", 1)[-1]:
            raise ValueError("image name must be a repository name without tag or digest")
        return value

    @field_validator("tag")
    @classmethod
    def _tag(cls, value: str | None) -> str | None:
        if value is not None and value.lower() == "latest":
            raise ValueError("the tag 'latest' is not allowed")
        return value

    @field_validator("digest")
    @classmethod
    def _digest(cls, value: str | None) -> str | None:
        if value is not None and not _DIGEST.match(value):
            raise ValueError("digest must look like sha256:<64 hex characters>")
        return value

    @field_validator("lock")
    @classmethod
    def _lock(cls, value: str | None) -> str | None:
        if value is not None and not _LOCK_NAME.match(value):
            raise ValueError("lock must be an upper-case name such as SEMGREP")
        return value


class MountSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Literal["src", "out", "config", "content"]
    target: str
    read_only: bool = True

    @field_validator("target")
    @classmethod
    def _target(cls, value: str) -> str:
        return _absolute_clean(value, "mount target")


class TmpfsSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    size: str = "64m"

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return _absolute_clean(value, "tmpfs path")

    @field_validator("size")
    @classmethod
    def _size(cls, value: str) -> str:
        parse_size(value)
        return value

    def options(self) -> str:
        return f"rw,size={self.size},mode=1777"


class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cpus: float = Field(default=1.0, gt=0, le=64)
    memory: str = "1g"
    pids: int = Field(default=256, ge=16, le=65536)

    @field_validator("memory")
    @classmethod
    def _memory(cls, value: str) -> str:
        parse_size(value)
        return value

    @property
    def nano_cpus(self) -> int:
        return int(self.cpus * 1_000_000_000)


class OptionalArg(BaseModel):
    """One switch the tool builder may append. Everything else is refused."""

    model_config = ConfigDict(extra="forbid")

    flag: str
    value: Literal["none", "fixed", "pattern", "path", "int", "choice"] = "none"
    fixed_value: str | None = None
    choices: list[str] = Field(default_factory=list)
    path_root: Literal["src", "out"] | None = None
    repeatable: bool = False
    max_count: int = Field(default=200, ge=1, le=1000)
    max_length: int = Field(default=200, ge=1, le=2000)

    @field_validator("flag")
    @classmethod
    def _flag(cls, value: str) -> str:
        if not _FLAG.match(value):
            raise ValueError(f"not a command-line switch: {value!r}")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> OptionalArg:
        if self.value == "fixed" and not self.fixed_value:
            raise ValueError("a fixed switch needs fixed_value")
        if self.value == "path" and self.path_root is None:
            raise ValueError("a path switch needs path_root (src or out)")
        if self.value == "choice" and not self.choices:
            raise ValueError("a choice switch needs choices")
        return self


class OutputSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    max_mb: int = Field(default=50, ge=1, le=4096)
    format: Literal["json", "xml", "none"] = "json"
    required: bool = True

    @field_validator("file")
    @classmethod
    def _file(cls, value: str) -> str:
        if not value or value.startswith("/") or "\\" in value or "\x00" in value:
            raise ValueError("output file must be a relative path")
        if any(part in ("", ".", "..") for part in value.split("/")):
            raise ValueError("output file must stay inside the out directory")
        return value

    @property
    def max_bytes(self) -> int:
        return self.max_mb * 1024 * 1024


class CatalogueEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    description: str = ""
    image: ImageRef
    user: str = "1000:1000"
    network: Literal["none", "sonarqube", "dast"] = "none"
    mounts: list[MountSpec] = Field(default_factory=list)
    tmpfs: list[TmpfsSpec] = Field(default_factory=list)
    limits: Limits = Field(default_factory=Limits)
    timeout_minutes: int = Field(default=60, ge=1, le=24 * 60)
    max_parallel: int = Field(default=1, ge=1, le=64)
    lock: str | None = None  # a fixed lock name (for example "dast") instead of tool:<name>:<slot>
    command: list[str]
    entrypoint: list[str] | None = Field(default_factory=lambda: [""])
    env: dict[str, str] = Field(default_factory=dict)
    optional_args: list[OptionalArg] = Field(default_factory=list)
    outputs: list[OutputSpec] = Field(default_factory=list)
    exit_codes: dict[str, Outcome] = Field(default_factory=lambda: {"0": "completed", "default": "failed"})
    target_kinds: list[str] = Field(
        default_factory=lambda: ["github_repo", "vendor_repo", "zip", "image"]
    )
    defectdojo_scan_type: str | None = None
    defectdojo_file: str | None = None

    # ------------------------------------------------------------------ validation
    @field_validator("tool")
    @classmethod
    def _tool(cls, value: str) -> str:
        if not _TOOL.match(value):
            raise ValueError("tool must be a lower-case name such as semgrep")
        return value

    @field_validator("user")
    @classmethod
    def _user(cls, value: str) -> str:
        if not _USER.match(value):
            raise ValueError("user must be a uid, uid:gid or root")
        return value

    @field_validator("env")
    @classmethod
    def _env(cls, value: dict[str, str]) -> dict[str, str]:
        for key, val in value.items():
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                raise ValueError(f"bad environment variable name {key!r}")
            if "\x00" in str(val):
                raise ValueError("environment values cannot contain NUL")
        return {k: str(v) for k, v in value.items()}

    @field_validator("exit_codes")
    @classmethod
    def _exit_codes(cls, value: dict[str, Outcome]) -> dict[str, Outcome]:
        normalised = {str(k): v for k, v in value.items()}
        for key in normalised:
            if not _EXIT_KEY.match(key):
                raise ValueError(f"exit code key {key!r} must be a number, '>=N' or 'default'")
        return normalised

    @field_validator("lock")
    @classmethod
    def _lock(cls, value: str | None) -> str | None:
        if value is not None and not re.match(r"^[a-z][a-z0-9:_-]{0,63}$", value):
            raise ValueError("lock must be a lower-case name")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> CatalogueEntry:
        if not self.command or not all(isinstance(part, str) and part for part in self.command):
            raise ValueError("command must be a non-empty list of non-empty strings")
        names = [m.name for m in self.mounts]
        if len(set(names)) != len(names):
            raise ValueError("a mount name can be used once")
        for mount in self.mounts:
            if mount.name != "out" and not mount.read_only:
                raise ValueError(f"mount {mount.name} must be read-only (only out is writable)")
        targets = [m.target for m in self.mounts] + [t.path for t in self.tmpfs]
        if len(set(targets)) != len(targets):
            raise ValueError("mount and tmpfs targets must be distinct")
        for outer in targets:
            for inner in targets:
                if outer != inner and inner.startswith(outer.rstrip("/") + "/"):
                    raise ValueError(f"{inner} is nested inside {outer}; nested mounts are not allowed")
        for part in self.command:
            for name in _BRACES.findall(part):
                if name not in PLACEHOLDERS:
                    raise ValueError(f"placeholder {{{name}}} is not allowed in command")
                if name in MOUNT_NAMES and name not in names:
                    raise ValueError(f"placeholder {{{name}}} needs a mount named {name}")
        for key, val in self.env.items():
            if _BRACES.search(val):
                raise ValueError(f"env {key} must not contain placeholders")
        flags = [a.flag for a in self.optional_args]
        if len(set(flags)) != len(flags):
            raise ValueError("optional_args flags must be unique")
        for arg in self.optional_args:
            if arg.path_root is not None and arg.path_root not in names:
                raise ValueError(f"optional arg {arg.flag} refers to missing mount {arg.path_root}")
        files = [o.file for o in self.outputs]
        if len(set(files)) != len(files):
            raise ValueError("output files must be unique")
        if "out" not in names and self.outputs:
            raise ValueError("outputs need a mount named out")
        if self.defectdojo_file is not None and self.defectdojo_file not in files:
            raise ValueError("defectdojo_file must be one of the outputs")
        if (self.defectdojo_scan_type is None) != (self.defectdojo_file is None):
            raise ValueError("defectdojo_scan_type and defectdojo_file go together")
        if "default" not in self.exit_codes and not self.exit_codes:
            raise ValueError("exit_codes cannot be empty")
        return self

    # ------------------------------------------------------------------ lookups
    def mount(self, name: str) -> MountSpec | None:
        for mount in self.mounts:
            if mount.name == name:
                return mount
        return None

    def mount_target(self, name: str) -> str:
        mount = self.mount(name)
        if mount is None:
            raise CatalogueError(f"{self.tool} has no mount named {name}")
        return mount.target

    def output(self, file: str) -> OutputSpec | None:
        for spec in self.outputs:
            if spec.file == file:
                return spec
        return None

    @property
    def timeout_seconds(self) -> float:
        return float(self.timeout_minutes * 60)

    def outcome_for(self, exit_code: int | None) -> Outcome:
        """Map an exit code with ``exit_codes``: exact number, then the highest ``>=N`` that
        applies, then ``default``; no exit code (killed, lost) is a failure."""
        if exit_code is None:
            return "failed"
        exact = self.exit_codes.get(str(exit_code))
        if exact is not None:
            return exact
        thresholds = sorted(
            (int(key[2:]), outcome) for key, outcome in self.exit_codes.items() if key.startswith(">=")
        )
        matched: Outcome | None = None
        for threshold, outcome in thresholds:
            if exit_code >= threshold:
                matched = outcome
        if matched is not None:
            return matched
        return self.exit_codes.get("default", "failed")

    # ------------------------------------------------------------------ rendering
    def placeholder_values(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        values = {m.name: m.target for m in self.mounts}
        values.update(extra or {})
        return values

    def render_command(self, extra: Mapping[str, str] | None = None) -> list[str]:
        """The command with placeholders replaced by container paths and builder-supplied values."""
        values = self.placeholder_values(extra)

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in values:
                raise CatalogueError(f"{self.tool}: no value for placeholder {{{name}}}")
            return values[name]

        return [_BRACES.sub(replace, part) for part in self.command]

    def optional_arg(self, flag: str) -> OptionalArg | None:
        for arg in self.optional_args:
            if arg.flag == flag:
                return arg
        return None

    def render_optional_args(self, requested: Sequence[tuple[str, str | None]]) -> list[str]:
        """Validate switches against the allowlist and return them as argv elements.

        Each request is ``(flag, value)``. A flag that is not in ``optional_args`` is refused; values
        are checked by kind (pattern, int, choice, path under the named mount).
        """
        rendered: list[str] = []
        counts: dict[str, int] = {}
        for flag, value in requested:
            spec = self.optional_arg(flag)
            if spec is None:
                raise OptionalArgError(f"{self.tool}: switch {flag} is not on the allowlist")
            counts[flag] = counts.get(flag, 0) + 1
            if counts[flag] > 1 and not spec.repeatable:
                raise OptionalArgError(f"{self.tool}: switch {flag} can be given once")
            if counts[flag] > spec.max_count:
                raise OptionalArgError(f"{self.tool}: switch {flag} given more than {spec.max_count} times")
            if spec.value == "none":
                if value is not None:
                    raise OptionalArgError(f"{self.tool}: switch {flag} takes no value")
                rendered.append(flag)
            elif spec.value == "fixed":
                rendered.extend([flag, str(spec.fixed_value)])
            else:
                if value is None:
                    raise OptionalArgError(f"{self.tool}: switch {flag} needs a value")
                rendered.extend([flag, self._check_value(spec, value)])
        return rendered

    def _check_value(self, spec: OptionalArg, value: str) -> str:
        text = str(value)
        if spec.value == "pattern":
            if not text or len(text) > spec.max_length:
                raise OptionalArgError(f"{spec.flag}: value must be 1 to {spec.max_length} characters")
            if text.startswith("-") or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
                raise OptionalArgError(f"{spec.flag}: value {text!r} is not an acceptable pattern")
            return text
        if spec.value == "int":
            if not re.match(r"^[0-9]{1,9}$", text):
                raise OptionalArgError(f"{spec.flag}: value must be a whole number")
            return text
        if spec.value == "choice":
            if text not in spec.choices:
                raise OptionalArgError(f"{spec.flag}: value must be one of {', '.join(spec.choices)}")
            return text
        if spec.value == "path":
            root = self.mount_target(str(spec.path_root))
            return contained_path(text, root)
        raise OptionalArgError(f"{spec.flag}: unsupported value kind {spec.value}")


def _absolute_clean(value: str, what: str) -> str:
    if not value.startswith("/") or "\x00" in value or "\\" in value:
        raise ValueError(f"{what} must be an absolute POSIX path")
    if any(part == ".." for part in value.split("/")):
        raise ValueError(f"{what} must not contain '..'")
    cleaned = posixpath.normpath(value)
    if cleaned == "/":
        raise ValueError(f"{what} cannot be the root directory")
    return cleaned


def contained_path(value: str, root: str) -> str:
    """``value`` as a normalised absolute container path that lies inside ``root``; else error."""
    if not value or "\x00" in value or "\\" in value:
        raise OptionalArgError(f"unsafe path {value!r}")
    if any(part == ".." for part in value.split("/")):
        raise OptionalArgError(f"path {value!r} must not contain '..'")
    absolute = value if value.startswith("/") else posixpath.join(root, value)
    cleaned = posixpath.normpath(absolute)
    base = posixpath.normpath(root)
    if cleaned != base and not cleaned.startswith(base.rstrip("/") + "/"):
        raise OptionalArgError(f"path {value!r} is outside {root}")
    return cleaned


# ----------------------------------------------------------------------------- image resolution
@dataclass(frozen=True)
class ResolvedImage:
    reference: str  # what Docker is asked to create: name@sha256:... (or name:tag in dev)
    name: str
    tag: str | None
    digest: str | None
    source: str  # candidate | override | env | catalogue | lock | tag

    @property
    def pinned(self) -> bool:
        return self.digest is not None


def _split_reference(reference: str) -> tuple[str, str | None]:
    if "@" in reference:
        name, _, digest = reference.partition("@")
        return name, digest
    return reference, None


def _lock_digests(scanners_dir: Path | None) -> dict[str, str]:
    """name -> digest from deploy/images.lock.yaml (searched next to the scanners directory)."""
    candidates: list[Path] = []
    if scanners_dir is not None:
        candidates.append(scanners_dir.parent / "deploy" / "images.lock.yaml")
        candidates.append(scanners_dir / "images.lock.yaml")
    for candidate in candidates:
        if candidate.is_file():
            try:
                data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                continue
            result: dict[str, str] = {}
            for item in data.get("images", []) or []:
                if isinstance(item, dict) and item.get("name") and item.get("digest"):
                    result[str(item["name"])] = str(item["digest"])
            return result
    return {}


def resolve_image(
    entry: CatalogueEntry,
    *,
    environ: Mapping[str, str] | None = None,
    settings: Settings | None = None,
    scanners_dir: Path | None = None,
) -> ResolvedImage:
    """The pinned image reference for an entry (without the database override; see ``image_override``)."""
    env = os.environ if environ is None else environ
    cfg = settings or get_settings()
    ref = entry.image
    if ref.lock:
        configured = env.get(IMAGE_ENV_PREFIX + ref.lock, "").strip()
        if configured:
            name, digest = _split_reference(configured)
            if digest is not None and not _DIGEST.match(digest):
                raise CatalogueError(f"{IMAGE_ENV_PREFIX}{ref.lock} must be name@sha256:<hex>")
            if digest is None and not cfg.is_dev:
                raise CatalogueError(f"{IMAGE_ENV_PREFIX}{ref.lock} is not pinned by digest")
            if (name + (":" + str(ref.tag) if ref.tag else "")).lower().endswith(":latest"):
                raise CatalogueError("the tag 'latest' is not allowed")
            return ResolvedImage(
                reference=configured, name=name, tag=ref.tag, digest=digest, source="env"
            )
    if ref.digest:
        return ResolvedImage(
            reference=f"{ref.name}@{ref.digest}", name=ref.name, tag=ref.tag, digest=ref.digest,
            source="catalogue",
        )  # fmt: skip
    if ref.lock:
        digest = _lock_digests(scanners_dir or find_scanners_dir(cfg)).get(ref.lock)
        if digest:
            return ResolvedImage(
                reference=f"{ref.name}@{digest}", name=ref.name, tag=ref.tag, digest=digest,
                source="lock",
            )  # fmt: skip
    if cfg.is_dev and ref.tag:
        return ResolvedImage(
            reference=f"{ref.name}:{ref.tag}", name=ref.name, tag=ref.tag, digest=None, source="tag"
        )  # fmt: skip
    raise CatalogueError(
        f"image of {entry.tool} is not pinned by digest: run 'python scripts/dev.py pin-images' "
        f"(variable {IMAGE_ENV_PREFIX}{ref.lock or '<NAME>'})"
    )


async def _candidate_override(
    session: AsyncSession, entry: CatalogueEntry, job_options: Mapping[str, Any] | None
) -> ResolvedImage | None:
    """The image of a proposal that is being regression-tested, for the scans of that test only.

    The job options carry ``image_candidates: {<tool>: {"id": <ImageVersion id>, "token": <secret>}}``.
    The row must be a proposal in state ``testing`` whose stored ``candidate_token`` equals the token
    (set by ``securescan/domain/regression.py``; the token is never shown by the API), so an ordinary
    scan request cannot run an image nobody approved.
    """
    from securescan.db.models.images import ImageVersion

    spec = (job_options or {}).get("image_candidates")
    item = spec.get(entry.tool) if isinstance(spec, dict) else None
    if not isinstance(item, dict):
        return None
    try:
        row_id = uuid.UUID(str(item.get("id")))
    except ValueError:
        return None
    row = await session.get(ImageVersion, row_id)
    if row is None or row.source != "proposal" or row.active:
        return None
    lock_name = (row.regression_detail or {}).get("lock_name")
    if row.tool != entry.tool and not (entry.image.lock and lock_name == entry.image.lock):
        return None
    expected = str((row.regression_detail or {}).get("candidate_token") or "")
    if row.regression_result != "testing" or not expected:
        return None
    if not hmac.compare_digest(expected.encode("utf-8"), str(item.get("token") or "").encode("utf-8")):
        return None
    if not _DIGEST.match(row.digest):
        raise CatalogueError(f"candidate image of {entry.tool} has no valid digest")
    return ResolvedImage(
        reference=f"{row.image}@{row.digest}", name=row.image, tag=row.tag, digest=row.digest,
        source="candidate",
    )  # fmt: skip


async def image_override(
    session: AsyncSession, entry: CatalogueEntry, job_options: Mapping[str, Any] | None = None
) -> ResolvedImage | None:
    """An approved, active ``ImageVersion`` row replaces the catalogue's image for its tool.

    A regression-test candidate (``job_options["image_candidates"]``, see ``_candidate_override``) wins
    over the approved row, but only for the scans that carry its token.
    """
    from securescan.db.models.images import ImageVersion

    candidate = await _candidate_override(session, entry, job_options)
    if candidate is not None:
        return candidate
    # Entries that share one image lock (Grype's scan, database update and status entries) share the approved
    # image: the row is stored under the primary tool and carries the lock name in its detail.
    same_image = ImageVersion.tool == entry.tool
    if entry.image.lock:
        same_image = or_(same_image, ImageVersion.regression_detail.op("->>")("lock_name") == entry.image.lock)
    row = await session.scalar(
        select(ImageVersion)
        .where(
            same_image,
            ImageVersion.active.is_(True),
            ImageVersion.approved_at.is_not(None),
        )
        .order_by(ImageVersion.approved_at.desc())
        .limit(1)
    )
    if row is None:
        return None
    if not _DIGEST.match(row.digest):
        raise CatalogueError(f"approved image of {entry.tool} has no valid digest")
    return ResolvedImage(
        reference=f"{row.image}@{row.digest}", name=row.image, tag=row.tag, digest=row.digest,
        source="override",
    )  # fmt: skip


async def resolve_image_with_override(
    session: AsyncSession,
    entry: CatalogueEntry,
    settings: Settings | None = None,
    job_options: Mapping[str, Any] | None = None,
) -> ResolvedImage:
    """Precedence: regression candidate (token-bound) > approved ImageVersion > env > catalogue > lock."""
    override = await image_override(session, entry, job_options)
    if override is not None:
        return override
    return resolve_image(entry, settings=settings)


# ----------------------------------------------------------------------------- loading
def find_scanners_dir(settings: Settings | None = None) -> Path | None:
    """The directory holding ``catalogue.yaml``: the setting, else the usual places."""
    cfg = settings or get_settings()
    candidates: list[Path] = []
    if cfg.scanners_dir:
        candidates.append(Path(cfg.scanners_dir))
    candidates.append(Path(__file__).resolve().parents[3] / "scanners")
    candidates.append(Path("/app/scanners"))
    candidates.append(Path.cwd() / "scanners")
    candidates.append(Path.cwd().parent / "scanners")
    for candidate in candidates:
        if (candidate / "catalogue.yaml").is_file():
            return candidate
    return None


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CatalogueError(f"cannot read {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise CatalogueError(f"{path} must contain a mapping")
    return data


def parse_catalogue(documents: Sequence[tuple[str, dict[str, Any]]]) -> dict[str, CatalogueEntry]:
    """Validate ``(source name, parsed document)`` pairs and merge them; a tool defined twice is an error."""
    entries: dict[str, CatalogueEntry] = {}
    origin: dict[str, str] = {}
    for source, document in documents:
        version = document.get("schema_version", 1)
        if version != 1:
            raise CatalogueError(f"{source}: unsupported schema_version {version!r}")
        scanners = document.get("scanners", [])
        if not isinstance(scanners, list):
            raise CatalogueError(f"{source}: 'scanners' must be a list")
        for raw in scanners:
            try:
                entry = CatalogueEntry.model_validate(raw)
            except ValidationError as exc:
                name = raw.get("tool", "?") if isinstance(raw, dict) else "?"
                raise CatalogueError(f"{source}: scanner {name}: {_summarise(exc)}") from exc
            if entry.tool in entries:
                raise CatalogueError(
                    f"{source}: tool {entry.tool} is already defined in {origin[entry.tool]}"
                )
            entries[entry.tool] = entry
            origin[entry.tool] = source
    return entries


def _summarise(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors():
        location = ".".join(str(p) for p in error.get("loc", ()))
        parts.append(f"{location}: {error.get('msg', 'invalid')}")
    return "; ".join(parts)


def load_catalogue_from(directory: Path) -> dict[str, CatalogueEntry]:
    """Load ``catalogue.yaml`` and ``catalogue.d/*.yaml`` from ``directory`` (not cached)."""
    main = directory / "catalogue.yaml"
    if not main.is_file():
        raise CatalogueError(f"{main} does not exist")
    documents: list[tuple[str, dict[str, Any]]] = [(main.name, _read_yaml(main))]
    extra_dir = directory / "catalogue.d"
    if extra_dir.is_dir():
        for path in sorted(extra_dir.glob("*.yaml")):
            documents.append((f"catalogue.d/{path.name}", _read_yaml(path)))
    return parse_catalogue(documents)


@lru_cache(maxsize=8)
def _load_cached(directory: str) -> dict[str, CatalogueEntry]:
    return load_catalogue_from(Path(directory))


def load_catalogue() -> dict[str, CatalogueEntry]:
    """The merged catalogue (cached per directory). Raises ``CatalogueError`` when it cannot be found."""
    directory = find_scanners_dir()
    if directory is None:
        raise CatalogueError("scanners/catalogue.yaml not found (set SECURESCAN_SCANNERS_DIR)")
    return _load_cached(str(directory))


def clear_catalogue_cache() -> None:
    _load_cached.cache_clear()


def catalogue_available() -> bool:
    """True when a catalogue can be loaded (the api container may not ship it)."""
    try:
        load_catalogue()
    except CatalogueError:
        return False
    return True


def get_entry(tool: str) -> CatalogueEntry:
    entries = load_catalogue()
    if tool not in entries:
        raise CatalogueError(f"tool {tool!r} is not in the scanner catalogue")
    return entries[tool]
