"""Scan profiles: validation of the YAML, per-tool settings files and the seeding used by ``migrate``.

A *scan profile* is versioned YAML stored in the ``scan_profiles`` table (immutable per name and version):

.. code-block:: yaml

    profile: code-standard
    version: 1
    kind: sast                    # sast | dast
    description: Semgrep and Gitleaks
    jobs:
      - tool: semgrep
        timeout_min: 60           # optional overrides of the catalogue (bounded)
        limits: {cpus: 2, memory: 4g}
        options: {exclude: ["*.generated.js"]}
      - tool: gitleaks
    verdict:
      fail_on: {critical: 1, high: 5}

A *tool settings file* (``scanners/profiles/<tool>.yaml`` with a top-level ``tool:`` key, for example the
Semgrep exclusion list) is not a profile and is never seeded as one.

Profile limits can only stay within fixed ceilings (``MAX_*`` below); the container itself is still built
only from the catalogue.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.logging import get_logger
from securescan.runner.catalogue import (
    CatalogueError,
    find_scanners_dir,
    load_catalogue,
)
from securescan.runner.specs import parse_size

log = get_logger(__name__)

MAX_CPUS = 16.0
MAX_MEMORY_BYTES = 32 * 1024**3
MAX_PIDS = 8192
MAX_TIMEOUT_MINUTES = 12 * 60
MAX_OPTIONS_KEYS = 50
SEVERITIES = ("critical", "high", "medium", "low", "info")
_SLUG = r"^[a-z0-9][a-z0-9-]{1,98}$"


class ProfileError(Exception):
    """The profile YAML is invalid. ``errors`` lists plain-language problems."""

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or [message]


class JobLimitOverrides(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cpus: float | None = Field(default=None, gt=0, le=MAX_CPUS)
    memory: str | None = None
    pids: int | None = Field(default=None, ge=16, le=MAX_PIDS)

    @field_validator("memory")
    @classmethod
    def _memory(cls, value: str | None) -> str | None:
        if value is not None:
            if parse_size(value) > MAX_MEMORY_BYTES:
                raise ValueError("memory is limited to 32g")
        return value


class ProfileJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    timeout_min: int | None = Field(default=None, ge=1, le=MAX_TIMEOUT_MINUTES)
    limits: JobLimitOverrides | None = None
    options: dict[str, Any] = Field(default_factory=dict)

    @field_validator("options")
    @classmethod
    def _options(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > MAX_OPTIONS_KEYS:
            raise ValueError("too many options")
        for key in value:
            if not isinstance(key, str) or not key.replace("_", "").isalnum():
                raise ValueError(f"option name {key!r} is not allowed")
        return value

    def job_options(self) -> dict[str, Any]:
        """What is stored on the ScanJob: overrides in the form the tool builders read."""
        result: dict[str, Any] = dict(self.options)
        if self.timeout_min is not None:
            result["timeout_minutes"] = self.timeout_min
        if self.limits is not None:
            limits = self.limits.model_dump(exclude_none=True)
            if limits:
                result["limits"] = limits
        return result


class VerdictSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fail_on: dict[str, int] = Field(default_factory=dict)

    @field_validator("fail_on")
    @classmethod
    def _fail_on(cls, value: dict[str, int]) -> dict[str, int]:
        for severity, count in value.items():
            if severity not in SEVERITIES:
                raise ValueError(f"unknown severity {severity!r}")
            if count < 0:
                raise ValueError("thresholds cannot be negative")
        return value


class ProfileDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: str = Field(pattern=_SLUG)
    version: int | None = Field(default=None, ge=1)
    kind: Literal["sast", "dast"]
    mode: Literal["baseline", "full", "api", "nuclei"] | None = None
    description: str | None = Field(default=None, max_length=2000)
    jobs: list[ProfileJob] = Field(min_length=1, max_length=20)
    verdict: VerdictSpec | None = None

    @model_validator(mode="after")
    def _consistent(self) -> ProfileDoc:
        tools = [job.tool for job in self.jobs]
        if len(set(tools)) != len(tools):
            raise ValueError("a tool can appear once in a profile")
        if self.kind == "dast" and self.mode is None:
            raise ValueError("a dast profile needs a mode (baseline, full, api or nuclei)")
        if self.kind == "sast" and self.mode is not None:
            raise ValueError("only dast profiles have a mode")
        return self

    @property
    def tools(self) -> list[str]:
        return [job.tool for job in self.jobs]

    def job(self, tool: str) -> ProfileJob | None:
        for job in self.jobs:
            if job.tool == tool:
                return job
        return None


def _problems(exc: ValidationError) -> list[str]:
    result: list[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ()))
        message = str(error.get("msg", "invalid")).removeprefix("Value error, ")
        result.append(f"{location}: {message}" if location else message)
    return result


def parse_profile_yaml(text: str) -> ProfileDoc:
    """Parse and validate profile YAML (structure only). Raises ``ProfileError``."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ProfileError("The YAML cannot be read.", [f"YAML: {str(exc)[:200]}"]) from exc
    if not isinstance(data, dict):
        raise ProfileError("The profile must be a YAML mapping.")
    try:
        return ProfileDoc.model_validate(data)
    except ValidationError as exc:
        problems = _problems(exc)
        raise ProfileError("The profile is not valid: " + "; ".join(problems[:5]), problems) from exc


def check_against_catalogue(doc: ProfileDoc) -> list[str]:
    """Problems with tools that are not in the catalogue or have no builder ([] when none or no catalogue)."""
    try:
        catalogue = load_catalogue()
    except CatalogueError:
        log.warning("profile_catalogue_unavailable")
        return []
    from securescan.runner.tools import registered_tools

    builders = set(registered_tools())
    problems: list[str] = []
    for job in doc.jobs:
        entry = catalogue.get(job.tool)
        if entry is None:
            problems.append(f"jobs: tool {job.tool!r} is not in the scanner catalogue")
        elif job.tool not in builders:
            problems.append(f"jobs: tool {job.tool!r} has no command builder yet")
        elif job.timeout_min is not None and job.timeout_min < 1:
            problems.append(f"jobs: {job.tool}: timeout_min must be positive")
    return problems


def validate_profile_yaml(text: str, *, check_catalogue: bool = True) -> ProfileDoc:
    """Full validation used by ``POST /profiles``: structure, then the tools against the catalogue."""
    doc = parse_profile_yaml(text)
    if check_catalogue:
        problems = check_against_catalogue(doc)
        if problems:
            raise ProfileError("The profile is not valid: " + "; ".join(problems[:5]), problems)
    return doc


def profile_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def profile_body(doc: ProfileDoc, version: int) -> dict[str, Any]:
    """The JSON stored in ``ScanProfile.body`` (what scan creation reads)."""
    body = doc.model_dump(mode="json", exclude_none=True)
    body["version"] = version
    return body


# --------------------------------------------------------------------------- tool settings files
def profiles_dir(scanners_dir: Path | None = None) -> Path | None:
    base = scanners_dir or find_scanners_dir()
    if base is None:
        return None
    directory = base / "profiles"
    return directory if directory.is_dir() else None


def load_tool_settings(tool: str, scanners_dir: Path | None = None) -> dict[str, Any]:
    """``scanners/profiles/<tool>.yaml`` when it carries ``tool: <tool>``; else an empty mapping."""
    directory = profiles_dir(scanners_dir)
    if directory is None:
        return {}
    path = directory / f"{tool}.yaml"
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ProfileError(f"{path.name} cannot be read: {str(exc)[:120]}") from exc
    if not isinstance(data, dict) or data.get("tool") != tool:
        return {}
    return data


def string_list(value: Any, what: str) -> list[str]:
    """A list of non-empty strings, or ``ProfileError``."""
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ProfileError(f"{what} must be a list of non-empty strings")
    return [v.strip() for v in value]


# --------------------------------------------------------------------------- seeding
async def seed_profiles(session: AsyncSession, scanners_dir: Path | None = None) -> list[str]:
    """Insert every ``scanners/profiles/*.yaml`` scan profile that is not yet in the table.

    Idempotent. A profile that exists (same name and version) is never overwritten: to roll out a
    change, raise ``version`` in the file. Returns the ``name@version`` strings that were inserted.
    """
    from securescan.db.models.profiles import ScanProfile
    from securescan.util import new_id, utcnow

    directory = profiles_dir(scanners_dir)
    if directory is None:
        log.warning("profiles_directory_not_found")
        return []
    inserted: list[str] = []
    for path in sorted(directory.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            log.warning("profile_file_unreadable", file=path.name)
            continue
        if not isinstance(data, dict) or "profile" not in data:
            continue  # a tool settings file
        try:
            doc = parse_profile_yaml(text)
        except ProfileError as exc:
            log.warning("profile_file_invalid", file=path.name, error=str(exc)[:200])
            continue
        version = doc.version or 1
        existing = await session.scalar(
            select(ScanProfile).where(ScanProfile.name == doc.profile, ScanProfile.version == version)
        )
        sha = profile_sha256(text)
        if existing is not None:
            if existing.sha256 != sha:
                log.warning(
                    "profile_file_changed_without_version", profile=doc.profile, version=version
                )
            continue
        now = utcnow()
        session.add(
            ScanProfile(
                id=new_id(),
                name=doc.profile,
                version=version,
                kind=doc.kind,
                description=doc.description,
                body_yaml=text,
                body=profile_body(doc, version),
                sha256=sha,
                active=True,
                created_by_id=None,
                created_at=now,
            )
        )
        inserted.append(f"{doc.profile}@{version}")
    await session.flush()
    return inserted
