"""CWE to OWASP Top 10 and CWE Top 25 lookups.

The tables live in ``securescan/reports/mappings/*.yaml`` (``owasp-top10-<year>.yaml`` and
``cwe-top25-<year>.yaml``); the highest year present is used. Each file cites its source and version
in its header. ``mapping_versions()`` is stored with every report so an old report can say which
editions it used.

A CWE belongs to at most one OWASP category (the loader rejects a file that lists a CWE twice).
Findings without a usable CWE are bucketed by the report builder, not here.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "reports" / "mappings"

_YEAR_RE = re.compile(r"-(\d{4})\.yaml$")


class MappingError(Exception):
    """A mapping file is missing or inconsistent."""


class OwaspCategory(BaseModel):
    id: str
    name: str
    url: str = ""
    cwes: list[int] = Field(default_factory=list)


class OwaspMapping(BaseModel):
    schema_version: int = Field(default=1, alias="schema")
    standard: str
    version: str
    source: str
    categories: list[OwaspCategory]

    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="after")
    def _unique_cwes(self) -> OwaspMapping:
        seen: dict[int, str] = {}
        ids: set[str] = set()
        for category in self.categories:
            if category.id in ids:
                raise ValueError(f"category {category.id} listed twice")
            ids.add(category.id)
            for cwe in category.cwes:
                if cwe in seen:
                    raise ValueError(f"CWE-{cwe} is in both {seen[cwe]} and {category.id}")
                seen[cwe] = category.id
        return self

    def index(self) -> dict[int, OwaspCategory]:
        return {cwe: category for category in self.categories for cwe in category.cwes}


class Top25Entry(BaseModel):
    rank: int
    cwe: int
    name: str


class Top25Mapping(BaseModel):
    schema_version: int = Field(default=1, alias="schema")
    standard: str
    version: str
    source: str
    entries: list[Top25Entry]

    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="after")
    def _unique(self) -> Top25Mapping:
        cwes = [e.cwe for e in self.entries]
        ranks = [e.rank for e in self.entries]
        if len(set(cwes)) != len(cwes):
            raise ValueError("a CWE is listed twice in the Top 25")
        if len(set(ranks)) != len(ranks):
            raise ValueError("a rank is used twice in the Top 25")
        return self


def _latest_file(prefix: str, directory: Path) -> Path:
    candidates: list[tuple[int, Path]] = []
    for path in directory.glob(f"{prefix}-*.yaml"):
        match = _YEAR_RE.search(path.name)
        if match:
            candidates.append((int(match.group(1)), path))
    if not candidates:
        raise MappingError(f"no {prefix}-<year>.yaml file in {directory}")
    candidates.sort()
    return candidates[-1][1]


def _read_yaml(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise MappingError(f"{path.name} is not a mapping")
    return data


def load_owasp_file(path: Path) -> OwaspMapping:
    return OwaspMapping.model_validate(_read_yaml(path))


def load_top25_file(path: Path) -> Top25Mapping:
    return Top25Mapping.model_validate(_read_yaml(path))


@lru_cache(maxsize=1)
def owasp_mapping() -> OwaspMapping:
    return load_owasp_file(_latest_file("owasp-top10", MAPPINGS_DIR))


@lru_cache(maxsize=1)
def top25_mapping() -> Top25Mapping:
    return load_top25_file(_latest_file("cwe-top25", MAPPINGS_DIR))


@lru_cache(maxsize=1)
def _owasp_index() -> dict[int, OwaspCategory]:
    return owasp_mapping().index()


@lru_cache(maxsize=1)
def _top25_index() -> dict[int, Top25Entry]:
    return {entry.cwe: entry for entry in top25_mapping().entries}


def owasp_categories() -> list[OwaspCategory]:
    """All ten categories in order (A01 first)."""
    return list(owasp_mapping().categories)


def owasp_category_for_cwe(cwe: int | None) -> OwaspCategory | None:
    """The OWASP Top 10 category of a CWE, or None when the CWE is not mapped."""
    if cwe is None:
        return None
    return _owasp_index().get(int(cwe))


def top25_entry_for_cwe(cwe: int | None) -> Top25Entry | None:
    """The CWE Top 25 entry of a CWE, or None when it is not in the list."""
    if cwe is None:
        return None
    return _top25_index().get(int(cwe))


def top25_entries() -> list[Top25Entry]:
    return sorted(top25_mapping().entries, key=lambda e: e.rank)


def mapping_versions() -> dict[str, str]:
    """Edition of each mapping, stored on every report."""
    return {"owasp_top10": owasp_mapping().version, "cwe_top25": top25_mapping().version}


def parse_cwe(value: object) -> int | None:
    """Turn ``79``, ``"79"``, ``"CWE-79"`` into an int; anything else (``0``, ``""``) into None."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    match = re.search(r"(\d+)", str(value))
    if not match:
        return None
    number = int(match.group(1))
    return number if number > 0 else None


def clear_caches() -> None:
    """For tests that point ``MAPPINGS_DIR`` somewhere else."""
    owasp_mapping.cache_clear()
    top25_mapping.cache_clear()
    _owasp_index.cache_clear()
    _top25_index.cache_clear()
