"""Shared builders for the scan runner tests (no database, no Docker, no network)."""

from __future__ import annotations

import types
import uuid
from pathlib import Path
from typing import Any

from securescan.config import Settings
from securescan.db.models.enums import TargetKind
from securescan.runner.catalogue import (
    CatalogueEntry,
    ResolvedImage,
    load_catalogue_from,
)
from securescan.runner.tools.base import ToolContext
from securescan.runner.workspace import Workspace

# backend/tests/unit/runner_helpers.py -> repository root is four levels up from this file's directory
REPO_ROOT = Path(__file__).resolve().parents[3]
REPO_SCANNERS = REPO_ROOT / "scanners"
SAMPLE_APPS = Path(__file__).resolve().parents[1] / "fixtures" / "sample-apps"
DIGEST = "sha256:" + "a" * 64


def entry_dict(**overrides: Any) -> dict[str, Any]:
    """A minimal valid catalogue entry (as parsed YAML), with fields replaced by ``overrides``."""
    base: dict[str, Any] = {
        "tool": "demo",
        "image": {"name": "example/demo", "tag": "1.0", "lock": "DEMO"},
        "mounts": [
            {"name": "src", "target": "/src", "read_only": True},
            {"name": "out", "target": "/out", "read_only": False},
        ],
        "command": ["demo", "scan", "{src}", "--output", "{out}/report.json"],
        "outputs": [{"file": "report.json", "max_mb": 5, "format": "json"}],
        "exit_codes": {"0": "completed", ">=2": "failed", "default": "failed"},
    }
    base.update(overrides)
    return base


def make_entry(**overrides: Any) -> CatalogueEntry:
    return CatalogueEntry.model_validate(entry_dict(**overrides))


def real_catalogue() -> dict[str, CatalogueEntry]:
    return load_catalogue_from(REPO_SCANNERS)


def make_image(tool: str = "demo") -> ResolvedImage:
    return ResolvedImage(
        reference=f"example/{tool}@{DIGEST}",
        name=f"example/{tool}",
        tag="1.0",
        digest=DIGEST,
        source="env",
    )


def make_ctx(
    tool: str,
    *,
    kind: TargetKind = TargetKind.ZIP,
    options: dict[str, Any] | None = None,
    settings: Settings | None = None,
    entry: CatalogueEntry | None = None,
    scanners_dir: Path | None = REPO_SCANNERS,
) -> ToolContext:
    """A ToolContext for a real catalogue entry with a real (temporary) workspace."""
    cfg = settings or Settings()
    job_id = uuid.uuid4()
    workspace = Workspace.create(job_id)
    return ToolContext(
        job=types.SimpleNamespace(id=job_id, options=options or {}),  # type: ignore[arg-type]
        scan=types.SimpleNamespace(id=uuid.uuid4(), commit_sha=None, source_ref=None),  # type: ignore[arg-type]
        version=types.SimpleNamespace(id=uuid.uuid4()),  # type: ignore[arg-type]
        target=types.SimpleNamespace(kind=kind, locator="owner/repo"),  # type: ignore[arg-type]
        workspace=workspace,
        entry=entry or real_catalogue()[tool],
        settings=cfg,
        session=None,
        options=dict(options or {}),
        image=make_image(tool),
        scanners_dir=scanners_dir,
    )
