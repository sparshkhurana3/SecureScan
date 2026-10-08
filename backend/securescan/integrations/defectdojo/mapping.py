"""How SecureScan objects map to DefectDojo objects (design: "Object mapping").

| SecureScan                | DefectDojo                                   |
| Internal / Vendor         | Product Type ("Organization")                |
| Application               | Product ("Asset"), named like the application |
| Application version       | Engagement, named like the version label     |
| Tool within a version     | Test, titled ``<tool>:<version label>``      |
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from securescan.config import get_settings
from securescan.db.models.enums import AppType

INTERNAL_PRODUCT_TYPE = "Internal Applications"
VENDOR_PRODUCT_TYPE = "Vendor Applications"
PRODUCT_TYPES = (INTERNAL_PRODUCT_TYPE, VENDOR_PRODUCT_TYPE)

_CONTENT_TYPES = {
    ".json": "application/json",
    ".jsonl": "application/json",
    ".xml": "application/xml",
    ".zip": "application/zip",
    ".csv": "text/csv",
    ".sarif": "application/json",
    ".html": "text/html",
}


def product_type_for(app_type: AppType) -> str:
    return VENDOR_PRODUCT_TYPE if app_type == AppType.VENDOR else INTERNAL_PRODUCT_TYPE


def title_for_test(tool: str, version_label: str) -> str:
    """``<tool>:<version label>``; one Test per tool and version, re-imported on every scan."""
    return f"{tool}:{version_label}"[:255]


@dataclass(frozen=True)
class ImportNames:
    product_type: str
    product: str
    engagement: str
    test_title: str


def import_names(app_type: AppType, application_name: str, version_label: str, tool: str) -> ImportNames:
    return ImportNames(
        product_type=product_type_for(app_type),
        product=application_name[:255],
        engagement=version_label[:255],
        test_title=title_for_test(tool, version_label),
    )


def branch_or_tag(label: str, label_kind: str | None) -> str | None:
    """DefectDojo's ``branch_tag`` is meaningful for branch and tag labels only."""
    return label if label_kind in ("branch", "tag") else None


def import_tags(scan_id: Any, tool: str) -> tuple[str, ...]:
    """Test tags (reimport overwrites them): the SecureScan scan that last updated the Test."""
    return (f"securescan-scan:{scan_id}", f"tool:{tool}")


def product_tags(application_id: Any) -> list[str]:
    return [f"securescan-app:{application_id}"]


def content_type_for(filename: str) -> str:
    return _CONTENT_TYPES.get(Path(filename).suffix.lower(), "application/octet-stream")


def defectdojo_link(path: str) -> str:
    """A link into DefectDojo's UI on the public (gateway) host."""
    return get_settings().defectdojo_public_url.rstrip("/") + "/" + path.lstrip("/")


def link_to_test(test_id: int | None) -> str | None:
    return defectdojo_link(f"test/{test_id}") if test_id else None


def engagement_link(engagement_id: int | None) -> str | None:
    return defectdojo_link(f"engagement/{engagement_id}") if engagement_id else None


def product_link(product_id: int | None) -> str | None:
    return defectdojo_link(f"product/{product_id}") if product_id else None
