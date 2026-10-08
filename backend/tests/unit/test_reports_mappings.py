from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from securescan.domain import mappings

MAPPING_DIR = Path(mappings.MAPPINGS_DIR)


def _raw(name: str) -> dict[str, object]:
    with (MAPPING_DIR / name).open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    assert isinstance(data, dict)
    return data


def test_files_state_their_source_in_a_header_comment() -> None:
    for name, needle in (
        ("owasp-top10-2021.yaml", "https://owasp.org/Top10/"),
        ("cwe-top25-2024.yaml", "https://cwe.mitre.org/top25/"),
    ):
        head = "\n".join((MAPPING_DIR / name).read_text(encoding="utf-8").splitlines()[:12])
        assert head.startswith("#")
        assert needle in head


def test_file_names_match_the_edition_inside() -> None:
    for path in MAPPING_DIR.glob("*.yaml"):
        year = re.search(r"-(\d{4})\.yaml$", path.name)
        assert year, path.name
        assert _raw(path.name)["version"] == year.group(1)


def test_owasp_has_the_ten_categories_in_order() -> None:
    categories = mappings.owasp_categories()
    assert [c.id for c in categories] == [f"A{n:02d}" for n in range(1, 11)]
    assert mappings.owasp_mapping().version == "2021"
    assert all(c.name and c.cwes for c in categories)
    assert sum(len(c.cwes) for c in categories) > 150


def test_a_cwe_is_in_at_most_one_owasp_category() -> None:
    counter: Counter[int] = Counter()
    for category in _raw("owasp-top10-2021.yaml")["categories"]:  # type: ignore[attr-defined]
        counter.update(category["cwes"])
    assert [cwe for cwe, n in counter.items() if n > 1] == []


@pytest.mark.parametrize(
    ("cwe", "category"),
    [
        (22, "A01"),
        (352, "A01"),
        (862, "A01"),
        (327, "A02"),
        (319, "A02"),
        (79, "A03"),
        (89, "A03"),
        (78, "A03"),
        (434, "A04"),
        (16, "A05"),
        (611, "A05"),
        (1104, "A06"),
        (287, "A07"),
        (798, "A07"),
        (259, "A07"),
        (502, "A08"),
        (117, "A09"),
        (778, "A09"),
        (918, "A10"),
    ],
)
def test_owasp_spot_checks(cwe: int, category: str) -> None:
    found = mappings.owasp_category_for_cwe(cwe)
    assert found is not None
    assert found.id == category


def test_unmapped_and_missing_cwes() -> None:
    assert mappings.owasp_category_for_cwe(999999) is None
    assert mappings.owasp_category_for_cwe(None) is None
    assert mappings.top25_entry_for_cwe(None) is None


def test_owasp_a06_and_a10_are_complete() -> None:
    by_id = {c.id: c for c in mappings.owasp_categories()}
    assert by_id["A06"].cwes == [937, 1035, 1104]
    assert by_id["A10"].cwes == [918]


def test_top25_is_a_complete_ranking() -> None:
    entries = mappings.top25_entries()
    assert [e.rank for e in entries] == list(range(1, 26))
    assert len({e.cwe for e in entries}) == 25
    assert mappings.top25_mapping().version == "2024"
    assert (entries[0].cwe, entries[1].cwe, entries[2].cwe) == (79, 787, 89)


def test_top25_lookup() -> None:
    entry = mappings.top25_entry_for_cwe(89)
    assert entry is not None and entry.rank == 3
    assert "SQL" in entry.name
    assert mappings.top25_entry_for_cwe(1) is None


def test_mapping_versions_are_recorded() -> None:
    assert mappings.mapping_versions() == {"owasp_top10": "2021", "cwe_top25": "2024"}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (79, 79),
        ("79", 79),
        ("CWE-79", 79),
        (" cwe-1021 ", 1021),
        (0, None),
        ("", None),
        (None, None),
        (True, None),
        ("none", None),
    ],
)
def test_parse_cwe(value: object, expected: int | None) -> None:
    assert mappings.parse_cwe(value) == expected


def test_a_file_that_lists_a_cwe_twice_is_rejected() -> None:
    data = {
        "standard": "x",
        "version": "1",
        "source": "y",
        "categories": [
            {"id": "A01", "name": "One", "cwes": [1, 2]},
            {"id": "A02", "name": "Two", "cwes": [2, 3]},
        ],
    }
    with pytest.raises(ValidationError):
        mappings.OwaspMapping.model_validate(data)


def test_the_highest_year_wins(tmp_path: Path) -> None:
    (tmp_path / "cwe-top25-2023.yaml").write_text("x", encoding="utf-8")
    (tmp_path / "cwe-top25-2025.yaml").write_text("x", encoding="utf-8")
    assert mappings._latest_file("cwe-top25", tmp_path).name == "cwe-top25-2025.yaml"
    with pytest.raises(mappings.MappingError):
        mappings._latest_file("owasp-top10", tmp_path)
