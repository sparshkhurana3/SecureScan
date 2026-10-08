"""Output validation: exists, regular file, under max_mb, well-formed JSON or XML."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from securescan.runner import validate
from securescan.runner.validate import structural_json_check, validate_outputs
from tests.unit.runner_helpers import make_entry


def entry_with(*outputs: dict[str, object]):  # type: ignore[no-untyped-def]
    return make_entry(outputs=list(outputs))


def test_valid_json_report_is_accepted(tmp_path: Path) -> None:
    (tmp_path / "report.json").write_text(json.dumps({"results": [1, 2, 3]}), encoding="utf-8")
    result = validate_outputs(entry_with({"file": "report.json", "max_mb": 1}), tmp_path)
    assert result.ok and len(result.outputs) == 1
    assert result.outputs[0].path == tmp_path / "report.json" and result.outputs[0].size > 0


def test_missing_required_report_fails_with_a_clear_reason(tmp_path: Path) -> None:
    result = validate_outputs(entry_with({"file": "report.json"}), tmp_path)
    assert not result.ok
    assert result.problems[0].code == "missing"
    assert "report.json" in result.reason() and "not produced" in result.reason()


def test_missing_optional_report_is_fine(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_text("[]", encoding="utf-8")
    result = validate_outputs(
        entry_with({"file": "a.json"}, {"file": "b.sarif", "required": False}), tmp_path
    )
    assert result.ok and [o.spec.file for o in result.outputs] == ["a.json"]


def test_malformed_json_fails(tmp_path: Path) -> None:
    (tmp_path / "report.json").write_text('{"results": [1, 2', encoding="utf-8")
    result = validate_outputs(entry_with({"file": "report.json"}), tmp_path)
    assert [p.code for p in result.problems] == ["malformed"]
    assert "not valid JSON" in result.reason()


def test_empty_report_fails(tmp_path: Path) -> None:
    (tmp_path / "report.json").write_bytes(b"")
    result = validate_outputs(entry_with({"file": "report.json"}), tmp_path)
    assert [p.code for p in result.problems] == ["empty"]


def test_oversized_report_fails(tmp_path: Path) -> None:
    (tmp_path / "report.json").write_bytes(b"[" + b"1," * 600_000 + b"1]")  # about 1.2 MB
    result = validate_outputs(entry_with({"file": "report.json", "max_mb": 1}), tmp_path)
    assert [p.code for p in result.problems] == ["too_large"]
    assert "1 MB" in result.reason()


def test_a_symlink_planted_by_the_container_is_not_followed(tmp_path: Path) -> None:
    secret = tmp_path / "secret.json"
    secret.write_text('{"worker": "file"}', encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    try:
        os.symlink(secret, out / "report.json")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")
    result = validate_outputs(entry_with({"file": "report.json"}), out)
    assert [p.code for p in result.problems] == ["not_regular"]
    (out / "report.json").unlink()
    (out / "report.json").mkdir()
    assert [p.code for p in validate_outputs(entry_with({"file": "report.json"}), out).problems] == ["not_regular"]


def test_format_none_only_checks_existence_and_size(tmp_path: Path) -> None:
    (tmp_path / "x.txt").write_text("plain", encoding="utf-8")
    assert validate_outputs(entry_with({"file": "x.txt", "format": "none"}), tmp_path).ok
    (tmp_path / "y.txt").write_text("", encoding="utf-8")
    assert validate_outputs(entry_with({"file": "y.txt", "format": "none"}), tmp_path).ok


def test_nested_output_paths(tmp_path: Path) -> None:
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "r.json").write_text("{}", encoding="utf-8")
    assert validate_outputs(entry_with({"file": "reports/r.json"}), tmp_path).ok


# --------------------------------------------------------------------------- xml
def test_valid_xml_is_accepted(tmp_path: Path) -> None:
    (tmp_path / "r.xml").write_text("<?xml version='1.0'?><report><item id='1'/></report>", encoding="utf-8")
    assert validate_outputs(entry_with({"file": "r.xml", "format": "xml"}), tmp_path).ok


def test_malformed_xml_fails(tmp_path: Path) -> None:
    (tmp_path / "r.xml").write_text("<report><item></report>", encoding="utf-8")
    result = validate_outputs(entry_with({"file": "r.xml", "format": "xml"}), tmp_path)
    assert [p.code for p in result.problems] == ["malformed"]


def test_xml_entity_declarations_are_refused(tmp_path: Path) -> None:
    bomb = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><r>&a;</r>'
    (tmp_path / "r.xml").write_text(bomb, encoding="utf-8")
    result = validate_outputs(entry_with({"file": "r.xml", "format": "xml"}), tmp_path)
    assert [p.code for p in result.problems] == ["malformed"]
    assert "entity" in result.reason()


# --------------------------------------------------------------------------- the large-file path
@pytest.mark.parametrize(
    "text",
    [
        '{"a": [1, 2, {"b": "]["}], "c": "}"}',
        "[]",
        "  [\n {\"k\": \"v\\\"}\"} \n]  \n",
        "[[], [[]], {}]",
    ],
)
def test_structural_check_accepts_balanced_documents(text: str) -> None:
    assert structural_json_check(text.encode("utf-8")) is None


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ('{"a": [1, 2}', "match"),
        ('{"a": [1, 2]', "closed"),
        ("[1, 2]]", "match"),
        ("42", "top level"),
        ('"text"', "top level"),
        ("", "empty"),
        ("   ", "empty"),
        ('{"a": 1} trailing', "end"),
    ],
)
def test_structural_check_rejects_broken_documents(text: str, reason: str) -> None:
    message = structural_json_check(text.encode("utf-8"))
    assert message is not None and reason in message


def test_large_files_take_the_constant_memory_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validate, "FULL_PARSE_BYTES", 10)
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"results": [{"x": i} for i in range(50)]}), encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text('{"results": [{"x": 1}, {"x": 2}', encoding="utf-8")
    assert validate_outputs(entry_with({"file": "good.json"}), tmp_path).ok
    result = validate_outputs(entry_with({"file": "bad.json"}), tmp_path)
    assert [p.code for p in result.problems] == ["malformed"]
