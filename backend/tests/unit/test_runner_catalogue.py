"""Catalogue validation: placeholders, optional_args allowlist, path containment, exit codes, images."""

from __future__ import annotations

import types
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from securescan.config import Settings
from securescan.runner.catalogue import (
    CatalogueEntry,
    CatalogueError,
    OptionalArgError,
    contained_path,
    image_override,
    load_catalogue_from,
    parse_catalogue,
    resolve_image,
)
from tests.unit.conftest import FakeSession
from tests.unit.runner_helpers import DIGEST, REPO_SCANNERS, entry_dict, make_entry


# --------------------------------------------------------------------------- the shipped catalogue
def test_shipped_catalogue_has_semgrep_and_gitleaks() -> None:
    catalogue = load_catalogue_from(REPO_SCANNERS)
    assert {"semgrep", "gitleaks"} <= set(catalogue)
    for name, entry in ((n, catalogue[n]) for n in ("semgrep", "gitleaks")):  # later milestones add tools of other shapes
        assert entry.network == "none", name
        assert entry.command[0] == name
        assert entry.image.tag and entry.image.tag.lower() != "latest"
        assert entry.image.lock, "images are resolved through deploy/images.lock.yaml"
        assert entry.defectdojo_scan_type and entry.defectdojo_file
        assert entry.mount("out") is not None and entry.mount("out").read_only is False  # type: ignore[union-attr]


def test_semgrep_entry_matches_the_plan() -> None:
    entry = load_catalogue_from(REPO_SCANNERS)["semgrep"]
    assert entry.image.name == "semgrep/semgrep" and entry.image.tag == "1.179.0-nonroot"
    assert entry.user == "1000:1000"
    assert entry.max_parallel == 1 and entry.lock == "scanner" and entry.timeout_minutes == 60
    assert entry.mount_target("content") == "/content/semgrep/rules"
    assert entry.defectdojo_scan_type == "Semgrep JSON Report"
    assert entry.defectdojo_file == "semgrep.json"
    assert entry.output("semgrep.json").max_mb == 90  # type: ignore[union-attr]
    assert entry.optional_arg("--exclude") is not None


def test_gitleaks_entry_matches_the_plan() -> None:
    entry = load_catalogue_from(REPO_SCANNERS)["gitleaks"]
    assert entry.image.name == "ghcr.io/gitleaks/gitleaks"
    assert entry.defectdojo_scan_type == "Gitleaks Scan"
    assert entry.defectdojo_file == "gitleaks.json"
    assert entry.mount("config") is not None


# --------------------------------------------------------------------------- placeholders
def test_unknown_placeholder_is_rejected() -> None:
    with pytest.raises(ValidationError, match="evil"):
        make_entry(command=["demo", "{evil}"])


def test_mount_placeholder_needs_the_mount() -> None:
    with pytest.raises(ValidationError, match="config"):
        make_entry(command=["demo", "{config}/x"])


def test_builder_placeholders_are_allowed_but_need_a_value() -> None:
    entry = make_entry(command=["demo", "--url", "{target_url}", "{src}"])
    assert entry.render_command({"target_url": "https://uat.example"}) == [
        "demo",
        "--url",
        "https://uat.example",
        "/src",
    ]
    with pytest.raises(CatalogueError, match="target_url"):
        entry.render_command()


def test_placeholders_in_env_are_rejected() -> None:
    with pytest.raises(ValidationError):
        make_entry(env={"X": "{src}"})


def test_render_replaces_mount_targets() -> None:
    entry = make_entry()
    assert entry.render_command() == ["demo", "scan", "/src", "--output", "/out/report.json"]


def test_empty_command_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_entry(command=[])


# --------------------------------------------------------------------------- mounts and paths
def test_only_out_can_be_writable() -> None:
    with pytest.raises(ValidationError, match="read-only"):
        make_entry(
            mounts=[
                {"name": "src", "target": "/src", "read_only": False},
                {"name": "out", "target": "/out", "read_only": False},
            ]
        )


@pytest.mark.parametrize("target", ["src", "/a/../etc", "/", "/a\\b"])
def test_mount_targets_must_be_clean_absolute_paths(target: str) -> None:
    with pytest.raises(ValidationError):
        make_entry(
            mounts=[
                {"name": "src", "target": target, "read_only": True},
                {"name": "out", "target": "/out", "read_only": False},
            ]
        )


def test_nested_and_duplicate_mounts_are_rejected() -> None:
    with pytest.raises(ValidationError, match="nested"):
        make_entry(
            mounts=[
                {"name": "src", "target": "/src", "read_only": True},
                {"name": "out", "target": "/src/out", "read_only": False},
            ]
        )
    with pytest.raises(ValidationError, match="once"):
        make_entry(
            mounts=[
                {"name": "src", "target": "/src", "read_only": True},
                {"name": "src", "target": "/other", "read_only": True},
                {"name": "out", "target": "/out", "read_only": False},
            ]
        )
    with pytest.raises(ValidationError, match="distinct"):
        make_entry(tmpfs=[{"path": "/src", "size": "10m"}])


def test_output_files_stay_inside_out() -> None:
    for bad in ("../x.json", "/etc/passwd", "a/../../b", "a\\b", ""):
        with pytest.raises(ValidationError):
            make_entry(outputs=[{"file": bad}])
    entry = make_entry(outputs=[{"file": "reports/r.json"}, {"file": "r2.json"}])
    assert [o.file for o in entry.outputs] == ["reports/r.json", "r2.json"]


def test_outputs_need_an_out_mount() -> None:
    with pytest.raises(ValidationError, match="out"):
        make_entry(mounts=[{"name": "src", "target": "/src", "read_only": True}])


def test_defectdojo_fields_go_together_and_name_an_output() -> None:
    with pytest.raises(ValidationError):
        make_entry(defectdojo_scan_type="X Scan")
    with pytest.raises(ValidationError, match="outputs"):
        make_entry(defectdojo_scan_type="X Scan", defectdojo_file="nope.json")
    ok = make_entry(defectdojo_scan_type="X Scan", defectdojo_file="report.json")
    assert ok.defectdojo_file == "report.json"


def test_contained_path() -> None:
    assert contained_path("a/b", "/src") == "/src/a/b"
    assert contained_path("/src/a", "/src") == "/src/a"
    assert contained_path("/src", "/src") == "/src"
    for bad in ("/etc/passwd", "../x", "a/../../x", "/src/../etc", "a\\b", "", "/srcx/y"):
        with pytest.raises(OptionalArgError):
            contained_path(bad, "/src")


# --------------------------------------------------------------------------- images
def test_latest_and_bad_digests_are_rejected() -> None:
    with pytest.raises(ValidationError, match="latest"):
        make_entry(image={"name": "example/demo", "tag": "latest"})
    with pytest.raises(ValidationError, match="latest"):
        make_entry(image={"name": "example/demo", "tag": "LATEST"})
    with pytest.raises(ValidationError, match="digest"):
        make_entry(image={"name": "example/demo", "tag": "1", "digest": "sha256:abc"})
    with pytest.raises(ValidationError):
        make_entry(image={"name": "example/demo:1.0", "tag": "1"})
    with pytest.raises(ValidationError):
        make_entry(image={"name": "example/demo", "tag": "1", "lock": "lower"})


def test_image_from_environment_variable() -> None:
    entry = make_entry()
    resolved = resolve_image(
        entry, environ={"SECURESCAN_IMAGE_DEMO": f"example/demo@{DIGEST}"}, settings=Settings(env="production")
    )
    assert resolved.reference == f"example/demo@{DIGEST}"
    assert resolved.pinned and resolved.source == "env"


def test_unpinned_image_is_refused_in_production_and_allowed_in_dev() -> None:
    entry = make_entry()
    with pytest.raises(CatalogueError, match="pinned"):
        resolve_image(entry, environ={}, settings=Settings(env="production"), scanners_dir=Path("/nonexistent"))
    with pytest.raises(CatalogueError, match="digest"):
        resolve_image(
            entry,
            environ={"SECURESCAN_IMAGE_DEMO": "example/demo:1.0"},
            settings=Settings(env="production"),
        )
    dev = resolve_image(entry, environ={}, settings=Settings(env="dev"), scanners_dir=Path("/nonexistent"))
    assert dev.reference == "example/demo:1.0" and not dev.pinned


def test_digest_in_the_entry_wins_over_the_lock_file(tmp_path: Path) -> None:
    entry = make_entry(image={"name": "example/demo", "tag": "1", "digest": DIGEST, "lock": "DEMO"})
    resolved = resolve_image(entry, environ={}, settings=Settings(env="production"))
    assert resolved.reference == f"example/demo@{DIGEST}" and resolved.source == "catalogue"


def test_digest_from_the_lock_file(tmp_path: Path) -> None:
    scanners = tmp_path / "scanners"
    deploy = tmp_path / "deploy"
    scanners.mkdir()
    deploy.mkdir()
    other = "sha256:" + "c" * 64
    (deploy / "images.lock.yaml").write_text(
        yaml.safe_dump({"images": [{"name": "DEMO", "image": "example/demo", "tag": "1.0", "digest": other}]}),
        encoding="utf-8",
    )
    resolved = resolve_image(make_entry(), environ={}, settings=Settings(env="production"), scanners_dir=scanners)
    assert resolved.digest == other and resolved.source == "lock"


async def test_approved_image_version_overrides_the_catalogue() -> None:
    row = types.SimpleNamespace(image="example/demo", digest="sha256:" + "b" * 64, tag="2.0")
    resolved = await image_override(FakeSession(rows=[row]), make_entry())  # type: ignore[arg-type]
    assert resolved is not None and resolved.source == "override"
    assert resolved.reference == "example/demo@sha256:" + "b" * 64
    assert await image_override(FakeSession(), make_entry()) is None  # type: ignore[arg-type]


# --------------------------------------------------------------------------- optional_args allowlist
def _with_args(*args: dict[str, Any]) -> CatalogueEntry:
    return make_entry(optional_args=list(args))


def test_switch_not_on_the_allowlist_is_refused() -> None:
    entry = _with_args({"flag": "--exclude", "value": "pattern", "repeatable": True})
    assert entry.render_optional_args([("--exclude", "*.map"), ("--exclude", "dist/")]) == [
        "--exclude",
        "*.map",
        "--exclude",
        "dist/",
    ]
    with pytest.raises(OptionalArgError, match="allowlist"):
        entry.render_optional_args([("--config", "x")])
    with pytest.raises(OptionalArgError, match="allowlist"):
        make_entry().render_optional_args([("--exclude", "x")])


def test_pattern_values_are_checked() -> None:
    entry = _with_args({"flag": "--exclude", "value": "pattern", "repeatable": True, "max_length": 20})
    for bad in ("-rf", "", "x" * 21, "a\nb", "a\x00b"):
        with pytest.raises(OptionalArgError):
            entry.render_optional_args([("--exclude", bad)])
    with pytest.raises(OptionalArgError, match="needs a value"):
        entry.render_optional_args([("--exclude", None)])


def test_non_repeatable_and_count_limits() -> None:
    entry = _with_args({"flag": "--one", "value": "pattern"}, {"flag": "--many", "value": "pattern", "repeatable": True, "max_count": 2})
    with pytest.raises(OptionalArgError, match="once"):
        entry.render_optional_args([("--one", "a"), ("--one", "b")])
    with pytest.raises(OptionalArgError, match="more than 2"):
        entry.render_optional_args([("--many", "a"), ("--many", "b"), ("--many", "c")])


def test_switch_kinds() -> None:
    entry = _with_args(
        {"flag": "--verbose"},
        {"flag": "--level", "value": "choice", "choices": ["low", "high"]},
        {"flag": "--depth", "value": "int"},
        {"flag": "--fixed", "value": "fixed", "fixed_value": "yes"},
        {"flag": "--rules", "value": "path", "path_root": "src"},
    )
    assert entry.render_optional_args([("--verbose", None)]) == ["--verbose"]
    with pytest.raises(OptionalArgError, match="no value"):
        entry.render_optional_args([("--verbose", "x")])
    assert entry.render_optional_args([("--level", "low")]) == ["--level", "low"]
    with pytest.raises(OptionalArgError):
        entry.render_optional_args([("--level", "medium")])
    assert entry.render_optional_args([("--depth", "3")]) == ["--depth", "3"]
    with pytest.raises(OptionalArgError):
        entry.render_optional_args([("--depth", "3; rm")])
    assert entry.render_optional_args([("--fixed", None)]) == ["--fixed", "yes"]
    assert entry.render_optional_args([("--rules", "sub/dir")]) == ["--rules", "/src/sub/dir"]
    with pytest.raises(OptionalArgError):
        entry.render_optional_args([("--rules", "/etc")])
    with pytest.raises(OptionalArgError):
        entry.render_optional_args([("--rules", "../../etc")])


def test_inconsistent_optional_arg_definitions_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _with_args({"flag": "--x", "value": "path"})
    with pytest.raises(ValidationError):
        _with_args({"flag": "--x", "value": "choice"})
    with pytest.raises(ValidationError):
        _with_args({"flag": "--x", "value": "fixed"})
    with pytest.raises(ValidationError):
        _with_args({"flag": "rm -rf"})
    with pytest.raises(ValidationError, match="unique"):
        _with_args({"flag": "--x"}, {"flag": "--x"})
    with pytest.raises(ValidationError, match="missing mount"):
        make_entry(
            mounts=[{"name": "src", "target": "/src", "read_only": True}],
            command=["demo", "{src}"],
            outputs=[],
            optional_args=[{"flag": "--x", "value": "path", "path_root": "out"}],
        )


# --------------------------------------------------------------------------- exit codes
def test_exit_code_mapping_uses_exact_then_threshold_then_default() -> None:
    entry = make_entry(exit_codes={"0": "completed", "3": "completed_partial", ">=10": "failed", "default": "completed_partial"})
    assert entry.outcome_for(0) == "completed"
    assert entry.outcome_for(3) == "completed_partial"
    assert entry.outcome_for(10) == "failed"
    assert entry.outcome_for(200) == "failed"
    assert entry.outcome_for(4) == "completed_partial"  # default
    assert entry.outcome_for(None) == "failed"  # no exit code is never a success


def test_exit_code_keys_are_validated() -> None:
    for bad in ("x", "-1", "1.5", ">2", "0-5"):
        with pytest.raises(ValidationError):
            make_entry(exit_codes={bad: "completed"})
    with pytest.raises(ValidationError):
        make_entry(exit_codes={"0": "success"})


@pytest.mark.parametrize(
    ("tool", "code", "expected"),
    [
        ("semgrep", 0, "completed"),
        ("semgrep", 1, "completed"),
        ("semgrep", 2, "failed"),
        ("semgrep", 7, "failed"),
        ("semgrep", 137, "failed"),
        ("gitleaks", 0, "completed"),
        ("gitleaks", 2, "completed"),
        ("gitleaks", 1, "failed"),
        ("gitleaks", 126, "failed"),
        ("gitleaks", 3, "failed"),
        ("gitleaks", 137, "failed"),
    ],
)
def test_shipped_exit_code_mapping(tool: str, code: int, expected: str) -> None:
    assert load_catalogue_from(REPO_SCANNERS)[tool].outcome_for(code) == expected


# --------------------------------------------------------------------------- merging files
def _scanner_doc(tool: str) -> dict[str, Any]:
    return {"schema_version": 1, "scanners": [entry_dict(tool=tool)]}


def test_documents_are_merged_and_duplicates_refused() -> None:
    merged = parse_catalogue([("a.yaml", _scanner_doc("one")), ("b.yaml", _scanner_doc("two"))])
    assert set(merged) == {"one", "two"}
    with pytest.raises(CatalogueError, match="already defined in a.yaml"):
        parse_catalogue([("a.yaml", _scanner_doc("one")), ("b.yaml", _scanner_doc("one"))])
    with pytest.raises(CatalogueError, match="schema_version"):
        parse_catalogue([("a.yaml", {"schema_version": 2, "scanners": []})])
    with pytest.raises(CatalogueError, match="list"):
        parse_catalogue([("a.yaml", {"scanners": {"x": 1}})])


def test_validation_errors_name_the_file_and_tool() -> None:
    bad = {"scanners": [entry_dict(tool="broken", command=["x", "{nope}"])]}
    with pytest.raises(CatalogueError, match=r"b\.yaml: scanner broken"):
        parse_catalogue([("b.yaml", bad)])


def test_catalogue_d_files_are_merged(tmp_path: Path) -> None:
    (tmp_path / "catalogue.d").mkdir()
    (tmp_path / "catalogue.yaml").write_text(yaml.safe_dump(_scanner_doc("one")), encoding="utf-8")
    (tmp_path / "catalogue.d" / "10-two.yaml").write_text(yaml.safe_dump(_scanner_doc("two")), encoding="utf-8")
    (tmp_path / "catalogue.d" / "20-three.yaml").write_text(yaml.safe_dump(_scanner_doc("three")), encoding="utf-8")
    assert set(load_catalogue_from(tmp_path)) == {"one", "two", "three"}
    (tmp_path / "catalogue.d" / "30-dup.yaml").write_text(yaml.safe_dump(_scanner_doc("one")), encoding="utf-8")
    with pytest.raises(CatalogueError, match="already defined"):
        load_catalogue_from(tmp_path)


def test_missing_catalogue_is_a_catalogue_error(tmp_path: Path) -> None:
    with pytest.raises(CatalogueError):
        load_catalogue_from(tmp_path)


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        make_entry(privileged=True)
