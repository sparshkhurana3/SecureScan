"""Command rendering, container specifications and preparation of the Semgrep and Gitleaks builders."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from securescan.config import Settings
from securescan.db.models.enums import TargetKind
from securescan.runner.catalogue import OptionalArgError
from securescan.runner.sources.base import SourceInfo
from securescan.runner.tools import get_builder, register_builder, registered_tools
from securescan.runner.tools import gitleaks as gitleaks_module
from securescan.runner.tools import semgrep as semgrep_module
from securescan.runner.tools.base import (
    DefaultToolBuilder,
    ToolPreparationError,
    container_name,
    docker_network,
    insert_before_target,
    normalise_user,
    remove_ignore_files,
)
from securescan.runner.tools.semgrep import BUILTIN_SKIPS, rules_version
from tests.unit.runner_helpers import DIGEST, REPO_SCANNERS, make_ctx

SEMGREP_PLAN_COMMAND = (
    "semgrep scan --config /content/semgrep/rules --metrics=off --disable-version-check "
    "--json-output=/out/semgrep.json --sarif-output=/out/semgrep.sarif --timeout 30 "
    "--timeout-threshold 3 --max-memory 3000 --jobs 2 /src"
).split()
GITLEAKS_PLAN_COMMAND = (
    "gitleaks git /src --redact --config /config/gitleaks.toml --ignore-gitleaks-allow "
    "--max-archive-depth 2 --report-format json --report-path /out/gitleaks.json --exit-code 2"
).split()


def install_rules(content_root: str, name: str = "rules-0123abc") -> Path:
    base = Path(content_root) / "semgrep"
    real = base / name
    real.mkdir(parents=True)
    (real / "rule.yaml").write_text("rules: []\n", encoding="utf-8")
    try:
        os.symlink(name, base / "rules")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")
    return real


# --------------------------------------------------------------------------- registry
def test_builders_are_registered_automatically() -> None:
    assert {"semgrep", "gitleaks"} <= set(registered_tools())
    assert get_builder("semgrep") is semgrep_module.BUILDER
    assert get_builder("gitleaks") is gitleaks_module.BUILDER
    with pytest.raises(KeyError):
        get_builder("codeql")


def test_every_builder_has_the_interface() -> None:
    for name in registered_tools():
        builder = get_builder(name)
        assert builder.tool == name
        for method in ("applicable", "prepare", "build_command", "container_spec", "post_run", "classify_exit"):
            assert callable(getattr(builder, method))


def test_a_builder_can_be_registered_programmatically() -> None:
    class Demo(DefaultToolBuilder):
        tool = "demo-tool"

    register_builder(Demo())
    assert get_builder("demo-tool").tool == "demo-tool"


# --------------------------------------------------------------------------- small helpers
def test_helpers() -> None:
    assert normalise_user("root") == "0"
    assert normalise_user("root:root") == "0:0"
    assert normalise_user("1000:1000") == "1000:1000"
    assert container_name("abc") == "securescan-job-abc"
    settings = Settings(network_sonarqube="sq", network_dast="dd")
    assert docker_network(settings, "none") == "none"
    assert docker_network(settings, "sonarqube") == "sq"
    assert docker_network(settings, "dast") == "dd"
    with pytest.raises(ToolPreparationError):
        docker_network(settings, "host")
    assert insert_before_target(["a", "/src"], ["--x", "1"], "/src") == ["a", "--x", "1", "/src"]
    assert insert_before_target(["a", "b"], ["--x"], "/src") == ["a", "b", "--x"]
    assert insert_before_target(["a", "/src"], [], "/src") == ["a", "/src"]


def test_ignore_files_are_removed_but_never_followed(tmp_path: Path) -> None:
    root = tmp_path / "src"
    (root / "wrapper").mkdir(parents=True)
    (root / "deep" / "er").mkdir(parents=True)
    (root / ".gitleaksignore").write_text("x")
    (root / "wrapper" / ".gitleaksignore").write_text("y")
    (root / "deep" / "er" / ".gitleaksignore").write_text("kept: too deep")
    outside = tmp_path / "outside.txt"
    outside.write_text("precious")
    try:
        os.symlink(outside, root / "deep" / ".gitleaksignore")
    except (OSError, NotImplementedError):
        pass
    removed = remove_ignore_files(root, (".gitleaksignore",))
    assert ".gitleaksignore" in removed and os.path.join("wrapper", ".gitleaksignore") in removed
    assert (root / "deep" / "er" / ".gitleaksignore").exists()
    assert outside.read_text() == "precious"
    assert not (root / "deep" / ".gitleaksignore").is_symlink()


# --------------------------------------------------------------------------- semgrep
async def test_semgrep_command_is_the_plan_command_plus_exclusions() -> None:
    ctx = make_ctx("semgrep")
    install_rules(ctx.settings.content_root)
    builder = get_builder("semgrep")
    await builder.prepare(ctx)
    command = builder.build_command(ctx)
    # the --exclude switches from scanners/profiles/semgrep.yaml go right before the final target
    assert command[-1] == "/src"
    assert command[:-5] == SEMGREP_PLAN_COMMAND[:-1]
    assert command[-5:-1] == ["--exclude", "*.min.css", "--exclude", "*.map"]


async def test_semgrep_prepare_records_versions_and_exclusions() -> None:
    ctx = make_ctx("semgrep", options={"exclude": ["*.generated.js", "*.map"]})
    real = install_rules(ctx.settings.content_root, "rules-feedbeef")
    (ctx.workspace.src / ".semgrepignore").write_text("*\n", encoding="utf-8")
    await get_builder("semgrep").prepare(ctx)
    assert ctx.content_versions == {"semgrep_rules": "rules-feedbeef"}
    assert ctx.extra_values["rules_dir"] == str(real.resolve())
    assert not (ctx.workspace.src / ".semgrepignore").exists()
    recorded = {(e["kind"], e["value"]) for e in ctx.applied_exclusions}
    assert ("source_file_removed", ".semgrepignore") in recorded
    assert {("pattern", "*.min.css"), ("pattern", "*.map"), ("pattern", "*.generated.js")} <= recorded
    for skip in BUILTIN_SKIPS:
        assert ("builtin", skip) in recorded
    assert sum(1 for e in ctx.applied_exclusions if e["value"] == "*.map") == 1  # de-duplicated
    assert any(".semgrepignore" in note for note in ctx.coverage_notes)
    assert ctx.tool_version == "1.0"


async def test_semgrep_container_spec_is_hardened_and_built_from_the_catalogue() -> None:
    ctx = make_ctx("semgrep")
    real = install_rules(ctx.settings.content_root)
    builder = get_builder("semgrep")
    await builder.prepare(ctx)
    spec = builder.container_spec(ctx)
    assert spec.image == f"example/semgrep@{DIGEST}"
    assert spec.network == "none" and spec.extra_networks == []
    assert spec.user == "1000:1000"
    assert spec.read_only_rootfs is True
    assert spec.entrypoint == [""]
    assert spec.name == f"securescan-job-{ctx.job.id}"
    assert spec.mem_limit == "4g" and spec.nano_cpus == 2_000_000_000 and spec.pids_limit == 256
    assert spec.tmpfs == {"/tmp": "rw,size=512m,mode=1777"}  # noqa: S108
    assert spec.binds == [
        (str(ctx.workspace.src), "/src", True),
        (str(ctx.workspace.out), "/out", False),
        (str(real.resolve()), "/content/semgrep/rules", True),
    ]
    assert spec.labels["securescan.job_id"] == str(ctx.job.id)
    assert spec.labels["securescan.scan_id"] == str(ctx.scan.id)
    assert spec.labels["securescan.tool"] == "semgrep"
    assert spec.env["SEMGREP_SEND_METRICS"] == "off" and spec.env["HOME"] == "/tmp"  # noqa: S108
    assert "--metrics=off" in spec.command and "--exclude" in spec.command


async def test_profile_overrides_change_limits_and_timeout_only() -> None:
    ctx = make_ctx("semgrep", options={"limits": {"cpus": 1, "memory": "2g"}, "timeout_minutes": 5})
    install_rules(ctx.settings.content_root)
    builder = get_builder("semgrep")
    await builder.prepare(ctx)
    spec = builder.container_spec(ctx)
    assert spec.mem_limit == "2g" and spec.nano_cpus == 1_000_000_000 and spec.pids_limit == 256
    assert builder.timeout_seconds(ctx) == 300.0  # type: ignore[attr-defined]
    ctx.options["timeout_minutes"] = True  # a boolean is not a number of minutes
    assert builder.timeout_seconds(ctx) == 3600.0  # type: ignore[attr-defined]
    ctx.options["limits"] = {"memory": "lots"}
    with pytest.raises((ValidationError, ValueError)):
        builder.container_spec(ctx)


async def test_semgrep_refuses_unsafe_exclusion_patterns() -> None:
    ctx = make_ctx("semgrep", options={"exclude": ["-x"]})
    install_rules(ctx.settings.content_root)
    builder = get_builder("semgrep")
    await builder.prepare(ctx)
    with pytest.raises(OptionalArgError):
        builder.build_command(ctx)


async def test_semgrep_without_rules_fails_with_a_clear_reason() -> None:
    ctx = make_ctx("semgrep")
    with pytest.raises(ToolPreparationError) as caught:
        await get_builder("semgrep").prepare(ctx)
    assert caught.value.code == "semgrep.rules_missing"
    assert "rules" in str(caught.value).lower()


async def test_rules_link_must_stay_inside_the_content_volume(tmp_path: Path) -> None:
    ctx = make_ctx("semgrep")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.yaml").write_text("rules: []\n", encoding="utf-8")
    base = Path(ctx.settings.content_root) / "semgrep"
    base.mkdir(parents=True)
    try:
        os.symlink(outside, base / "rules")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")
    with pytest.raises(ToolPreparationError) as caught:
        await get_builder("semgrep").prepare(ctx)
    assert caught.value.code == "semgrep.rules_invalid"


def test_rules_version_names() -> None:
    assert rules_version(Path("/x/semgrep/rules-abc")) == "rules-abc"


def test_rules_version_from_commit_marker(tmp_path: Path) -> None:
    rules = tmp_path / "semgrep-rules"
    rules.mkdir()
    (tmp_path / "semgrep-rules.commit").write_text("0123456789abcdef\n", encoding="utf-8")
    assert rules_version(rules) == "rules-0123456789abcdef"


# --------------------------------------------------------------------------- gitleaks
async def test_gitleaks_uses_git_mode_for_repositories() -> None:
    ctx = make_ctx("gitleaks", kind=TargetKind.GITHUB_REPO)
    builder = get_builder("gitleaks")
    await builder.prepare(ctx)
    assert builder.build_command(ctx) == GITLEAKS_PLAN_COMMAND


async def test_gitleaks_uses_dir_mode_for_zips_with_the_same_flags() -> None:
    ctx = make_ctx("gitleaks", kind=TargetKind.ZIP)
    builder = get_builder("gitleaks")
    await builder.prepare(ctx)
    expected = list(GITLEAKS_PLAN_COMMAND)
    expected[1] = "dir"
    assert builder.build_command(ctx) == expected


async def test_gitleaks_source_info_decides_over_the_target_kind() -> None:
    ctx = make_ctx("gitleaks", kind=TargetKind.ZIP)
    ctx.source = SourceInfo(kind="git", is_git=True)
    assert get_builder("gitleaks").build_command(ctx)[1] == "git"
    ctx.source = SourceInfo(kind="image", is_git=False)
    ctx.target.kind = TargetKind.GITHUB_REPO  # type: ignore[union-attr]
    assert get_builder("gitleaks").build_command(ctx)[1] == "dir"


async def test_gitleaks_prepare_removes_the_ignore_file_and_installs_our_rules() -> None:
    ctx = make_ctx("gitleaks")
    (ctx.workspace.src / ".gitleaksignore").write_text("abc:file:1\n", encoding="utf-8")
    (ctx.workspace.src / "repo-main").mkdir()
    (ctx.workspace.src / "repo-main" / ".gitleaksignore").write_text("def\n", encoding="utf-8")
    await get_builder("gitleaks").prepare(ctx)
    assert not (ctx.workspace.src / ".gitleaksignore").exists()
    assert not (ctx.workspace.src / "repo-main" / ".gitleaksignore").exists()
    values = [e["value"] for e in ctx.applied_exclusions if e["kind"] == "source_file_removed"]
    assert ".gitleaksignore" in values and os.path.join("repo-main", ".gitleaksignore") in values
    config = (ctx.workspace.config / "gitleaks.toml").read_text(encoding="utf-8")
    assert "useDefault = true" in config
    assert config == (REPO_SCANNERS / "gitleaks.toml").read_text(encoding="utf-8")


async def test_gitleaks_without_its_rule_file_fails_clearly(tmp_path: Path) -> None:
    ctx = make_ctx("gitleaks", scanners_dir=tmp_path)
    with pytest.raises(ToolPreparationError) as caught:
        await get_builder("gitleaks").prepare(ctx)
    assert caught.value.code == "gitleaks.config_missing"


async def test_gitleaks_container_spec() -> None:
    ctx = make_ctx("gitleaks", kind=TargetKind.GITHUB_REPO)
    builder = get_builder("gitleaks")
    await builder.prepare(ctx)
    spec = builder.container_spec(ctx)
    assert spec.network == "none"
    assert spec.user == "1000:1000" and spec.read_only_rootfs is True
    assert spec.binds == [
        (str(ctx.workspace.src), "/src", True),
        (str(ctx.workspace.out), "/out", False),
        (str(ctx.workspace.config), "/config", True),
    ]
    assert spec.mem_limit == "1g" and spec.pids_limit == 128 and spec.nano_cpus == 1_000_000_000
    assert spec.env["GIT_CONFIG_KEY_0"] == "safe.directory"
    assert spec.command[:3] == ["gitleaks", "git", "/src"]
    assert "--redact" in spec.command and "--ignore-gitleaks-allow" in spec.command


def test_gitleaks_exit_code_classification_through_the_builder() -> None:
    ctx = make_ctx("gitleaks")
    builder = get_builder("gitleaks")
    assert builder.classify_exit(ctx, 0) == "completed"
    assert builder.classify_exit(ctx, 2) == "completed"
    assert builder.classify_exit(ctx, 1) == "failed"
    assert builder.classify_exit(ctx, 126) == "failed"
    assert builder.classify_exit(ctx, None) == "failed"


# --------------------------------------------------------------------------- applicability
def test_applicability_follows_the_catalogue_target_kinds() -> None:
    for kind in (TargetKind.ZIP, TargetKind.GITHUB_REPO, TargetKind.VENDOR_REPO, TargetKind.IMAGE):
        assert get_builder("semgrep").applicable(make_ctx("semgrep", kind=kind))[0] is True
    ok, note = get_builder("gitleaks").applicable(make_ctx("gitleaks", kind=TargetKind.URL))
    assert ok is False and "url" in note
