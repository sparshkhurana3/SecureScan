"""Syft then Grype: commands, container specifications, the stale-database message, SBOM artifacts."""

from __future__ import annotations

import types
from pathlib import Path
from typing import Any

import pytest

from securescan.config import Settings, get_settings
from securescan.db.models.enums import ArtifactKind, TargetKind
from securescan.runner.catalogue import clear_catalogue_cache
from securescan.runner.sources.base import SourceInfo
from securescan.runner.specs import ContainerResult
from securescan.runner.tools import get_builder, syft_grype
from securescan.runner.tools.base import ToolPreparationError
from securescan.runner.tools.syft_grype import (
    SyftGrypeBuilder,
    explain_grype_failure,
    humanise_age,
    is_image_source,
    syft_command,
)
from tests.unit.conftest import FakeSession
from tests.unit.m8_helpers import FakeLauncher, ctx_for, host_path_of, put_file, set_pin
from tests.unit.runner_helpers import REPO_SCANNERS, real_catalogue

BUILDER = SyftGrypeBuilder()


@pytest.fixture
def catalogue_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_SCANNERS_DIR", str(REPO_SCANNERS))
    get_settings.cache_clear()
    clear_catalogue_cache()
    set_pin(monkeypatch, "SYFT", "anchore/syft")
    set_pin(monkeypatch, "GRYPE", "anchore/grype")


# --------------------------------------------------------------------------- registration and commands
def test_builder_is_registered_under_the_profile_name() -> None:
    assert get_builder("syft-grype") is syft_grype.BUILDER


def test_syft_command_for_a_directory_and_for_an_image() -> None:
    entry = real_catalogue()["syft"]
    directory = syft_command(entry, False)
    assert directory == [
        "scan", "dir:/src", "-o", "syft-json=/out/sbom.syft.json", "-o", "cyclonedx-json=/out/sbom.cdx.json",
    ]  # fmt: skip
    image = syft_command(entry, True)
    assert image[:2] == ["scan", "docker-archive:/config/image.tar"]
    assert image[2:] == directory[2:], "same output flags"


def test_image_source_detection() -> None:
    zip_ctx = ctx_for("syft-grype", kind=TargetKind.ZIP)
    assert not is_image_source(zip_ctx)
    image_ctx = ctx_for("syft-grype", kind=TargetKind.IMAGE)
    assert is_image_source(image_ctx)
    image_ctx.source = SourceInfo(kind="zip", is_git=False)
    assert not is_image_source(image_ctx), "the source handler's answer wins"


def test_the_syft_container_has_no_network_and_reads_the_source_read_only() -> None:
    ctx = ctx_for("syft-grype")
    entry = real_catalogue()["syft"]
    spec = BUILDER.syft_spec(ctx, entry, "anchore/syft@sha256:" + "a" * 64)
    assert spec.network == "none" and spec.extra_networks == [] and spec.read_only_rootfs is True
    assert spec.user == "1000:1000" and spec.name == f"securescan-job-{ctx.job.id}-syft"
    assert spec.env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
    binds = {target: (Path(source), ro) for source, target, ro in spec.binds}
    assert binds["/src"] == (ctx.workspace.src, True)
    assert binds["/out"] == (ctx.workspace.out, False)
    assert binds["/config"] == (ctx.workspace.config, True)
    assert spec.tmpfs["/tmp"].startswith("rw,size=512m")
    assert spec.labels["securescan.job_id"] == str(ctx.job.id)
    assert not any("token" in v.lower() or "password" in v.lower() for v in spec.env.values())


def test_the_syft_container_for_an_image_reads_the_archive_and_gets_a_bigger_tmpfs() -> None:
    ctx = ctx_for("syft-grype", kind=TargetKind.IMAGE)
    entry = real_catalogue()["syft"]
    with pytest.raises(ToolPreparationError):  # the archive must exist
        BUILDER.syft_spec(ctx, entry, "anchore/syft@sha256:" + "a" * 64)
    put_file(ctx.workspace.config, "image.tar")
    spec = BUILDER.syft_spec(ctx, entry, "anchore/syft@sha256:" + "a" * 64)
    assert "docker-archive:/config/image.tar" in spec.command and "dir:/src" not in spec.command
    assert spec.tmpfs["/tmp"].startswith("rw,size=1536m")


def test_the_grype_container_runs_against_the_sbom_with_the_database_mounted() -> None:
    ctx = ctx_for("syft-grype")
    spec = BUILDER.container_spec(ctx)
    assert spec.command == ["sbom:/out/sbom.syft.json", "-o", "json=/out/grype.json"]
    assert spec.network == "none" and spec.read_only_rootfs is True
    assert spec.env["GRYPE_DB_AUTO_UPDATE"] == "false" and spec.env["GRYPE_DB_VALIDATE_AGE"] == "true"
    assert spec.env["GRYPE_DB_CACHE_DIR"] == "/content/grype-db"
    assert spec.env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] == "120h"
    assert spec.env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"
    database = host_path_of(spec, "/content/grype-db")
    assert database == Path(get_settings().content_root) / "grype-db" and database.is_dir()
    assert [ro for _s, target, ro in spec.binds if target == "/content/grype-db"] == [False], "read-write until S7 says otherwise"


def test_the_database_mount_and_the_age_limit_follow_the_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_GRYPE_DB_READ_ONLY", "true")
    monkeypatch.setenv("SECURESCAN_GRYPE_DB_MAX_AGE", "1h")
    ctx = ctx_for("syft-grype", settings=Settings())
    spec = BUILDER.container_spec(ctx)
    assert [ro for _s, target, ro in spec.binds if target == "/content/grype-db"] == [True]
    assert spec.env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] == "1h"


# --------------------------------------------------------------------------- exit codes and the stale database
def test_exit_code_mapping_without_a_log(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(syft_grype, "tail_lines", lambda *_a, **_k: [])
    ctx = ctx_for("syft-grype")
    assert BUILDER.classify_exit(ctx, 0) == "completed"
    for code in (1, 2, 126, 137, None):
        assert BUILDER.classify_exit(ctx, code) == "failed"


STALE_LINES = [
    "[0000]  INFO grype version: 0.120.0",
    "1 error occurred:",
    "\t* failed to load vulnerability db: the vulnerability database was built 6 days ago (max allowed age is 120h0m0s)",
]
MISSING_LINES = ["[0000] ERROR failed to load vulnerability db: no vulnerability database found; run 'grype db update'"]


def test_a_stale_database_fails_the_job_with_a_plain_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(syft_grype, "tail_lines", lambda *_a, **_k: STALE_LINES)
    ctx = ctx_for("syft-grype")
    with pytest.raises(ToolPreparationError) as info:
        BUILDER.classify_exit(ctx, 1)
    assert info.value.code == "grype.stale_database"
    assert "older than the allowed 5 days" in str(info.value) and "instead of reporting against old data" in str(info.value)
    assert BUILDER.classify_exit(ctx, 0) == "completed", "a good run is never second-guessed"


def test_explaining_grype_failures() -> None:
    assert "older than the allowed 1 hours" in (explain_grype_failure(STALE_LINES, "1h") or "")
    assert "could not load its vulnerability database" in (explain_grype_failure(MISSING_LINES, "120h") or "")
    assert explain_grype_failure(["panic: out of memory"], "120h") is None
    assert explain_grype_failure(["failed to read sbom: no such file or directory"], "120h") is None
    assert explain_grype_failure([], "120h") is None


def test_humanise_age() -> None:
    assert humanise_age("120h") == "5 days" and humanise_age("36h") == "36 hours" and humanise_age("7d") == "7d"


# --------------------------------------------------------------------------- prepare
async def test_prepare_is_blocked_until_a_database_is_installed(monkeypatch: pytest.MonkeyPatch, catalogue_env: None) -> None:
    from securescan.jobs import scanner_health

    async def none(_session: Any) -> dict[str, Any]:
        return {}

    monkeypatch.setattr(scanner_health, "active_versions", none)
    ctx = ctx_for("syft-grype")
    ctx.session = FakeSession()  # type: ignore[assignment]
    with pytest.raises(ToolPreparationError) as info:
        await BUILDER.prepare(ctx)
    assert info.value.code == "grype.db_missing" and "07:30 UTC" in str(info.value)


async def test_prepare_runs_syft_and_records_the_database_version(monkeypatch: pytest.MonkeyPatch, catalogue_env: None) -> None:
    from securescan.jobs import scanner_health

    async def installed(_session: Any) -> dict[str, Any]:
        return {"grype_db": types.SimpleNamespace(version="v6-20261007T013003Z")}

    monkeypatch.setattr(scanner_health, "active_versions", installed)
    ctx = ctx_for("syft-grype")
    ctx.session = None

    def syft_writes_the_sbom(spec: Any) -> int:
        out = host_path_of(spec, "/out")
        (out / "sbom.syft.json").write_text('{"artifacts": [{"name": "a"}, {"name": "b"}]}', encoding="utf-8")
        (out / "sbom.cdx.json").write_text('{"components": []}', encoding="utf-8")
        return 0

    launcher = FakeLauncher(syft_writes_the_sbom)
    monkeypatch.setattr(syft_grype, "get_launcher", lambda: launcher)
    await BUILDER.prepare(ctx)
    assert ctx.content_versions == {"grype_db": "v6-20261007T013003Z"}
    assert len(launcher.specs) == 1 and launcher.specs[0].network == "none"
    assert launcher.timeouts == [30 * 60.0]
    assert ctx.tool_version and ctx.tool_version.startswith("syft v1.54.0 + grype")


@pytest.mark.parametrize(
    ("exit_code", "timed_out", "logs", "fragment"),
    [
        (2, False, "boom\nfatal: cannot read source", "exit code 2"),
        (0, True, "", "did not finish within 30 minutes"),
        (0, False, "", "no usable SBOM"),  # exit 0 but no files written
    ],
)
async def test_a_failing_syft_stage_fails_the_job_with_a_reason(
    monkeypatch: pytest.MonkeyPatch, catalogue_env: None, exit_code: int, timed_out: bool, logs: str, fragment: str
) -> None:
    from securescan.jobs import scanner_health

    async def installed(_session: Any) -> dict[str, Any]:
        return {"grype_db": types.SimpleNamespace(version="v6-x")}

    class Launcher:
        async def run(self, spec: Any, timeout_s: Any, on_log: Any = None, **_kw: Any) -> ContainerResult:
            return ContainerResult("c", exit_code, timed_out, logs)

    monkeypatch.setattr(scanner_health, "active_versions", installed)
    monkeypatch.setattr(syft_grype, "get_launcher", lambda: Launcher())
    ctx = ctx_for("syft-grype")
    ctx.session = None
    with pytest.raises(ToolPreparationError) as info:
        await BUILDER.prepare(ctx)
    assert fragment in str(info.value)


# --------------------------------------------------------------------------- the SBOMs
async def test_post_run_stores_both_sboms_as_artifacts() -> None:
    ctx = ctx_for("syft-grype")
    put_file(ctx.workspace.out, "sbom.syft.json", b'{"artifacts": []}')
    put_file(ctx.workspace.out, "sbom.cdx.json", b'{"components": []}')
    put_file(ctx.workspace.out, "grype.json", b'{"matches": []}')
    session = FakeSession()
    ctx.session = session  # type: ignore[assignment]
    await BUILDER.post_run(ctx, ContainerResult("c", 0, False, ""))
    assert sorted(a.filename for a in session.added) == ["sbom.cdx.json", "sbom.syft.json"]
    assert {a.kind for a in session.added} == {ArtifactKind.SBOM}
    assert all(a.scan_id == ctx.scan.id and a.job_id == ctx.job.id for a in session.added)
    assert all(a.size_bytes > 0 and len(a.sha256) == 64 for a in session.added)
    assert not any("grype.json" == a.filename for a in session.added), "the Grype report is the executor's raw report"
