"""The SonarQube scanner builder: applicability, command, token handling, post-run export."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from securescan.config import Settings
from securescan.db.models.enums import ArtifactKind, JobState, TargetKind
from securescan.integrations.sonarqube.client import SonarNotReady, SonarQubeClient
from securescan.runner.sources.base import SourceInfo
from securescan.runner.specs import ContainerResult
from securescan.runner.tools import get_builder
from securescan.runner.tools import sonarqube as sonar_module
from securescan.runner.tools.base import ToolPreparationError
from securescan.runner.tools.sonarqube import (
    IMAGE_EXCLUSIONS,
    LanguageSummary,
    SonarQubeBuilder,
    decide,
    merge_options,
    project_key_for,
    scan_languages,
)
from tests.unit.conftest import FakeSession
from tests.unit.m8_helpers import ctx_for, make_class_file, put_file

BUILDER = SonarQubeBuilder()


def test_registered() -> None:
    assert get_builder("sonarqube") is sonar_module.BUILDER


# --------------------------------------------------------------------------- languages and applicability
def test_language_counts_skip_dependencies_and_build_output(tmp_path: Path) -> None:
    put_file(tmp_path, "src/A.java")
    put_file(tmp_path, "web/app.ts")
    put_file(tmp_path, "web/app.min.js")
    put_file(tmp_path, "web/index.html")
    put_file(tmp_path, "tool/run.py")
    put_file(tmp_path, "node_modules/lib/index.js")
    put_file(tmp_path, "vendor/x.py")
    put_file(tmp_path, "build/Generated.java")
    put_file(tmp_path, "Program.cs")
    summary = scan_languages(tmp_path)
    assert (summary.java, summary.web, summary.python, summary.csharp) == (1, 2, 1, 1)
    assert summary.analysable == 4


def test_image_system_directories_are_not_application_source(tmp_path: Path) -> None:
    put_file(tmp_path, "rootfs/usr/lib/python3/dist.py")
    put_file(tmp_path, "rootfs/usr/share/doc/page.html")
    put_file(tmp_path, "rootfs/etc/script.py")
    summary = scan_languages(tmp_path, image=True)
    assert summary.analysable == 0
    put_file(tmp_path, "rootfs/app/main.py")
    put_file(tmp_path, "rootfs/srv/site/index.html")
    assert scan_languages(tmp_path, image=True).analysable == 2
    assert scan_languages(tmp_path, image=False).analysable == 5, "without image mode nothing is system"


def test_the_skip_decisions() -> None:
    assert decide(LanguageSummary(java=3), image=False) is None
    assert decide(LanguageSummary(web=1, csharp=9), image=False) is None, "mixed: analysed, C# files are noted"
    reason = decide(LanguageSummary(csharp=4), image=False)
    assert reason is not None and "C# needs the .NET scanner and a build" in reason
    reason = decide(LanguageSummary(), image=True)
    assert reason is not None and "image holds no application source" in reason
    reason = decide(LanguageSummary(), image=False)
    assert reason is not None and "no source files" in reason
    only_c_sharp_image = decide(LanguageSummary(csharp=2), image=True)
    assert only_c_sharp_image is not None and "C#" in only_c_sharp_image


def test_project_keys_are_safe_and_unique() -> None:
    key = project_key_for("My App (v2)!", "release/2.0", "0194-abcd-ef01-2345")
    assert key == "ss-my-app-v2-release-2-0-0194abcd"
    assert project_key_for("a", "b", "11111111-2222").endswith("-11111111")
    assert project_key_for("My App", "x", "aaaaaaaa-1") != project_key_for("my-app", "x", "bbbbbbbb-1")


def test_merge_options_puts_the_gate_and_measures_where_the_report_reads_them() -> None:
    gate = {"status": "OK", "conditions": []}
    merged = merge_options({"exclude": ["a"], "sonarqube": {"old": 1}}, gate, {"bugs": "2", "coverage": None}, {"project_key": "k"})
    assert merged["quality_gate"] == gate and merged["measures"] == {"bugs": "2"}
    assert merged["exclude"] == ["a"] and merged["sonarqube"] == {"old": 1, "project_key": "k"}
    assert merge_options(None, gate, {}, {})["measures"] == {}


# --------------------------------------------------------------------------- command and container
def with_token(**kwargs: Any) -> Any:
    ctx = ctx_for("sonarqube", **kwargs)
    ctx.extra_values.update({"project_key": "ss-shop-main-1234", "sonar_token": "sqp_analysis", "sonar_token_name": "ss-job"})
    return ctx


def test_the_command_is_the_plans_without_a_token() -> None:
    ctx = with_token()
    command = BUILDER.build_command(ctx)
    assert command == [
        "sonar-scanner",
        "-Dsonar.projectKey=ss-shop-main-1234",
        "-Dsonar.sources=.",
        "-Dsonar.scm.disabled=true",
        "-Dsonar.working.directory=/out/.scannerwork",
    ]
    assert not any("sqp_analysis" in part or "token" in part.lower() for part in command)


def test_java_binaries_are_added_from_the_discovery() -> None:
    ctx = with_token()
    ctx.options["sonar_binaries"] = ["target/classes", "build/libs/app.jar"]
    command = BUILDER.build_command(ctx)
    assert command[-1] == "-Dsonar.java.binaries=/usr/src/target/classes,/usr/src/build/libs/app.jar"
    ctx.options["sonar_binaries"] = ["../outside"]
    from securescan.runner.catalogue import OptionalArgError

    with pytest.raises(OptionalArgError):
        BUILDER.build_command(ctx)


def test_an_empty_binaries_directory_lives_in_out() -> None:
    ctx = with_token()
    ctx.options["sonar_binaries_out"] = ["empty-classes"]
    assert BUILDER.build_command(ctx)[-1] == "-Dsonar.java.binaries=/out/empty-classes"


def test_image_sources_exclude_the_operating_system() -> None:
    ctx = with_token(kind=TargetKind.IMAGE)
    ctx.source = SourceInfo(kind="image", is_git=False)
    command = BUILDER.build_command(ctx)
    assert command[-1] == "-Dsonar.exclusions=" + IMAGE_EXCLUSIONS
    assert "rootfs/usr/lib/**" in command[-1] and "rootfs/etc/**" in command[-1]


def test_the_analysis_token_is_the_only_credential_and_only_in_the_environment() -> None:
    ctx = with_token()
    spec = BUILDER.container_spec(ctx)
    assert spec.env["SONAR_TOKEN"] == "sqp_analysis"
    assert spec.env["SONAR_HOST_URL"] == "http://sonarqube:9000" and spec.env["SONAR_USER_HOME"] == "/tmp/.sonar"
    secrets = [k for k in spec.env if any(w in k.lower() for w in ("token", "password", "secret", "key"))]
    assert secrets == ["SONAR_TOKEN"]
    assert not any("sqp_analysis" in part for part in spec.command)
    assert spec.network == ctx.settings.network_sonarqube and spec.extra_networks == []
    assert spec.user == "1000:1000" and spec.read_only_rootfs is True
    assert [ro for _s, target, ro in spec.binds if target == "/usr/src"] == [True]
    assert [ro for _s, target, ro in spec.binds if target == "/out"] == [False]
    assert "exec" in spec.tmpfs["/tmp"].split(",") and spec.tmpfs["/tmp"].startswith("rw,exec,size=512m")


def test_without_an_analysis_token_there_is_no_container() -> None:
    ctx = ctx_for("sonarqube")
    ctx.extra_values["project_key"] = "k"
    with pytest.raises(ToolPreparationError) as info:
        BUILDER.container_spec(ctx)
    assert info.value.code == "sonarqube.no_token"


def test_exit_codes() -> None:
    ctx = ctx_for("sonarqube")
    assert BUILDER.classify_exit(ctx, 0) == "completed"
    for code in (1, 2, 3, 137, None):
        assert BUILDER.classify_exit(ctx, code) == "failed"


# --------------------------------------------------------------------------- prepare
class Server:
    """The project and token calls of SonarQube."""

    def __init__(self) -> None:
        self.projects: set[str] = set()
        self.tokens: list[dict[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if request.url.path == "/api/projects/search":
            key = request.url.params["projects"]
            return httpx.Response(200, json={"components": [{"key": key}] if key in self.projects else []})
        if request.url.path == "/api/projects/create":
            self.projects.add(form["project"])
            return httpx.Response(200, json={})
        if request.url.path == "/api/user_tokens/generate":
            self.tokens.append(form)
            return httpx.Response(200, json={"token": "sqp_minted"})
        return httpx.Response(404)


@pytest.fixture
def sonar(monkeypatch: pytest.MonkeyPatch) -> Server:
    """A server behind every ``SonarQubeClient`` the builder makes, a stored service token, and ``ensure_running``."""
    from securescan.jobs import sonarqube_lifecycle

    server = Server()
    seen: list[str] = []

    def make_client(url: str, **kwargs: Any) -> SonarQubeClient:
        seen.append(str(kwargs.get("token")))
        return SonarQubeClient(url, transport=httpx.MockTransport(server_handler(server)), **kwargs)

    async def stored(_session: Any) -> str:
        return "squ_service"

    async def running(**_kw: Any) -> None:
        return None

    monkeypatch.setattr(sonar_module, "SonarQubeClient", make_client)
    monkeypatch.setattr(sonar_module, "stored_service_token", stored)
    monkeypatch.setattr(sonarqube_lifecycle, "ensure_running", running)
    server.seen_tokens = seen  # type: ignore[attr-defined]
    return server


def server_handler(server: Server) -> Any:
    return server


async def test_prepare_starts_the_server_creates_the_project_and_mints_an_analysis_token(sonar: Server) -> None:
    ctx = ctx_for("sonarqube")
    put_file(ctx.workspace.src, "app.py")
    session = FakeSession()
    ctx.session = session  # type: ignore[assignment]
    await BUILDER.prepare(ctx)
    key = project_key_for("Shop", "main", ctx.version.id)
    assert sonar.projects == {key} and ctx.extra_values["project_key"] == key
    assert len(sonar.tokens) == 1
    minted = sonar.tokens[0]
    assert minted["type"] == "PROJECT_ANALYSIS_TOKEN" and minted["projectKey"] == key
    assert minted["name"] == f"ss-{str(ctx.job.id).replace('-', '')[:24]}" and "expirationDate" in minted
    assert ctx.extra_values["sonar_token"] == "sqp_minted"
    assert len(session.executed) == 1, "the project key is stored on the application version"
    assert "squ_service" in sonar.seen_tokens  # type: ignore[attr-defined]


async def test_an_existing_project_key_is_reused(sonar: Server) -> None:
    ctx = ctx_for("sonarqube")
    ctx.version.sonar_project_key = "ss-existing"
    sonar.projects.add("ss-existing")
    put_file(ctx.workspace.src, "app.py")
    session = FakeSession()
    ctx.session = session  # type: ignore[assignment]
    await BUILDER.prepare(ctx)
    assert ctx.extra_values["project_key"] == "ss-existing" and sonar.projects == {"ss-existing"}
    assert session.executed == [], "nothing to store"


@pytest.mark.parametrize(
    ("files", "fragment"),
    [(["Program.cs", "App.csproj"], "C# needs the .NET scanner and a build"), (["README.md"], "no source files")],
)
async def test_sources_sonarqube_cannot_analyse_are_skipped_before_the_server_starts(
    sonar: Server, files: list[str], fragment: str
) -> None:
    from securescan.runner.executor import _Finish

    ctx = ctx_for("sonarqube")
    for name in files:
        put_file(ctx.workspace.src, name)
    ctx.session = FakeSession()  # type: ignore[assignment]
    with pytest.raises(_Finish) as info:
        await BUILDER.prepare(ctx)
    assert info.value.skipped and info.value.state == JobState.COMPLETED and fragment in (info.value.reason or "")
    assert sonar.projects == set(), "the server was not even asked"


async def test_an_image_without_application_source_is_skipped(sonar: Server) -> None:
    from securescan.runner.executor import _Finish

    ctx = ctx_for("sonarqube", kind=TargetKind.IMAGE)
    ctx.source = SourceInfo(kind="image", is_git=False)
    put_file(ctx.workspace.src, "rootfs/usr/lib/python3/stdlib.py")
    ctx.session = FakeSession()  # type: ignore[assignment]
    with pytest.raises(_Finish) as info:
        await BUILDER.prepare(ctx)
    assert "image holds no application source" in (info.value.reason or "")


async def test_java_without_classes_is_analysed_with_reduced_precision(sonar: Server) -> None:
    ctx = ctx_for("sonarqube")
    put_file(ctx.workspace.src, "src/main/java/App.java")
    ctx.session = FakeSession()  # type: ignore[assignment]
    await BUILDER.prepare(ctx)
    assert any("without bytecode" in note and "reduced precision" in note for note in ctx.coverage_notes)
    assert "sonar_binaries" not in ctx.options and "sonar_binaries_out" not in ctx.options


async def test_the_empty_binaries_fallback_is_a_setting(sonar: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_SONARQUBE_EMPTY_BINARIES_FALLBACK", "true")
    ctx = ctx_for("sonarqube", settings=Settings())
    put_file(ctx.workspace.src, "src/main/java/App.java")
    ctx.session = FakeSession()  # type: ignore[assignment]
    await BUILDER.prepare(ctx)
    assert (ctx.workspace.out / "empty-classes").is_dir()
    assert BUILDER.build_command(ctx)[-1] == "-Dsonar.java.binaries=/out/empty-classes"


async def test_java_with_classes_passes_them_as_binaries(sonar: Server) -> None:
    ctx = ctx_for("sonarqube")
    put_file(ctx.workspace.src, "src/main/java/App.java")
    put_file(ctx.workspace.src, "target/classes/com/example/App.class", make_class_file("com/example/App"))
    put_file(ctx.workspace.src, "target/app.jar")
    ctx.session = FakeSession()  # type: ignore[assignment]
    await BUILDER.prepare(ctx)
    assert not any("without bytecode" in note for note in ctx.coverage_notes)
    assert BUILDER.build_command(ctx)[-1] == "-Dsonar.java.binaries=/usr/src/target/app.jar"


async def test_a_server_that_does_not_start_fails_the_job_with_a_reason(sonar: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.jobs import sonarqube_lifecycle

    async def not_ready(**_kw: Any) -> None:
        raise SonarNotReady("SonarQube did not become ready within 600 seconds (last status: STARTING).")

    monkeypatch.setattr(sonarqube_lifecycle, "ensure_running", not_ready)
    ctx = ctx_for("sonarqube")
    put_file(ctx.workspace.src, "app.py")
    ctx.session = FakeSession()  # type: ignore[assignment]
    with pytest.raises(ToolPreparationError) as info:
        await BUILDER.prepare(ctx)
    assert info.value.code == "sonarqube.not_ready" and "600 seconds" in str(info.value)


async def test_a_server_without_a_service_token_fails_the_job_with_a_reason(sonar: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    async def nothing(_session: Any) -> None:
        return None

    monkeypatch.setattr(sonar_module, "stored_service_token", nothing)
    ctx = ctx_for("sonarqube")
    put_file(ctx.workspace.src, "app.py")
    ctx.session = FakeSession()  # type: ignore[assignment]
    with pytest.raises(ToolPreparationError) as info:
        await BUILDER.prepare(ctx)
    assert info.value.code == "sonarqube.not_initialised"


# --------------------------------------------------------------------------- post run
class Analysis:
    """The results side of the API for one finished analysis."""

    def __init__(self, ce_status: str = "SUCCESS", issues: int = 2) -> None:
        self.ce_status = ce_status
        self.issues = issues
        self.revoked: list[str] = []
        self.requests: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append(path)
        params = request.url.params
        if path == "/api/ce/task":
            assert params["id"] == "AY-task"
            return httpx.Response(200, json={"task": {"id": "AY-task", "status": self.ce_status, "analysisId": "an-9", "errorMessage": "out of heap"}})
        if path == "/api/qualitygates/project_status":
            assert params["analysisId"] == "an-9"
            return httpx.Response(200, json={"projectStatus": {"status": "ERROR", "conditions": [
                {"status": "ERROR", "metricKey": "new_vulnerabilities", "comparator": "GT", "errorThreshold": "0", "actualValue": "2"}]}})  # fmt: skip
        if path == "/api/measures/component":
            return httpx.Response(200, json={"component": {"measures": [{"metric": "bugs", "value": "3"}, {"metric": "ncloc", "value": "420"}]}})
        if path == "/api/issues/search":
            issues = [{"key": f"I-{i}", "type": "VULNERABILITY", "severity": "CRITICAL"} for i in range(self.issues)]
            return httpx.Response(200, json={"paging": {"total": self.issues}, "issues": issues})
        if path == "/api/user_tokens/revoke":
            self.revoked.append(request.content.decode())
            return httpx.Response(204)
        return httpx.Response(404)


def post_run_ctx(monkeypatch: pytest.MonkeyPatch, analysis: Analysis) -> Any:
    async def stored(_session: Any) -> str:
        return "squ_service"

    def make_client(url: str, **kwargs: Any) -> SonarQubeClient:
        return SonarQubeClient(url, transport=httpx.MockTransport(analysis), **kwargs)

    monkeypatch.setattr(sonar_module, "SonarQubeClient", make_client)
    monkeypatch.setattr(sonar_module, "stored_service_token", stored)
    ctx = with_token()
    ctx.job.options = {"exclude": ["x"]}
    put_file(ctx.workspace.out, ".scannerwork/report-task.txt", b"projectKey=ss-shop-main-1234\nceTaskId=AY-task\n")
    ctx.session = FakeSession()
    return ctx


async def test_post_run_exports_the_issues_and_records_the_quality_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    analysis = Analysis()
    ctx = post_run_ctx(monkeypatch, analysis)
    await BUILDER.post_run(ctx, ContainerResult("c", 0, False, ""))
    session: FakeSession = ctx.session
    artifact = session.added[0]
    assert artifact.kind == ArtifactKind.RAW_REPORT and artifact.filename == "sonarqube-issues.zip"
    assert artifact.scan_id == ctx.scan.id and artifact.job_id == ctx.job.id and artifact.size_bytes > 0
    with zipfile.ZipFile(ctx.workspace.out / "sonarqube-issues.zip") as archive:
        assert archive.namelist() == ["issues-1.json"]
        assert [i["key"] for i in json.loads(archive.read("issues-1.json"))["issues"]] == ["I-0", "I-1"]
    assert len(session.executed) == 1, "the job's options are updated"
    assert analysis.revoked == ["name=ss-job"], "the analysis token is revoked after use"
    assert ctx.coverage_notes == []


async def test_the_recorded_options_are_what_the_report_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.reports.snapshot import _code_quality

    analysis = Analysis()
    ctx = post_run_ctx(monkeypatch, analysis)
    captured: dict[str, Any] = {}

    class FakeUpdate:
        def __init__(self, _model: Any) -> None:
            pass

        def where(self, *_a: Any) -> FakeUpdate:
            return self

        def values(self, **kwargs: Any) -> FakeUpdate:
            captured.update(kwargs)
            return self

    monkeypatch.setattr(sonar_module, "update", FakeUpdate)
    await BUILDER.post_run(ctx, ContainerResult("c", 0, False, ""))
    options = captured["options"]
    assert options["exclude"] == ["x"], "existing options are kept"
    assert options["measures"] == {"bugs": "3", "ncloc": "420"}
    assert options["sonarqube"]["issues_exported"] == 2 and options["sonarqube"]["export_truncated"] is False
    job = type("J", (), {"tool": "sonarqube", "options": options})()
    quality = _code_quality([job])
    assert quality.available and quality.quality_gate == "ERROR" and quality.quality_gate_label == "Failed"
    assert [(c.metric, c.actual) for c in quality.conditions] == [("new_vulnerabilities", "2")]
    assert {m.key: m.value for m in quality.measures} == {"bugs": "3", "ncloc": "420"}


async def test_a_failed_compute_engine_task_fails_the_job(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = post_run_ctx(monkeypatch, Analysis(ce_status="FAILED"))
    with pytest.raises(ToolPreparationError) as info:
        await BUILDER.post_run(ctx, ContainerResult("c", 0, False, ""))
    assert info.value.code == "sonarqube.ce_failed" and "out of heap" in str(info.value)


async def test_a_missing_report_task_file_fails_the_job(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = post_run_ctx(monkeypatch, Analysis())
    (ctx.workspace.out / ".scannerwork" / "report-task.txt").unlink()
    with pytest.raises(ToolPreparationError) as info:
        await BUILDER.post_run(ctx, ContainerResult("c", 0, False, ""))
    assert info.value.code == "sonarqube.no_report_task"


async def test_a_server_error_while_reading_results_fails_the_job(monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken(Analysis):
        def __call__(self, request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/issues/search":
                return httpx.Response(500, json={"errors": [{"msg": "boom"}]})
            return super().__call__(request)

    ctx = post_run_ctx(monkeypatch, Broken())
    with pytest.raises(ToolPreparationError) as info:
        await BUILDER.post_run(ctx, ContainerResult("c", 0, False, ""))
    assert info.value.code == "sonarqube.export_failed" and "boom" in str(info.value)
