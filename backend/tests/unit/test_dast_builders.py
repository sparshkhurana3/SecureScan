"""The ZAP and Nuclei tool builders end to end without Docker: preparation, command line, secrets, cleanup."""

from __future__ import annotations

import os
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from securescan.db.models.credentials import Credential
from securescan.db.models.enums import AppType, CredentialKind, TargetEnvironment
from securescan.domain.credentials import store_credential
from securescan.domain.dast_rules import LoginSecret, LoginSettings
from securescan.runner.catalogue import OptionalArgError
from securescan.runner.specs import ContainerResult
from securescan.runner.tools import get_builder
from securescan.runner.tools import nuclei as nuclei_module
from securescan.runner.tools import zap as zap_module
from securescan.runner.tools.base import ToolPreparationError
from securescan.runner.tools.nuclei import ensure_report, rate_flags, resolve_templates_dir
from securescan.runner.tools.zap import STATE_KEY, DastState, state_of
from securescan.util import utcnow
from tests.unit.conftest import FakeSession
from tests.unit.dast_helpers import make_application, make_target, prepared_ctx, work_dir

PASSWORD = "Very-Secret-Pa55word"
PRODUCTION = TargetEnvironment.PRODUCTION
RESULT = ContainerResult(container_id="c" * 64, exit_code=0, timed_out=False, logs="")


async def login_credential(session: FakeSession, **overrides: Any) -> Credential:
    settings = LoginSettings.model_validate(
        {
            "method": "form",
            "login_page_url": "http://10.20.30.40:8080/login",
            "login_request_url": "http://10.20.30.40:8080/login",
            "login_request_body": "user={%username%}&pass={%password%}",
            "logged_in_regex": "\\QSign out\\E",
            **overrides.pop("settings", {}),
        }
    )
    secret = overrides.pop("secret", LoginSecret(username="analyst", password=PASSWORD).to_json())
    return await store_credential(
        session,
        kind=CredentialKind.DAST_LOGIN,
        name="uat login",
        secret=secret,
        extra=settings.model_dump(mode="json", exclude_none=True),
        **overrides,
    )


# --------------------------------------------------------------------------- ZAP prepare
async def test_zap_full_scan_with_a_form_login_end_to_end(monkeypatch: pytest.MonkeyPatch, master_key: str) -> None:
    session = FakeSession()
    credential = await login_credential(session)
    target = make_target(
        login_profile_id=credential.id, scope_excludes=["/admin/.*"], rate_limit_rps=5, name="Shop",
    )  # fmt: skip
    ctx, fake, scheduled = prepared_ctx("zap", "full", monkeypatch, target=target, session=session)
    builder = get_builder("zap")
    await builder.prepare(ctx)  # type: ignore[arg-type]

    # the proxy: dast + egress, only the target host and port, watched until the job ends
    assert len(fake.created) == 1
    squid = fake.created[0]
    assert squid.network == ctx.settings.network_dast and squid.extra_networks == [ctx.settings.network_egress]
    assert squid.name.startswith("securescan-dast-proxy-") and squid.labels["securescan.job_id"] == str(ctx.job.id)
    conf = (work_dir(ctx) / "proxy" / "squid.conf").read_text(encoding="ascii")
    assert "acl dast_ips dst 10.20.30.40" in conf and "acl dast_ports port 8080" in conf
    assert len(scheduled.calls) == 1 and scheduled.calls[0][0] == ctx.job.id

    # the plan: written to the config mount, secrets only as references
    plan_text = (ctx.workspace.config / "plan.yaml").read_text(encoding="utf-8")
    assert PASSWORD not in plan_text and "analyst" not in plan_text
    assert "${ZAP_AUTH_PASSWORD}" in plan_text and "${ZAP_AUTH_USERNAME}" in plan_text
    plan = yaml.safe_load(plan_text)
    context = plan["env"]["contexts"][0]
    assert context["authentication"]["verification"]["loggedInRegex"] == "\\QSign out\\E"
    assert r"http://10\.20\.30\.40:8080/admin/.*" in context["excludePaths"]
    assert [j["type"] for j in plan["jobs"]][0] == "requestor"
    assert plan["jobs"][[j["type"] for j in plan["jobs"]].index("activeScan")]["parameters"]["delayInMs"] == 400  # 5 rps
    assert (os.stat(ctx.workspace.config / "plan.yaml").st_mode & 0o044) == 0o044  # readable by the scanner's uid

    # the container: secret in the environment, never on the command line, proxy switches appended
    spec = builder.container_spec(ctx)  # type: ignore[arg-type]
    state = state_of(ctx)
    assert state is not None and state.login is True
    assert spec.env["ZAP_AUTH_PASSWORD"] == PASSWORD and spec.env["ZAP_AUTH_USERNAME"] == "analyst"
    assert PASSWORD not in " ".join(spec.command)
    assert f"network.connection.httpProxy.host={squid.name}" in spec.command
    assert spec.network == ctx.settings.network_dast and spec.extra_networks == []
    assert any("Authenticated scan (form login)" in note for note in ctx.coverage_notes)
    assert {"kind": "scope_exclude", "value": r"http://10\.20\.30\.40:8080/admin/.*", "source": "target scope"} in ctx.applied_exclusions
    assert credential.last_used_at is not None
    assert builder.classify_exit(ctx, 1) == "failed"  # a login scan never reports on a plan error  # type: ignore[arg-type]


async def test_zap_baseline_of_a_production_target(monkeypatch: pytest.MonkeyPatch) -> None:
    target = make_target(environment=PRODUCTION, locator="http://10.20.30.40/", rate_limit_rps=2)
    ctx, fake, _ = prepared_ctx("zap", "baseline", monkeypatch, target=target, options={"timeout_minutes": 30})
    builder = get_builder("zap")
    await builder.prepare(ctx)  # type: ignore[arg-type]
    plan_text = (ctx.workspace.config / "plan.yaml").read_text(encoding="utf-8")
    plan = yaml.safe_load(plan_text)
    assert [j["type"] for j in plan["jobs"]] == ["passiveScan-config", "spider", "passiveScan-wait", "report", "report"]
    assert "activeScan" not in plan_text and "postForm: true" not in plan_text and "authentication" not in plan_text
    spider = plan["jobs"][1]["parameters"]
    assert spider["postForm"] is False and spider["requestWaitTime"] == 500  # 2 requests per second
    assert any("Unauthenticated" in note for note in ctx.coverage_notes)
    assert builder.timeout_seconds(ctx) == 1800.0  # type: ignore[arg-type]
    assert builder.classify_exit(ctx, 1) == "completed_partial"  # type: ignore[arg-type]
    squid_conf = (work_dir(ctx) / "proxy" / "squid.conf").read_text(encoding="ascii")
    assert "http_access allow dast_ips dast_ports" in squid_conf


async def test_zap_api_scan_with_an_uploaded_definition(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.db.models.artifacts import Artifact
    from securescan.db.models.enums import ArtifactKind
    from securescan.storage.artifacts import save_bytes

    session = FakeSession()
    artifact = await save_bytes(session, kind=ArtifactKind.UPLOAD, data=b'{"openapi":"3.0.0"}', filename="shop-api.json")
    assert isinstance(artifact, Artifact)
    target = make_target(api_spec_type="openapi", api_spec_artifact_id=artifact.id)
    ctx, _fake, _ = prepared_ctx("zap", "api", monkeypatch, target=target, session=session)
    await get_builder("zap").prepare(ctx)  # type: ignore[arg-type]
    assert (ctx.workspace.config / "api-spec.json").read_bytes() == b'{"openapi":"3.0.0"}'
    plan = yaml.safe_load((ctx.workspace.config / "plan.yaml").read_text(encoding="utf-8"))
    importer = next(j for j in plan["jobs"] if j["type"] == "openapi")
    assert importer["parameters"]["apiFile"] == "/zap/config/api-spec.json"


async def test_zap_api_scan_with_a_definition_url_allows_its_host(monkeypatch: pytest.MonkeyPatch) -> None:
    target = make_target(api_spec_type="openapi", api_spec_locator="http://10.99.0.5:9000/openapi.json")
    ctx, fake, _ = prepared_ctx("zap", "api", monkeypatch, target=target)
    await get_builder("zap").prepare(ctx)  # type: ignore[arg-type]
    conf = (work_dir(ctx) / "proxy" / "squid.conf").read_text(encoding="ascii")
    assert "acl dast_ips dst 10.20.30.40 10.99.0.5" in conf and "acl dast_ports port 8080 9000" in conf
    plan = yaml.safe_load((ctx.workspace.config / "plan.yaml").read_text(encoding="utf-8"))
    assert next(j for j in plan["jobs"] if j["type"] == "openapi")["parameters"]["apiUrl"] == "http://10.99.0.5:9000/openapi.json"


async def test_a_missing_uploaded_definition_removes_the_proxy_again(monkeypatch: pytest.MonkeyPatch) -> None:
    target = make_target(api_spec_type="openapi", api_spec_artifact_id=uuid.uuid4())
    ctx, fake, _ = prepared_ctx("zap", "api", monkeypatch, target=target)
    with pytest.raises(ToolPreparationError) as caught:
        await get_builder("zap").prepare(ctx)  # type: ignore[arg-type]
    assert caught.value.code == "zap.api_spec_missing"
    assert len(fake.created) == 1 and fake.removed, "the proxy that was started is removed"


@pytest.mark.parametrize(
    "mode, target_overrides, application, code",
    [
        ("full", {"environment": PRODUCTION}, None, "dast.production_baseline_only"),
        ("api", {"environment": PRODUCTION, "api_spec_type": "openapi", "api_spec_locator": "http://10.20.30.40/o.json"}, None, "dast.production_baseline_only"),
        ("baseline", {"environment": PRODUCTION, "login_profile_id": uuid.uuid4()}, None, "dast.production_baseline_only"),
        ("nuclei", {}, None, "zap.mode_unsupported"),
        ("baseline", {"locator": "http://172.16.0.5/"}, None, "dast.host_not_allowlisted"),
        ("baseline", {"locator": "http://127.0.0.1:3000/", "host_approved": True}, None, "dast.host_blocked"),
        ("baseline", {"blackout_windows": [{"days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "00:00"}]}, None, "dast.blackout_window"),
        ("baseline", {}, make_application(AppType.VENDOR, "saas"), "dast.vendor_authorization_required"),
        ("api", {}, None, "dast.api_spec_required"),
    ],
)
async def test_prepare_asks_the_rules_again(
    monkeypatch: pytest.MonkeyPatch, mode: str, target_overrides: dict[str, Any], application: Any, code: str
) -> None:
    ctx, fake, scheduled = prepared_ctx("zap", mode, monkeypatch, target=make_target(**target_overrides), application=application)
    with pytest.raises(ToolPreparationError) as caught:
        await get_builder("zap").prepare(ctx)  # type: ignore[arg-type]
    assert caught.value.code == code
    assert fake.created == [] and scheduled.calls == [], "no proxy is started for a scan the rules forbid"


async def test_an_authorization_that_ran_out_while_queued_stops_the_job(monkeypatch: pytest.MonkeyPatch) -> None:
    target = make_target(
        vendor_authorization_artifact_id=uuid.uuid4(), vendor_authorized_from=utcnow() - timedelta(days=2),
        vendor_authorized_until=utcnow() - timedelta(minutes=1), vendor_contact="pat@vendor.example",
    )  # fmt: skip
    ctx, fake, _ = prepared_ctx("zap", "baseline", monkeypatch, target=target, application=make_application(AppType.VENDOR, "saas"))
    with pytest.raises(ToolPreparationError) as caught:
        await get_builder("zap").prepare(ctx)  # type: ignore[arg-type]
    assert caught.value.code == "dast.vendor_authorization_expired" and "ended" in str(caught.value)


@pytest.mark.parametrize(
    "case, code",
    [
        ("revoked", "zap.login_missing"),
        ("expired", "zap.login_expired"),
        ("foreign_host", "zap.login_invalid"),
        ("incomplete_secret", "zap.login_invalid"),
        ("wrong_kind", "zap.login_missing"),
        ("gone", "zap.login_missing"),
    ],
)
async def test_a_broken_login_profile_fails_the_job_with_a_reason(
    monkeypatch: pytest.MonkeyPatch, master_key: str, case: str, code: str
) -> None:
    session = FakeSession()
    overrides: dict[str, Any] = {}
    if case == "foreign_host":
        overrides["settings"] = {"login_page_url": "http://10.99.9.9/login", "login_request_url": "http://10.99.9.9/login"}
    if case == "incomplete_secret":
        overrides["secret"] = '{"username":"analyst"}'
    credential = await login_credential(session, **overrides)
    if case == "revoked":
        credential.revoked_at = utcnow()
    if case == "expired":
        credential.expires_at = utcnow() - timedelta(days=1)
    if case == "wrong_kind":
        credential.kind = CredentialKind.VENDOR_TOKEN
    login_id = uuid.uuid4() if case == "gone" else credential.id
    ctx, fake, _ = prepared_ctx("zap", "full", monkeypatch, target=make_target(login_profile_id=login_id), session=session)
    with pytest.raises(ToolPreparationError) as caught:
        await get_builder("zap").prepare(ctx)  # type: ignore[arg-type]
    assert caught.value.code == code
    assert PASSWORD not in str(caught.value)
    assert fake.created == []


async def test_a_proxy_that_will_not_start_fails_the_job(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.unit.dast_helpers import FakeLauncher

    ctx, fake, _ = prepared_ctx("zap", "baseline", monkeypatch, launcher=FakeLauncher(running=False, exits=True))
    with pytest.raises(ToolPreparationError) as caught:
        await get_builder("zap").prepare(ctx)  # type: ignore[arg-type]
    assert caught.value.code == "dast.proxy_failed" and "scan proxy" in str(caught.value)
    assert fake.removed


async def test_zap_post_run_summarises_stores_and_removes(monkeypatch: pytest.MonkeyPatch) -> None:
    session = FakeSession()
    ctx, fake, _ = prepared_ctx("zap", "baseline", monkeypatch, session=session)
    builder = get_builder("zap")
    await builder.prepare(ctx)  # type: ignore[arg-type]
    state = state_of(ctx)
    assert state is not None
    logs = state.proxy.directory / "logs"
    (logs / "access.log").write_text(
        "1 1 c TCP_MISS/200 1 GET http://10.20.30.40:8080/ - HIER_DIRECT/10.20.30.40 -\n"
        "2 1 c TCP_DENIED/403 1 GET http://example.com/ - HIER_NONE/- -\n",
        encoding="utf-8",
    )
    await builder.post_run(ctx, RESULT)  # type: ignore[arg-type]
    note = next(n for n in ctx.coverage_notes if n.startswith("Scan proxy:"))
    assert "10.20.30.40 (1)" in note and "example.com (1)" in note and "WARNING" not in note
    names = sorted(str(a.filename) for a in session.added)
    assert names == ["dast-proxy-access.log", "zap-plan.yaml"]
    assert fake.removed, "the proxy is removed once the job is done"
    stored = [a for a in session.added if a.filename == "zap-plan.yaml"][0]
    from securescan.storage.artifacts import read_bytes

    assert PASSWORD.encode() not in await read_bytes(stored)


async def test_cleanup_hook_removes_the_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, fake, _ = prepared_ctx("zap", "baseline", monkeypatch)
    builder = get_builder("zap")
    await builder.prepare(ctx)  # type: ignore[arg-type]
    await builder.cleanup(ctx)  # type: ignore[attr-defined]
    assert fake.removed


# --------------------------------------------------------------------------- Nuclei
def install_templates(ctx: Any, *, linked: bool = True) -> Path:
    content = Path(ctx.settings.content_root)
    real = content / "nuclei-templates-2026-10-05"
    real.mkdir(parents=True)
    (real / "http").mkdir()
    (real / "http" / "x.yaml").write_text("id: x\n", encoding="utf-8")
    if linked:
        try:
            os.symlink(real.name, content / "nuclei-templates")
        except (OSError, NotImplementedError):
            real.rename(content / "nuclei-templates")
            return content / "nuclei-templates"
    return real


NUCLEI_FIXED = (
    "-duc -ni -dut -nc -ud /content/nuclei-templates -etags dos,fuzz,bruteforce,local,txt-service,intrusive "
    "-severity low,medium,high,critical -r /config/resolvers.txt -rd Authorization,Cookie "
    "-json-export /out/nuclei.json"
).split()


async def test_nuclei_command_line_and_container(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, fake, scheduled = prepared_ctx("nuclei", "full", monkeypatch)
    install_templates(ctx)
    builder = get_builder("nuclei")
    await builder.prepare(ctx)  # type: ignore[arg-type]
    spec = builder.container_spec(ctx)  # type: ignore[arg-type]
    state = state_of(ctx)
    assert state is not None
    expected = (
        ["nuclei", "-u", "http://10.20.30.40:8080/"] + NUCLEI_FIXED
        + ["-proxy", f"http://{state.proxy.name}:3128", "-rl", "50", "-c", "10"]
    )  # fmt: skip
    assert spec.command == expected
    for flag in ("-duc", "-ni", "-dut"):  # no update check, no interactsh, no unsigned templates
        assert flag in spec.command
    assert "-update-templates" not in spec.command and "-ut" not in spec.command and "-iserver" not in spec.command
    assert spec.network == ctx.settings.network_dast and spec.extra_networks == []
    mounts = {target: (src, ro) for src, target, ro in spec.binds}
    assert mounts["/out"][1] is False and mounts["/config"][1] is True and mounts["/content/nuclei-templates"][1] is True
    assert mounts["/content/nuclei-templates"][0].endswith("nuclei-templates-2026-10-05") or mounts["/content/nuclei-templates"][0].endswith("nuclei-templates")
    assert spec.env["NUCLEI_CONFIG_DIR"] == "/tmp/nuclei-config" and spec.env["HOME"] == "/tmp"  # noqa: S108
    assert ctx.content_versions["nuclei_templates"] in ("nuclei-templates-2026-10-05", "nuclei-templates")
    assert (ctx.workspace.config / "resolvers.txt").read_text(encoding="utf-8").strip() == "127.0.0.11"
    assert len(fake.created) == 1 and len(scheduled.calls) == 1
    assert not any(PASSWORD in part for part in spec.command)


async def test_nuclei_rate_follows_the_target_and_the_platform_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, _fake, _ = prepared_ctx("nuclei", "full", monkeypatch, target=make_target(rate_limit_rps=4))
    install_templates(ctx)
    await get_builder("nuclei").prepare(ctx)  # type: ignore[arg-type]
    command = get_builder("nuclei").container_spec(ctx).command  # type: ignore[arg-type]
    assert command[command.index("-rl") + 1] == "4" and command[command.index("-c") + 1] == "4"  # never more workers than the rate
    capped, _f, _s = prepared_ctx("nuclei", "full", monkeypatch, extra_env={"SECURESCAN_DAST_MAX_RPS": "20"})
    await get_builder("nuclei").prepare(capped)  # type: ignore[arg-type]
    command = get_builder("nuclei").container_spec(capped).command  # type: ignore[arg-type]
    assert command[command.index("-rl") + 1] == "20" and command[command.index("-c") + 1] == "10"
    assert rate_flags(1, 10) == [("-rl", "1"), ("-c", "1")] and rate_flags(0, 0) == [("-rl", "1"), ("-c", "1")]


@pytest.mark.parametrize("mode", ["full", "api", "nuclei"])
async def test_nuclei_modes_on_uat_are_accepted(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    target = make_target(api_spec_type="openapi", api_spec_locator="http://10.20.30.40:8080/o.json")
    ctx, fake, _ = prepared_ctx("nuclei", mode, monkeypatch, target=target)
    install_templates(ctx)
    await get_builder("nuclei").prepare(ctx)  # type: ignore[arg-type]
    assert len(fake.created) == 1


@pytest.mark.parametrize(
    "mode, environment, code",
    [
        ("full", PRODUCTION, "dast.production_baseline_only"),
        ("nuclei", PRODUCTION, "dast.production_baseline_only"),
        ("baseline", TargetEnvironment.UAT, "dast.production_baseline_only"),
        ("full", None, "dast.production_baseline_only"),
    ],
)
async def test_nuclei_never_runs_outside_uat(monkeypatch: pytest.MonkeyPatch, mode: str, environment: Any, code: str) -> None:
    ctx, fake, _ = prepared_ctx("nuclei", mode, monkeypatch, target=make_target(environment=environment))
    install_templates(ctx)
    with pytest.raises(ToolPreparationError) as caught:
        await get_builder("nuclei").prepare(ctx)  # type: ignore[arg-type]
    assert caught.value.code == code and fake.created == []


async def test_nuclei_needs_installed_templates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ctx, fake, _ = prepared_ctx("nuclei", "full", monkeypatch)
    with pytest.raises(ToolPreparationError) as caught:
        await get_builder("nuclei").prepare(ctx)  # type: ignore[arg-type]
    assert caught.value.code == "nuclei.templates_missing" and "template update" in str(caught.value)
    assert fake.created == []
    content = Path(ctx.settings.content_root)
    (content / "nuclei-templates").mkdir(parents=True)  # an empty directory is as good as none
    with pytest.raises(ToolPreparationError):
        resolve_templates_dir(content)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "t.yaml").write_text("id: t\n", encoding="utf-8")
    (content / "nuclei-templates").rmdir()
    try:
        os.symlink(outside, content / "nuclei-templates")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")
    with pytest.raises(ToolPreparationError) as escaped:
        resolve_templates_dir(content)
    assert escaped.value.code == "nuclei.templates_invalid"


def test_nuclei_exit_codes_and_the_empty_report(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, _fake, _ = prepared_ctx("nuclei", "full", monkeypatch)
    builder = get_builder("nuclei")
    report = ctx.workspace.out / "nuclei.json"
    assert builder.classify_exit(ctx, 1) == "failed" and not report.exists()  # type: ignore[arg-type]
    assert builder.classify_exit(ctx, 137) == "failed" and builder.classify_exit(ctx, None) == "failed"  # type: ignore[arg-type]
    assert builder.classify_exit(ctx, 0) == "completed"  # type: ignore[arg-type]
    assert report.read_text(encoding="utf-8").strip() == "[]"  # a clean run exports nothing: the report is made
    report.write_text('[{"template-id":"x"}]', encoding="utf-8")
    assert builder.classify_exit(ctx, 0) == "completed"  # type: ignore[arg-type]
    assert report.read_text(encoding="utf-8") == '[{"template-id":"x"}]'  # never overwritten
    report.write_text("", encoding="utf-8")
    assert ensure_report(report) is True and report.read_text(encoding="utf-8").strip() == "[]"
    assert ensure_report(report) is False


def test_nuclei_catalogue_entry_and_flag_allowlist() -> None:
    from tests.unit.runner_helpers import real_catalogue

    entry = real_catalogue()["nuclei"]
    assert entry.network == "dast" and entry.lock == "dast" and entry.max_parallel == 1 and entry.target_kinds == ["url"]
    assert entry.defectdojo_scan_type == "Nuclei Scan" and entry.defectdojo_file == "nuclei.json"
    assert entry.outcome_for(0) == "completed" and entry.outcome_for(1) == "failed" and entry.outcome_for(2) == "failed"
    assert entry.render_command({"target_url": "http://t/"})[:2] == ["nuclei", "-u"]
    with pytest.raises(OptionalArgError):
        entry.render_optional_args([("-update-templates", None)])
    with pytest.raises(OptionalArgError):
        entry.render_optional_args([("-iserver", "oast.example")])
    assert entry.render_optional_args([("-rl", "10")]) == ["-rl", "10"]
    with pytest.raises(OptionalArgError):
        entry.render_optional_args([("-rl", "10; rm -rf /")])
    assert nuclei_module.BUILDER is get_builder("nuclei") and zap_module.BUILDER is get_builder("zap")


async def test_nuclei_post_run_collects_the_proxy_log(monkeypatch: pytest.MonkeyPatch) -> None:
    session = FakeSession()
    ctx, fake, _ = prepared_ctx("nuclei", "full", monkeypatch, session=session)
    install_templates(ctx)
    builder = get_builder("nuclei")
    await builder.prepare(ctx)  # type: ignore[arg-type]
    state = state_of(ctx)
    assert isinstance(state, DastState)
    (state.proxy.directory / "logs" / "access.log").write_text(
        "1 1 c TCP_MISS/200 1 GET http://10.20.30.40:8080/ - HIER_DIRECT/10.20.30.40 -\n", encoding="utf-8"
    )
    await builder.post_run(ctx, RESULT)  # type: ignore[arg-type]
    assert [a.filename for a in session.added] == ["dast-proxy-access.log"]
    assert any(n.startswith("Scan proxy: 1 requests to 10.20.30.40 (1).") for n in ctx.coverage_notes)
    assert fake.removed
    assert STATE_KEY in ctx.options
