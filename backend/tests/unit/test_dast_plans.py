"""ZAP plan rendering: every mode, login methods, production safety, secrets handling and exit codes."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
import yaml

from securescan.db.models.enums import TargetKind
from securescan.domain.dast_rules import LoginSettings, login_env, parse_login_secret
from securescan.runner.dast_egress import ProxyHandle
from securescan.runner.tools import get_builder
from securescan.runner.tools import zap as zap_module
from securescan.runner.tools.zap import (
    LOGOUT_EXCLUDE,
    STATE_KEY,
    ApiSpec,
    DastState,
    PlanError,
    PlanInputs,
    PlanSafetyError,
    api_job,
    assert_plan_safe,
    build_values,
    dump_plan,
    exclude_regex,
    fill,
    include_regex,
    load_auth_fragment,
    load_auth_verification,
    load_plan_template,
    proxy_config_args,
    render_plan,
)
from tests.unit.runner_helpers import REPO_SCANNERS, make_ctx

TARGET = "http://10.20.30.40:8080/shop"
PASSWORD = "Very-Secret-Pa55word"
TOKEN = "Bearer eyJhbGciOiJIUzI1NiJ9.very.secret"


def render(mode: str, **overrides: Any) -> dict[str, Any]:
    inputs = PlanInputs(mode=mode, target_url=TARGET, **overrides)
    fragment = load_auth_fragment(inputs.login.method, REPO_SCANNERS) if inputs.login is not None else None
    tests = load_auth_verification(REPO_SCANNERS) if inputs.login is not None else None
    return render_plan(inputs, load_plan_template(mode, REPO_SCANNERS), auth_fragment=fragment, auth_tests=tests)


def types_of(plan: dict[str, Any]) -> list[str]:
    return [str(job["type"]) for job in plan["jobs"]]


def job(plan: dict[str, Any], kind: str, index: int = 0) -> dict[str, Any]:
    return [j for j in plan["jobs"] if j["type"] == kind][index]


def form_login(**overrides: Any) -> LoginSettings:
    values: dict[str, Any] = {
        "method": "form",
        "login_page_url": "http://10.20.30.40:8080/login",
        "login_request_url": "http://10.20.30.40:8080/login",
        "login_request_body": "user={%username%}&pass={%password%}",
        "logged_in_regex": "\\QSign out\\E",
        "logged_out_regex": "\\QSign in\\E",
    }
    values.update(overrides)
    return LoginSettings.model_validate(values)


# --------------------------------------------------------------------------- placeholders
def test_fill_keeps_types_drops_none_and_refuses_unknown_names() -> None:
    values = {"n": 5, "d": {"a": 1}, "none": None, "s": "x"}
    assert fill("{{n}}", values) == 5 and fill(" {{ n }} ", values) == 5
    assert fill("{{d}}", values) == {"a": 1}
    assert fill("v={{n}};{{s}}", values) == "v=5;x"
    assert fill({"a": "{{none}}", "b": ["{{none}}", "{{s}}"], "c": 1}, values) == {"b": ["x"], "c": 1}
    assert fill("${ZAP_AUTH_PASSWORD} {%username%}", values) == "${ZAP_AUTH_PASSWORD} {%username%}"
    with pytest.raises(PlanError, match="unknown value"):
        fill("{{nope}}", values)
    with pytest.raises(PlanError, match="unknown value"):
        fill("a {{nope}} b", values)


def test_every_template_placeholder_is_a_known_value() -> None:
    """A typo in a template must show up here, not in the first scan."""
    login = form_login()
    for mode in ("baseline", "full", "api"):
        api = ApiSpec("openapi", url="http://10.20.30.40:8080/openapi.json") if mode == "api" else None
        render(mode, api=api)
        render(mode, api=api, login=login)
    for method, settings in {
        "json": form_login(method="json"),
        "header": LoginSettings.model_validate(
            {"method": "header", "header_name": "Authorization", "poll_url": "http://10.20.30.40:8080/api/me"}
        ),
        "browser": LoginSettings.model_validate(
            {"method": "browser", "login_page_url": "http://10.20.30.40:8080/", "logged_in_regex": "Logout"}
        ),
    }.items():
        assert render("full", login=settings)["jobs"], method


def test_the_templates_are_not_scan_profiles_and_the_dast_profiles_are() -> None:
    from securescan.runner.profiles import parse_profile_yaml

    for name in ("zap-baseline-prod", "zap-full-uat", "zap-api-uat", "nuclei-uat"):
        data = yaml.safe_load((REPO_SCANNERS / "profiles" / f"{name}.yaml").read_text(encoding="utf-8"))
        assert "profile" not in data and "tool" not in data, name  # seeding and tool settings skip them
    expected = {
        "dast-baseline": ("baseline", ["zap"]),
        "dast-full": ("full", ["zap", "nuclei"]),
        "dast-api": ("api", ["zap", "nuclei"]),
    }
    for name, (mode, tools) in expected.items():
        doc = parse_profile_yaml((REPO_SCANNERS / "profiles" / f"{name}.yaml").read_text(encoding="utf-8"))
        assert doc.profile == name and doc.kind == "dast" and doc.mode == mode and doc.tools == tools
        assert doc.version == 1


def test_dast_profile_timeouts() -> None:
    from securescan.runner.profiles import parse_profile_yaml

    baseline = parse_profile_yaml((REPO_SCANNERS / "profiles" / "dast-baseline.yaml").read_text(encoding="utf-8"))
    assert baseline.job("zap").job_options()["timeout_minutes"] == 30  # type: ignore[union-attr]
    full = parse_profile_yaml((REPO_SCANNERS / "profiles" / "dast-full.yaml").read_text(encoding="utf-8"))
    assert full.job("zap").job_options()["timeout_minutes"] == 480  # type: ignore[union-attr]


# --------------------------------------------------------------------------- baseline (production)
def test_production_baseline_has_only_passive_jobs_and_never_posts_forms() -> None:
    plan = render("baseline", production=True)
    assert types_of(plan) == ["passiveScan-config", "spider", "passiveScan-wait", "report", "report"]
    text = dump_plan(plan)
    assert "activeScan" not in text and "spiderAjax" not in text and "requestor" not in text
    assert "postForm: true" not in text and "processForm: true" not in text
    spider = job(plan, "spider")["parameters"]
    assert spider["postForm"] is False and spider["processForm"] is False
    assert spider["maxDuration"] == 5 and spider["threadCount"] == 1 and spider["context"] == "target"
    assert spider["url"] == TARGET and "user" not in spider
    reports = [j["parameters"] for j in plan["jobs"] if j["type"] == "report"]
    assert [(r["template"], r["reportDir"], r["reportFile"]) for r in reports] == [
        ("traditional-xml-plus", "/zap/wrk", "zap"),
        ("traditional-html", "/zap/wrk", "zap-report"),
    ]
    context = plan["env"]["contexts"][0]
    assert "authentication" not in context and "users" not in context
    assert plan["env"]["parameters"]["failOnError"] is True


def test_the_request_wait_follows_the_rate_cap() -> None:
    assert job(render("baseline", production=True, rate_rps=5), "spider")["parameters"]["requestWaitTime"] == 200
    assert job(render("baseline", production=True, rate_rps=1), "spider")["parameters"]["requestWaitTime"] == 1000
    assert job(render("baseline", production=True, rate_rps=1000), "spider")["parameters"]["requestWaitTime"] == 1
    full = render("full", rate_rps=5)
    assert job(full, "activeScan")["parameters"]["delayInMs"] == 400  # two threads, 5 requests per second
    assert job(full, "spider")["parameters"]["requestWaitTime"] == 400


def test_a_production_plan_is_refused_when_it_could_attack_or_log_in() -> None:
    with pytest.raises(PlanSafetyError):
        render("full", production=True)
    with pytest.raises(PlanSafetyError):
        render("baseline", production=True, login=form_login())
    with pytest.raises(PlanSafetyError):
        render("api", production=True, api=ApiSpec("openapi", url="http://x/o.json"))
    good = render("baseline", production=True)
    for mutate in (
        lambda p: p["jobs"].append({"type": "activeScan", "parameters": {}}),
        lambda p: p["jobs"].append({"type": "openapi", "parameters": {}}),
        lambda p: p["jobs"].append({"type": "spiderAjax", "parameters": {}}),
        lambda p: p["jobs"].insert(0, {"type": "requestor", "requests": []}),
        lambda p: job(p, "spider")["parameters"].update(postForm=True),
        lambda p: job(p, "spider")["parameters"].update(processForm=True),
        lambda p: job(p, "spider")["parameters"].pop("postForm"),
        lambda p: p["env"]["contexts"][0].update(users=[{"name": "x"}]),
        lambda p: p["env"]["contexts"][0].update(authentication={"method": "form"}),
    ):
        broken = yaml.safe_load(dump_plan(good))
        mutate(broken)
        with pytest.raises(PlanSafetyError):
            assert_plan_safe(broken, production=True)
    assert_plan_safe(good, production=True)
    assert_plan_safe(render("full"), production=False)  # the check is for production only


def test_baseline_on_uat_may_carry_a_login() -> None:
    plan = render("baseline", login=form_login())
    assert job(plan, "requestor")["parameters"]["user"] == "scan-user"
    assert job(plan, "spider")["parameters"]["user"] == "scan-user"
    assert job(plan, "spider")["parameters"]["postForm"] is False


# --------------------------------------------------------------------------- full and api (UAT)
def test_full_plan_jobs() -> None:
    plan = render("full", timeout_minutes=480)
    assert types_of(plan) == [
        "passiveScan-config", "spider", "spiderAjax", "passiveScan-wait", "activeScan", "passiveScan-wait", "report", "report",
    ]  # fmt: skip
    ajax = job(plan, "spiderAjax")["parameters"]
    assert ajax["numberOfBrowsers"] == 1 and ajax["browserId"] == "firefox-headless" and ajax["inScopeOnly"] is True
    active = job(plan, "activeScan")["parameters"]
    assert active["threadPerHost"] == 2 and active["maxScanDurationInMins"] == 360
    assert isinstance(active["delayInMs"], int) and active["delayInMs"] == 200  # 2 threads at the default 10 rps
    assert job(plan, "spider")["parameters"]["maxDuration"] == 15 and ajax["maxDuration"] == 20
    assert "postForm" not in job(plan, "spider")["parameters"]  # UAT: ZAP's default (forms are exercised)


def test_durations_follow_the_timeout_and_the_options() -> None:
    short = job(render("full", timeout_minutes=120), "activeScan")["parameters"]["maxScanDurationInMins"]
    assert short == 30
    tiny = job(render("full", timeout_minutes=20), "activeScan")["parameters"]["maxScanDurationInMins"]
    assert tiny == 10
    chosen = render("full", timeout_minutes=480, active_minutes=45, spider_minutes=3, ajax_minutes=4)
    assert job(chosen, "activeScan")["parameters"]["maxScanDurationInMins"] == 45
    assert job(chosen, "spider")["parameters"]["maxDuration"] == 3
    assert job(chosen, "spiderAjax")["parameters"]["maxDuration"] == 4
    huge = render("full", active_minutes=100000)
    assert job(huge, "activeScan")["parameters"]["maxScanDurationInMins"] == 720


@pytest.mark.parametrize(
    "spec, job_type, parameters",
    [
        (ApiSpec("openapi", url="http://10.20.30.40:8080/openapi.json"), "openapi", {"context": "target", "targetUrl": TARGET, "apiUrl": "http://10.20.30.40:8080/openapi.json"}),
        (ApiSpec("openapi", file="/zap/config/api-spec.json"), "openapi", {"context": "target", "targetUrl": TARGET, "apiFile": "/zap/config/api-spec.json"}),
        (ApiSpec("graphql", url="http://10.20.30.40:8080/schema"), "graphql", {"endpoint": TARGET, "schemaUrl": "http://10.20.30.40:8080/schema"}),
        (ApiSpec("graphql", file="/zap/config/api-spec.graphql"), "graphql", {"endpoint": TARGET, "schemaFile": "/zap/config/api-spec.graphql"}),
        (ApiSpec("soap", url="http://10.20.30.40:8080/svc?wsdl"), "soap", {"wsdlUrl": "http://10.20.30.40:8080/svc?wsdl"}),
        (ApiSpec("soap", file="/zap/config/api-spec.wsdl"), "soap", {"wsdlFile": "/zap/config/api-spec.wsdl"}),
    ],
)
def test_api_plan_imports_the_definition_then_attacks(spec: ApiSpec, job_type: str, parameters: dict[str, Any]) -> None:
    plan = render("api", api=spec)
    assert types_of(plan) == ["passiveScan-config", job_type, "passiveScan-wait", "activeScan", "passiveScan-wait", "report", "report"]
    assert job(plan, job_type)["parameters"] == parameters
    assert api_job(spec, TARGET) == (job_type, parameters)


def test_api_definition_errors() -> None:
    with pytest.raises(PlanError):
        api_job(ApiSpec("raml", url="http://x"), TARGET)
    with pytest.raises(PlanError):
        api_job(ApiSpec("openapi"), TARGET)
    with pytest.raises(PlanError):
        render("api")  # no definition at all: the placeholders stay empty and the type is missing
    with pytest.raises(PlanError):
        load_plan_template("nuclei", REPO_SCANNERS)  # no ZAP plan for the Nuclei mode


# --------------------------------------------------------------------------- scope
def test_scope_defaults_to_the_targets_own_subtree() -> None:
    context = render("baseline", production=True)["env"]["contexts"][0]
    assert context["name"] == "target" and context["urls"] == [TARGET]
    assert context["includePaths"] == [r"http://10\.20\.30\.40:8080/shop(/.*)?"]
    assert "excludePaths" not in context
    import re

    assert re.fullmatch(context["includePaths"][0], "http://10.20.30.40:8080/shop/items?id=1")
    assert re.fullmatch(context["includePaths"][0], "http://10.20.30.40:8080/shop")
    assert not re.fullmatch(context["includePaths"][0], "http://10.20.30.40:8080/shopping")
    assert not re.fullmatch(context["includePaths"][0], "http://evil.example/shop/")


def test_scope_entries_become_regexes() -> None:
    origin = "http://10.20.30.40:8080"
    assert include_regex(origin, "/shop/.*") == r"http://10\.20\.30\.40:8080/shop/.*"
    assert include_regex(origin, r"http://10\.20\.30\.40:8080/api/.*") == r"http://10\.20\.30\.40:8080/api/.*"
    assert exclude_regex(origin, "/logout") == r"http://10\.20\.30\.40:8080/logout.*"
    assert exclude_regex(origin, "/admin/.*") == r"http://10\.20\.30\.40:8080/admin/.*"
    assert exclude_regex(origin, ".*delete.*") == ".*delete.*"
    with pytest.raises(PlanError, match="regular expression"):
        exclude_regex(origin, "(")
    context = render("full", includes=["/shop/.*"], excludes=["/logout", ".*\\.pdf"])["env"]["contexts"][0]
    assert context["includePaths"] == [r"http://10\.20\.30\.40:8080/shop/.*"]
    assert context["excludePaths"] == [r"http://10\.20\.30\.40:8080/logout.*", r".*\.pdf"]


# --------------------------------------------------------------------------- logins
def test_form_login_context_and_verification_block() -> None:
    plan = render("full", login=form_login())
    context = plan["env"]["contexts"][0]
    auth = context["authentication"]
    assert auth["method"] == "form"
    assert auth["parameters"] == {
        "loginPageUrl": "http://10.20.30.40:8080/login",
        "loginRequestUrl": "http://10.20.30.40:8080/login",
        "loginRequestBody": "user={%username%}&pass={%password%}",
    }
    verification = auth["verification"]  # mandatory
    assert verification == {"method": "response", "loggedInRegex": "\\QSign out\\E", "loggedOutRegex": "\\QSign in\\E"}
    assert context["sessionManagement"] == {"method": "cookie"}
    assert context["users"] == [
        {"name": "scan-user", "credentials": {"username": "${ZAP_AUTH_USERNAME}", "password": "${ZAP_AUTH_PASSWORD}"}}
    ]
    assert LOGOUT_EXCLUDE in context["excludePaths"]  # the scan never logs its own user out
    assert types_of(plan)[0] == "requestor"
    probe = plan["jobs"][0]
    assert probe["parameters"] == {"user": "scan-user"} and probe["requests"][0]["url"] == TARGET
    check = probe["tests"][0]
    assert check["type"] == "stats" and check["onFail"] == "error" and check["operator"] == ">=" and check["value"] == 1
    for kind in ("spider", "spiderAjax", "activeScan"):
        assert job(plan, kind)["parameters"]["user"] == "scan-user"


def test_poll_verification_fields_only_for_poll() -> None:
    poll = form_login(verification_method="poll", poll_url="http://10.20.30.40:8080/me", poll_frequency=30, poll_units="seconds")
    verification = render("full", login=poll)["env"]["contexts"][0]["authentication"]["verification"]
    assert verification["method"] == "poll" and verification["pollUrl"] == "http://10.20.30.40:8080/me"
    assert verification["pollFrequency"] == 30 and verification["pollUnits"] == "seconds"


def test_json_and_browser_logins() -> None:
    body = '{"user":"{%username%}","password":"{%password%}"}'
    plan = render("full", login=form_login(method="json", login_request_body=body))
    assert plan["env"]["contexts"][0]["authentication"]["method"] == "json"
    assert plan["env"]["contexts"][0]["authentication"]["parameters"]["loginRequestBody"] == body
    browser = LoginSettings.model_validate(
        {
            "method": "browser", "login_page_url": "http://10.20.30.40:8080/", "logged_in_regex": "Logout", "totp": True,
            "steps": [{"type": "USERNAME", "css_selector": "#u"}, {"type": "PASSWORD", "css_selector": "#p"}],
        }
    )  # fmt: skip
    context = render("full", login=browser)["env"]["contexts"][0]
    assert context["authentication"]["method"] == "browser"
    assert context["authentication"]["parameters"]["browserId"] == "firefox-headless"
    assert context["authentication"]["parameters"]["steps"][0] == {"type": "USERNAME", "cssSelector": "#u"}
    credentials = context["users"][0]["credentials"]
    assert credentials["totp"] == {"secret": "${ZAP_AUTH_TOTP_SECRET}", "period": 30, "digits": 6, "algorithm": "SHA1"}
    plain = LoginSettings.model_validate({"method": "browser", "login_page_url": "http://10.20.30.40:8080/", "logged_in_regex": "x"})
    assert "totp" not in render("full", login=plain)["env"]["contexts"][0]["users"][0]["credentials"]


def test_header_login_uses_a_replacer_and_a_token_check() -> None:
    login = LoginSettings.model_validate(
        {"method": "header", "header_name": "Authorization", "poll_url": "http://10.20.30.40:8080/api/me", "expected_status": 200}
    )
    plan = render("full", login=login)
    assert types_of(plan)[:2] == ["replacer", "requestor"]
    rule = plan["jobs"][0]["rules"][0]
    assert rule["matchType"] == "req_header" and rule["matchString"] == "${ZAP_AUTH_HEADER}"
    assert rule["replacementString"] == "${ZAP_AUTH_HEADER_VALUE}"
    assert rule["url"] == r"http://10\.20\.30\.40:8080.*"  # the token only goes to the target's origin
    request = plan["jobs"][1]["requests"][0]
    assert request["url"] == "http://10.20.30.40:8080/api/me" and request["responseCode"] == 200
    context = plan["env"]["contexts"][0]
    assert "users" not in context and "authentication" not in context
    assert "user" not in job(plan, "spider")["parameters"]


def test_no_secret_value_is_ever_in_the_plan_text() -> None:
    form = form_login()
    secret = parse_login_secret(f'{{"username":"analyst","password":"{PASSWORD}"}}', form)
    env = login_env(form, secret, "http://10.20.30.40:8080")
    text = dump_plan(render("full", login=form))
    assert PASSWORD not in text and "analyst" not in text
    assert "${ZAP_AUTH_PASSWORD}" in text and env["ZAP_AUTH_PASSWORD"] == PASSWORD
    header = LoginSettings.model_validate({"method": "header", "header_name": "Authorization", "poll_url": "http://10.20.30.40:8080/me"})
    header_env = login_env(header, parse_login_secret(f'{{"header_value":"{TOKEN}"}}', header), "http://10.20.30.40:8080")
    header_text = dump_plan(render("api", login=header, api=ApiSpec("openapi", url="http://10.20.30.40:8080/o.json")))
    assert TOKEN not in header_text and "eyJ" not in header_text and header_env["ZAP_AUTH_HEADER_VALUE"] == TOKEN


def test_a_login_scan_needs_its_templates() -> None:
    inputs = PlanInputs(mode="full", target_url=TARGET, login=form_login())
    template = load_plan_template("full", REPO_SCANNERS)
    with pytest.raises(PlanError):
        render_plan(inputs, template, auth_fragment=None, auth_tests=[])
    with pytest.raises(PlanError, match="login check"):
        render_plan(inputs, template, auth_fragment=load_auth_fragment("form", REPO_SCANNERS), auth_tests=[])
    with pytest.raises(PlanError):
        load_auth_fragment("form", None)


def test_the_yaml_round_trips_and_has_jobs() -> None:
    for mode in ("baseline", "full"):
        plan = render(mode, production=(mode == "baseline"))
        loaded = yaml.safe_load(dump_plan(plan))
        assert loaded == plan and loaded["jobs"] and "contexts" in loaded["env"]
    assert list(yaml.safe_load(dump_plan(render("full")))) == ["env", "jobs"]  # order kept: env first


def test_proxy_switches_for_zap() -> None:
    assert proxy_config_args("securescan-dast-proxy-x") == [
        ("-config", "network.connection.httpProxy.enabled=true"),
        ("-config", "network.connection.httpProxy.host=securescan-dast-proxy-x"),
        ("-config", "network.connection.httpProxy.port=3128"),
    ]


def test_build_values_cover_the_templates() -> None:
    values = build_values(PlanInputs(mode="full", target_url=TARGET))
    assert {"context", "target_url", "user", "spider_threads", "spider_wait_ms", "active_threads", "active_delay_ms",
            "spider_minutes", "ajax_minutes", "active_minutes", "report_title", "api_job_type", "api_parameters"} <= set(values)  # fmt: skip
    assert values["user"] is None and values["api_job_type"] is None


# --------------------------------------------------------------------------- the builder: command, spec, exit codes
def zap_ctx(mode: str = "full", login: bool = False, **options: Any) -> Any:
    ctx = make_ctx("zap", kind=TargetKind.URL, options=dict(options))
    ctx.scan.mode = mode
    handle = ProxyHandle(
        name=f"securescan-dast-proxy-{uuid.uuid4()}", token="t", container_id="c" * 64, url="http://p:3128",
        hosts=["10.20.30.40"], ports=[8080], directory=Path(ctx.workspace.root) / "proxy",
    )  # fmt: skip
    env = {"ZAP_AUTH_USERNAME": "analyst", "ZAP_AUTH_PASSWORD": PASSWORD} if login else {}
    ctx.options[STATE_KEY] = DastState(proxy=handle, env=env, login=login)
    return ctx


def test_builder_is_registered_and_runs_on_the_dast_network_only() -> None:
    assert get_builder("zap") is zap_module.BUILDER
    ctx = zap_ctx()
    spec = zap_module.BUILDER.container_spec(ctx)
    state = ctx.options[STATE_KEY]
    assert spec.command[:5] == ["zap.sh", "-cmd", "-autorun", "/zap/config/plan.yaml", "-silent"]
    assert spec.command[5:] == [
        "-config", "network.connection.httpProxy.enabled=true",
        "-config", f"network.connection.httpProxy.host={state.proxy.name}",
        "-config", "network.connection.httpProxy.port=3128",
    ]  # fmt: skip
    assert spec.network == ctx.settings.network_dast and spec.extra_networks == []  # no way out except the proxy
    assert spec.shm_size == "1g" and spec.user == "1000:1000" and spec.read_only_rootfs is True
    assert spec.entrypoint == [""] and spec.mem_limit == "4g"
    targets = {target: (ro) for _src, target, ro in spec.binds}
    assert targets == {"/zap/wrk": False, "/zap/config": True}
    assert "/home/zap" in spec.tmpfs and spec.env["HOME"] == "/home/zap"


def test_login_secrets_travel_in_the_environment_only() -> None:
    ctx = zap_ctx(login=True)
    spec = zap_module.BUILDER.container_spec(ctx)
    assert spec.env["ZAP_AUTH_PASSWORD"] == PASSWORD and spec.env["ZAP_AUTH_USERNAME"] == "analyst"
    assert all(PASSWORD not in part and "analyst" != part for part in spec.command)
    assert PASSWORD not in " ".join(spec.command) and PASSWORD not in repr(spec.labels) and PASSWORD not in spec.name  # type: ignore[operator]
    clean = zap_module.BUILDER.container_spec(zap_ctx())
    assert "ZAP_AUTH_PASSWORD" not in clean.env


@pytest.mark.parametrize(
    "login, exit_code, outcome",
    [
        (False, 0, "completed"),
        (False, 2, "completed"),
        (False, 1, "completed_partial"),
        (False, 3, "failed"),
        (False, 125, "failed"),
        (False, 137, "failed"),
        (False, None, "failed"),
        (True, 0, "completed"),
        (True, 2, "completed"),
        (True, 1, "failed"),  # a plan error may be the failed login check: never report on a broken session
        (True, 137, "failed"),
        (True, None, "failed"),
    ],
)
def test_exit_codes(login: bool, exit_code: int | None, outcome: str) -> None:
    assert zap_module.BUILDER.classify_exit(zap_ctx(login=login), exit_code) == outcome


def test_catalogue_entry_of_zap() -> None:
    from tests.unit.runner_helpers import real_catalogue

    entry = real_catalogue()["zap"]
    assert entry.network == "dast" and entry.lock == "dast" and entry.max_parallel == 1
    assert entry.defectdojo_scan_type == "ZAP Scan" and entry.defectdojo_file == "zap.xml"
    assert entry.target_kinds == ["url"] and entry.user == "1000:1000"
    assert entry.mount_target("out") == "/zap/wrk"
    assert entry.outputs[0].file == "zap.xml" and entry.output("zap-report.html") is not None
    assert [entry.outcome_for(code) for code in (0, 1, 2, 3)] == ["completed", "completed_partial", "completed", "failed"]
    assert entry.optional_arg("-config") is not None and entry.optional_arg("-config").repeatable  # type: ignore[union-attr]

