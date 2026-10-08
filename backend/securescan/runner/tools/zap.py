"""ZAP: renders the Automation Framework plan and builds the container (no parsing, no findings).

What this builder adds to the catalogue entry (``scanners/catalogue.d/zap.yaml``):

* **The plan.** ``scanners/profiles/zap-<mode>.yaml`` is the skeleton of the jobs (baseline, full or API);
  this module generates the ``env`` (context with in-scope and excluded paths, the login profile's
  authentication and user) and fills the placeholders with the target's values (rate cap, durations, API
  definition). The result is written to ``/zap/config/plan.yaml`` (read-only mount). Secrets appear in the plan
  only as ``${ENV_NAME}`` references; the values travel as container environment variables.
* **The production guarantee.** A production plan may contain only passive jobs and a spider that does not
  post forms; ``assert_plan_safe`` refuses anything else, whatever the template or the options say.
* **The network.** The scanner joins the ``dast`` network only; ZAP is told to use the job's squid
  (``-config network.connection.httpProxy.*``) through the catalogue's ``-config`` switch. The proxy is
  started in ``prepare`` (``runner/dast_egress.py``) and removed with the job.
* **Exit codes.** 0 and 2 completed, 1 completed_partial (plan errors, the report exists), anything else failed.
  With a login profile exit 1 means failed: a plan error there may be the failed login check, and a scan whose
  login broke must not produce a clean-looking report.
"""

from __future__ import annotations

import math
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from securescan.db.models.credentials import Credential
from securescan.db.models.enums import CredentialKind
from securescan.domain.credentials import reveal_secret
from securescan.domain.dast_rules import (
    LoginProfileError,
    LoginSettings,
    api_spec_url,
    check_java_regex,
    effective_rate,
    login_env,
    parse_login_secret,
    parse_login_settings,
    split_url,
)
from securescan.logging import get_logger
from securescan.runner.catalogue import find_scanners_dir
from securescan.runner.dast_egress import (
    PROXY_PORT,
    ProxyHandle,
    finish_job_proxy,
    prepare_job_network,
    release_proxy,
)
from securescan.runner.specs import ContainerResult, ContainerSpec
from securescan.runner.tools.base import (
    DefaultToolBuilder,
    JobOutcome,
    ToolContext,
    ToolPreparationError,
)
from securescan.runner.workspace import make_world_readable
from securescan.security.secrets import SecretsError
from securescan.storage.artifacts import StorageError, artifact_path
from securescan.util import ensure_utc, utcnow

log = get_logger(__name__)

TOOL = "zap"
STATE_KEY = "_dast_state"
CONTEXT_NAME = "target"
USER_NAME = "scan-user"
PLAN_NAME = "plan.yaml"
CONFIG_MOUNT = "/zap/config"
DEFAULT_RPS = 10  # the target has no rate cap: a modest default for ZAP
TEMPLATE_BY_MODE = {"baseline": "zap-baseline-prod", "full": "zap-full-uat", "api": "zap-api-uat"}
PRODUCTION_JOB_TYPES = frozenset({"passiveScan-config", "spider", "passiveScan-wait", "report"})
LOGOUT_EXCLUDE = "(?i).*(logout|log-out|signout|sign-out|logoff).*"
API_SPEC_MAX_BYTES = 20 * 1024 * 1024
API_JOB_TYPES = ("openapi", "graphql", "soap")
MAX_MINUTES = 720

_PLACEHOLDER = re.compile(r"\{\{\s*([a-z_0-9]+)\s*\}\}")
_SPEC_EXTENSION = re.compile(r"^\.[A-Za-z0-9]{1,8}$")


class PlanError(Exception):
    """The plan cannot be rendered (a template is missing or damaged, or a value is not usable)."""


class PlanSafetyError(PlanError):
    """The rendered plan would break the production rule (passive, no form posting)."""


# --------------------------------------------------------------------------- templates
def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PlanError("The plan template %s cannot be read: %s" % (path.name, str(exc)[:120])) from exc
    if not isinstance(data, dict):
        raise PlanError("The plan template %s must be a YAML mapping." % path.name)
    return data


def load_plan_template(mode: str, scanners_dir: Path | None) -> dict[str, Any]:
    name = TEMPLATE_BY_MODE.get(mode)
    if name is None:
        raise PlanError("ZAP has no plan for the mode %r." % mode)
    if scanners_dir is None:
        raise PlanError("The scanners directory was not found, so the ZAP plan template cannot be read.")
    return _read_yaml(scanners_dir / "profiles" / ("%s.yaml" % name))


def load_auth_fragment(method: str, scanners_dir: Path | None) -> dict[str, Any]:
    if scanners_dir is None:
        raise PlanError("The scanners directory was not found, so the login template cannot be read.")
    return _read_yaml(scanners_dir / "dast" / "templates" / ("auth-%s.yaml" % method))


def load_auth_verification(scanners_dir: Path | None) -> list[dict[str, Any]]:
    if scanners_dir is None:
        raise PlanError("The scanners directory was not found, so the login template cannot be read.")
    tests = _read_yaml(scanners_dir / "dast" / "templates" / "auth-verify.yaml").get("tests")
    if not isinstance(tests, list) or not tests:
        raise PlanError("auth-verify.yaml must list at least one test: login scans need the check.")
    return [dict(t) for t in tests if isinstance(t, dict)]


def fill(value: Any, values: dict[str, Any]) -> Any:
    """Replace ``{{name}}`` in a template.

    A string that is exactly one placeholder takes the value's type (an int stays an int, a dict stays a
    dict). A mapping entry or list item whose value is None is dropped. A placeholder inside a longer string
    is replaced by text. An unknown name is an error, so a typo cannot silently weaken a plan.
    """
    if isinstance(value, str):
        whole = _PLACEHOLDER.fullmatch(value.strip())
        if whole is not None:
            name = whole.group(1)
            if name not in values:
                raise PlanError("The plan template uses an unknown value {{%s}}." % name)
            return values[name]

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in values:
                raise PlanError("The plan template uses an unknown value {{%s}}." % name)
            current = values[name]
            return "" if current is None else str(current)

        return _PLACEHOLDER.sub(replace, value)
    if isinstance(value, list):
        items = [fill(item, values) for item in value]
        return [item for item in items if item is not None]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            filled = fill(item, values)
            if filled is not None:
                result[key] = filled
        return result
    return value


# --------------------------------------------------------------------------- plan inputs
@dataclass
class ApiSpec:
    kind: str  # openapi | graphql | soap
    url: str | None = None  # fetched by ZAP through the proxy
    file: str | None = None  # path inside the container (/zap/config/...)


@dataclass
class PlanInputs:
    mode: str
    target_url: str
    production: bool = False
    includes: list[str] = field(default_factory=list)  # regexes; empty: the target's own subtree
    excludes: list[str] = field(default_factory=list)  # paths or regexes
    rate_rps: int = DEFAULT_RPS
    login: LoginSettings | None = None
    api: ApiSpec | None = None
    timeout_minutes: int = 480
    spider_minutes: int | None = None
    ajax_minutes: int | None = None
    active_minutes: int | None = None
    report_title: str = "SecureScan web scan"


def origin_of(url: str) -> str:
    return split_url(url).origin


def base_of(url: str) -> str:
    """The target's URL without query and fragment, no trailing slash: the root of its scope."""
    parts = urlsplit(url.strip())
    origin = origin_of(url)
    return origin + (parts.path or "").rstrip("/")


def include_regex(origin: str, entry: str) -> str:
    """An in-scope entry as a regular expression over the full URL (a path starts at the origin)."""
    text = entry.strip()
    pattern = re.escape(origin) + text if text.startswith("/") else text
    _compile(pattern, entry)
    return pattern


def exclude_regex(origin: str, entry: str) -> str:
    """An excluded entry: a path (``/logout``, ``/admin/.*``) becomes a prefix pattern on the origin."""
    text = entry.strip()
    if text.startswith("/"):
        pattern = re.escape(origin) + text
        if not text.endswith((".*", "$")):
            pattern += ".*"
    else:
        pattern = text
    _compile(pattern, entry)
    return pattern


def _compile(pattern: str, original: str) -> None:
    try:
        check_java_regex(pattern)
    except re.error as exc:
        raise PlanError("The scope pattern %r is not a valid regular expression: %s" % (original[:80], exc)) from exc


def _clamp_minutes(value: int | None, default: int) -> int:
    if value is None:
        return default
    return max(1, min(MAX_MINUTES, int(value)))


def build_values(inputs: PlanInputs, login_values: dict[str, Any] | None = None) -> dict[str, Any]:
    """Every value the three plan templates may refer to."""
    rps = max(1, int(inputs.rate_rps))
    spider_threads = 1 if inputs.mode == "baseline" else 2
    active_threads = 2
    timeout = max(10, int(inputs.timeout_minutes))
    values: dict[str, Any] = {
        "context": CONTEXT_NAME,
        "target_url": inputs.target_url,
        "user": USER_NAME if inputs.login is not None and inputs.login.method != "header" else None,
        "spider_threads": spider_threads,
        "spider_wait_ms": int(math.ceil(1000.0 * spider_threads / rps)),
        "active_threads": active_threads,
        "active_delay_ms": int(math.ceil(1000.0 * active_threads / rps)),
        "spider_minutes": _clamp_minutes(inputs.spider_minutes, 15),
        "ajax_minutes": _clamp_minutes(inputs.ajax_minutes, 20),
        "active_minutes": _clamp_minutes(inputs.active_minutes, max(10, min(360, timeout - 90))),
        "report_title": inputs.report_title,
        "api_job_type": None,
        "api_parameters": None,
    }
    if inputs.api is not None:
        job_type, parameters = api_job(inputs.api, inputs.target_url)
        values["api_job_type"] = job_type
        values["api_parameters"] = parameters
    if login_values:
        values.update(login_values)
    return values


def api_job(spec: ApiSpec, target_url: str) -> tuple[str, dict[str, Any]]:
    """The import job (type, parameters) for an API definition."""
    if spec.kind not in API_JOB_TYPES:
        raise PlanError("The API definition type %r is not supported (openapi, graphql or soap)." % spec.kind)
    if not (spec.url or spec.file):
        raise PlanError("The API definition has neither an address nor a file.")
    if spec.kind == "openapi":
        parameters: dict[str, Any] = {"context": CONTEXT_NAME, "targetUrl": target_url}
        parameters["apiUrl" if spec.url else "apiFile"] = spec.url or spec.file
    elif spec.kind == "graphql":
        parameters = {"endpoint": target_url}
        parameters["schemaUrl" if spec.url else "schemaFile"] = spec.url or spec.file
    else:
        parameters = {}
        parameters["wsdlUrl" if spec.url else "wsdlFile"] = spec.url or spec.file
    return spec.kind, parameters


# --------------------------------------------------------------------------- rendering
def _expand_includes(jobs: list[Any], login_jobs: list[dict[str, Any]]) -> list[Any]:
    expanded: list[Any] = []
    for job in jobs:
        if isinstance(job, dict) and "$include" in job:
            if job["$include"] != "login":
                raise PlanError("Unknown include %r in a plan template." % job["$include"])
            expanded.extend(login_jobs)
        else:
            expanded.append(job)
    return expanded


def _context(inputs: PlanInputs, origin: str) -> dict[str, Any]:
    includes = [include_regex(origin, e) for e in inputs.includes] or [
        re.escape(base_of(inputs.target_url)) + "(/.*)?"
    ]
    excludes = [exclude_regex(origin, e) for e in inputs.excludes]
    if inputs.login is not None and inputs.login.method != "header":
        excludes.append(LOGOUT_EXCLUDE)  # never log the scan user out
    context: dict[str, Any] = {
        "name": CONTEXT_NAME,
        "urls": [inputs.target_url],
        "includePaths": includes,
    }
    if excludes:
        context["excludePaths"] = excludes
    return context


def render_plan(
    inputs: PlanInputs,
    template: dict[str, Any],
    *,
    auth_fragment: dict[str, Any] | None = None,
    auth_tests: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The complete Automation Framework plan as a dictionary. Pure; no secret is ever in it."""
    origin = origin_of(inputs.target_url)
    if inputs.production and (inputs.login is not None or inputs.mode != "baseline"):
        raise PlanSafetyError("A production target only gets the unauthenticated baseline plan.")
    context = _context(inputs, origin)
    login_jobs: list[dict[str, Any]] = []
    login_values: dict[str, Any] = {}
    if inputs.login is not None:
        if auth_fragment is None:
            raise PlanError("The login template is missing.")
        login_values = dict(inputs.login.fragment_values())
        login_values["site_regex"] = re.escape(origin) + ".*"
        fragment = fill(auth_fragment, {**build_values(inputs), **login_values})
        if inputs.login.method == "header":
            login_jobs = [job for job in fragment.get("jobs", []) if isinstance(job, dict)]
        else:
            for key in ("authentication", "sessionManagement", "users"):
                if key in fragment:
                    context[key] = fragment[key]
            if not auth_tests:
                raise PlanError("A login scan needs the login check (auth-verify.yaml).")
            # one request as the scan user, first of all: it forces the login, and the check on ZAP's
            # authentication statistics ends the plan in error before anything is scanned if it failed
            login_jobs = [
                {
                    "type": "requestor",
                    "parameters": {"user": USER_NAME},
                    "requests": [{"name": "SecureScan login probe", "url": inputs.target_url, "method": "GET"}],
                    "tests": [dict(t) for t in auth_tests],
                }
            ]
    values = build_values(inputs, login_values)
    jobs_template = template.get("jobs")
    if not isinstance(jobs_template, list) or not jobs_template:
        raise PlanError("The plan template has no jobs.")
    jobs = _expand_includes(fill(jobs_template, values), login_jobs)  # login jobs are already filled: not re-read
    for position, entry in enumerate(jobs, start=1):
        if not isinstance(entry, dict) or not isinstance(entry.get("type"), str) or not entry["type"]:
            raise PlanError(
                "Job %d of the plan has no type (is the API definition missing?)." % position
            )
    plan: dict[str, Any] = {
        "env": {
            "contexts": [context],
            "parameters": {"failOnError": True, "failOnWarning": False, "progressToStdout": True},
        },
        "jobs": jobs,
    }
    assert_plan_safe(plan, production=inputs.production)
    return plan


def assert_plan_safe(plan: dict[str, Any], *, production: bool) -> None:
    """Raise ``PlanSafetyError`` when a production plan could attack or write to the application."""
    if not production:
        return
    jobs = plan.get("jobs")
    if not isinstance(jobs, list):
        raise PlanSafetyError("The plan has no jobs.")
    for job in jobs:
        job_type = str(job.get("type")) if isinstance(job, dict) else "?"
        if job_type not in PRODUCTION_JOB_TYPES:
            raise PlanSafetyError("A production plan cannot contain a %s job." % job_type)
        parameters = job.get("parameters", {}) if isinstance(job, dict) else {}
        if job_type == "spider" and (parameters.get("postForm") is not False or parameters.get("processForm") is not False):
            raise PlanSafetyError("The production spider must not post or process forms.")
    contexts = (plan.get("env") or {}).get("contexts", [])
    for context in contexts:
        if "authentication" in context or "users" in context:
            raise PlanSafetyError("A production plan cannot carry a login.")


def dump_plan(plan: dict[str, Any]) -> str:
    return yaml.safe_dump(plan, sort_keys=False, default_flow_style=False, allow_unicode=False, width=1000)


def proxy_config_args(proxy_name: str) -> list[tuple[str, str | None]]:
    """The ``-config`` switches that send every ZAP request through the job's proxy."""
    return [
        ("-config", "network.connection.httpProxy.enabled=true"),
        ("-config", "network.connection.httpProxy.host=%s" % proxy_name),
        ("-config", "network.connection.httpProxy.port=%d" % PROXY_PORT),
    ]


# --------------------------------------------------------------------------- the builder
@dataclass
class DastState:
    """Per-job preparation result, kept on ``ctx.options`` (never persisted by the executor)."""

    proxy: ProxyHandle
    env: dict[str, str] = field(default_factory=dict)
    login: bool = False
    plan_path: Path | None = None


def state_of(ctx: ToolContext) -> DastState | None:
    value = ctx.options.get(STATE_KEY)
    return value if isinstance(value, DastState) else None


def _int_option(ctx: ToolContext, key: str) -> int | None:
    value = ctx.options.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


class ZapBuilder(DefaultToolBuilder):
    tool = TOOL

    # ------------------------------------------------------------------ preparation
    async def prepare(self, ctx: ToolContext) -> None:
        target = ctx.target
        mode = ctx.scan.mode
        if target is None:
            raise ToolPreparationError("This scan has no target.", code="scan.no_target")
        if mode not in TEMPLATE_BY_MODE:
            raise ToolPreparationError(
                "ZAP does not run in the %r mode of this profile." % mode, code="zap.mode_unsupported"
            )
        production = _is_production(target)
        if production and (mode != "baseline" or target.login_profile_id is not None):
            raise ToolPreparationError(
                "Production targets accept the unauthenticated ZAP baseline scan only.",
                code="dast.production_baseline_only",
            )
        timeout_minutes = int(self.timeout_seconds(ctx) // 60)
        login, secret_env = await self._load_login(ctx)
        proxy, _hosts = await prepare_job_network(ctx, tool=TOOL, timeout_s=timeout_minutes * 60.0)
        try:
            api = await self._api_spec(ctx, mode) if mode == "api" else None
            inputs = PlanInputs(
                mode=str(mode),
                target_url=str(target.locator).strip(),
                production=production,
                includes=[str(p) for p in (target.scope_includes or [])],
                excludes=[str(p) for p in (target.scope_excludes or [])],
                rate_rps=effective_rate(target, DEFAULT_RPS, ctx.settings),
                login=login,
                api=api,
                timeout_minutes=timeout_minutes,
                spider_minutes=_int_option(ctx, "spider_minutes"),
                ajax_minutes=_int_option(ctx, "ajax_minutes"),
                active_minutes=_int_option(ctx, "active_minutes"),
                report_title="SecureScan %s scan" % mode,
            )
            scanners = ctx.scanners_dir or find_scanners_dir(ctx.settings)
            try:
                plan = render_plan(
                    inputs,
                    load_plan_template(str(mode), scanners),
                    auth_fragment=load_auth_fragment(login.method, scanners) if login is not None else None,
                    auth_tests=load_auth_verification(scanners) if login is not None else None,
                )
            except PlanError as exc:
                raise ToolPreparationError(str(exc), code="zap.plan_invalid") from exc
            plan_path = ctx.workspace.config / PLAN_NAME
            plan_path.write_text(dump_plan(plan), encoding="utf-8")
            make_world_readable(ctx.workspace.config)
        except BaseException:
            await release_proxy(ctx.job.id, proxy)
            raise
        ctx.options[STATE_KEY] = DastState(proxy=proxy, env=secret_env, login=login is not None, plan_path=plan_path)
        self._record(ctx, inputs, plan)

    def _record(self, ctx: ToolContext, inputs: PlanInputs, plan: dict[str, Any]) -> None:
        context = plan["env"]["contexts"][0]
        for pattern in context.get("includePaths", []):
            ctx.applied_exclusions.append({"kind": "scope_include", "value": pattern, "source": "target scope"})
        for pattern in context.get("excludePaths", []):
            ctx.applied_exclusions.append({"kind": "scope_exclude", "value": pattern, "source": "target scope"})
        ctx.tool_version = ctx.image.tag if ctx.image is not None else None
        notes = ["Request rate capped at about %d requests per second." % inputs.rate_rps]
        if inputs.login is not None:
            notes.append("Authenticated scan (%s login); the scan fails if the login check fails." % inputs.login.method)
        else:
            notes.append("Unauthenticated scan: only what is reachable without signing in was tested.")
        ctx.coverage_notes.extend(notes)

    async def _load_login(self, ctx: ToolContext) -> tuple[LoginSettings | None, dict[str, str]]:
        target = ctx.target
        if target is None or target.login_profile_id is None:
            return None, {}
        if ctx.session is None:
            raise ToolPreparationError("The login profile cannot be read right now.", code="zap.login_unavailable")
        credential = await ctx.session.get(Credential, target.login_profile_id)
        if credential is None or credential.revoked_at is not None or credential.kind != CredentialKind.DAST_LOGIN:
            raise ToolPreparationError(
                "The login profile of this target was removed or revoked. Choose another one on the target.",
                code="zap.login_missing",
            )
        if credential.expires_at is not None and ensure_utc(credential.expires_at) <= utcnow():
            raise ToolPreparationError(
                "The login profile of this target has expired. Replace it on the target.", code="zap.login_expired"
            )
        try:
            settings = parse_login_settings(credential.extra or {})
            target_host = split_url(str(target.locator)).host
            foreign = [h for h in settings.hosts() if h != target_host]
            if foreign:
                raise LoginProfileError(
                    "The login profile talks to %s, which is not the target's host (%s). A login can only "
                    "use the target's own host." % (", ".join(foreign), target_host)
                )
            secret = parse_login_secret(reveal_secret(credential), settings)
        except (LoginProfileError, SecretsError, ValueError) as exc:
            raise ToolPreparationError(str(exc)[:300], code="zap.login_invalid") from exc
        credential.last_used_at = utcnow()
        return settings, login_env(settings, secret, origin_of(str(target.locator)))

    async def _api_spec(self, ctx: ToolContext, mode: str) -> ApiSpec:
        target = ctx.target
        assert target is not None  # noqa: S101 - checked by prepare
        kind = str(target.api_spec_type or "").lower()
        if kind not in API_JOB_TYPES:
            raise ToolPreparationError(
                "The target's API definition type must be openapi, graphql or soap.", code="zap.api_spec_type"
            )
        url = api_spec_url(target)
        if url:
            return ApiSpec(kind=kind, url=url)
        if target.api_spec_artifact_id is None or ctx.session is None:
            raise ToolPreparationError(
                "The target has no API definition (address or uploaded file).", code="zap.api_spec_missing"
            )
        from securescan.db.models.artifacts import Artifact

        artifact = await ctx.session.get(Artifact, target.api_spec_artifact_id)
        if artifact is None or artifact.deleted_at is not None:
            raise ToolPreparationError("The uploaded API definition is missing.", code="zap.api_spec_missing")
        try:
            source = artifact_path(artifact)
        except StorageError as exc:
            raise ToolPreparationError("The uploaded API definition is missing.", code="zap.api_spec_missing") from exc
        if not source.is_file() or source.stat().st_size > API_SPEC_MAX_BYTES:
            raise ToolPreparationError(
                "The uploaded API definition is missing or larger than 20 MB.", code="zap.api_spec_missing"
            )
        suffix = Path(artifact.filename or "").suffix.lower()
        extension = suffix if _SPEC_EXTENSION.match(suffix) else ".txt"
        name = "api-spec%s" % extension
        shutil.copyfile(source, ctx.workspace.config / name)
        return ApiSpec(kind=kind, file="%s/%s" % (CONFIG_MOUNT, name))

    # ------------------------------------------------------------------ container
    def optional_args(self, ctx: ToolContext) -> list[tuple[str, str | None]]:
        state = state_of(ctx)
        if state is None:
            raise ToolPreparationError("The scan proxy is not ready.", code="dast.proxy_failed")
        return proxy_config_args(state.proxy.name)

    def extra_env(self, ctx: ToolContext) -> dict[str, str]:
        state = state_of(ctx)
        return dict(state.env) if state is not None else {}

    def container_spec(self, ctx: ToolContext) -> ContainerSpec:
        spec = super().container_spec(ctx)
        spec.shm_size = "1g"  # the AJAX spider and browser-based logins need a large /dev/shm
        return spec

    # ------------------------------------------------------------------ after the run
    def classify_exit(self, ctx: ToolContext, exit_code: int | None) -> JobOutcome:
        outcome = super().classify_exit(ctx, exit_code)
        state = state_of(ctx)
        if outcome == "completed_partial" and state is not None and state.login:
            return "failed"  # a plan error may be the failed login check: never report on a broken session
        return outcome

    async def post_run(self, ctx: ToolContext, result: ContainerResult) -> None:
        state = state_of(ctx)
        if state is None:
            return
        extra: list[tuple[Path, str, str]] = []
        if state.plan_path is not None:
            extra.append((state.plan_path, "zap-plan.yaml", "application/yaml"))
        await finish_job_proxy(ctx, state.proxy, extra_files=extra)

    async def cleanup(self, ctx: ToolContext) -> None:
        """Remove the job's proxy now (the executor may call this when a job ends on any path)."""
        state = state_of(ctx)
        if state is not None:
            await release_proxy(ctx.job.id, state.proxy)


def _is_production(target: Any) -> bool:
    value = getattr(target, "environment", None)
    return str(getattr(value, "value", value)) == "production"


BUILDER = ZapBuilder()
