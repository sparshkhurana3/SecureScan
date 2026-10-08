"""The DAST safety rules (design "DAST safety controls", plan M9) and the login profile model.

``check_scan_allowed(profile, targets)`` is the one place that decides whether a web scan may be created
(and, again just before a container starts, whether it may still run). It raises a ``Problem`` whose
detail is written in plain words for the person who clicked Start:

* **Environment rule.** A ``production`` target accepts the unauthenticated ZAP baseline scan only. Any
  profile with an active scan (mode ``full``), an API scan (``api``), Nuclei (``nuclei``) or a login
  profile is refused with ``403``. There is no override. A target without an environment tag is refused.
* **Vendor SaaS rule.** An application of type ``vendor`` with hosting ``saas`` needs the vendor's written
  authorization on the target (document, window, contact) and the scan must fall inside the window.
* **Allowlist.** Every host the scan will contact (the target and the API specification host) must resolve
  into the Admin's allowlisted CIDRs (``SECURESCAN_DAST_ALLOWED_CIDRS``) or the target must carry an explicit
  Admin approval (``host_approved``). Loopback, link-local (cloud metadata), multicast and unspecified
  addresses are never allowed, approval or not.
* **Blackout windows** of the target keep scans out of busy hours.
* **One DAST job at a time.** The catalogue entries of the DAST tools carry ``lock: dast``; the check
  verifies it, so that the Procrastinate queue serialises the jobs (a second scan waits, it is not refused).

The functions are pure (the caller passes the resolved addresses or a resolver), so the table of every
combination is unit-tested without a network. ``check_scan_allowed_async`` resolves the hosts in a thread
and is what ``domain/scans.py`` calls.

The login profile model (``LoginSettings`` and ``LoginSecret``) lives here too: the API validates it when
a profile is stored, the ZAP builder renders it. Secrets are separate from settings; the settings go in
``Credential.extra``, the secret in the encrypted ``Credential.ciphertext``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Union
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from securescan.api.problems import Forbidden, ServiceUnavailable, UnprocessableEntity
from securescan.config import Settings, get_settings
from securescan.db.models.enums import AppType, TargetEnvironment, TargetKind
from securescan.integrations.github.scheduling import CronError, blackout_end, in_blackout
from securescan.util import ensure_utc, utcnow

DAST_LOCK = "dast"
ZAP_TOOL = "zap"
NUCLEI_TOOL = "nuclei"
DAST_TOOLS = (ZAP_TOOL, NUCLEI_TOOL)
MODES = ("baseline", "full", "api", "nuclei")
BASELINE_MODE = "baseline"
# modes that attack the application (active scan, API scan, templates with requests that can change state)
ACTIVE_MODES = frozenset({"full", "api", "nuclei"})
PRODUCTION_TOOLS = frozenset({ZAP_TOOL})
RATE_FLOOR = 1
RESOLVE_TIMEOUT_SECONDS = 5.0

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
Resolver = Callable[[str], Sequence[str]]

# Never scanned, whatever the allowlist or an approval says: this machine, cloud metadata services, multicast.
ALWAYS_BLOCKED: list[IPNetwork] = [
    ipaddress.ip_network(text)
    for text in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fe80::/10",
        "fd00:ec2::/32",
        "ff00::/8",
    )
]

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


# --------------------------------------------------------------------------- addresses and hosts
def parse_cidrs(text: str | Iterable[str]) -> list[IPNetwork]:
    """Networks from a comma-separated string or a list; ``ValueError`` names the entries that are bad."""
    items = [p.strip() for p in (text.split(",") if isinstance(text, str) else text)]
    networks: list[IPNetwork] = []
    bad: list[str] = []
    for item in items:
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            bad.append(item)
    if bad:
        raise ValueError("not a network in CIDR notation: " + ", ".join(bad))
    return networks


def normalise_address(text: str) -> IPAddress | None:
    """The address in ``text`` (an IPv4-mapped IPv6 address becomes IPv4), or None when it is not one."""
    try:
        address = ipaddress.ip_address(text.strip().split("%", 1)[0])
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped if mapped is not None else address


def is_always_blocked(address: IPAddress) -> bool:
    return any(address.version == net.version and address in net for net in ALWAYS_BLOCKED)


@dataclass(frozen=True)
class HostInfo:
    scheme: str
    host: str
    port: int

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        host = "[%s]" % self.host if ":" in self.host else self.host
        return "%s://%s%s" % (self.scheme, host, "" if self.port == default else ":%d" % self.port)


def split_url(url: str) -> HostInfo:
    """Scheme, host and port of an http(s) URL. ``ValueError`` (plain message) when it is not usable."""
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("The address must start with http:// or https:// and name a host.")
    if parts.username or parts.password:
        raise ValueError("The address must not contain a user name or password.")
    host = parts.hostname.lower().rstrip(".")
    if normalise_address(host) is None and not _HOST_RE.match(host):
        raise ValueError("'%s' is not a valid host name." % host[:80])
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("The port in the address is not valid.") from exc
    return HostInfo(scheme=scheme, host=host, port=port or (443 if scheme == "https" else 80))


def api_spec_url(target: Any) -> str | None:
    """The target's API specification locator when it is a web address (it is fetched through the proxy)."""
    locator = getattr(target, "api_spec_locator", None)
    if isinstance(locator, str) and locator.strip().lower().startswith(("http://", "https://")):
        return locator.strip()
    return None


def target_hosts(target: Any) -> list[HostInfo]:
    """Every host a scan of ``target`` contacts: the target itself, then the API specification host."""
    found: list[HostInfo] = []
    for url in (getattr(target, "locator", None), api_spec_url(target)):
        if not url:
            continue
        info = split_url(str(url))
        if all((h.host, h.port) != (info.host, info.port) for h in found):
            found.append(info)
    return found


def resolve_host(host: str) -> list[str]:
    """Addresses of ``host`` (an address literal is returned as it is). An unresolvable name gives ``[]``."""
    literal = normalise_address(host)
    if literal is not None:
        return [str(literal)]
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []
    seen: list[str] = []
    for info in infos:
        address = normalise_address(str(info[4][0]))
        if address is not None and str(address) not in seen:
            seen.append(str(address))
    return seen


async def resolve_hosts(hosts: Iterable[str], timeout: float = RESOLVE_TIMEOUT_SECONDS) -> dict[str, list[str]]:
    """Resolve names in worker threads (never blocks the event loop; a slow resolver gives ``[]``)."""
    unique = sorted({h for h in hosts})

    async def one(name: str) -> tuple[str, list[str]]:
        try:
            return name, await asyncio.wait_for(asyncio.to_thread(resolve_host, name), timeout)
        except asyncio.TimeoutError:
            return name, []

    results = await asyncio.gather(*(one(name) for name in unique))
    return dict(results)


# --------------------------------------------------------------------------- the rules
@dataclass(frozen=True)
class ProfileFacts:
    """What the rules need to know about a scan profile (a ``ProfileDoc`` has the same attributes)."""

    kind: str
    mode: str | None
    tools: Sequence[str] = field(default_factory=tuple)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _is_production(target: Any) -> bool:
    return _enum_value(getattr(target, "environment", None)) == TargetEnvironment.PRODUCTION.value


def _label(target: Any) -> str:
    name = getattr(target, "name", None) or getattr(target, "locator", None) or "this target"
    return str(name)[:120]


def is_vendor_saas(application: Any | None) -> bool:
    if application is None:
        return False
    kind = _enum_value(getattr(application, "type", None))
    hosting = str(getattr(application, "hosting", "") or "").strip().lower()
    return kind == AppType.VENDOR.value and hosting == "saas"


def _aware(value: datetime) -> datetime:
    return ensure_utc(value)


def _check_environment(profile: Any, target: Any) -> None:
    mode = profile.mode
    tools = list(profile.tools)
    if _enum_value(getattr(target, "environment", None)) is None:
        raise UnprocessableEntity(
            "This web address has no environment tag. Tag it production or uat before scanning it.",
            code="target.environment_required",
        )
    if not _is_production(target):
        return
    if mode != BASELINE_MODE:
        raise Forbidden(
            "Production targets accept the unauthenticated ZAP baseline scan only. "
            "Full scans, API scans and Nuclei run on UAT targets.",
            code="dast.production_baseline_only",
        )
    extra = sorted(set(tools) - PRODUCTION_TOOLS)
    if extra:
        raise Forbidden(
            "%s cannot run against a production target. Production accepts the ZAP baseline scan only."
            % ", ".join(extra),
            code="dast.production_baseline_only",
        )
    if getattr(target, "login_profile_id", None) is not None:
        raise Forbidden(
            "Production targets cannot use a login profile. Remove the login profile from the target "
            "or tag the target uat.",
            code="dast.production_no_login",
        )


def _check_mode_tools(profile: Any) -> None:
    if profile.mode == BASELINE_MODE and NUCLEI_TOOL in profile.tools:
        raise UnprocessableEntity(
            "A baseline scan runs ZAP only; Nuclei belongs to the full, API and Nuclei profiles.",
            code="dast.mode_tool_mismatch",
        )
    if profile.mode == "nuclei" and ZAP_TOOL in profile.tools:
        raise UnprocessableEntity(
            "A Nuclei profile does not run ZAP.", code="dast.mode_tool_mismatch"
        )
    unknown = sorted(set(profile.tools) - set(DAST_TOOLS))
    if unknown:
        raise UnprocessableEntity(
            "%s is not a web scanner. Web profiles run ZAP and Nuclei." % ", ".join(unknown),
            code="dast.mode_tool_mismatch",
        )


def _check_api_spec(profile: Any, target: Any) -> None:
    if profile.mode != "api":
        return
    has_spec = bool(
        getattr(target, "api_spec_type", None)
        and (getattr(target, "api_spec_locator", None) or getattr(target, "api_spec_artifact_id", None))
    )
    if not has_spec:
        raise UnprocessableEntity(
            "An API scan needs the API definition of the target (OpenAPI, GraphQL or SOAP): add its type "
            "and address or upload it on the target.",
            code="dast.api_spec_required",
        )


def _check_vendor(target: Any, application: Any | None, now: datetime) -> None:
    if not is_vendor_saas(application):
        return
    missing: list[str] = []
    if getattr(target, "vendor_authorization_artifact_id", None) is None:
        missing.append("the vendor's written authorization document")
    start = getattr(target, "vendor_authorized_from", None)
    end = getattr(target, "vendor_authorized_until", None)
    if start is None or end is None:
        missing.append("the authorized scan window")
    if not str(getattr(target, "vendor_contact", "") or "").strip():
        missing.append("the vendor's contact person")
    if missing:
        raise Forbidden(
            "This is a vendor-hosted (SaaS) product. A web scan needs the vendor's authorization on the "
            "target first; missing: %s." % ", ".join(missing),
            code="dast.vendor_authorization_required",
        )
    if now < _aware(start):
        raise Forbidden(
            "The vendor's authorization window for this target has not started yet (it opens %s UTC)."
            % _aware(start).strftime("%Y-%m-%d %H:%M"),
            code="dast.vendor_authorization_not_started",
        )
    if now > _aware(end):
        raise Forbidden(
            "The vendor's authorization for this target ended on %s UTC. Ask the vendor for a new window "
            "and record it on the target." % _aware(end).strftime("%Y-%m-%d %H:%M"),
            code="dast.vendor_authorization_expired",
        )


def _check_allowlist(
    target: Any,
    cidrs: Sequence[IPNetwork],
    resolved: Mapping[str, Sequence[str]],
    resolver: Resolver,
) -> None:
    approved = bool(getattr(target, "host_approved", False))
    try:
        hosts = target_hosts(target)
    except ValueError as exc:
        raise UnprocessableEntity(str(exc), code="target.invalid_url") from exc
    if not hosts:
        raise UnprocessableEntity("This target has no web address.", code="target.invalid_url")
    for info in hosts:
        literal = normalise_address(info.host)
        if literal is not None:
            addresses = [str(literal)]
        elif info.host in resolved:
            addresses = list(resolved[info.host])
        else:
            addresses = list(resolver(info.host))
        parsed = [a for a in (normalise_address(text) for text in addresses) if a is not None]
        for address in parsed:
            if is_always_blocked(address):
                raise Forbidden(
                    "%s points at %s, which SecureScan never scans (this machine, cloud metadata and "
                    "multicast addresses are blocked)." % (info.host, address),
                    code="dast.host_blocked",
                )
        if approved:
            continue
        if not cidrs:
            raise Forbidden(
                "No network range is allowlisted for web scans, and %s is not an approved host. "
                "An Admin must set SECURESCAN_DAST_ALLOWED_CIDRS in deploy/.env (then restart api and worker) "
                "or approve this host on the target."
                % info.host,
                code="dast.host_not_allowlisted",
            )
        if not parsed:
            raise Forbidden(
                "%s could not be resolved, so SecureScan cannot check it against the allowlist. "
                "Check the address, or ask an Admin to approve the host." % info.host,
                code="dast.host_unresolvable",
            )
        outside = [a for a in parsed if not any(a.version == n.version and a in n for n in cidrs)]
        if outside:
            raise Forbidden(
                "%s resolves to %s, which is outside the allowlisted network ranges. An Admin can add the "
                "range in Settings or approve this host on the target." % (info.host, outside[0]),
                code="dast.host_not_allowlisted",
            )


def check_allowlist(
    target: Any,
    *,
    allowed_cidrs: str | Sequence[IPNetwork] | None = None,
    resolved: Mapping[str, Sequence[str]] | None = None,
    resolver: Resolver | None = None,
) -> None:
    """Only the allowlist rule (the target host and the API definition host), for the validation endpoint."""
    if allowed_cidrs is None:
        cidrs = parse_cidrs(get_settings().dast_cidrs)
    elif isinstance(allowed_cidrs, str):
        cidrs = parse_cidrs(allowed_cidrs)
    else:
        cidrs = list(allowed_cidrs)
    _check_allowlist(target, cidrs, resolved or {}, resolver or resolve_host)


def _check_blackout(target: Any, now: datetime) -> None:
    windows = list(getattr(target, "blackout_windows", None) or [])
    if not windows:
        return
    try:
        if not in_blackout(windows, now):
            return
        until = blackout_end(windows, now)
    except (CronError, KeyError, TypeError, ValueError) as exc:
        raise Forbidden(
            "A blackout window of this target cannot be read (%s), so the scan was not started." % exc,
            code="dast.blackout_invalid",
        ) from exc
    when = " until %s UTC" % until.strftime("%Y-%m-%d %H:%M") if until is not None else ""
    raise Forbidden(
        "%s is inside a blackout window%s. Scans are not started during blackout windows."
        % (_label(target), when),
        code="dast.blackout_window",
    )


def _check_locks(profile: Any, catalogue: Mapping[str, Any] | None) -> None:
    if not catalogue:
        return
    for tool in profile.tools:
        entry = catalogue.get(tool)
        if entry is not None and getattr(entry, "lock", None) != DAST_LOCK:
            raise ServiceUnavailable(
                "The scanner catalogue does not give %s the one-at-a-time lock (lock: %s). "
                "Web scans are not started until it does." % (tool, DAST_LOCK),
                code="dast.lock_not_configured",
            )


def effective_rate(target: Any, default: int, settings: Settings | None = None) -> int:
    """Requests per second for the target: its cap, else ``default``, never above the platform maximum."""
    cap = (settings or get_settings()).dast_max_rps
    value = getattr(target, "rate_limit_rps", None)
    if isinstance(value, int) and not isinstance(value, bool) and value >= RATE_FLOOR:
        return min(value, max(RATE_FLOOR, cap))
    return min(max(RATE_FLOOR, default), max(RATE_FLOOR, cap))


def check_scan_allowed(
    profile: Any,
    targets: Sequence[Any],
    *,
    application: Any | None = None,
    now: datetime | None = None,
    allowed_cidrs: str | Sequence[IPNetwork] | None = None,
    resolved: Mapping[str, Sequence[str]] | None = None,
    resolver: Resolver | None = None,
    catalogue: Mapping[str, Any] | None = None,
) -> None:
    """Raise a problem when ``profile`` must not run on ``targets``; return None when it may.

    ``profile`` has ``kind``, ``mode`` and ``tools`` (a ``ProfileDoc``). Only ``dast`` profiles are
    checked; the code-scan rules are in ``domain/scans.py``. ``application`` is needed for the vendor SaaS
    rule. ``resolved`` maps host names to addresses (from ``resolve_hosts``); a host missing from it is
    resolved with ``resolver`` (default: the system resolver). ``allowed_cidrs`` defaults to the Admin
    setting. ``catalogue`` (tool -> entry) enables the one-at-a-time lock check.
    """
    if str(profile.kind) != "dast":
        return
    moment = _aware(now) if now is not None else utcnow()
    if allowed_cidrs is None:
        cidrs = parse_cidrs(get_settings().dast_cidrs)
    elif isinstance(allowed_cidrs, str):
        cidrs = parse_cidrs(allowed_cidrs)
    else:
        cidrs = list(allowed_cidrs)
    lookup = resolver or resolve_host
    for target in targets:
        if _enum_value(getattr(target, "kind", None)) != TargetKind.URL.value:
            raise UnprocessableEntity(
                "Web scan profiles run on web addresses (URL targets) only.",
                code="scan.target_kind_mismatch",
            )
        _check_environment(profile, target)
        _check_mode_tools(profile)
        _check_api_spec(profile, target)
        _check_locks(profile, catalogue)
        _check_vendor(target, application, moment)
        _check_allowlist(target, cidrs, resolved or {}, lookup)
        _check_blackout(target, moment)


def check_job_allowed(
    target: Any,
    application: Any | None,
    *,
    tool: str,
    mode: str | None,
    now: datetime | None = None,
    resolved: Mapping[str, Sequence[str]] | None = None,
    resolver: Resolver | None = None,
    allowed_cidrs: str | Sequence[IPNetwork] | None = None,
) -> None:
    """The same rules, asked again by the worker just before a DAST container starts (a queued scan can
    outlive its authorization window, its blackout start or an allowlist change)."""
    check_scan_allowed(
        ProfileFacts(kind="dast", mode=mode, tools=(tool,)),
        [target],
        application=application,
        now=now,
        allowed_cidrs=allowed_cidrs,
        resolved=resolved,
        resolver=resolver,
    )


async def check_scan_allowed_async(
    profile: Any,
    targets: Sequence[Any],
    *,
    application: Any | None = None,
    now: datetime | None = None,
    allowed_cidrs: str | Sequence[IPNetwork] | None = None,
) -> None:
    """``check_scan_allowed`` with the name resolution done in threads and the catalogue lock checked.

    Called by ``domain/scans.py::create_scan_result`` before the generic rules, so that the API answers a
    production violation with ``403`` and the rule in plain words.
    """
    if str(profile.kind) != "dast":
        return
    names: list[str] = []
    for target in targets:
        if _enum_value(getattr(target, "kind", None)) != TargetKind.URL.value:
            continue
        try:
            names.extend(info.host for info in target_hosts(target))
        except ValueError:
            continue  # the rules report the unusable address
    resolved = await resolve_hosts(names) if names else {}
    from securescan.runner.catalogue import CatalogueError, load_catalogue

    catalogue: Mapping[str, Any] | None
    try:
        catalogue = load_catalogue()
    except CatalogueError:  # the api container may not ship the catalogue; the worker checks again
        catalogue = None
    check_scan_allowed(
        profile,
        targets,
        application=application,
        now=now,
        allowed_cidrs=allowed_cidrs,
        resolved=resolved,
        catalogue=catalogue,
    )


def allowed_modes(environment: Any, *, has_login: bool = False) -> list[str]:
    """The profile modes a target of this environment accepts (for the Start button)."""
    value = _enum_value(environment)
    if value == TargetEnvironment.PRODUCTION.value:
        return [] if has_login else [BASELINE_MODE]
    if value == TargetEnvironment.UAT.value:
        return list(MODES)
    return []


# --------------------------------------------------------------------------- login profiles
LOGIN_METHODS = ("form", "json", "header", "browser")
BROWSER_STEP_TYPES = (
    "AUTO_STEPS",
    "USERNAME",
    "PASSWORD",
    "TOTP_FIELD",
    "CLICK",
    "ESCAPE",
    "RETURN",
    "WAIT",
)
SECRET_ENV_USERNAME = "ZAP_AUTH_USERNAME"
SECRET_ENV_PASSWORD = "ZAP_AUTH_PASSWORD"
SECRET_ENV_TOTP = "ZAP_AUTH_TOTP_SECRET"
SECRET_ENV_HEADER = "ZAP_AUTH_HEADER"
SECRET_ENV_HEADER_VALUE = "ZAP_AUTH_HEADER_VALUE"
SECRET_ENV_HEADER_SITE = "ZAP_AUTH_HEADER_SITE"
SECRET_ENV_NAMES = (
    SECRET_ENV_USERNAME,
    SECRET_ENV_PASSWORD,
    SECRET_ENV_TOTP,
    SECRET_ENV_HEADER,
    SECRET_ENV_HEADER_VALUE,
    SECRET_ENV_HEADER_SITE,
)
_HEADER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_FORBIDDEN_HEADERS = frozenset({"host", "content-length", "transfer-encoding", "connection"})


class BrowserStep(BaseModel):
    """One step of a browser-based login (no values: credentials come from the secret)."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["AUTO_STEPS", "USERNAME", "PASSWORD", "TOTP_FIELD", "CLICK", "ESCAPE", "RETURN", "WAIT"]
    description: str | None = Field(default=None, max_length=200)
    css_selector: str | None = Field(default=None, max_length=300)
    xpath: str | None = Field(default=None, max_length=300)
    timeout: int | None = Field(default=None, ge=0, le=120_000)

    def zap(self) -> dict[str, Any]:
        step: dict[str, Any] = {"type": self.type}
        if self.description:
            step["description"] = self.description
        if self.css_selector:
            step["cssSelector"] = self.css_selector
        if self.xpath:
            step["xpath"] = self.xpath
        if self.timeout is not None:
            step["timeout"] = self.timeout
        return step


_QUOTED = re.compile(r"\\Q(.*?)(?:\\E|$)", re.DOTALL)


def check_java_regex(pattern: str) -> None:
    r"""``re.error`` when ``pattern`` is clearly not a regular expression.

    ZAP evaluates Java regular expressions. The ``\Q...\E`` quoting is Java only, so the quoted parts are turned
    into escaped literals before Python's parser looks at the rest; constructs that only Java knows may still be
    refused here or accepted and then rejected by ZAP (the plan fails with ZAP's message in the job log).
    """
    re.compile(_QUOTED.sub(lambda match: re.escape(match.group(1)), pattern))


def _http_url(value: str | None, what: str) -> str | None:
    if value is None:
        return None
    try:
        split_url(value)
    except ValueError as exc:
        raise ValueError("%s: %s" % (what, exc)) from exc
    return value.strip()


class LoginSettings(BaseModel):
    """The non-secret part of a login profile (stored in ``Credential.extra``).

    ``verification`` is mandatory for every method: ZAP must be able to tell a logged-in session from a
    logged-out one, otherwise a broken session would produce a clean-looking report. For ``form``, ``json``
    and ``browser`` give ``logged_in_regex`` and/or ``logged_out_regex``; for ``header`` give ``poll_url``
    (a page that answers ``expected_status`` only with a valid token).
    """

    model_config = ConfigDict(extra="forbid")

    method: Literal["form", "json", "header", "browser"]
    login_page_url: str | None = Field(default=None, max_length=2000)
    login_request_url: str | None = Field(default=None, max_length=2000)
    login_request_body: str | None = Field(default=None, max_length=4000)
    header_name: str | None = Field(default=None, max_length=64)
    verification_method: Literal["response", "poll", "autodetect"] = "response"
    logged_in_regex: str | None = Field(default=None, max_length=500)
    logged_out_regex: str | None = Field(default=None, max_length=500)
    poll_url: str | None = Field(default=None, max_length=2000)
    poll_frequency: int = Field(default=60, ge=1, le=3600)
    poll_units: Literal["requests", "seconds"] = "requests"
    poll_post_data: str | None = Field(default=None, max_length=2000)
    expected_status: int = Field(default=200, ge=100, le=599)
    browser_id: Literal["firefox-headless", "chrome-headless"] = "firefox-headless"
    login_page_wait: int = Field(default=5, ge=0, le=120)
    steps: list[BrowserStep] = Field(default_factory=list, max_length=20)
    totp: bool = False

    @field_validator("login_page_url", "login_request_url", "poll_url")
    @classmethod
    def _urls(cls, value: str | None, info: Any) -> str | None:
        return _http_url(value, str(getattr(info, "field_name", "url")))

    @field_validator("logged_in_regex", "logged_out_regex")
    @classmethod
    def _regex(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.strip():
            return None
        try:
            check_java_regex(value)
        except re.error as exc:
            raise ValueError("not a valid regular expression: %s" % exc) from exc
        return value

    @field_validator("header_name")
    @classmethod
    def _header(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _HEADER_NAME.match(value) or value.lower() in _FORBIDDEN_HEADERS:
            raise ValueError("not an acceptable header name")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> LoginSettings:
        for name, value in self.model_dump().items():
            if isinstance(value, str) and "${" in value:
                raise ValueError("%s must not contain '${' (variable references are not allowed)" % name)
        if self.method in ("form", "json"):
            if not (self.login_request_url and self.login_request_body):
                raise ValueError("form and json logins need login_request_url and login_request_body")
            if "{%username%}" not in self.login_request_body or "{%password%}" not in self.login_request_body:
                raise ValueError("login_request_body must contain {%username%} and {%password%}")
        if self.method == "browser" and not self.login_page_url:
            raise ValueError("a browser login needs login_page_url")
        if self.method == "header":
            if not self.header_name:
                raise ValueError("a header login needs header_name")
            if not self.poll_url:
                raise ValueError("a header login needs poll_url so that the token can be checked")
        else:
            if not (self.logged_in_regex or self.logged_out_regex):
                raise ValueError(
                    "give logged_in_regex or logged_out_regex: the scan must be able to tell that the "
                    "login still works"
                )
            if self.verification_method == "poll" and not self.poll_url:
                raise ValueError("poll verification needs poll_url")
        if self.totp and self.method != "browser":
            raise ValueError("a one-time code (totp) is supported for browser logins only")
        return self

    def hosts(self) -> list[str]:
        """Host names the login talks to (they must be the target's host)."""
        found: list[str] = []
        for url in (self.login_page_url, self.login_request_url, self.poll_url):
            if url:
                host = split_url(url).host
                if host not in found:
                    found.append(host)
        return found

    def fragment_values(self) -> dict[str, Any]:
        """The placeholder values of ``scanners/dast/templates/auth-<method>.yaml``."""
        poll = self.verification_method == "poll"
        values: dict[str, Any] = {
            "login_page_url": self.login_page_url,
            "login_request_url": self.login_request_url,
            "login_request_body": self.login_request_body,
            "verification_method": self.verification_method,
            "logged_in_regex": self.logged_in_regex,
            "logged_out_regex": self.logged_out_regex,
            "poll_url": self.poll_url if poll else None,
            "poll_frequency": self.poll_frequency if poll else None,
            "poll_units": self.poll_units if poll else None,
            "poll_post_data": self.poll_post_data if poll else None,
            "browser_id": self.browser_id,
            "login_page_wait": self.login_page_wait,
            "steps": [s.zap() for s in self.steps] or None,
            "expected_status": self.expected_status,
            "header_poll_url": self.poll_url,
        }
        if self.totp:
            values["totp"] = {
                "secret": "${%s}" % SECRET_ENV_TOTP,
                "period": 30,
                "digits": 6,
                "algorithm": "SHA1",
            }
        else:
            values["totp"] = None
        return values


class LoginSecret(BaseModel):
    """The secret part of a login profile (JSON inside the encrypted credential)."""

    model_config = ConfigDict(extra="forbid")

    username: str | None = Field(default=None, max_length=300)
    password: str | None = Field(default=None, max_length=1000)
    totp_secret: str | None = Field(default=None, max_length=200)
    header_value: str | None = Field(default=None, max_length=4000)

    def __repr__(self) -> str:  # never show a value
        return "LoginSecret(<redacted>)"

    __str__ = __repr__

    def check_for(self, settings: LoginSettings) -> None:
        """``ValueError`` when the secret lacks what the method needs."""
        if settings.method == "header":
            if not self.header_value:
                raise ValueError("a header login needs header_value")
        else:
            if not self.username or not self.password:
                raise ValueError("this login needs username and password")
        if settings.totp and not self.totp_secret:
            raise ValueError("this login needs totp_secret")
        for value in (self.username, self.password, self.totp_secret, self.header_value):
            if value is not None and ("\x00" in value or "\n" in value or "\r" in value):
                raise ValueError("secret values cannot contain line breaks or NUL")

    def to_json(self) -> str:
        return json.dumps(self.model_dump(exclude_none=True), separators=(",", ":"))


class LoginProfileError(Exception):
    """A stored login profile cannot be used (message is plain language)."""


def parse_login_settings(extra: Mapping[str, Any]) -> LoginSettings:
    """``LoginSettings`` from ``Credential.extra`` (extra keys that are not settings are ignored)."""
    wanted = set(LoginSettings.model_fields)
    data = {k: v for k, v in dict(extra).items() if k in wanted}
    try:
        return LoginSettings.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        raise LoginProfileError(
            "The login profile is not valid (%s). Edit or recreate it."
            % str(first.get("msg", "invalid")).removeprefix("Value error, ")[:200]
        ) from exc


def parse_login_secret(text: str, settings: LoginSettings) -> LoginSecret:
    """``LoginSecret`` from the decrypted JSON, checked against the method. Never echoes the content."""
    try:
        secret = LoginSecret.model_validate(json.loads(text))
        secret.check_for(settings)
    except (ValueError, ValidationError) as exc:
        raise LoginProfileError(
            "The secret of the login profile is incomplete. Replace the login profile."
        ) from exc
    return secret


def login_env(settings: LoginSettings, secret: LoginSecret, origin: str) -> dict[str, str]:
    """Container environment carrying the login secret. The plan refers to these names with ``${NAME}``."""
    env: dict[str, str] = {}
    if settings.method == "header":
        env[SECRET_ENV_HEADER] = str(settings.header_name)
        env[SECRET_ENV_HEADER_VALUE] = str(secret.header_value)
        env[SECRET_ENV_HEADER_SITE] = origin
        return env
    env[SECRET_ENV_USERNAME] = str(secret.username)
    env[SECRET_ENV_PASSWORD] = str(secret.password)
    if settings.totp:
        env[SECRET_ENV_TOTP] = str(secret.totp_secret)
    return env
