"""The DAST safety rules: environment, vendor SaaS authorization, allowlist, blackout windows, locks.

Every combination of environment, mode and login profile is tested against the rule of the design, and each
other rule has its own table. No network, no database: names are resolved by stubs.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
import types
import uuid
from datetime import timedelta
from typing import Any

import pytest

from securescan.api.problems import Forbidden, Problem, ServiceUnavailable
from securescan.config import Settings
from securescan.db.models.enums import AppType, TargetEnvironment, TargetKind
from securescan.domain import dast_rules
from securescan.domain.dast_rules import (
    ALWAYS_BLOCKED,
    DAST_LOCK,
    LoginProfileError,
    LoginSecret,
    LoginSettings,
    ProfileFacts,
    allowed_modes,
    check_allowlist,
    check_job_allowed,
    check_scan_allowed,
    check_scan_allowed_async,
    effective_rate,
    login_env,
    normalise_address,
    parse_cidrs,
    parse_login_secret,
    parse_login_settings,
    split_url,
    target_hosts,
)
from securescan.runner.catalogue import CatalogueEntry
from securescan.util import utcnow
from tests.unit.runner_helpers import make_entry, real_catalogue

UAT, PROD = TargetEnvironment.UAT, TargetEnvironment.PRODUCTION
CIDRS = "10.0.0.0/8, 192.168.50.0/24, 2001:db8::/32"
NOW = utcnow()

BASELINE = ProfileFacts("dast", "baseline", ("zap",))
FULL = ProfileFacts("dast", "full", ("zap", "nuclei"))
API = ProfileFacts("dast", "api", ("zap", "nuclei"))
NUCLEI = ProfileFacts("dast", "nuclei", ("nuclei",))
MODES = {"baseline": BASELINE, "full": FULL, "api": API, "nuclei": NUCLEI}


def make_target(**overrides: Any) -> Any:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "name": "Shop (UAT)",
        "kind": TargetKind.URL,
        "locator": "http://10.20.30.40:8080/",
        "environment": UAT,
        "login_profile_id": None,
        "host_approved": False,
        "blackout_windows": [],
        "api_spec_type": None,
        "api_spec_locator": None,
        "api_spec_artifact_id": None,
        "rate_limit_rps": None,
        "vendor_authorization_artifact_id": None,
        "vendor_authorized_from": None,
        "vendor_authorized_until": None,
        "vendor_contact": None,
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def make_application(kind: AppType = AppType.INTERNAL, hosting: str | None = None) -> Any:
    return types.SimpleNamespace(id=uuid.uuid4(), type=kind, hosting=hosting)


def no_dns(host: str) -> list[str]:
    raise AssertionError(f"unexpected name resolution of {host}")


def check(profile: Any, target: Any, **kwargs: Any) -> None:
    kwargs.setdefault("allowed_cidrs", CIDRS)
    kwargs.setdefault("resolver", no_dns)
    kwargs.setdefault("now", NOW)
    check_scan_allowed(profile, [target], **kwargs)


def refused(profile: Any, target: Any, code: str, status: int = 403, **kwargs: Any) -> Problem:
    with pytest.raises(Problem) as caught:
        check(profile, target, **kwargs)
    assert caught.value.code == code, (caught.value.code, caught.value.detail)
    assert caught.value.status_code == status
    return caught.value


# --------------------------------------------------------------------------- environment x mode x login
ENVIRONMENT_TABLE = [
    # (environment, mode, tools override, login, api spec, expected code or None, status)
    (PROD, "baseline", None, False, False, None, 200),
    (PROD, "baseline", None, True, False, "dast.production_no_login", 403),
    (PROD, "full", None, False, False, "dast.production_baseline_only", 403),
    (PROD, "full", None, True, False, "dast.production_baseline_only", 403),
    (PROD, "api", None, False, True, "dast.production_baseline_only", 403),
    (PROD, "api", None, True, True, "dast.production_baseline_only", 403),
    (PROD, "nuclei", None, False, False, "dast.production_baseline_only", 403),
    (PROD, "nuclei", None, True, False, "dast.production_baseline_only", 403),
    (PROD, "baseline", ("zap", "nuclei"), False, False, "dast.production_baseline_only", 403),
    (PROD, "baseline", ("nuclei",), False, False, "dast.production_baseline_only", 403),
    (PROD, "full", ("zap",), False, False, "dast.production_baseline_only", 403),
    (UAT, "baseline", None, False, False, None, 200),
    (UAT, "baseline", None, True, False, None, 200),
    (UAT, "full", None, False, False, None, 200),
    (UAT, "full", None, True, False, None, 200),
    (UAT, "api", None, False, False, "dast.api_spec_required", 422),
    (UAT, "api", None, False, True, None, 200),
    (UAT, "api", None, True, True, None, 200),
    (UAT, "nuclei", None, False, False, None, 200),
    (UAT, "baseline", ("zap", "nuclei"), False, False, "dast.mode_tool_mismatch", 422),
    (UAT, "nuclei", ("zap", "nuclei"), False, False, "dast.mode_tool_mismatch", 422),
    (UAT, "full", ("zap", "other"), False, False, "dast.mode_tool_mismatch", 422),
    (None, "baseline", None, False, False, "target.environment_required", 422),
    (None, "full", None, False, False, "target.environment_required", 422),
]


@pytest.mark.parametrize("environment, mode, tools, login, spec, code, status", ENVIRONMENT_TABLE)
def test_environment_rule_table(
    environment: Any, mode: str, tools: Any, login: bool, spec: bool, code: str | None, status: int
) -> None:
    profile = MODES[mode] if tools is None else ProfileFacts("dast", mode, tools)
    target = make_target(
        environment=environment,
        login_profile_id=uuid.uuid4() if login else None,
        api_spec_type="openapi" if spec else None,
        api_spec_locator="http://10.20.30.40:8080/openapi.json" if spec else None,
    )
    if code is None:
        check(profile, target)
    else:
        refused(profile, target, code, status)


def oracle(environment: Any, mode: str, login: bool, spec: bool) -> tuple[str, int] | None:
    """The rule of the design written out once more, independently of the implementation."""
    if environment is None:
        return "target.environment_required", 422
    if environment == PROD:
        if mode != "baseline":
            return "dast.production_baseline_only", 403
        if login:
            return "dast.production_no_login", 403
        return None
    if mode == "api" and not spec:
        return "dast.api_spec_required", 422
    return None


@pytest.mark.parametrize(
    "environment, mode, login, spec",
    list(itertools.product((PROD, UAT, None), ("baseline", "full", "api", "nuclei"), (False, True), (False, True))),
)
def test_every_combination_follows_the_design(environment: Any, mode: str, login: bool, spec: bool) -> None:
    target = make_target(
        environment=environment,
        login_profile_id=uuid.uuid4() if login else None,
        api_spec_type="openapi" if spec else None,
        api_spec_locator="http://10.20.30.40:8080/api.json" if spec else None,
    )
    expected = oracle(environment, mode, login, spec)
    if expected is None:
        check(MODES[mode], target)
    else:
        refused(MODES[mode], target, expected[0], expected[1])


def test_production_refusal_is_a_403_in_plain_words() -> None:
    problem = refused(FULL, make_target(environment=PROD), "dast.production_baseline_only")
    assert isinstance(problem, Forbidden)
    assert "Production targets accept the unauthenticated ZAP baseline scan only" in str(problem.detail)
    login = refused(BASELINE, make_target(environment=PROD, login_profile_id=uuid.uuid4()), "dast.production_no_login")
    assert "login profile" in str(login.detail)


def test_non_dast_profiles_and_other_kinds() -> None:
    sast = types.SimpleNamespace(kind="sast", mode=None, tools=("semgrep",))
    check_scan_allowed(sast, [make_target(kind=TargetKind.ZIP, environment=None)], resolver=no_dns)  # not ours
    refused(BASELINE, make_target(kind=TargetKind.ZIP, environment=None), "scan.target_kind_mismatch", 422)
    refused(BASELINE, make_target(kind=TargetKind.GITHUB_REPO), "scan.target_kind_mismatch", 422)


def test_a_profile_doc_works_like_the_facts() -> None:
    from securescan.runner.profiles import ProfileDoc

    doc = ProfileDoc.model_validate(
        {"profile": "dast-full", "kind": "dast", "mode": "full", "jobs": [{"tool": "zap"}, {"tool": "nuclei"}]}
    )
    refused(doc, make_target(environment=PROD), "dast.production_baseline_only")
    check(doc, make_target())


# --------------------------------------------------------------------------- vendor SaaS authorization
def authorized(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "vendor_authorization_artifact_id": uuid.uuid4(),
        "vendor_authorized_from": NOW - timedelta(days=1),
        "vendor_authorized_until": NOW + timedelta(days=1),
        "vendor_contact": "Pat Vendor <pat@vendor.example>",
    }
    values.update(overrides)
    return values


VENDOR_TABLE = [
    # (application type, hosting, target fields, expected code)
    (AppType.INTERNAL, None, {}, None),
    (AppType.INTERNAL, "saas", {}, None),  # the rule is about vendor products
    (AppType.VENDOR, None, {}, None),
    (AppType.VENDOR, "deployable", {}, None),  # the company hosts it in UAT: no vendor paperwork
    (AppType.VENDOR, "saas", authorized(), None),
    (AppType.VENDOR, "SaaS", authorized(), None),
    (AppType.VENDOR, "saas", {}, "dast.vendor_authorization_required"),
    (AppType.VENDOR, "saas", authorized(vendor_authorization_artifact_id=None), "dast.vendor_authorization_required"),
    (AppType.VENDOR, "saas", authorized(vendor_contact=None), "dast.vendor_authorization_required"),
    (AppType.VENDOR, "saas", authorized(vendor_contact="   "), "dast.vendor_authorization_required"),
    (AppType.VENDOR, "saas", authorized(vendor_authorized_from=None), "dast.vendor_authorization_required"),
    (AppType.VENDOR, "saas", authorized(vendor_authorized_until=None), "dast.vendor_authorization_required"),
    (
        AppType.VENDOR,
        "saas",
        authorized(vendor_authorized_from=NOW + timedelta(hours=1), vendor_authorized_until=NOW + timedelta(days=2)),
        "dast.vendor_authorization_not_started",
    ),
    (
        AppType.VENDOR,
        "saas",
        authorized(vendor_authorized_from=NOW - timedelta(days=3), vendor_authorized_until=NOW - timedelta(minutes=1)),
        "dast.vendor_authorization_expired",
    ),
]


@pytest.mark.parametrize("kind, hosting, fields, code", VENDOR_TABLE)
def test_vendor_saas_needs_the_authorization_record(kind: AppType, hosting: str | None, fields: dict[str, Any], code: str | None) -> None:
    target = make_target(**fields)
    application = make_application(kind, hosting)
    if code is None:
        check(BASELINE, target, application=application)
        check(FULL, target, application=application)  # a UAT instance of a SaaS product, authorized
    else:
        refused(BASELINE, target, code, application=application)
        refused(FULL, target, code, application=application)


def test_vendor_saas_on_production_is_still_baseline_only() -> None:
    target = make_target(environment=PROD, **authorized())
    application = make_application(AppType.VENDOR, "saas")
    check(BASELINE, target, application=application)
    refused(FULL, target, "dast.production_baseline_only", application=application)


# --------------------------------------------------------------------------- allowlist
def resolver_of(table: dict[str, list[str]]) -> Any:
    def lookup(host: str) -> list[str]:
        return list(table.get(host, []))

    return lookup


ALLOWLIST_TABLE = [
    # (locator, approved, cidrs, dns table, api spec locator, expected code)
    ("http://10.20.30.40:8080/", False, CIDRS, {}, None, None),
    ("http://192.168.50.7/", False, CIDRS, {}, None, None),
    ("http://172.16.0.5/", False, CIDRS, {}, None, "dast.host_not_allowlisted"),
    ("http://[2001:db8::5]:8443/", False, CIDRS, {}, None, None),
    ("http://[2001:4860::1]/", False, CIDRS, {}, None, "dast.host_not_allowlisted"),
    ("https://shop.uat.example/", False, CIDRS, {"shop.uat.example": ["10.1.2.3"]}, None, None),
    ("https://shop.uat.example/", False, CIDRS, {"shop.uat.example": ["10.1.2.3", "8.8.8.8"]}, None, "dast.host_not_allowlisted"),
    ("https://shop.uat.example/", False, CIDRS, {"shop.uat.example": ["::ffff:10.1.2.3"]}, None, None),  # IPv4-mapped
    ("https://shop.uat.example/", False, CIDRS, {"shop.uat.example": ["::ffff:8.8.8.8"]}, None, "dast.host_not_allowlisted"),
    ("https://shop.uat.example/", False, CIDRS, {}, None, "dast.host_unresolvable"),
    ("https://shop.uat.example/", True, CIDRS, {}, None, None),  # approved: no resolution needed
    ("https://shop.uat.example/", True, "", {}, None, None),
    ("https://shop.uat.example/", True, "", {"shop.uat.example": ["8.8.8.8"]}, None, None),
    ("https://shop.uat.example/", False, "", {"shop.uat.example": ["10.1.2.3"]}, None, "dast.host_not_allowlisted"),
    ("http://10.20.30.40/", False, "", {}, None, "dast.host_not_allowlisted"),  # nothing allowlisted, fail closed
    # never scanned, approval or not
    ("http://127.0.0.1:8000/", True, CIDRS, {}, None, "dast.host_blocked"),
    ("http://localhost/", True, CIDRS, {"localhost": ["127.0.0.1"]}, None, "dast.host_blocked"),
    ("http://169.254.169.254/latest/meta-data/", True, "169.254.0.0/16", {}, None, "dast.host_blocked"),
    ("http://metadata.internal/", True, CIDRS, {"metadata.internal": ["169.254.169.254"]}, None, "dast.host_blocked"),
    ("http://[::1]/", True, CIDRS, {}, None, "dast.host_blocked"),
    ("http://[fe80::1]/", True, CIDRS, {}, None, "dast.host_blocked"),
    ("http://224.0.0.1/", True, CIDRS, {}, None, "dast.host_blocked"),
    ("http://0.0.0.0/", True, CIDRS, {}, None, "dast.host_blocked"),
    ("https://shop.uat.example/", True, CIDRS, {"shop.uat.example": ["127.0.0.2"]}, None, "dast.host_blocked"),
    # the API definition host is checked like the target
    ("http://10.20.30.40/", False, CIDRS, {}, "http://10.20.30.41/openapi.json", None),
    ("http://10.20.30.40/", False, CIDRS, {}, "http://8.8.8.8/openapi.json", "dast.host_not_allowlisted"),
    ("http://10.20.30.40/", False, CIDRS, {"specs.example": ["10.9.9.9"]}, "https://specs.example/o.json", None),
    ("http://10.20.30.40/", True, CIDRS, {"specs.example": ["169.254.169.254"]}, "https://specs.example/o.json", "dast.host_blocked"),
    ("http://10.20.30.40/", False, CIDRS, {}, "/uploaded/spec.json", None),  # a path is not a host
]


@pytest.mark.parametrize("locator, approved, cidrs, dns, spec, code", ALLOWLIST_TABLE)
def test_allowlist_table(locator: str, approved: bool, cidrs: str, dns: dict[str, list[str]], spec: str | None, code: str | None) -> None:
    target = make_target(locator=locator, host_approved=approved, api_spec_locator=spec, api_spec_type="openapi" if spec else None)
    if code is None:
        check(BASELINE, target, allowed_cidrs=cidrs, resolver=resolver_of(dns))
    else:
        refused(BASELINE, target, code, allowed_cidrs=cidrs, resolver=resolver_of(dns))


def test_resolved_mapping_wins_over_the_resolver() -> None:
    target = make_target(locator="https://shop.uat.example/")
    check(BASELINE, target, resolved={"shop.uat.example": ["10.1.1.1"]}, resolver=no_dns)
    refused(BASELINE, target, "dast.host_not_allowlisted", resolved={"shop.uat.example": ["1.2.3.4"]}, resolver=no_dns)


def test_check_allowlist_alone_and_settings_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_DAST_ALLOWED_CIDRS", "10.0.0.0/8")
    from securescan.config import get_settings

    get_settings.cache_clear()
    check_allowlist(make_target(), resolver=no_dns)
    with pytest.raises(Forbidden):
        check_allowlist(make_target(locator="http://172.16.1.1/"), resolver=no_dns)
    assert get_settings().dast_cidrs == ["10.0.0.0/8"]
    monkeypatch.delenv("SECURESCAN_DAST_ALLOWED_CIDRS")
    get_settings.cache_clear()
    with pytest.raises(Forbidden) as caught:
        check_allowlist(make_target(), resolver=no_dns)  # nothing allowlisted: fail closed
    assert caught.value.code == "dast.host_not_allowlisted"


def test_the_blocked_ranges_cover_loopback_metadata_and_multicast() -> None:
    for text in ("127.0.0.1", "169.254.169.254", "224.0.0.251", "0.0.0.0", "::1", "fe80::1", "fd00:ec2::254"):
        address = normalise_address(text)
        assert address is not None and dast_rules.is_always_blocked(address), text
    for text in ("10.1.1.1", "192.168.1.1", "8.8.8.8", "2001:db8::1"):
        address = normalise_address(text)
        assert address is not None and not dast_rules.is_always_blocked(address), text
    assert all(isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network)) for n in ALWAYS_BLOCKED)


def test_parse_cidrs_and_urls() -> None:
    assert [str(n) for n in parse_cidrs("10.0.0.0/8, 192.168.1.5/32 ,, 2001:db8::/32")] == [
        "10.0.0.0/8", "192.168.1.5/32", "2001:db8::/32",
    ]  # fmt: skip
    assert [str(n) for n in parse_cidrs(["10.1.0.1/16"])] == ["10.1.0.0/16"]  # host bits are dropped
    with pytest.raises(ValueError, match="not-a-network"):
        parse_cidrs("10.0.0.0/8, not-a-network")
    info = split_url("HTTPS://Shop.UAT.example:8443/path?a=1")
    assert (info.scheme, info.host, info.port, info.origin) == ("https", "shop.uat.example", 8443, "https://shop.uat.example:8443")
    assert split_url("http://example.com").port == 80 and split_url("https://example.com").origin == "https://example.com"
    assert split_url("http://[2001:db8::1]:8080/").origin == "http://[2001:db8::1]:8080"
    for bad in ("ftp://x", "example.com", "http://", "http://user:pw@host/", "http://exa mple.com/", "http://host:99999/"):
        with pytest.raises(ValueError):
            split_url(bad)
    assert [h.host for h in target_hosts(make_target(api_spec_locator="https://specs.example/o.json"))] == ["10.20.30.40", "specs.example"]
    assert len(target_hosts(make_target(api_spec_locator="http://10.20.30.40:8080/o.json"))) == 1  # same host and port


# --------------------------------------------------------------------------- blackout windows
def one_off(start_offset: timedelta, end_offset: timedelta) -> dict[str, Any]:
    return {"starts_at": (NOW + start_offset).isoformat(), "ends_at": (NOW + end_offset).isoformat()}


def weekly_all_day() -> dict[str, Any]:
    return {"days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "00:00"}  # equal times: the whole day


BLACKOUT_TABLE = [
    ([], None),
    ([one_off(timedelta(hours=-1), timedelta(hours=1))], "dast.blackout_window"),
    ([one_off(timedelta(hours=1), timedelta(hours=2))], None),
    ([one_off(timedelta(hours=-3), timedelta(hours=-2))], None),
    ([weekly_all_day()], "dast.blackout_window"),
    ([{"days": [], "start": "00:00", "end": "23:59"}], None),
    ([one_off(timedelta(hours=1), timedelta(hours=2)), weekly_all_day()], "dast.blackout_window"),
    ([{"starts_at": NOW.isoformat()}], "dast.blackout_invalid"),  # unreadable: refuse rather than scan
    ([{"days": [1], "start": "9am", "end": "10am"}], "dast.blackout_invalid"),
    ([{"nothing": True}], "dast.blackout_invalid"),
]


@pytest.mark.parametrize("windows, code", BLACKOUT_TABLE)
def test_blackout_windows(windows: list[dict[str, Any]], code: str | None) -> None:
    target = make_target(blackout_windows=windows)
    if code is None:
        check(BASELINE, target)
    else:
        problem = refused(BASELINE, target, code)
        if code == "dast.blackout_window":
            assert "blackout window" in str(problem.detail)


def test_blackout_message_says_when_it_ends() -> None:
    problem = refused(BASELINE, make_target(blackout_windows=[one_off(timedelta(hours=-1), timedelta(hours=3))]), "dast.blackout_window")
    assert "until" in str(problem.detail) and "UTC" in str(problem.detail)


# --------------------------------------------------------------------------- the one-at-a-time lock
def test_the_real_catalogue_gives_both_tools_the_dast_lock() -> None:
    catalogue = real_catalogue()
    assert DAST_LOCK == "scanner"
    assert catalogue["zap"].lock == DAST_LOCK and catalogue["nuclei"].lock == DAST_LOCK
    assert catalogue["zap"].max_parallel == 1 and catalogue["nuclei"].max_parallel == 1
    check(FULL, make_target(), catalogue=catalogue)


def test_a_dast_tool_without_the_lock_stops_scans() -> None:
    broken: dict[str, CatalogueEntry] = {"zap": make_entry(tool="zap", lock=None), "nuclei": make_entry(tool="nuclei", lock=DAST_LOCK)}
    with pytest.raises(ServiceUnavailable) as caught:
        check(FULL, make_target(), catalogue=broken)
    assert caught.value.code == "dast.lock_not_configured" and caught.value.status_code == 503
    check(NUCLEI, make_target(), catalogue=broken)  # only the tools of the profile matter


def test_lock_names_come_from_the_catalogue_for_the_queue() -> None:
    from securescan.domain.scans import job_lock_name

    entry = real_catalogue()["zap"]
    assert job_lock_name("zap", uuid.uuid4(), entry.max_parallel, entry.lock) == "scanner"
    assert job_lock_name("nuclei", uuid.uuid4(), 1, real_catalogue()["nuclei"].lock) == "scanner"


# --------------------------------------------------------------------------- job-time re-check and async form
def test_the_worker_asks_again_before_a_container_starts() -> None:
    target = make_target(blackout_windows=[weekly_all_day()])
    with pytest.raises(Problem) as caught:
        check_job_allowed(target, None, tool="zap", mode="baseline", now=NOW, allowed_cidrs=CIDRS, resolver=no_dns)
    assert caught.value.code == "dast.blackout_window"
    check_job_allowed(make_target(), None, tool="nuclei", mode="full", now=NOW, allowed_cidrs=CIDRS, resolver=no_dns)
    expired = make_target(**authorized(vendor_authorized_until=NOW - timedelta(minutes=5)))
    with pytest.raises(Problem) as vendor:
        check_job_allowed(
            expired, make_application(AppType.VENDOR, "saas"), tool="zap", mode="baseline",
            now=NOW, allowed_cidrs=CIDRS, resolver=no_dns,
        )  # fmt: skip
    assert vendor.value.code == "dast.vendor_authorization_expired"


async def test_async_form_resolves_names_and_loads_the_catalogue(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[list[str]] = []

    async def fake_resolve(hosts: Any, timeout: float = 5.0) -> dict[str, list[str]]:
        asked.append(sorted(hosts))
        return {"shop.uat.example": ["10.5.5.5"]}

    monkeypatch.setattr(dast_rules, "resolve_hosts", fake_resolve)
    monkeypatch.setenv("SECURESCAN_DAST_ALLOWED_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("SECURESCAN_SCANNERS_DIR", str(real_scanners()))
    from securescan.config import get_settings
    from securescan.runner.catalogue import clear_catalogue_cache

    get_settings.cache_clear()
    clear_catalogue_cache()
    target = make_target(locator="https://shop.uat.example/")
    await check_scan_allowed_async(FULL, [target])
    assert asked == [["shop.uat.example"]]
    with pytest.raises(Forbidden) as caught:
        await check_scan_allowed_async(FULL, [make_target(locator="https://shop.uat.example/", environment=PROD)])
    assert caught.value.code == "dast.production_baseline_only"
    sast = types.SimpleNamespace(kind="sast", mode=None, tools=())
    await check_scan_allowed_async(sast, [target])
    assert len(asked) == 2  # nothing is resolved for a code profile


def real_scanners() -> Any:
    from tests.unit.runner_helpers import REPO_SCANNERS

    return REPO_SCANNERS


async def test_resolve_hosts_never_blocks_on_a_slow_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    def slow(host: str) -> list[str]:
        time.sleep(0.5)
        return ["10.0.0.1"]

    real = dast_rules.resolve_host
    monkeypatch.setattr(dast_rules, "resolve_host", slow)
    result = await dast_rules.resolve_hosts(["slow.example"], timeout=0.05)
    assert result == {"slow.example": []}
    monkeypatch.setattr(dast_rules, "resolve_host", real)
    assert dast_rules.resolve_host("10.1.2.3") == ["10.1.2.3"]  # a literal needs no lookup
    assert dast_rules.resolve_host("::ffff:10.1.2.3") == ["10.1.2.3"]


# --------------------------------------------------------------------------- rate, modes
def test_rate_cap_is_bounded_by_the_platform_maximum() -> None:
    settings = Settings(dast_max_rps=40)
    assert effective_rate(make_target(rate_limit_rps=5), 50, settings) == 5
    assert effective_rate(make_target(rate_limit_rps=500), 50, settings) == 40
    assert effective_rate(make_target(rate_limit_rps=None), 50, settings) == 40
    assert effective_rate(make_target(rate_limit_rps=None), 10, settings) == 10
    assert effective_rate(make_target(rate_limit_rps=0), 10, settings) == 10  # zero is no cap
    assert effective_rate(make_target(rate_limit_rps=True), 10, settings) == 10


@pytest.mark.parametrize(
    "environment, login, modes",
    [
        (PROD, False, ["baseline"]),
        (PROD, True, []),
        (UAT, False, ["baseline", "full", "api", "nuclei"]),
        (UAT, True, ["baseline", "full", "api", "nuclei"]),
        (None, False, []),
        ("production", False, ["baseline"]),
    ],
)
def test_allowed_modes(environment: Any, login: bool, modes: list[str]) -> None:
    assert allowed_modes(environment, has_login=login) == modes


# --------------------------------------------------------------------------- login profile model
def form_settings(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "method": "form",
        "login_page_url": "http://10.20.30.40:8080/login",
        "login_request_url": "http://10.20.30.40:8080/login",
        "login_request_body": "user={%username%}&pass={%password%}",
        "logged_in_regex": "\\QSign out\\E",
    }
    values.update(overrides)
    return values


@pytest.mark.parametrize(
    "overrides, problem",
    [
        ({"logged_in_regex": None}, "logged_in_regex or logged_out_regex"),
        ({"logged_in_regex": "("}, "regular expression"),
        ({"login_request_body": "user=x&pass=y"}, "{%username%}"),
        ({"login_request_url": None}, "login_request_url"),
        ({"logged_in_regex": "x${ZAP_AUTH_PASSWORD}"}, "variable references"),
        ({"login_request_body": "u={%username%}&p={%password%}&x=${HOME}"}, "variable references"),
        ({"login_page_url": "ftp://x"}, "http"),
        ({"login_request_url": "http://u:p@host/login"}, "user name"),
        ({"verification_method": "poll"}, "poll_url"),
        ({"totp": True}, "browser logins only"),
        ({"method": "header"}, "header_name"),
        ({"method": "bogus"}, "method"),
        ({"surprise": 1}, "surprise"),
    ],
)
def test_login_settings_are_refused_with_a_reason(overrides: dict[str, Any], problem: str) -> None:
    with pytest.raises(Exception) as caught:
        LoginSettings.model_validate(form_settings(**overrides))
    assert problem in str(caught.value)


def test_valid_logins_of_every_method() -> None:
    form = LoginSettings.model_validate(form_settings())
    assert form.hosts() == ["10.20.30.40"] and form.fragment_values()["totp"] is None
    json_login = LoginSettings.model_validate(
        form_settings(method="json", login_request_body='{"u":"{%username%}","p":"{%password%}"}', logged_out_regex="Please sign in", logged_in_regex=None)
    )
    assert json_login.method == "json"
    header = LoginSettings.model_validate(
        {"method": "header", "header_name": "Authorization", "poll_url": "http://10.20.30.40:8080/api/me", "expected_status": 200}
    )
    assert header.method == "header"
    browser = LoginSettings.model_validate(
        {
            "method": "browser", "login_page_url": "http://10.20.30.40:8080/", "logged_in_regex": "Logout", "totp": True,
            "steps": [{"type": "USERNAME", "css_selector": "#user"}, {"type": "PASSWORD"}, {"type": "CLICK", "xpath": "//button", "timeout": 500}],
        }
    )  # fmt: skip
    values = browser.fragment_values()
    assert values["steps"][0] == {"type": "USERNAME", "cssSelector": "#user"}
    assert values["totp"]["secret"] == "${ZAP_AUTH_TOTP_SECRET}" and values["browser_id"] == "firefox-headless"
    poll = LoginSettings.model_validate(form_settings(verification_method="poll", poll_url="http://10.20.30.40:8080/me"))
    assert poll.fragment_values()["poll_url"] == "http://10.20.30.40:8080/me"
    assert form.fragment_values()["poll_url"] is None  # poll fields only for poll verification


def test_secrets_are_checked_against_the_method_and_never_shown() -> None:
    form = LoginSettings.model_validate(form_settings())
    secret = LoginSecret(username="analyst", password="s3cr3t-Pa55")
    secret.check_for(form)
    assert "s3cr3t-Pa55" not in repr(secret) and "s3cr3t-Pa55" not in str(secret)
    with pytest.raises(ValueError):
        LoginSecret(username="analyst").check_for(form)
    with pytest.raises(ValueError):
        LoginSecret(username="a", password="line\nbreak").check_for(form)
    header = LoginSettings.model_validate({"method": "header", "header_name": "X-Api-Key", "poll_url": "http://10.20.30.40/me"})
    with pytest.raises(ValueError):
        LoginSecret(username="a", password="b").check_for(header)
    LoginSecret(header_value="abc123").check_for(header)
    assert json.loads(secret.to_json()) == {"username": "analyst", "password": "s3cr3t-Pa55"}


def test_secret_parsing_and_the_container_environment() -> None:
    form = LoginSettings.model_validate(form_settings())
    parsed = parse_login_secret('{"username":"analyst","password":"pw-1"}', form)
    env = login_env(form, parsed, "http://10.20.30.40:8080")
    assert env == {"ZAP_AUTH_USERNAME": "analyst", "ZAP_AUTH_PASSWORD": "pw-1"}
    header = LoginSettings.model_validate({"method": "header", "header_name": "Authorization", "poll_url": "http://10.20.30.40/me"})
    header_env = login_env(header, parse_login_secret('{"header_value":"Bearer abc"}', header), "http://10.20.30.40")
    assert header_env == {
        "ZAP_AUTH_HEADER": "Authorization",
        "ZAP_AUTH_HEADER_VALUE": "Bearer abc",
        "ZAP_AUTH_HEADER_SITE": "http://10.20.30.40",
    }
    for bad in ("not json", '{"username":"a"}', '{"unknown":"x"}', "[]"):
        with pytest.raises(LoginProfileError) as caught:
            parse_login_secret(bad, form)
        assert "pw-1" not in str(caught.value)
    assert parse_login_settings({**form_settings(), "ignored": 1, "target_id": "x"}).method == "form"
    with pytest.raises(LoginProfileError):
        parse_login_settings({"method": "form"})
