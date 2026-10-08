#!/usr/bin/env python3
"""Spike S1: DefectDojo 3.4.0 import, deduplication, service accounts (plan M1, S1 steps 2-10).

Run (repository root), after the stack from spikes/s1/docker-compose.yml is up:

    uv run --project backend python spikes/s1/run.py

Environment variables
    DD_URL                 DefectDojo base URL (default http://127.0.0.1:8080)
    DD_ADMIN_USER          admin user name (default admin)
    DD_ADMIN_PASSWORD      admin password, the value given to the initializer (required; or DD_ADMIN_PASSWORD_FILE)
    S1_REPORTS_DIR         directory with the fixture reports (default backend/tests/fixtures/reports)
    S1_PRODUCT             product (Asset) name used for the imports (default spike-app)
    S1_ENGAGEMENT          engagement name (default main)
    S1_WAIT_SECONDS        how long to wait for DefectDojo to answer (default 900)
    S1_REQUIRE_ALL         1 = a missing fixture report for step 8 is a failure (default 0: skipped with a warning)

What it does, in order (numbers are the plan's S1 steps):
    2  admin token                         3  securescan-sync (staff) and securescan-accounts (superuser)
    3b staff token cannot create users; superuser token can create a staff user
    4  enable deduplication                5  product types Internal Applications and Vendor Applications
    6  reimport-scan twice, then with one finding removed (closed), then the original again (reopened)
    7  findings API fields, id filters, per-product paging
    8  every other fixture report with its scan type
    9  force_password_reset through the API
    10 deduplication algorithm and hash fields per test

Exit codes: 0 all as expected; 1 first unexpected result (the run stops); 2 finished, but at least one
step-8 import was rejected or a report was missing under S1_REQUIRE_ALL (record these in the findings file).
Accounts and passwords created here are kept in spikes/s1/.data/accounts.json (mode 0600) so that a re-run
works; delete the file together with the users to start over. Nothing secret is printed.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spikelib  # noqa: E402
from spikelib import Spike, SpikeFailure, env  # noqa: E402

HERE = Path(__file__).resolve().parent
WANTED_FINDING_FIELDS = [
    "id", "title", "severity", "cwe", "vulnerability_ids", "component_name", "component_version", "file_path",
    "line", "hash_code", "active", "verified", "false_p", "duplicate", "out_of_scope", "risk_accepted",
    "is_mitigated", "date", "test", "description", "unique_id_from_tool", "vuln_id_from_tool",
]
# (fixture file, DefectDojo scan_type, test_title, content type)
OTHER_REPORTS = [
    ("gitleaks.json", "Gitleaks Scan", "gitleaks:main", "application/json"),
    ("grype.json", "Anchore Grype", "grype:main", "application/json"),
    ("dependency-check-report.xml", "Dependency Check Scan", "dependency-check:main", "application/xml"),
    ("zap.xml", "ZAP Scan", "zap:main", "application/xml"),
    ("nuclei.json", "Nuclei Scan", "nuclei:main", "application/json"),
    ("spotbugs.xml", "SpotBugs Scan", "spotbugs:main", "application/xml"),
    ("sonarqube-issues.zip", "SonarQube Scan", "sonarqube:main", "application/zip"),
]
ACTIVE_FILTER = {"active": "true", "duplicate": "false", "false_p": "false", "out_of_scope": "false",
                 "risk_accepted": "false"}


def token_headers(token: str) -> Dict[str, str]:
    return {"Authorization": "Token " + token}


class Dojo:
    """Thin wrapper holding the client, base URL and the spike for printing."""

    def __init__(self, spike: Spike, client: Any, base: str) -> None:
        self.spike = spike
        self.c = client
        self.base = base.rstrip("/")

    def url(self, path: str) -> str:
        return self.base + path

    def get_token(self, username: str, password: str, label: str) -> str:
        r = self.spike.http(
            self.c, "POST", self.url("/api/v2/api-token-auth/"), expect=[200], label=label,
            json_body={"username": username, "password": password},
        )
        token = r.json().get("token")
        self.spike.expect(isinstance(token, str) and token, "token received for %s (length %d)" % (username, len(token or "")))
        return str(token)

    def find_user(self, headers: Dict[str, str], username: str) -> Optional[Dict[str, Any]]:
        r = self.spike.http(
            self.c, "GET", self.url("/api/v2/users/"), expect=[200], headers=headers,
            params={"username": username, "limit": 100}, label="look up user %s" % username, max_body=1500,
        )
        for item in r.json().get("results", []):
            if item.get("username") == username:
                return item
        return None

    def count(self, headers: Dict[str, str], params: Dict[str, Any]) -> int:
        q = dict(params)
        q["limit"] = 1
        r = self.c.get(self.url("/api/v2/findings/"), headers=headers, params=q)
        if r.status_code != 200:
            raise SpikeFailure("findings count failed: HTTP %d %s" % (r.status_code, r.text[:300]))
        return int(r.json()["count"])


def ensure_user(
    spike: Spike, dojo: Dojo, admin_h: Dict[str, str], store: spikelib.SecretStore, username: str,
    is_staff: bool, is_superuser: bool,
) -> str:
    """Create the user (or reuse the one from an earlier run) and return its password."""
    existing = dojo.find_user(admin_h, username)
    stored = store.get("password:" + username)
    if existing is not None and stored:
        spike.note("user %s exists and its password is in accounts.json: reused" % username)
        return str(stored)
    if existing is not None:
        spike.note("user %s exists but its password is unknown (PATCH cannot set a password: 'Update of password "
                   "though API is not allowed'); deleting it with the admin token and recreating" % username)
        spike.http(dojo.c, "DELETE", dojo.url("/api/v2/users/%d/" % existing["id"]), expect=[204], headers=admin_h,
                   label="delete stale user %s" % username)
    password = spikelib.random_password(24)
    spike.http(
        dojo.c, "POST", dojo.url("/api/v2/users/"), expect=[201], headers=admin_h,
        label="create user %s (is_staff=%s, is_superuser=%s)" % (username, is_staff, is_superuser),
        json_body={
            "username": username, "password": password, "email": username + "@securescan.invalid",
            "first_name": "SecureScan", "last_name": "Spike", "is_active": True,
            "is_staff": is_staff, "is_superuser": is_superuser,
        },
    )
    store.set("password:" + username, password)
    return password


def reimport(
    spike: Spike, dojo: Dojo, headers: Dict[str, str], file_path: Path, scan_type: str, test_title: str,
    product: str, engagement: str, content_type: str, label: str, probe: bool = False,
    file_bytes: Optional[bytes] = None,
) -> Tuple[Any, float]:
    """Reimport one report. ``probe=True`` accepts any HTTP status (the result is recorded, not judged)."""
    content = file_bytes if file_bytes is not None else file_path.read_bytes()
    fields = {
        "scan_type": scan_type,
        "product_type_name": "Internal Applications",
        "product_name": product,
        "engagement_name": engagement,
        "test_title": test_title,
        "auto_create_context": "true",
        "deduplication_on_engagement": "true",
        "close_old_findings": "true",
        "deduplication_execution_mode": "async_wait",
        "minimum_severity": "Info",
    }
    started = time.monotonic()
    r = spike.http(
        dojo.c, "POST", dojo.url("/api/v2/reimport-scan/"), expect=None if probe else [200, 201],
        headers=headers, data=fields, files={"file": (file_path.name, content, content_type)}, label=label,
        timeout=600, max_body=2500,
    )
    return r, time.monotonic() - started


def active_params(extra: Dict[str, Any]) -> Dict[str, Any]:
    q = dict(ACTIVE_FILTER)
    q.update(extra)
    return q


def body(spike: Spike) -> int:
    base = env("DD_URL", "http://127.0.0.1:8080") or ""
    admin_user = env("DD_ADMIN_USER", "admin") or "admin"
    admin_pw = env("DD_ADMIN_PASSWORD", required=True) or ""
    reports_dir = Path(env("S1_REPORTS_DIR", str(spikelib.DEFAULT_REPORTS_DIR)) or "")
    product = env("S1_PRODUCT", "spike-app") or "spike-app"
    engagement = env("S1_ENGAGEMENT", "main") or "main"
    wait_s = float(env("S1_WAIT_SECONDS", "900") or "900")
    require_all = (env("S1_REQUIRE_ALL", "0") or "0") == "1"
    store = spikelib.SecretStore(HERE / ".data" / "accounts.json")
    client = spikelib.make_http_client(timeout=120.0)
    dojo = Dojo(spike, client, base)
    spike.fact("defectdojo_url", base)
    soft_problems = []  # type: List[str]

    # ---- wait for DefectDojo -----------------------------------------------------------
    spike.step("Wait until DefectDojo answers (the initializer must have finished)")

    def ready() -> bool:
        r = client.post(base + "/api/v2/api-token-auth/", json={"username": admin_user, "password": admin_pw})
        return bool(r.status_code == 200)

    waited = spikelib.wait_until(spike, "DefectDojo API (admin login)", ready, wait_s, interval_s=5.0)
    spike.fact("time_until_api_ready_s", "%.0f" % waited)

    # ---- step 2: admin token -------------------------------------------------------------
    spike.step("S1.2 admin token (spike only; production uses the two service accounts)")
    admin_token = dojo.get_token(admin_user, admin_pw, "POST api-token-auth as admin")
    admin_h = token_headers(admin_token)
    spike.fact("admin_token_length", len(admin_token))

    # ---- step 3: service accounts ---------------------------------------------------------
    spike.step("S1.3 service accounts securescan-sync (staff) and securescan-accounts (superuser)")
    sync_pw = ensure_user(spike, dojo, admin_h, store, "securescan-sync", is_staff=True, is_superuser=False)
    accounts_pw = ensure_user(spike, dojo, admin_h, store, "securescan-accounts", is_staff=False, is_superuser=True)
    sync_token = dojo.get_token("securescan-sync", sync_pw, "POST api-token-auth as securescan-sync")
    accounts_token = dojo.get_token("securescan-accounts", accounts_pw, "POST api-token-auth as securescan-accounts")
    sync_h = token_headers(sync_token)
    accounts_h = token_headers(accounts_token)
    spike.fact("sync_token_length", len(sync_token))
    spike.fact("accounts_token_length", len(accounts_token))
    me = spike.http(client, "GET", dojo.url("/api/v2/user_profile/"), expect=[200], headers=sync_h,
                    label="GET user_profile as securescan-sync (is_staff / is_superuser flags)")
    flags = me.json().get("user", {})
    spike.expect(flags.get("is_staff") is True and flags.get("is_superuser") is False,
                 "securescan-sync is staff and not superuser")
    me2 = spike.http(client, "GET", dojo.url("/api/v2/user_profile/"), expect=[200], headers=accounts_h,
                     label="GET user_profile as securescan-accounts")
    spike.expect(me2.json().get("user", {}).get("is_superuser") is True, "securescan-accounts is superuser")

    # ---- step 3b: privilege checks ----------------------------------------------------------
    spike.step("S1.3 privilege checks: staff token must NOT create users; superuser token can")
    probe_user = {
        "username": "spike-denied-user", "password": spikelib.random_password(24),
        "email": "spike-denied@securescan.invalid", "is_active": True, "is_staff": False, "is_superuser": False,
    }
    r = spike.http(client, "POST", dojo.url("/api/v2/users/"), expect=[401, 403], headers=sync_h,
                   json_body=probe_user, label="POST /users/ with the SYNC token (must be refused)")
    spike.fact("sync_token_create_user_status", r.status_code)
    stale = dojo.find_user(admin_h, "spike-staff-check")
    if stale is not None:
        spike.http(client, "DELETE", dojo.url("/api/v2/users/%d/" % stale["id"]), expect=[204], headers=admin_h,
                   label="remove leftover spike-staff-check from an earlier run")
    r = spike.http(
        client, "POST", dojo.url("/api/v2/users/"), expect=[201], headers=accounts_h,
        label="POST /users/ with the ACCOUNTS token: create a staff user (must work)",
        json_body={"username": "spike-staff-check", "password": spikelib.random_password(24),
                   "email": "spike-staff-check@securescan.invalid", "first_name": "Spike", "last_name": "Staff",
                   "is_active": True, "is_staff": True, "is_superuser": False},
    )
    spike.fact("accounts_token_create_staff_user_status", r.status_code)
    new_id = r.json()["id"]
    spike.http(client, "DELETE", dojo.url("/api/v2/users/%d/" % new_id), expect=[204], headers=accounts_h,
               label="DELETE the staff user again with the ACCOUNTS token (cleanup, shows delete works)")
    spike.fact("accounts_token_delete_staff_user_status", 204)

    # ---- step 4: deduplication -----------------------------------------------------------------
    spike.step("S1.4 system settings: enable deduplication (off by default)")
    r = spike.http(client, "GET", dojo.url("/api/v2/system_settings/"), expect=None, headers=sync_h,
                   label="probe: GET system_settings with the SYNC token (source says superuser-only)")
    spike.fact("sync_token_system_settings_get_status", r.status_code)
    r = spike.http(client, "GET", dojo.url("/api/v2/system_settings/"), expect=[200], headers=accounts_h,
                   label="GET system_settings with the ACCOUNTS token", max_body=1200)
    results = r.json().get("results", [])
    spike.expect(len(results) >= 1, "system_settings returned a row")
    settings_id = results[0]["id"]
    spike.fact("system_settings_id", settings_id)
    spike.fact("enable_deduplication_before", results[0].get("enable_deduplication"))
    r = spike.http(client, "PATCH", dojo.url("/api/v2/system_settings/%d/" % settings_id), expect=[200],
                   headers=accounts_h, json_body={"enable_deduplication": True},
                   label="PATCH system_settings enable_deduplication=true (ACCOUNTS token)", max_body=800)
    spike.expect(r.json().get("enable_deduplication") is True, "enable_deduplication is now true")
    r = spike.http(client, "PATCH", dojo.url("/api/v2/system_settings/%d/" % settings_id), expect=None,
                   headers=sync_h, json_body={"enable_deduplication": True},
                   label="probe: PATCH system_settings with the SYNC token", max_body=400)
    spike.fact("sync_token_system_settings_patch_status", r.status_code)
    spike.note("Design impact if the sync probe was refused: dojo-init must use the accounts (superuser) token for "
               "system settings; the plan says dojo-init uses the sync token for everything.")

    # ---- step 5: product types ---------------------------------------------------------------------
    spike.step("S1.5 product types Internal Applications and Vendor Applications (GET first, create if missing)")
    for name in ("Internal Applications", "Vendor Applications"):
        r = spike.http(client, "GET", dojo.url("/api/v2/product_types/"), expect=[200], headers=sync_h,
                       params={"name": name, "limit": 100}, label="GET product_types name=%s (SYNC token)" % name,
                       max_body=800)
        found = [x for x in r.json().get("results", []) if x.get("name") == name]
        if found:
            spike.fact("product_type_%s" % name.split()[0].lower(), "existed, id %s" % found[0]["id"])
            continue
        r = spike.http(client, "POST", dojo.url("/api/v2/product_types/"), expect=[201], headers=sync_h,
                       json_body={"name": name, "description": "SecureScan " + name},
                       label="POST product_types %s (SYNC token, staff must be enough)" % name, max_body=800)
        spike.fact("product_type_%s" % name.split()[0].lower(), "created, id %s" % r.json()["id"])

    # ---- step 6: reimport -----------------------------------------------------------------------------
    spike.step("S1.6 reimport-scan semgrep.json twice, then with one finding removed, then the original again")
    semgrep_path = reports_dir / "semgrep.json"
    if not semgrep_path.exists():
        spike.fail("%s does not exist. Run S7 first (spikes/s7/run_all.sh) to produce the fixture reports." % semgrep_path)
    original = semgrep_path.read_bytes()
    parsed = json.loads(original.decode("utf-8"))
    results_list = parsed.get("results")
    spike.expect(isinstance(results_list, list) and len(results_list) >= 2,
                 "semgrep.json has at least 2 results (it has %s)" % (len(results_list) if isinstance(results_list, list) else "none"))
    spike.fact("semgrep_fixture_results", len(results_list))

    r1, t1 = reimport(spike, dojo, sync_h, semgrep_path, "Semgrep JSON Report", "semgrep:" + engagement, product,
                      engagement, "application/json", "FIRST reimport (creates Product Type/Asset/Engagement/Test)")
    j1 = r1.json()
    test_id = j1["test_id"]
    spike.fact("import1_http_status", r1.status_code)
    spike.fact("import1_seconds", "%.1f" % t1)
    spike.fact("import1_test_id", test_id)
    spike.fact("import1_engagement_id", j1.get("engagement_id"))
    spike.fact("import1_product_id", j1.get("product_id"))
    spike.fact("import1_product_type_id", j1.get("product_type_id"))
    spike.fact("import1_statistics_after", j1.get("statistics", {}).get("after"))
    spike.fact("import1_statistics_delta", j1.get("statistics", {}).get("delta"))
    spike.fact("import1_deduplication_complete", j1.get("deduplication_complete"))
    product_id = j1.get("product_id")
    active_params_test = active_params({"test": test_id})
    count_after_first = dojo.count(sync_h, active_params_test)
    spike.fact("active_findings_after_first_import", count_after_first)
    spike.expect(count_after_first > 0, "the first import produced active findings (%d)" % count_after_first)

    r2, t2 = reimport(spike, dojo, sync_h, semgrep_path, "Semgrep JSON Report", "semgrep:" + engagement, product,
                      engagement, "application/json", "SECOND reimport of the identical file (must not add findings)")
    j2 = r2.json()
    spike.fact("import2_seconds", "%.1f" % t2)
    spike.fact("import2_same_test_id", j2.get("test_id") == test_id)
    spike.fact("import2_statistics_delta", j2.get("statistics", {}).get("delta"))
    spike.fact("import2_deduplication_complete", j2.get("deduplication_complete"))
    count_after_second = dojo.count(sync_h, active_params_test)
    spike.expect(j2.get("test_id") == test_id, "second import reused the same Test")
    spike.expect(count_after_second == count_after_first,
                 "active count unchanged after re-importing the same file (%d -> %d)" % (count_after_first, count_after_second))

    modified = json.loads(original.decode("utf-8"))
    removed = modified["results"].pop()
    spike.fact("removed_finding", "%s %s:%s" % (removed.get("check_id"), removed.get("path"),
                                                (removed.get("start") or {}).get("line")))
    mitigated_before = dojo.count(sync_h, {"test": test_id, "is_mitigated": "true"})
    r3, t3 = reimport(spike, dojo, sync_h, semgrep_path, "Semgrep JSON Report", "semgrep:" + engagement, product,
                      engagement, "application/json", "THIRD reimport with one finding removed (must be closed)",
                      file_bytes=json.dumps(modified).encode("utf-8"))
    j3 = r3.json()
    spike.fact("import3_statistics_delta", j3.get("statistics", {}).get("delta"))
    spike.fact("import3_deduplication_complete", j3.get("deduplication_complete"))
    count_after_third = dojo.count(sync_h, active_params_test)
    mitigated_after = dojo.count(sync_h, {"test": test_id, "is_mitigated": "true"})
    spike.fact("active_after_removal", count_after_third)
    spike.fact("mitigated_after_removal", mitigated_after)
    spike.expect(mitigated_after > mitigated_before,
                 "the removed finding is now is_mitigated (%d -> %d)" % (mitigated_before, mitigated_after))
    spike.expect(count_after_third < count_after_second,
                 "active count dropped (%d -> %d)" % (count_after_second, count_after_third))

    r4, t4 = reimport(spike, dojo, sync_h, semgrep_path, "Semgrep JSON Report", "semgrep:" + engagement, product,
                      engagement, "application/json", "FOURTH reimport of the original (the removed finding returns)")
    count_after_fourth = dojo.count(sync_h, active_params_test)
    spike.fact("import4_statistics_delta", r4.json().get("statistics", {}).get("delta"))
    spike.fact("active_after_reappearance", count_after_fourth)
    spike.expect(count_after_fourth == count_after_first,
                 "the finding was reopened: active count back to %d (is %d)" % (count_after_first, count_after_fourth))

    # ---- step 7: findings API ---------------------------------------------------------------------------------
    spike.step("S1.7 findings API: fields, id filters, paging")
    r = spike.http(
        client, "GET", dojo.url("/api/v2/findings/"), expect=[200], headers=sync_h,
        params=active_params({"test": test_id, "limit": 200}), label="GET findings for the test (plan query)",
        max_body=1500,
    )
    payload = r.json()
    items = payload.get("results", [])
    spike.fact("findings_count_for_test", payload.get("count"))
    spike.expect(len(items) > 0, "findings returned")
    first = items[0]
    spike.out("First finding, all fields (long values shortened):")
    short = {k: (v[:160] + "..." if isinstance(v, str) and len(v) > 160 else v) for k, v in first.items()}
    spike.block(json.dumps(spikelib.redact_json(short), indent=2, default=str), "json")
    present = sorted(k for k in WANTED_FINDING_FIELDS if k in first)
    missing = sorted(k for k in WANTED_FINDING_FIELDS if k not in first)
    spike.fact("finding_fields_present", ", ".join(present))
    spike.fact("finding_fields_missing", ", ".join(missing) or "none")
    spike.fact("finding_all_keys", ", ".join(sorted(first.keys())))
    spike.fact("finding_vulnerability_ids_shape", type(first.get("vulnerability_ids")).__name__ + " " +
               json.dumps(first.get("vulnerability_ids"))[:120])
    spike.fact("finding_hash_code_example", first.get("hash_code"))
    spike.fact("findings_total_matches_count", len(items) == min(200, payload.get("count", 0)))

    ids = [x["id"] for x in items[:3]]
    if len(ids) == 3 and payload.get("count", 0) > 3:
        for param in ("id", "id__in"):
            rr = spike.http(client, "GET", dojo.url("/api/v2/findings/"), expect=None, headers=sync_h,
                            params={param: ",".join(str(i) for i in ids), "limit": 50},
                            label="probe filter ?%s=<3 ids> (supported if exactly those 3 come back)" % param,
                            max_body=300, show_body=False)
            ok = False
            if rr.status_code == 200:
                got = sorted(x["id"] for x in rr.json().get("results", []))
                ok = got == sorted(ids)
            spike.fact("filter_%s_supported" % param, ok)
    else:
        spike.warn("fewer than 4 findings: the id / id__in filter probe was skipped")

    if product_id is not None:
        offset = 0
        pages = 0
        started = time.monotonic()
        total_seen = 0
        while True:
            rr = client.get(dojo.url("/api/v2/findings/"), headers=sync_h,
                            params=active_params({"test__engagement__product": product_id, "limit": 200, "offset": offset}))
            if rr.status_code != 200:
                spike.fail("per-product paging failed: HTTP %d" % rr.status_code)
            data = rr.json()
            pages += 1
            total_seen += len(data.get("results", []))
            if not data.get("next"):
                break
            offset += 200
        spike.fact("per_product_paging", "%d findings in %d page(s) of 200, %.1f s" % (total_seen, pages, time.monotonic() - started))

    tr = spike.http(client, "GET", dojo.url("/api/v2/tests/%d/" % test_id), expect=[200], headers=sync_h,
                    label="GET the Test (deduplication_algorithm and hash_code_fields)", max_body=1800)
    spike.fact("semgrep_test_deduplication_algorithm", tr.json().get("deduplication_algorithm"))
    spike.fact("semgrep_test_hash_code_fields", tr.json().get("hash_code_fields"))

    # ---- step 8: other reports ------------------------------------------------------------------------------------
    spike.step("S1.8 every other fixture report with its scan type")
    test_ids = {"Semgrep JSON Report": test_id}  # type: Dict[str, int]
    rejected = []  # type: List[str]
    skipped = []  # type: List[str]
    for filename, scan_type, title, ctype in OTHER_REPORTS:
        path = reports_dir / filename
        key = filename.split(".")[0]
        if not path.exists():
            skipped.append(filename)
            spike.fact("import_%s" % key, "SKIPPED: %s missing" % filename)
            spike.warn("%s not found; produce it with S7 (or S3 for the SonarQube zip)" % filename)
            continue
        r, secs = reimport(spike, dojo, sync_h, path, scan_type, title, product, engagement, ctype,
                           "reimport %s as '%s'" % (filename, scan_type), probe=True)
        if r.status_code in (200, 201):
            data = r.json()
            tid = data.get("test_id")
            test_ids[scan_type] = tid
            n_active = dojo.count(sync_h, active_params({"test": tid}))
            n_all = dojo.count(sync_h, {"test": tid})
            spike.fact("import_%s" % key, "HTTP %d, test %s, findings total %d, active %d, %.1f s, dedup_complete=%s" % (
                r.status_code, tid, n_all, n_active, secs, data.get("deduplication_complete")))
            if n_all == 0:
                soft_problems.append("%s imported but produced zero findings" % filename)
        else:
            spike.fact("import_%s" % key, "REJECTED HTTP %d: %s" % (r.status_code, r.text[:300].replace("\n", " ")))
            rejected.append(filename)
    if skipped and require_all:
        spike.fail("missing reports with S1_REQUIRE_ALL=1: %s" % ", ".join(skipped))

    # ---- step 9: force_password_reset ----------------------------------------------------------------------------------
    spike.step("S1.9 can force_password_reset be set through the API?")
    name = "spike-reset-check"
    stale = dojo.find_user(admin_h, name)
    if stale is not None:
        spike.http(client, "DELETE", dojo.url("/api/v2/users/%d/" % stale["id"]), expect=[204], headers=admin_h,
                   label="remove leftover %s" % name)
    reset_pw = spikelib.random_password(24)
    r = spike.http(client, "POST", dojo.url("/api/v2/users/"), expect=[201], headers=accounts_h,
                   label="create %s with an (ignored?) force_password_reset field in the body" % name,
                   json_body={"username": name, "password": reset_pw, "email": name + "@securescan.invalid",
                              "is_active": True, "is_staff": True, "is_superuser": False, "force_password_reset": True})
    uid = r.json()["id"]
    spike.fact("users_endpoint_has_force_password_reset_field", "force_password_reset" in r.json())
    rr = spike.http(client, "GET", dojo.url("/api/v2/user_contact_infos/"), expect=None, headers=accounts_h,
                    params={"user": uid}, label="GET user_contact_infos for the user", max_body=800)
    infos = rr.json().get("results", []) if rr.status_code == 200 else []
    if infos:
        info_id = infos[0]["id"]
        rr = spike.http(client, "PATCH", dojo.url("/api/v2/user_contact_infos/%d/" % info_id), expect=None,
                        headers=accounts_h, json_body={"force_password_reset": True},
                        label="PATCH user_contact_infos force_password_reset=true", max_body=800)
        spike.fact("user_contact_info_row_exists_after_user_create", True)
    else:
        rr = spike.http(client, "POST", dojo.url("/api/v2/user_contact_infos/"), expect=None, headers=accounts_h,
                        json_body={"user": uid, "force_password_reset": True},
                        label="POST user_contact_infos force_password_reset=true", max_body=800)
        spike.fact("user_contact_info_row_exists_after_user_create", False)
    spike.fact("user_contact_infos_set_flag_status", rr.status_code)
    rr = spike.http(client, "POST", dojo.url("/api/v2/api-token-auth/"), expect=None,
                    json_body={"username": name, "password": reset_pw},
                    label="effect: api-token-auth for that user (source: refused while a reset is owed)", max_body=600)
    spike.fact("api_token_refused_while_reset_owed", rr.status_code in (400, 401, 403))
    spike.fact("api_token_auth_status_for_reset_user", rr.status_code)
    spike.http(client, "DELETE", dojo.url("/api/v2/users/%d/" % uid), expect=[204], headers=admin_h,
               label="cleanup: delete %s" % name)
    spike.note("If the flag works only through /user_contact_infos/ (superuser token), SecureScan sets it right "
               "after creating an Analyst/Admin user. Note: while the flag is set the user cannot obtain an API token, "
               "which is fine for people and wrong for the two service accounts (never set it for them).")

    # ---- step 10: dedup decision input ----------------------------------------------------------------------------------
    spike.step("S1.10 deduplication algorithm and hash fields of every imported Test")
    for scan_type, tid in sorted(test_ids.items()):
        rr = client.get(dojo.url("/api/v2/tests/%d/" % tid), headers=sync_h)
        if rr.status_code == 200:
            spike.fact("dedup[%s]" % scan_type, "algorithm=%s hash_code_fields=%s" % (
                rr.json().get("deduplication_algorithm"), rr.json().get("hash_code_fields")))
    spike.note("Decision input for DD_HASHCODE_FIELDS_PER_SCANNER: start with the defaults. Semgrep CE emits no "
               "fingerprint, so the hash is title + cwe + line + file_path + description and a shifted line becomes a "
               "new finding. To experiment: spikes/s1/docker-compose.dedupe.yml, then re-run this script.")

    if rejected:
        spike.warn("rejected imports: %s" % ", ".join(rejected))
    for text in soft_problems:
        spike.warn(text)
    if skipped:
        spike.warn("skipped (missing) reports: %s" % ", ".join(skipped))
    return 2 if (rejected or soft_problems) else 0


def main() -> int:
    spike = Spike("s1", "S1 DefectDojo import and deduplication", HERE)
    return spikelib.run_spike(spike, body)


if __name__ == "__main__":
    sys.exit(main())
