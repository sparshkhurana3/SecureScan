#!/usr/bin/env python3
"""Seed a TEST database with synthetic history and time the queries the portal runs on it.

Plan M11 task 9: 300 applications and five years of history, loaded with bulk COPY, then the history
queries and the CSV export are timed against the design's target (95 percent of page loads under
2 seconds with 300 applications and five years of history).

NEVER run this against a production database: history is permanent by design and the cleanup below
deletes rows (the application refuses to delete history, this script does it for its own synthetic rows
only). Everything it creates is named ``SYN-...`` and tagged ``synthetic``. It refuses to run unless you
pass ``--i-know-this-is-a-test-database``.

Examples (the database is reachable only on the Compose network; docs/runbooks/performance.md has the
full ``docker run`` command)::

    python scripts/seed_history.py --host db --dbname securescan --user securescan \
        --password-file /run/secrets/pw --sslrootcert /run/secrets/ca --i-know-this-is-a-test-database
    python scripts/seed_history.py ... --apps 30 --scans-per-app-year 6   # a quick smoke run
    python scripts/seed_history.py ... --benchmark-only                   # time the queries on what is there
    python scripts/seed_history.py ... --clean                            # delete the synthetic rows again

Needs psycopg 3 (the backend image has it). The generator is deterministic for one ``--seed``.
Written without being run (no database on the writing machine): see docs/build-notes/M11.md.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import random
import statistics
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

UTC = timezone.utc
NULL = r"\N"
PREFIX = "SYN-"
TOOLS = ("semgrep", "gitleaks", "syft-grype", "dependency-check")
FLAG_KEYS = ("active", "duplicate", "false_p", "out_of_scope", "is_mitigated", "risk_accepted", "under_review")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHTS = (2, 10, 35, 40, 13)
CRITICALITY = ("low", "medium", "high", "critical")
CLASSIFICATION = ("public", "internal", "confidential", "restricted")
TRIGGERS = ("user", "change", "weekly", "schedule")
TRIGGER_WEIGHTS = (20, 45, 30, 5)

SEMGREP_TITLES = [
    "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
    "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
    "java.lang.security.audit.sqli.tainted-sql-string.tainted-sql-string",
    "javascript.express.security.audit.xss.direct-response-write.direct-response-write",
    "javascript.lang.security.audit.eval-detected.eval-detected",
    "csharp.lang.security.sqli.csharp-sqli.csharp-sqli",
    "generic.secrets.security.detected-generic-secret.detected-generic-secret",
    "python.lang.security.deserialization.pickle.avoid-pickle",
    "java.lang.security.audit.crypto.use-of-md5.use-of-md5",
    "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal",
]
GITLEAKS_TITLES = ["generic-api-key", "aws-access-token", "private-key", "github-pat", "slack-webhook-url"]
COMPONENTS = [
    ("log4j-core", "2.14.1"), ("flask", "0.12"), ("jackson-databind", "2.9.8"), ("lodash", "4.17.15"),
    ("spring-core", "5.2.0"), ("django", "2.2.1"), ("openssl", "1.1.1k"), ("requests", "2.19.0"),
    ("express", "4.16.0"), ("newtonsoft.json", "9.0.1"), ("commons-text", "1.9"), ("guava", "24.1"),
]  # fmt: skip
PATH_PARTS = ("src", "app", "lib", "services", "web", "api", "util", "db", "auth", "handlers")
FILE_NAMES = ("UserController.java", "views.py", "server.js", "Program.cs", "routes.ts", "query.py", "Auth.java")


# ================================================================================ generation


@dataclass
class Plan:
    apps: int
    years: float
    scans_per_app_year: float
    findings_per_scan: float
    seed: int
    now: datetime


class Writers:
    """One temporary CSV file per table; rows are streamed to disk so a million rows never sit in memory."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.files: dict[str, Any] = {}
        self.writers: dict[str, Any] = {}
        self.counts: dict[str, int] = {}

    def open(self, table: str) -> None:
        handle = (self.directory / (table + ".csv")).open("w", newline="", encoding="utf-8")
        self.files[table] = handle
        self.writers[table] = csv.writer(handle, quoting=csv.QUOTE_MINIMAL)
        self.counts[table] = 0

    def row(self, table: str, values: list[Any]) -> None:
        self.writers[table].writerow([cell(v) for v in values])
        self.counts[table] += 1

    def close(self) -> None:
        for handle in self.files.values():
            handle.close()


def cell(value: Any) -> str:
    if value is None:
        return NULL
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def rid(rng: random.Random) -> uuid.UUID:
    """A random UUID from the seeded generator (the seed makes a run repeatable)."""
    return uuid.UUID(int=rng.getrandbits(128), version=4)


def verdict_for(counts: dict[str, int]) -> str:
    if counts["critical"] >= 1 or counts["high"] >= 5:
        return "fail"
    if counts["high"] >= 1 or counts["medium"] >= 10:
        return "conditional"
    return "pass"


def make_finding(rng: random.Random, tool: str, app_no: int, finding_id: int) -> dict[str, Any]:
    severity = rng.choices(SEVERITIES, SEVERITY_WEIGHTS)[0]
    path = "/".join([rng.choice(PATH_PARTS), rng.choice(PATH_PARTS), rng.choice(FILE_NAMES)])
    finding: dict[str, Any] = {
        "dd_finding_id": finding_id, "severity": severity, "cwe": None, "cve": None, "cvss": None,
        "component": None, "component_version": None, "file_path": None, "line": None,
        "title": "", "tool": tool,
    }  # fmt: skip
    if tool == "semgrep":
        finding.update(title=rng.choice(SEMGREP_TITLES), cwe=rng.choice((79, 89, 78, 502, 327, 22, 798)),
                       file_path=path, line=rng.randint(1, 900))  # fmt: skip
    elif tool == "gitleaks":
        finding.update(title=rng.choice(GITLEAKS_TITLES), cwe=798, file_path=path, line=rng.randint(1, 400), severity=rng.choice(("high", "high", "medium")))  # fmt: skip
    else:
        name, version = rng.choice(COMPONENTS)
        cve = "CVE-%d-%d" % (rng.randint(2016, 2026), rng.randint(1000, 49999))
        finding.update(title="%s in %s:%s" % (cve, name, version), cve=cve, cvss=round(rng.uniform(2.0, 9.9), 1),
                       component=name, component_version=version, cwe=rng.choice((None, 79, 400, 502, 1104)))  # fmt: skip
    finding["hash_code"] = hashlib.sha1(  # noqa: S324 - a stand-in for DefectDojo's hash, not a security use
        ("%d|%s|%s|%s" % (app_no, tool, finding["title"], finding["file_path"] or finding["component"])).encode()
    ).hexdigest()
    return finding


def flags_json(state: str) -> dict[str, bool]:
    flags = {key: False for key in FLAG_KEYS}
    if state == "open":
        flags["active"] = True
    elif state == "mitigated":
        flags["is_mitigated"] = True
    elif state == "false_positive":
        flags["false_p"] = True
    elif state == "risk_accepted":
        flags["risk_accepted"] = True
    return flags


def generate(plan: Plan, out: Writers) -> dict[str, int]:
    rng = random.Random(plan.seed)
    start_of_history = plan.now - timedelta(days=int(365.25 * plan.years))
    for table in ("vendors", "applications", "application_versions", "scans", "scan_jobs", "finding_history"):
        out.open(table)
    vendors: list[uuid.UUID] = []
    for number in range(max(3, plan.apps // 15)):
        vendor_id = rid(rng)
        vendors.append(vendor_id)
        out.row("vendors", [vendor_id, "%sVendor %03d" % (PREFIX, number + 1), "Contact %d" % number,
                            "contact%d@vendor.example" % number, rng.choice(("low", "medium", "high")),
                            None, None, None, start_of_history, start_of_history])  # fmt: skip
    finding_counter = 1_000_000
    test_counter = 5_000
    totals = {"scans": 0, "jobs": 0, "findings": 0}
    app_rows: list[list[Any]] = []
    for number in range(1, plan.apps + 1):
        app_id = rid(rng)
        is_vendor = rng.random() < 0.3
        vendor_id = rng.choice(vendors) if is_vendor else None
        created = start_of_history + timedelta(days=rng.uniform(0, 365.25 * plan.years * 0.4))
        versions = [(rid(rng), "main" if v == 0 else "release-%d" % v) for v in range(rng.choice((1, 1, 2, 3)))]
        for version_id, label in versions:
            out.row("application_versions", [version_id, app_id, label, "branch", None, None, None, None, None,
                                             None, created, created])  # fmt: skip
        mean_scans = max(1.0, rng.gauss(plan.scans_per_app_year, plan.scans_per_app_year * 0.5))
        scan_count = max(1, int(mean_scans * (plan.now - created).days / 365.25))
        times = sorted(created + (plan.now - created) * rng.random() for _ in range(scan_count))
        live: list[dict[str, Any]] = [
            make_finding(rng, rng.choice(TOOLS), number, finding_counter + i)
            for i in range(max(0, int(rng.gauss(plan.findings_per_scan, plan.findings_per_scan * 0.4))))
        ]
        finding_counter += len(live) + 1
        last_counts = {s: 0 for s in SEVERITIES}
        last_scan = (None, None, None)
        test_ids = {tool: test_counter + index for index, tool in enumerate(TOOLS)}
        test_counter += len(TOOLS)
        for when in times:
            # the live set drifts: most findings stay, a few are fixed, a few appear
            live = [f for f in live if rng.random() < 0.97]
            for _ in range(max(0, int(rng.gauss(plan.findings_per_scan * 0.06, 1.5)))):
                live.append(make_finding(rng, rng.choice(TOOLS), number, finding_counter))
                finding_counter += 1
            version_id = rng.choice(versions)[0]
            scan_id = rid(rng)
            counts = {s: 0 for s in SEVERITIES}
            for f in live:
                counts[f["severity"]] += 1
            counts_json = dict(counts, total=sum(counts.values()))
            verdict = verdict_for(counts)
            finished = when + timedelta(minutes=rng.randint(3, 40))
            tools_here = [t for t in TOOLS if t != "dependency-check" or rng.random() < 0.8]
            out.row("scans", [scan_id, app_id, version_id, None, None, "code-standard", 1, "sast", None,
                              rng.choices(TRIGGERS, TRIGGER_WEIGHTS)[0], None, "completed", verdict, {}, None, None,
                              None, tools_here, {}, None, None, None, counts_json, [], None, when, when, finished,
                              None, None, finished])  # fmt: skip
            totals["scans"] += 1
            for tool in tools_here:
                job_id = rid(rng)
                mine = [f for f in live if f["tool"] == tool]
                job_counts = {s: sum(1 for f in mine if f["severity"] == s) for s in SEVERITIES}
                out.row("scan_jobs", [job_id, scan_id, tool, "completed", "imported", 1, None, None, None, None,
                                      "synthetic/%s" % tool, "sha256:" + hashlib.sha256(tool.encode()).hexdigest(),
                                      None, {}, 0, None, False, dict(job_counts, total=len(mine)),
                                      test_ids[tool], finished, {}, None, [], None, {}, when, when, finished, finished])  # fmt: skip
                totals["jobs"] += 1
                for f in mine:
                    state = rng.choices(("open", "mitigated", "false_positive", "risk_accepted"), (70, 20, 5, 5))[0]
                    out.row("finding_history", [
                        rid(rng), scan_id, job_id, app_id, version_id, vendor_id, None,
                        "zip" if rng.random() < 0.3 else "github_repo", tool, f["dd_finding_id"], f["hash_code"],
                        test_ids[tool], f["severity"], f["title"], f["cwe"], f["cve"], f["cvss"], f["component"],
                        f["component_version"], f["file_path"], f["line"], None, "open", flags_json("open"), state,
                        flags_json(state), finished, finished, finished])  # fmt: skip
                    totals["findings"] += 1
            last_counts, last_scan = counts, (scan_id, finished, verdict)
        app_rows.append([app_id, "%s%s%04d" % (PREFIX, "vendor-" if is_vendor else "app-", number),
                         "vendor" if is_vendor else "internal", vendor_id,
                         ("Synthetic product %d" % number) if is_vendor else None,
                         rng.choice(("deployable", "saas")) if is_vendor else None,
                         "Synthetic application for the performance test", rng.choice(CRITICALITY),
                         rng.choice(CLASSIFICATION), ["synthetic"], True, False, None, None, None, None, None,
                         dict(last_counts, total=sum(last_counts.values())), last_scan[1], last_scan[1], last_scan[0],
                         last_scan[2], None, None, created, last_scan[1] or created])  # fmt: skip
    for row in app_rows:
        out.row("applications", row)
    totals["applications"] = len(app_rows)
    out.close()
    return totals


# Column lists in the order generate() writes them. (applications is written last but loaded before the rest.)
COLUMNS = {
    "vendors": "id, name, contact_name, contact_email, risk_tier, notes, archived_at, created_by_id, created_at, updated_at",
    "applications": (
        "id, name, type, vendor_id, vendor_product, hosting, description, criticality, data_classification, tags, "
        "confirmed, automatic, github_repo_id, github_full_name, default_branch, github_removed_at, dd_product_id, "
        "cached_counts, cached_counts_at, last_scan_at, last_scan_id, last_verdict, archived_at, created_by_id, "
        "created_at, updated_at"
    ),
    "application_versions": (
        "id, application_id, label, label_kind, description, commit_sha, dd_engagement_id, sonar_project_key, "
        "archived_at, created_by_id, created_at, updated_at"
    ),
    "scans": (
        "id, application_id, version_id, target_id, profile_id, profile_name, profile_version, kind, mode, trigger, "
        "trigger_detail, state, verdict, verdict_detail, policy_id, started_by_id, idempotency_key, requested_tools, "
        "options, commit_sha, source_ref, source_digest, counts, coverage_notes, error, created_at, started_at, "
        "finished_at, cancel_requested_at, cancelled_by_id, updated_at"
    ),
    "scan_jobs": (
        "id, scan_id, tool, state, import_state, attempts, procrastinate_job_id, container_id, worker_name, "
        "heartbeat_at, image, image_digest, tool_version, content_versions, exit_code, outcome_reason, partial, "
        "counts, dd_test_id, dd_imported_at, dd_import_stats, log_path, applied_exclusions, coverage_note, options, "
        "created_at, started_at, finished_at, updated_at"
    ),
    "finding_history": (
        "id, scan_id, job_id, application_id, version_id, vendor_id, started_by_id, source_kind, tool, dd_finding_id, "
        "hash_code, dd_test_id, severity, title, cwe, cve, cvss, component, component_version, file_path, line, url, "
        "state_at_scan, flags_at_scan, state_now, flags_now, state_now_updated_at, scanned_at, created_at"
    ),
}
LOAD_ORDER = ("vendors", "applications", "application_versions", "scans", "scan_jobs", "finding_history")


def check_columns(csv_directory: Path) -> None:
    """A cheap guard: every CSV row has as many cells as the column list names (catches an edit that forgot one)."""
    for table, columns in COLUMNS.items():
        expected = len([c for c in columns.split(",") if c.strip()])
        with (csv_directory / (table + ".csv")).open(newline="", encoding="utf-8") as handle:
            first = next(csv.reader(handle), None)
        if first is not None and len(first) != expected:
            raise SystemExit("internal error: %s rows have %d cells, the column list has %d" % (table, len(first), expected))


# ================================================================================ database


def connect(args: argparse.Namespace) -> Any:
    import psycopg  # imported late: --help must work without it

    kwargs: dict[str, Any] = {"host": args.host, "port": args.port, "dbname": args.dbname, "user": args.user}
    password = args.password
    if args.password_file:
        password = Path(args.password_file).read_text(encoding="utf-8").strip()
    if password:
        kwargs["password"] = password
    if args.sslmode:
        kwargs["sslmode"] = args.sslmode
    if args.sslrootcert:
        kwargs["sslrootcert"] = args.sslrootcert
    return psycopg.connect(**kwargs)


def load(conn: Any, directory: Path, counts: dict[str, int]) -> None:
    with conn.cursor() as cur:
        cur.execute("SET synchronous_commit = off")
        cur.execute("SET maintenance_work_mem = '256MB'")
        for table in LOAD_ORDER:
            started = time.monotonic()
            with cur.copy("COPY %s (%s) FROM STDIN WITH (FORMAT csv, NULL '\\N')" % (table, COLUMNS[table])) as copy:
                with (directory / (table + ".csv")).open("rb") as handle:
                    while True:
                        chunk = handle.read(1 << 20)
                        if not chunk:
                            break
                        copy.write(chunk)
            print("  loaded %-22s %9d rows in %5.1f s" % (table, counts.get(table, 0), time.monotonic() - started))
    conn.commit()
    with conn.cursor() as cur:
        for table in LOAD_ORDER:
            cur.execute("ANALYZE %s" % table)
    conn.commit()


def existing_real_applications(conn: Any) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM applications WHERE name NOT LIKE %s", (PREFIX + "%",))
        return int(cur.fetchone()[0])


def clean(conn: Any) -> None:
    """Delete the synthetic rows (test databases only)."""
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM applications WHERE name LIKE %s", (PREFIX + "%",))
        cur.execute("CREATE TEMP TABLE syn_apps ON COMMIT DROP AS SELECT id FROM applications WHERE name LIKE %s", (PREFIX + "%",))
        cur.execute("DELETE FROM finding_history WHERE application_id IN (SELECT id FROM syn_apps)")
        print("  deleted %d finding_history rows" % cur.rowcount)
        cur.execute("DELETE FROM scan_jobs WHERE scan_id IN (SELECT id FROM scans WHERE application_id IN (SELECT id FROM syn_apps))")
        cur.execute("DELETE FROM scans WHERE application_id IN (SELECT id FROM syn_apps)")
        print("  deleted %d scans" % cur.rowcount)
        cur.execute("DELETE FROM application_versions WHERE application_id IN (SELECT id FROM syn_apps)")
        cur.execute("DELETE FROM applications WHERE id IN (SELECT id FROM syn_apps)")
        print("  deleted %d applications" % cur.rowcount)
        cur.execute("DELETE FROM vendors WHERE name LIKE %s", (PREFIX + "%",))
    conn.commit()


# ================================================================================ benchmark


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(math.ceil(fraction * len(ordered))) - 1))
    return ordered[index]


def queries(conn: Any) -> Iterator[tuple[str, str, tuple[Any, ...]]]:
    """(name, sql, params): the shapes of the portal's list, filter, count and detail queries."""
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM applications WHERE name LIKE %s ORDER BY random() LIMIT 1", (PREFIX + "%",))
        row = cur.fetchone()
        cur.execute(
            "SELECT s.id FROM scans s JOIN applications a ON a.id = s.application_id WHERE a.name LIKE %s "
            "ORDER BY random() LIMIT 1", (PREFIX + "%",),
        )  # fmt: skip
        scan = cur.fetchone()
    if row is None or scan is None:
        return
    app_id, scan_id = row[0], scan[0]
    yield ("applications page (by last scan)", "SELECT id, name, type, criticality, cached_counts, last_scan_at, last_verdict FROM applications WHERE archived_at IS NULL ORDER BY last_scan_at DESC NULLS LAST, id LIMIT 50", ())  # fmt: skip
    yield ("application scans page", "SELECT id, state, verdict, counts, created_at FROM scans WHERE application_id = %s ORDER BY created_at DESC, id LIMIT 50", (app_id,))  # fmt: skip
    yield ("scan findings (Critical first)", "SELECT id, tool, severity, title, file_path, line FROM finding_history WHERE scan_id = %s AND state_now = 'open' ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, title, id LIMIT 200", (scan_id,))  # fmt: skip
    yield ("history: critical, vendor apps, this year (page)", "SELECT h.id, h.title, h.severity, h.scanned_at, a.name FROM finding_history h JOIN applications a ON a.id = h.application_id WHERE h.severity = 'critical' AND a.type = 'vendor' AND h.scanned_at >= date_trunc('year', now()) ORDER BY h.scanned_at DESC, h.id DESC LIMIT 50", ())  # fmt: skip
    yield ("history: same filter, total count", "SELECT count(*) FROM finding_history h JOIN applications a ON a.id = h.application_id WHERE h.severity = 'critical' AND a.type = 'vendor' AND h.scanned_at >= date_trunc('year', now())", ())  # fmt: skip
    yield ("history: one application, all severities (page)", "SELECT id, tool, severity, title, scanned_at FROM finding_history WHERE application_id = %s ORDER BY scanned_at DESC, id DESC LIMIT 50", (app_id,))  # fmt: skip
    yield ("history: tool and window (page)", "SELECT id, title, severity, scanned_at FROM finding_history WHERE tool = 'semgrep' AND scanned_at >= now() - interval '90 days' ORDER BY scanned_at DESC, id DESC LIMIT 50", ())  # fmt: skip
    yield ("history: scans in a window (page)", "SELECT id, application_id, state, verdict, created_at FROM scans WHERE created_at >= now() - interval '30 days' ORDER BY created_at DESC, id DESC LIMIT 50", ())  # fmt: skip
    yield ("dashboard: open counts by severity", "SELECT severity, count(*) FROM finding_history WHERE state_now = 'open' AND scanned_at >= now() - interval '7 days' GROUP BY severity", ())  # fmt: skip


def benchmark(conn: Any, repeat: int, target_seconds: float) -> int:
    failures = 0
    print("\nQuery timings (%d runs each; target: 95th percentile under %.1f s)" % (repeat, target_seconds))
    for name, sql, params in queries(conn):
        timings: list[float] = []
        for _ in range(repeat):
            started = time.perf_counter()
            with conn.cursor() as cur:
                cur.execute(sql, params)
                cur.fetchall()
            timings.append(time.perf_counter() - started)
        p95 = percentile(timings, 0.95)
        mark = "ok  " if p95 <= target_seconds else "SLOW"
        failures += p95 > target_seconds
        print("  [%s] %-52s median %7.1f ms  p95 %7.1f ms" % (mark, name, statistics.median(timings) * 1000, p95 * 1000))
    # The CSV export streams the whole filtered result: measure time to the first row and to the end.
    export = (
        "COPY (SELECT h.id, a.name, h.tool, h.severity, h.title, h.file_path, h.line, h.scanned_at FROM finding_history h "
        "JOIN applications a ON a.id = h.application_id WHERE h.scanned_at >= now() - interval '2 years' "
        "ORDER BY h.scanned_at DESC, h.id DESC) TO STDOUT WITH (FORMAT csv, HEADER)"
    )
    started = time.perf_counter()
    first = None
    rows = 0
    size = 0
    with conn.cursor() as cur:
        with cur.copy(export) as copy:
            for chunk in copy:
                if first is None:
                    first = time.perf_counter() - started
                data = bytes(chunk)
                size += len(data)
                rows += data.count(b"\n")
    total = time.perf_counter() - started
    mark = "ok  " if (first or 0) <= target_seconds else "SLOW"
    failures += (first or 0) > target_seconds
    print("  [%s] CSV export, 2 years: first byte %.2f s, %d rows, %.1f MB in %.1f s" % (mark, first or 0, rows, size / 1e6, total))
    conn.rollback()
    return failures


# ================================================================================ command line


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=os.environ.get("PGHOST", "db"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    parser.add_argument("--dbname", default=os.environ.get("PGDATABASE", "securescan"))
    parser.add_argument("--user", default=os.environ.get("PGUSER", "securescan"))
    parser.add_argument("--password", default=os.environ.get("PGPASSWORD", ""), help="prefer --password-file")
    parser.add_argument("--password-file", help="file holding the password (a Docker secret)")
    parser.add_argument("--sslmode", default=os.environ.get("PGSSLMODE", "verify-full"))
    parser.add_argument("--sslrootcert", default=os.environ.get("PGSSLROOTCERT", ""))
    parser.add_argument("--apps", type=int, default=300, help="applications (default 300)")
    parser.add_argument("--years", type=float, default=5.0, help="years of history (default 5)")
    parser.add_argument("--scans-per-app-year", type=float, default=20.0, help="average scans per application and year (default 20)")
    parser.add_argument("--findings-per-scan", type=float, default=30.0, help="average live findings of an application (default 30)")
    parser.add_argument("--seed", type=int, default=20261007)
    parser.add_argument("--repeat", type=int, default=20, help="runs per timed query (default 20)")
    parser.add_argument("--target-seconds", type=float, default=2.0, help="the design target for a page load")
    parser.add_argument("--benchmark-only", action="store_true", help="only time the queries")
    parser.add_argument("--clean", action="store_true", help="delete the synthetic rows (SYN-...)")
    parser.add_argument("--i-know-this-is-a-test-database", action="store_true", dest="confirmed")
    parser.add_argument("--dry-run", action="store_true", help="generate the CSV files and report the row counts; no database")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.dry_run:
        plan = Plan(args.apps, args.years, args.scans_per_app_year, args.findings_per_scan, args.seed, datetime.now(UTC))
        with tempfile.TemporaryDirectory() as tmp:
            writers = Writers(Path(tmp))
            started = time.monotonic()
            totals = generate(plan, writers)
            check_columns(Path(tmp))
            print("generated in %.1f s: %s" % (time.monotonic() - started, ", ".join("%s=%d" % kv for kv in sorted({**writers.counts, **totals}.items()))))
        return 0
    if not args.confirmed:
        print("Refusing to run: this writes (or deletes) thousands of rows. Pass --i-know-this-is-a-test-database.", file=sys.stderr)
        return 2
    conn = connect(args)
    try:
        if args.clean:
            clean(conn)
            return 0
        if not args.benchmark_only:
            real = existing_real_applications(conn)
            if real:
                print("Refusing to seed: the database holds %d real application(s). Use an empty test database." % real, file=sys.stderr)
                return 2
            plan = Plan(args.apps, args.years, args.scans_per_app_year, args.findings_per_scan, args.seed, datetime.now(UTC))
            with tempfile.TemporaryDirectory() as tmp:
                writers = Writers(Path(tmp))
                print("generating %d applications, %.1f years ..." % (args.apps, args.years))
                started = time.monotonic()
                totals = generate(plan, writers)
                check_columns(Path(tmp))
                print("generated in %.1f s: %d scans, %d jobs, %d finding rows" % (time.monotonic() - started, totals["scans"], totals["jobs"], totals["findings"]))
                load(conn, Path(tmp), writers.counts)
        return 1 if benchmark(conn, args.repeat, args.target_seconds) else 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
