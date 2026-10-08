#!/usr/bin/env python3
"""Spike S8: Opengrep CLI binary on js-planted with the same local rules as Semgrep (plan M1, S8; optional outcome).

Run (repository root; needs network for the release download and, for the optional import, DefectDojo from S1):

    sh spikes/s7/prefetch.sh semgrep          # once: the rules directory used by both spikes
    uv run --project backend python spikes/s8/run.py

Environment variables (all optional)
    S8_OPENGREP_TAG     release tag (default: the latest non-prerelease release, from the GitHub API)
    S8_RULES            rules directory (default spikes/s7/.data/content/semgrep-rules, created by S7's prefetch.sh)
    S8_TARGET           directory to scan (default backend/tests/fixtures/sample-apps/js-planted)
    S8_DD_URL, S8_DD_TOKEN   when both are set, the SARIF output is imported into DefectDojo as scan type "SARIF"
                        (use the securescan-sync token from S1; product spike-app, test title opengrep:main)

What it does: downloads opengrep_manylinux_<arch> from GitHub releases and compares its SHA-256 with the digest GitHub lists
for the asset; prints --help flags relevant to the Semgrep command line of the plan; scans with --sarif-output and
--json-output; counts SARIF results and compares rule ids with the Semgrep fixture (backend/tests/fixtures/reports/semgrep.json,
when present); probes whether an official container image exists (Docker Hub, GHCR); optionally imports the SARIF into
DefectDojo. Nothing is installed system-wide: the binary stays under spikes/s8/.data/. Exit code 1 on the first unexpected result.

Decision to write into docs/spikes/s8-opengrep.md and docs/decisions.md: "deferred, fallback engine only" unless the numbers
say otherwise (design: Opengrep is the fallback engine for in-file cross-function taint, not planned for version 1).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spikelib  # noqa: E402
from spikelib import Spike, SpikeFailure, env, run_cmd  # noqa: E402

HERE = Path(__file__).resolve().parent
API = "https://api.github.com/repos/opengrep/opengrep"


def sarif_rule_ids(sarif: Dict[str, Any]) -> Set[str]:
    ids = set()  # type: Set[str]
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            if result.get("ruleId"):
                ids.add(str(result["ruleId"]))
    return ids


def last_part(rule_id: str) -> str:
    return rule_id.split(".")[-1]


def body(spike: Spike) -> int:
    client = spikelib.make_http_client(timeout=300.0)
    client.follow_redirects = True
    target = Path(env("S8_TARGET", str(spikelib.SAMPLE_APPS_DIR / "js-planted")) or "")
    rules = Path(env("S8_RULES", str(spikelib.SPIKES_DIR / "s7" / ".data" / "content" / "semgrep-rules")) or "")
    spike.expect(target.is_dir(), "scan target exists: %s" % target)
    spike.expect(rules.is_dir(), "rules directory exists: %s (run: sh spikes/s7/prefetch.sh semgrep)" % rules)
    machine = platform.machine().lower()
    asset_name = "opengrep_manylinux_aarch64" if machine in ("aarch64", "arm64") else "opengrep_manylinux_x86"
    spike.fact("host_machine", machine)

    # ---- release -------------------------------------------------------------------------------------------------
    spike.step("Find the release and download the binary")
    tag = env("S8_OPENGREP_TAG")
    if tag:
        r = spike.http(client, "GET", "%s/releases/tags/%s" % (API, tag), expect=[200], max_body=600, show_body=False)
    else:
        r = spike.http(client, "GET", API + "/releases/latest", expect=[200], max_body=600, show_body=False,
                       label="latest non-prerelease release")
    release = r.json()
    tag = release["tag_name"]
    spike.fact("release_tag", tag)
    spike.fact("release_published_at", release.get("published_at"))
    assets = {a["name"]: a for a in release.get("assets", [])}
    spike.fact("release_assets", ", ".join(sorted(assets)))
    spike.expect(asset_name in assets, "the release has %s" % asset_name)
    asset = assets[asset_name]
    work = HERE / ".data"
    work.mkdir(parents=True, exist_ok=True)
    binary = work / asset_name
    started = time.monotonic()
    data = client.get(asset["browser_download_url"]).content
    spike.fact("download_seconds", "%.1f" % (time.monotonic() - started))
    sha = hashlib.sha256(data).hexdigest()
    spike.fact("binary_size_bytes", len(data))
    spike.fact("binary_sha256", sha)
    published = str(asset.get("digest") or "")
    spike.fact("github_listed_digest", published or "none listed")
    if published:
        spike.expect(published == "sha256:" + sha, "the download matches the digest GitHub lists for the asset")
    else:
        spike.warn("GitHub lists no digest for the asset; verify the cosign signature (.sig and .cert assets) by hand")
    spike.fact("signature_assets_present", sorted(n for n in assets if n.startswith(asset_name + ".")))
    binary.write_bytes(data)
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)

    # ---- help ------------------------------------------------------------------------------------------------------
    spike.step("Version and the flags the Semgrep command line of the plan uses")
    run_cmd(spike, [str(binary), "--version"], check=False, timeout=120)
    code, help_text, _ = run_cmd(spike, [str(binary), "scan", "--help"], check=False, timeout=120, max_out=300)
    supported = {}  # type: Dict[str, bool]
    for flag in ("--config", "--metrics", "--disable-version-check", "--json-output", "--sarif-output", "--sarif",
                 "--timeout", "--timeout-threshold", "--max-memory", "--jobs", "--exclude", "--taint-intrafile", "--no-git-ignore"):
        supported[flag] = flag in help_text
    spike.fact("scan_flags_in_help", supported)

    # ---- scan ---------------------------------------------------------------------------------------------------------------
    spike.step("Scan js-planted with the same local rules, SARIF and JSON output")
    out_sarif = work / "opengrep.sarif"
    out_json = work / "opengrep.json"
    for p in (out_sarif, out_json):
        if p.exists():
            p.unlink()
    argv = [str(binary), "scan", "--config", str(rules)]
    if supported.get("--metrics"):
        argv += ["--metrics=off"]
    if supported.get("--disable-version-check"):
        argv += ["--disable-version-check"]
    argv += ["--sarif-output=%s" % out_sarif, "--json-output=%s" % out_json, str(target)]
    code, output, secs = run_cmd(spike, argv, check=False, timeout=1800, env_extra={"SEMGREP_SEND_METRICS": "off"})
    spike.fact("scan_exit_code", code)
    spike.fact("scan_seconds", "%.1f" % secs)
    spike.expect(code == 0, "opengrep exited 0 (it may exit 1 on findings only with --error)")
    spike.expect(out_sarif.exists() and out_sarif.stat().st_size > 0, "a SARIF file was written (%s)" % out_sarif)
    sarif = json.loads(out_sarif.read_text(encoding="utf-8"))
    runs = sarif.get("runs", [])
    spike.fact("sarif_version", sarif.get("version"))
    spike.fact("sarif_driver", (runs[0].get("tool", {}).get("driver", {}).get("name") if runs else None))
    spike.fact("sarif_driver_version", (runs[0].get("tool", {}).get("driver", {}).get("semanticVersion") if runs else None))
    count = sum(len(r.get("results", [])) for r in runs)
    spike.fact("sarif_results", count)
    spike.fact("sarif_has_partial_fingerprints", any("partialFingerprints" in res for r in runs for res in r.get("results", [])))
    if out_json.exists():
        native = json.loads(out_json.read_text(encoding="utf-8"))
        spike.fact("json_results", len(native.get("results", [])))
        spike.fact("json_has_fingerprint_field", any("fingerprint" in (x.get("extra") or {}) for x in native.get("results", [])))

    # ---- comparison with Semgrep ------------------------------------------------------------------------------------------------
    spike.step("Compare with the Semgrep fixture (same rules, same target)")
    semgrep_json = spikelib.DEFAULT_REPORTS_DIR / "semgrep.json"
    if semgrep_json.exists():
        sg = json.loads(semgrep_json.read_text(encoding="utf-8"))
        sg_ids = {str(x.get("check_id")) for x in sg.get("results", [])}
        og_ids = sarif_rule_ids(sarif)
        spike.fact("semgrep_fixture_results", len(sg.get("results", [])))
        spike.fact("semgrep_fixture_semgrep_version", sg.get("version"))
        common = {last_part(x) for x in sg_ids} & {last_part(x) for x in og_ids}
        spike.fact("rule_ids_in_semgrep_only", sorted({last_part(x) for x in sg_ids} - {last_part(x) for x in og_ids})[:20])
        spike.fact("rule_ids_in_opengrep_only", sorted({last_part(x) for x in og_ids} - {last_part(x) for x in sg_ids})[:20])
        spike.fact("rule_ids_in_both", len(common))
        spike.note("The fixture may have been produced from another app (S7_FIXTURE_APP_SEMGREP); compare only when it was js-planted.")
    else:
        spike.warn("backend/tests/fixtures/reports/semgrep.json not found; run S7 first to compare")

    # ---- official image -----------------------------------------------------------------------------------------------------------
    spike.step("Does an official container image exist?")
    r = spike.http(client, "GET", "https://hub.docker.com/v2/repositories/opengrep/opengrep/", expect=None, max_body=500,
                   label="Docker Hub: opengrep/opengrep", show_body=False)
    spike.fact("dockerhub_opengrep_opengrep_status", r.status_code)
    code, out, _ = run_cmd(spike, ["docker", "manifest", "inspect", "ghcr.io/opengrep/opengrep:latest"], check=False, timeout=120,
                           max_out=400)
    spike.fact("ghcr_opengrep_opengrep_manifest_exit_code", code)
    if code == 0:
        spike.warn("ghcr.io/opengrep/opengrep:latest exists: if used later, pin by digest like every other image")

    # ---- DefectDojo ------------------------------------------------------------------------------------------------------------------
    spike.step("DefectDojo's SARIF parser")
    dd_url, dd_token = env("S8_DD_URL"), env("S8_DD_TOKEN")
    if dd_url and dd_token:
        r = spike.http(
            client, "POST", dd_url.rstrip("/") + "/api/v2/reimport-scan/", expect=None,
            headers={"Authorization": "Token " + dd_token},
            data={"scan_type": "SARIF", "product_type_name": "Internal Applications", "product_name": "spike-app",
                  "engagement_name": "main", "test_title": "opengrep:main", "auto_create_context": "true",
                  "close_old_findings": "true", "deduplication_on_engagement": "true",
                  "deduplication_execution_mode": "async_wait", "minimum_severity": "Info"},
            files={"file": ("opengrep.sarif", out_sarif.read_bytes(), "application/sarif+json")},
            label="import opengrep.sarif as scan type 'SARIF'", timeout=600, max_body=1500)
        spike.fact("defectdojo_sarif_import_status", r.status_code)
        if r.status_code in (200, 201):
            spike.fact("defectdojo_sarif_statistics_after", r.json().get("statistics", {}).get("after"))
    else:
        spike.note("S8_DD_URL / S8_DD_TOKEN not set: the SARIF import into DefectDojo was not tried")
    spike.note("Decision to record: deferred, fallback engine only (design). Revisit only if in-file cross-function taint "
               "is needed and the numbers above show Opengrep matches Semgrep's rule coverage.")
    return 0


def main() -> int:
    spike = Spike("s8", "S8 Opengrep", HERE)
    return spikelib.run_spike(spike, body)


if __name__ == "__main__":
    sys.exit(main())
