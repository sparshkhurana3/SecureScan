from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from securescan.reports import snapshot as snap
from securescan.reports.sample import (
    SAMPLE_TIME,
    XSS_TITLE,
    sample_findings,
    sample_jobs,
    sample_snapshot,
)


def _finding(**values: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "tool": "semgrep",
        "severity": "medium",
        "title": "A finding",
        "cwe": None,
        "cve": None,
        "cvss": None,
        "component": None,
        "component_version": None,
        "file_path": None,
        "line": None,
        "url": None,
        "hash_code": None,
        "dd_finding_id": 1,
        "state_at_scan": "open",
        "state_now": "open",
        "flags_at_scan": {},
        "flags_now": {},
    }
    base.update(values)
    return SimpleNamespace(**base)


def _build(findings: list[Any], jobs: list[Any] | None = None, **extra: Any) -> snap.Snapshot:
    application = SimpleNamespace(name="App", type="internal", data_classification="internal")
    version = SimpleNamespace(label="main", label_kind="branch", commit_sha="abc")
    scan = SimpleNamespace(
        id="scan-1",
        kind="sast",
        mode=None,
        profile_name="code-standard",
        profile_version=1,
        verdict="pass",
        verdict_detail={},
        commit_sha=None,
        source_ref=None,
        source_digest=None,
        coverage_notes=[],
        requested_tools=[],
        started_at=SAMPLE_TIME,
        finished_at=SAMPLE_TIME,
        created_at=SAMPLE_TIME,
    )
    return snap.build_snapshot(
        kind=extra.pop("kind", "application"),
        application=application,
        version=version,
        scan=scan,
        jobs=jobs or [],
        findings=findings,
        generated_at=datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc),
        **extra,
    )


def test_counts_by_severity_exclude_triaged_findings() -> None:
    snapshot = sample_snapshot()
    counts = snapshot.summary.counts
    assert (counts.critical, counts.high, counts.medium, counts.low, counts.info) == (1, 3, 1, 1, 1)
    assert counts.total == 7
    assert snapshot.summary.triaged_out == 1
    assert [t.title for t in snapshot.triaged] == ["Weak hash algorithm MD5"]
    assert snapshot.triaged[0].state == "false_positive"


def test_findings_are_sorted_by_severity_and_numbered() -> None:
    findings = sample_snapshot().findings
    assert [f.index for f in findings] == list(range(1, 8))
    assert findings[0].severity == "critical"
    assert findings[0].title == XSS_TITLE
    ranks = [snap.SEVERITIES.index(f.severity) for f in findings]
    assert ranks == sorted(ranks)


def test_per_tool_counts_include_tools_with_no_findings() -> None:
    by_tool = {t.tool: t.counts for t in sample_snapshot().summary.by_tool}
    assert list(by_tool) == ["semgrep", "sonarqube", "gitleaks", "syft", "grype"]
    semgrep = by_tool["semgrep"]
    assert (semgrep.critical, semgrep.high, semgrep.total) == (1, 1, 3)
    assert by_tool["syft"].total == 0
    assert by_tool["grype"].total == 2


def test_owasp_breakdown_has_all_ten_categories_and_catch_all() -> None:
    rows = {r.id: r for r in sample_snapshot().summary.by_owasp}
    assert [r for r in rows][:10] == [f"A{n:02d}" for n in range(1, 11)]
    assert rows["A03"].count == 2 and rows["A03"].critical == 1 and rows["A03"].high == 1
    assert rows["A07"].count == 2  # hard-coded password (semgrep) and secret (gitleaks)
    assert rows["A06"].count == 2  # both dependency findings, whatever their CWE
    assert rows["A01"].count == 0
    assert rows["NOCWE"].count == 1
    assert "OTHER" not in rows


def test_dependency_findings_count_as_vulnerable_components_despite_their_cwe() -> None:
    snapshot = _build(
        [_finding(tool="grype", cwe=79, title="CVE in lib", component="lib", severity="high")]
    )
    assert snapshot.findings[0].owasp_id == "A06"
    assert snapshot.findings[0].top25_rank == 1  # the CWE still counts for the Top 25


def test_catalogue_tool_name_syft_grype_counts_as_a_vulnerable_component() -> None:
    snapshot = _build(
        [_finding(tool="syft-grype", cwe=79, title="CVE in lib", component="lib", severity="high")]
    )
    assert snapshot.findings[0].owasp_id == "A06"
    assert snap.tool_label("syft-grype") == "Syft and Grype"


def test_unmapped_cwe_goes_to_the_other_bucket() -> None:
    snapshot = _build([_finding(cwe=123456)])
    assert snapshot.findings[0].owasp_id == "OTHER"
    assert {r.id: r.count for r in snapshot.summary.by_owasp}["OTHER"] == 1
    assert sum(r.count for r in snapshot.summary.by_owasp) == 1


def test_cwe_top25_presence() -> None:
    summary = sample_snapshot().summary
    present = {e.cwe: e.count for e in summary.cwe_top25 if e.count}
    assert present == {79: 1, 89: 1, 502: 1, 798: 2}
    assert summary.cwe_top25_present == 4
    assert len(summary.cwe_top25) == 25


def test_delta_against_the_previous_report() -> None:
    delta = sample_snapshot().summary.delta
    assert delta is not None
    assert (delta.fixed, delta.remaining, delta.new) == (1, 1, 6)
    assert delta.fixed_findings[0].title == "Open redirect"
    assert "SQL injection in UserServlet.find" not in [f.title for f in delta.new_findings]
    findings = {f.hash_code: f for f in sample_snapshot().findings}
    assert findings["h-sqli"].vs_previous == "remaining"
    assert findings["h-xss"].vs_previous == "new"


def test_no_delta_without_a_previous_report() -> None:
    snapshot = _build([_finding(title="x")])
    assert snapshot.summary.delta is None
    assert snapshot.findings[0].vs_previous == ""


def test_finding_key_falls_back_to_a_digest_of_the_fields() -> None:
    first = _build([_finding(title="Same", file_path="a.py", cwe=79)]).findings[0]
    second = _build([_finding(title="Same", file_path="a.py", cwe=79)]).findings[0]
    other = _build([_finding(title="Same", file_path="b.py", cwe=79)]).findings[0]
    assert first.key == second.key != other.key
    assert first.key.startswith("x")
    assert _build([_finding(hash_code="abc")]).findings[0].key == "abc"


def test_secret_findings_never_carry_text() -> None:
    snapshot = sample_snapshot()
    gitleaks = next(f for f in snapshot.findings if f.tool == "gitleaks")
    assert gitleaks.description == "" and gitleaks.mitigation == ""
    assert "sk_live_THIS_MUST_NOT_APPEAR" not in snap.canonical_json(snapshot).decode()


def test_token_shapes_are_scrubbed_from_finding_text() -> None:
    token = "ghp_" + "A" * 36
    snapshot = _build([_finding(flags_now={"description": f"found {token} here"})])
    assert token not in snapshot.findings[0].description
    assert "[redacted-github-token]" in snapshot.findings[0].description


def test_long_descriptions_are_capped() -> None:
    snapshot = _build([_finding(flags_now={"description": "x" * 10000})])
    assert len(snapshot.findings[0].description) <= snap.MAX_TEXT_CHARS


def test_texts_from_defectdojo_are_used() -> None:
    row = _finding(dd_finding_id=42)
    snapshot = _build(
        [row], finding_texts={42: {"description": "From DefectDojo", "mitigation": "Fix it"}}
    )
    assert snapshot.findings[0].description == "From DefectDojo"
    assert snapshot.findings[0].mitigation == "Fix it"


def test_location_prefers_file_then_url_then_component() -> None:
    built = _build(
        [
            _finding(title="a", file_path="x/y.py", line=3),
            _finding(title="b", url="https://app.example/login"),
            _finding(title="c", component="lib", component_version="1.0"),
        ]
    ).findings
    assert {f.title: f.location for f in built} == {
        "a": "x/y.py:3",
        "b": "https://app.example/login",
        "c": "lib 1.0",
    }


def test_header_and_methodology_record_the_versions() -> None:
    header = sample_snapshot().header
    assert header.mapping_versions == {"owasp_top10": "2021", "cwe_top25": "2024"}
    assert header.report_ref == "SSR-20261007-SAMPLE1"
    assert header.review_state == "automatic"
    assert header.review_label == "Automatic, not yet reviewed"
    assert header.classification_label == "CONFIDENTIAL"
    assert header.scan_date == "2026-10-07T09:30:00Z"
    assert [t.name for t in header.tools][0] == "semgrep"
    assert header.tools[0].content_versions == {"semgrep_rules": "2026-10-03"}


def test_known_limits_are_the_five_design_statements() -> None:
    limits = sample_snapshot().known_limits
    assert len(limits) == 5
    assert limits[0].startswith("Semgrep CE traces taint only within one function")
    assert "Betterleaks" in limits[3]
    assert "no scanner output is fed to external AI services" in limits[4]


def test_code_quality_from_the_sonarqube_job() -> None:
    quality = sample_snapshot().code_quality
    assert quality.available
    assert quality.quality_gate == "ERROR" and quality.quality_gate_label == "Failed"
    assert quality.conditions[0].metric == "new_vulnerabilities"
    assert [(m.label, m.value) for m in quality.measures] == [
        ("Bugs", "3"),
        ("Vulnerabilities", "2"),
        ("Code smells", "41"),
        ("Coverage (%)", "63.5"),
    ]


def test_code_quality_is_absent_without_sonarqube() -> None:
    quality = _build([]).code_quality
    assert not quality.available
    assert "did not run" in quality.note


def test_code_quality_accepts_a_plain_status_and_a_measure_list() -> None:
    job = SimpleNamespace(
        tool="sonarqube",
        options={"quality_gate": "OK", "measures": [{"metric": "bugs", "value": "0"}]},
    )
    quality = _build([], [job]).code_quality
    assert quality.available and quality.quality_gate_label == "Passed"
    assert quality.measures[0].label == "Bugs"


def test_components_from_sbom_artifacts_and_count() -> None:
    components = sample_snapshot().components
    assert components.available and components.count == 187
    assert components.sbom_files[0].filename == "sbom.cdx.json"
    assert not _build([]).components.available


def test_components_count_from_the_syft_job_when_no_count_is_passed() -> None:
    job = SimpleNamespace(tool="syft", options={"component_count": 12})
    assert _build([], [job]).components.count == 12


def test_coverage_lists_partial_failed_and_unrun_tools() -> None:
    coverage = sample_snapshot().coverage
    status = {e.tool: e.status for e in coverage.entries}
    assert status["semgrep"] == "ran"
    assert status["grype"] == "partial"
    assert status["dependency-check"] == "skipped"
    assert not coverage.complete
    assert coverage.notes == ["Dependency-Check was not requested for this scan."]

    failed = SimpleNamespace(
        tool="gitleaks",
        state="failed",
        import_state="failed",
        partial=False,
        outcome_reason="exit code 2",
    )
    entry = _build([], [failed]).coverage.entries[0]
    assert entry.status == "failed"
    assert "exit code 2" in entry.reason and "not imported" in entry.reason


def test_complete_coverage() -> None:
    job = SimpleNamespace(tool="semgrep", state="completed", import_state="imported", partial=False)
    assert _build([], [job]).coverage.complete


def test_verdict_text_and_overall_risk() -> None:
    summary = sample_snapshot().summary
    assert summary.verdict == "fail" and summary.verdict_label == "Fail"
    assert summary.overall_risk == "Critical"
    assert "1 open Critical and 3 open High findings" in summary.verdict_explanation
    assert len(summary.top_risks) == 4
    assert summary.top_risks[0].startswith("Critical: ")
    assert _build([]).summary.overall_risk == "None identified"


def test_vendor_snapshot_has_a_review_with_conditions() -> None:
    snapshot = sample_snapshot("vendor")
    assert snapshot.vendor is not None and snapshot.vendor.name == "Example Software Ltd"
    review = snapshot.review
    assert review.state == "reviewed" and review.overridden
    assert review.proposed_verdict == "fail" and review.verdict == "conditional"
    assert snapshot.summary.verdict == "conditional"
    assert [(c.finding_hash, c.deadline) for c in review.conditions] == [
        ("h-sqli", "2026-12-01"),
        ("h-log4j", "2026-11-15"),
    ]
    assert review.conditions[0].finding_title == "SQL injection in UserServlet.find"
    assert snapshot.header.review_label == "Reviewed by an analyst"


def test_with_review_updates_verdict_and_hides_notes_in_a_vendor_copy() -> None:
    base = sample_snapshot("application")
    review = snap.ReviewInput(
        state="reviewed",
        reviewer="Ann",
        reviewed_at=SAMPLE_TIME,
        proposed_verdict="fail",
        verdict="fail",
        conditions=[{"finding_hash": "h-sqli", "deadline": "2027-01-01"}],
        internal_notes="private words",
    )
    internal = snap.with_review(base, review)
    assert internal.review.internal_notes == "private words"
    assert internal.header.review_state == "reviewed"
    copy = snap.with_review(base, review, vendor_copy=True)
    assert copy.review.internal_notes == "" and copy.vendor_copy
    assert base.review.state == "automatic"  # the original is untouched


def test_the_hash_is_stable_and_changes_with_the_content() -> None:
    first = snap.snapshot_sha256(sample_snapshot())
    assert first == snap.snapshot_sha256(sample_snapshot())
    assert len(first) == 64
    changed = sample_snapshot()
    changed.findings[0].title = "different"
    assert snap.snapshot_sha256(changed) != first


def test_snapshot_round_trips_through_json() -> None:
    snapshot = sample_snapshot("vendor")
    loaded = snap.load_snapshot(snap.canonical_json(snapshot))
    assert loaded == snapshot


def test_many_findings_keep_all_rows_and_the_detail_limit() -> None:
    rows = [
        _finding(title=f"finding {n}", dd_finding_id=n, file_path=f"f{n}.py") for n in range(50)
    ]
    snapshot = _build(rows, detail_limit=10)
    assert len(snapshot.findings) == 50 and snapshot.detail_limit == 10


def test_sample_data_is_what_the_tests_assume() -> None:
    assert len(sample_findings()) == 8
    assert len(sample_jobs()) == 5
