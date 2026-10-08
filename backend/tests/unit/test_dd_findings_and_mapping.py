"""Finding helpers (states, counts, history values) and the SecureScan -> DefectDojo object mapping."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from securescan.db.models.enums import AppType, Severity
from securescan.integrations.defectdojo import mapping
from securescan.integrations.defectdojo.findings import (
    add_counts,
    belongs_to_scan,
    closed_by_import,
    counts_from_statistics,
    empty_counts,
    finding_cve,
    finding_cwe,
    finding_flags,
    finding_state,
    finding_url,
    history_values,
    is_open,
    parse_datetime,
    severity_counts,
    severity_of,
    state_from_flags,
)

UTC = timezone.utc


def finding(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": 1,
        "title": "SQL injection",
        "severity": "High",
        "active": True,
        "verified": False,
        "duplicate": False,
        "false_p": False,
        "out_of_scope": False,
        "is_mitigated": False,
        "risk_accepted": False,
        "cwe": 89,
        "file_path": "src/app.py",
        "line": 12,
        "hash_code": "h" * 64,
    }
    base.update(overrides)
    return base


# --- states ----------------------------------------------------------------------------------------------------


def test_state_vocabulary() -> None:
    assert finding_state(finding()) == "open"
    assert finding_state(finding(active=False, false_p=True)) == "false_positive"
    assert finding_state(finding(active=False, risk_accepted=True)) == "risk_accepted"
    assert finding_state(finding(active=False, out_of_scope=True)) == "out_of_scope"
    assert finding_state(finding(active=False, duplicate=True)) == "duplicate"
    assert finding_state(finding(active=False, is_mitigated=True)) == "mitigated"
    assert finding_state(finding(active=False)) == "closed"


def test_false_positive_beats_every_other_flag() -> None:
    flags = finding_flags(finding(false_p=True, duplicate=True, risk_accepted=True, is_mitigated=True))
    assert state_from_flags(flags) == "false_positive"


def test_open_means_active_and_not_triaged_away() -> None:
    assert is_open(finding_flags(finding()))
    for flag in ("duplicate", "false_p", "out_of_scope", "risk_accepted", "is_mitigated"):
        assert not is_open(finding_flags(finding(**{flag: True})))
    assert not is_open(finding_flags(finding(active=False)))


# --- counts -----------------------------------------------------------------------------------------------------


def test_severity_counts_count_open_findings_only() -> None:
    findings = [
        finding(id=1, severity="Critical"),
        finding(id=2, severity="High"),
        finding(id=3, severity="High", false_p=True, active=False),
        finding(id=4, severity="High", duplicate=True, active=False),
        finding(id=5, severity="Medium", risk_accepted=True),
        finding(id=6, severity="Low"),
        finding(id=7, severity="Info"),
        finding(id=8, severity="Informational"),
    ]
    counts = severity_counts(findings)
    assert counts == {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 2, "total": 5}


def test_add_counts_sums_and_recomputes_total() -> None:
    a = {"critical": 1, "high": 2, "total": 99}
    b = {"high": 1, "low": 4}
    assert add_counts(a, b) == {"critical": 1, "high": 3, "medium": 0, "low": 4, "info": 0, "total": 8}
    assert add_counts() == empty_counts()


def test_counts_from_statistics_reads_the_active_column() -> None:
    after = {
        "critical": {"active": 1, "total": 3},
        "high": {"active": 4, "total": 4},
        "total": {"active": 5, "total": 7},
    }
    assert counts_from_statistics(after) == {
        "critical": 1,
        "high": 4,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": 5,
    }


def test_unknown_severity_is_info() -> None:
    assert severity_of({"severity": "weird"}) == Severity.INFO
    assert severity_of({}) == Severity.INFO
    assert severity_of({"severity": "CRITICAL"}) == Severity.CRITICAL


# --- what belongs to a scan ---------------------------------------------------------------------------------------


def test_closed_by_import_uses_last_status_update() -> None:
    since = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
    closed_now = finding(is_mitigated=True, active=False, last_status_update="2026-10-07T12:30:00Z")
    closed_before = finding(is_mitigated=True, active=False, last_status_update="2026-10-06T08:00:00Z")
    assert closed_by_import(closed_now, since)
    assert not closed_by_import(closed_before, since)
    assert not closed_by_import(finding(), since)


def test_closed_by_import_falls_back_to_the_mitigated_day() -> None:
    since = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
    assert closed_by_import(finding(is_mitigated=True, active=False, mitigated="2026-10-07"), since)
    assert not closed_by_import(finding(is_mitigated=True, active=False, mitigated="2026-10-06"), since)
    assert not closed_by_import(finding(is_mitigated=True, active=False), since)


def test_history_holds_everything_not_mitigated_plus_what_this_import_closed() -> None:
    since = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
    assert belongs_to_scan(finding(), since)
    assert belongs_to_scan(finding(false_p=True, active=False), since)
    assert belongs_to_scan(finding(is_mitigated=True, active=False, last_status_update="2026-10-07T13:00:00Z"), since)
    assert not belongs_to_scan(
        finding(is_mitigated=True, active=False, last_status_update="2026-09-01T00:00:00Z"), since
    )


def test_parse_datetime_shapes() -> None:
    assert parse_datetime("2026-10-07T12:30:00Z") == datetime(2026, 10, 7, 12, 30, tzinfo=UTC)
    assert parse_datetime("2026-10-07") == datetime(2026, 10, 7, tzinfo=UTC)
    assert parse_datetime("2026-10-07T12:30:00+02:00") == datetime(2026, 10, 7, 10, 30, tzinfo=UTC)
    assert parse_datetime(None) is None
    assert parse_datetime("") is None
    assert parse_datetime("not a date") is None


# --- field extraction ------------------------------------------------------------------------------------------------


def test_cwe_zero_means_none_and_cwes_list_is_used() -> None:
    assert finding_cwe(finding(cwe=0)) is None
    assert finding_cwe(finding(cwe=None, cwes=[79, 80])) == 79
    assert finding_cwe(finding(cwe="22")) == 22
    assert finding_cwe({}) is None


def test_cve_prefers_a_cve_id() -> None:
    assert finding_cve({"vulnerability_ids": [{"vulnerability_id": "GHSA-1"}, {"vulnerability_id": "CVE-2021-44228"}]}) == "CVE-2021-44228"
    assert finding_cve({"vulnerability_ids": ["CVE-2020-1"]}) == "CVE-2020-1"
    assert finding_cve({"vulnerability_ids": [], "cve": "CVE-2019-9"}) == "CVE-2019-9"
    assert finding_cve({"vulnerability_ids": [{"vulnerability_id": "GHSA-x"}]}) == "GHSA-x"
    assert finding_cve({}) is None


def test_url_from_the_shapes_defectdojo_3_may_send() -> None:
    assert finding_url({"url": "https://a.example/x"}) == "https://a.example/x"
    assert finding_url({"locations": ["https://b.example/"]}) == "https://b.example/"
    assert finding_url({"endpoints": [{"host": "c.example"}]}) == "c.example"
    assert finding_url({"locations": []}) is None


def test_history_values_carry_state_and_flags() -> None:
    values = history_values(
        finding(
            id=77,
            title="Hard-coded secret",
            severity="Critical",
            cwe=798,
            component_name="requests",
            component_version="2.0",
            vulnerability_ids=[{"vulnerability_id": "CVE-2024-1"}],
            cvssv3_score=9.8,
            line=0,
        )
    )
    assert values["dd_finding_id"] == 77
    assert values["severity"] == Severity.CRITICAL
    assert values["cwe"] == 798
    assert values["cve"] == "CVE-2024-1"
    assert values["cvss"] == 9.8
    assert values["component"] == "requests"
    assert values["line"] is None
    assert values["state_at_scan"] == values["state_now"] == "open"
    assert values["flags_at_scan"] == values["flags_now"]
    assert values["flags_at_scan"]["active"] is True


# --- mapping ------------------------------------------------------------------------------------------------------------------


def test_product_type_by_application_type() -> None:
    assert mapping.product_type_for(AppType.INTERNAL) == "Internal Applications"
    assert mapping.product_type_for(AppType.VENDOR) == "Vendor Applications"
    assert mapping.PRODUCT_TYPES == ("Internal Applications", "Vendor Applications")


def test_import_names() -> None:
    names = mapping.import_names(AppType.VENDOR, "Acme CRM", "v2.1", "semgrep")
    assert names.product_type == "Vendor Applications"
    assert names.product == "Acme CRM"
    assert names.engagement == "v2.1"
    assert names.test_title == "semgrep:v2.1"


def test_branch_or_tag_only_for_branches_and_tags() -> None:
    assert mapping.branch_or_tag("main", "branch") == "main"
    assert mapping.branch_or_tag("v1", "tag") == "v1"
    assert mapping.branch_or_tag("upload-1", "upload") is None
    assert mapping.branch_or_tag("sha256:abc", "image_digest") is None


def test_content_types_and_links() -> None:
    assert mapping.content_type_for("semgrep.json") == "application/json"
    assert mapping.content_type_for("dc.xml") == "application/xml"
    assert mapping.content_type_for("sonar.zip") == "application/zip"
    assert mapping.content_type_for("x.bin") == "application/octet-stream"
    assert mapping.link_to_test(12) == "https://dojo.securescan.localtest.me:8443/test/12"
    assert mapping.link_to_test(None) is None
    assert mapping.engagement_link(3) == "https://dojo.securescan.localtest.me:8443/engagement/3"
    assert mapping.product_link(4) == "https://dojo.securescan.localtest.me:8443/product/4"
