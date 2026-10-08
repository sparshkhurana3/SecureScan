"""Golden-outline tests: render the sample snapshot with the default template and compare its text.

A byte-for-byte golden HTML file would break on every whitespace change, so the comparison is
made on the *visible text*: the HTML is parsed, scripts and styles dropped, whitespace collapsed,
and an ordered list of expected passages is looked up in it. The passages are the report as a
reader sees it.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

import pytest

from securescan.reports import renderer
from securescan.reports.sample import XSS_PAYLOAD, sample_snapshot
from securescan.reports.snapshot import Snapshot

HASH = "0123456789abcdef" * 4


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("style", "script", "title"):
            self._skip += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("style", "script", "title") and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def visible_text(html: str) -> str:
    parser = _Text()
    parser.feed(html)
    text = " ".join(parser.parts)
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s+([.,;:)])", r"\1", text)
    return re.sub(r"\(\s+", "(", text).strip()


def render_text(snapshot: Snapshot, target: str = "html") -> str:
    html = renderer.render_html(
        renderer.DEFAULT_TEMPLATE_DIR, "template.html", snapshot, HASH, target=target
    )
    return visible_text(html)


def assert_outline(text: str, outline: list[str]) -> None:
    position = 0
    for fragment in outline:
        found = text.find(fragment, position)
        assert found >= 0, f"missing or out of order: {fragment!r}\nafter position {position}"
        position = found + len(fragment)


APPLICATION_OUTLINE = [
    "Payroll Portal",
    "Application security report - v2.4.0",
    "Policy result Fail The default policy found 1 open Critical and 3 open High findings.",
    "Automatic, not yet reviewed",
    "Report ID SSR-20261007-SAMPLE1",
    "Application Payroll Portal (criticality: high)",
    "Version v2.4.0 (release)",
    "Scan date 2026-10-07 09:30 UTC",
    "Tools Semgrep CE 1.179.0; SonarQube Community Build 26.9.0; Gitleaks 8.30.1; "
    "Syft 1.54.0; Grype 0.120.0",
    "Mappings OWASP Top 10 2021; CWE Top 25 2024",
    "Template Sample template, version 1",
    f"Report hash {HASH}",
    "Summary Overall risk rating: Critical. 7 open findings "
    "(1 more was triaged out and is not counted).",
    "Critical High Medium Low Info Total 1 3 1 1 1 7",
    "Top risks Critical: <script>alert(1)</script> injected title (web/render.js:7) "
    "High: Generic API key in config.yaml (deploy/config.yaml:3) "
    "High: CVE-2021-44228 in log4j-core 2.14.1 (log4j-core 2.14.1) "
    "High: SQL injection in UserServlet.find (src/main/java/com/example/UserServlet.java:42)",
    "Change since the previous report Compared with SSR-20260901-ABC123 "
    "(version v2.3.0, scanned 2026-09-01): 1 fixed, 1 remaining, 6 new.",
    "New findings Severity Finding Tool Location "
    "Critical <script>alert(1)</script> injected title Semgrep CE web/render.js:7",
    "Fixed findings Severity Finding Tool Location "
    "Medium Open redirect Semgrep CE web/redirect.js:9",
    "Findings by tool Tool Critical High Medium Low Info Total "
    "Semgrep CE 1 1 1 0 0 3 SonarQube Community Build 0 0 0 0 1 1 "
    "Gitleaks 0 1 0 0 0 1 Syft 0 0 0 0 0 0 Grype 0 1 0 1 0 2",
    "Findings by category",
    "A03 Injection 2 2",
    "A06 Vulnerable and Outdated Components 2 1",
    "A07 Identification and Authentication Failures 2 1",
    "NOCWE No CWE recorded 1 0",
    "CWE Top 25 (2024) 4 of the 25 most dangerous weaknesses are present.",
    "1 CWE-79 Improper Neutralization of Input During Web Page Generation "
    "('Cross-site Scripting') 1",
    "22 CWE-798 Use of Hard-coded Credentials 2",
    "Detailed findings",
    "Critical 1. <script>alert(1)</script> injected title Tool Semgrep CE "
    "Weakness CWE-79; OWASP A03 Injection; CWE Top 25 rank 1 Location web/render.js:7 "
    "Status Open; new since the previous report "
    "Description Output is written to the page unescaped: <script>alert(1)</script>",
    "Status Open; still present from the previous report",
    "Remediation Use a PreparedStatement with bound parameters.",
    "Triaged out (1)",
    "Medium Weak hash algorithm MD5 Semgrep CE False positive app/crypto.py:30",
    "Code quality SonarQube quality gate: Failed.",
    "Condition Result Actual Threshold new_vulnerabilities ERROR 2 0",
    "Measure Value Bugs 3 Vulnerabilities 2 Code smells 41 Coverage (%) 63.5",
    "Components The software bill of materials lists 187 components.",
    "SBOM file SHA-256 Size (bytes) sbom.cdx.json " + "cd" * 32 + " 48213",
    "Coverage Coverage is incomplete: read the table below before relying on this report.",
    "Tool Result Notes Semgrep CE Ran SonarQube Community Build Ran Gitleaks Ran Syft Ran "
    "Grype Partial The vulnerability database is 9 days old. "
    "OWASP Dependency-Check Skipped The tool was requested but did not run.",
    "Dependency-Check was not requested for this scan.",
    "Tool versions Tool Version Image digest Content versions "
    "Semgrep CE 1.179.0 sha256:" + "ab" * 32 + " semgrep_rules: 2026-10-03",
    "Methodology Each tool in the list above ran as a separate, isolated job.",
    "Known limits Semgrep CE traces taint only within one function",
    "Semgrep's rules and SonarQube's analyzers are free but not open source.",
    "Review Review state Automatic, not yet reviewed Verdict Fail (proposed by the policy)",
    f"Report hash (SHA-256 of the frozen snapshot): {HASH}",
]

VENDOR_OUTLINE = [
    "Vendor security assessment - v2.4.0",
    "Assessment verdict Conditional pass The default policy found 3 open High findings; "
    "each needs a remediation date agreed with the vendor.",
    "Reviewed by an analyst - Analyst Example, 2026-10-07 09:30 UTC",
    "Vendor Example Software Ltd Product Payroll Suite",
    "Executive summary Overall risk rating: Critical.",
    "Delta from the last assessment Compared with SSR-20260901-ABC123",
    "Findings summary by category",
    "Detailed findings",
    "Conditions Remediation deadlines attached to the conditional pass. "
    "Finding Severity Location Deadline "
    "SQL injection in UserServlet.find High src/main/java/com/example/UserServlet.java:42 "
    "2026-12-01 "
    "CVE-2021-44228 in log4j-core 2.14.1 High log4j-core 2.14.1 2026-11-15",
    "Scope and coverage",
    "Review Review state Reviewed by an analyst Reviewing analyst Analyst Example "
    "Date 2026-10-07 09:30 UTC Proposed verdict Fail "
    "Verdict decision Conditional pass (overridden) "
    "Reason for override The Critical finding is a false positive in a test-only file. "
    "Internal notes Discussed with the vendor on a call.",
]


def test_application_report_matches_the_golden_outline() -> None:
    assert_outline(render_text(sample_snapshot("application")), APPLICATION_OUTLINE)


def test_vendor_report_matches_the_golden_outline() -> None:
    assert_outline(render_text(sample_snapshot("vendor")), VENDOR_OUTLINE)


def test_the_pdf_variant_has_the_same_text() -> None:
    snapshot = sample_snapshot("application")
    assert render_text(snapshot, "pdf") == render_text(snapshot, "html")


def test_application_report_has_no_vendor_sections() -> None:
    text = render_text(sample_snapshot("application"))
    assert "Executive summary" not in text
    assert "Remediation deadlines" not in text
    assert "Reviewing analyst" not in text


def test_a_vendor_copy_omits_the_internal_notes() -> None:
    snapshot = sample_snapshot("vendor")
    snapshot.vendor_copy = True
    text = render_text(snapshot)
    assert "Internal notes" not in text
    assert "Discussed with the vendor" not in text
    assert "Reason for override" in text


def test_a_script_in_a_finding_title_is_escaped_in_the_html() -> None:
    html = renderer.render_html(
        renderer.DEFAULT_TEMPLATE_DIR, "template.html", sample_snapshot(), HASH
    )
    assert XSS_PAYLOAD not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt; injected title" in html
    # the visible text shows the characters, which proves the parser saw text and not a tag
    assert "<script>alert(1)</script> injected title" in visible_text(html)


def test_no_script_element_is_ever_produced() -> None:
    for kind in ("application", "vendor"):
        html = renderer.render_html(
            renderer.DEFAULT_TEMPLATE_DIR, "template.html", sample_snapshot(kind), HASH
        )
        assert "<script" not in html.lower()
        assert "javascript:" not in html.lower()


def test_secret_text_never_reaches_the_html() -> None:
    html = renderer.render_html(
        renderer.DEFAULT_TEMPLATE_DIR, "template.html", sample_snapshot(), HASH
    )
    assert "sk_live_THIS_MUST_NOT_APPEAR" not in html


def test_the_html_is_self_contained() -> None:
    html = renderer.render_html(
        renderer.DEFAULT_TEMPLATE_DIR, "template.html", sample_snapshot(), HASH
    )
    assert "<link" not in html
    assert not re.search(r"""(?:src|href)=["'](?!data:|#)""", html)
    assert "data:image/svg+xml;base64," in html  # the wordmark
    assert "@page" in html  # the stylesheet is inlined


def test_the_wordmark_and_the_chart_are_in_the_html() -> None:
    html = renderer.render_html(
        renderer.DEFAULT_TEMPLATE_DIR, "template.html", sample_snapshot(), HASH
    )
    assert 'alt="SonaComstar"' in html
    assert "<svg" in html and "Open findings by OWASP Top 10 category" in html
    assert html.count("<rect") >= 10


def test_an_empty_report_still_renders() -> None:
    snapshot = sample_snapshot()
    empty = Snapshot(header=snapshot.header, summary=snapshot.summary.model_copy(update={
        "by_tool": [], "by_owasp": [], "delta": None, "top_risks": [], "cwe_top25": [],
        "cwe_top25_present": 0,
    }))
    text = render_text(empty)
    assert "No open findings." in text
    assert "No tool ran." in text
    assert "None of the CWE Top 25 weaknesses was found." in text


@pytest.mark.parametrize("kind", ["application", "vendor"])
def test_every_section_heading_is_present(kind: str) -> None:
    text = render_text(sample_snapshot(kind))
    headings = (
        "Findings by tool",
        "Detailed findings",
        "Code quality",
        "Components",
        "Methodology",
        "Known limits",
        "Review",
    )
    for heading in headings:
        assert heading in text
