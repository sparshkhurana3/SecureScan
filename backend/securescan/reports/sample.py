"""A sample snapshot for test renders, previews and the unit tests.

It touches every section of the default template: findings of several tools and severities, a
finding whose title contains a ``<script>`` payload (a template that prints titles without
escaping is rejected), a dependency finding, a secret finding, a SonarQube quality gate, an SBOM
component count, a delta against an earlier report, and for the vendor kind a review with
conditions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from securescan.reports.snapshot import (
    BriefFinding,
    PreviousReport,
    ReviewInput,
    Snapshot,
    build_snapshot,
)

XSS_TITLE = "<script>alert(1)</script> injected title"
XSS_PAYLOAD = "<script>alert(1)</script>"

SAMPLE_TIME = datetime(2026, 10, 7, 9, 30, tzinfo=timezone.utc)


def _finding(**values: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "tool": "semgrep",
        "severity": "medium",
        "title": "Finding",
        "cwe": None,
        "cve": None,
        "cvss": None,
        "component": None,
        "component_version": None,
        "file_path": None,
        "line": None,
        "url": None,
        "hash_code": None,
        "state_at_scan": "open",
        "state_now": "open",
        "flags_at_scan": {},
        "flags_now": {},
    }
    base.update(values)
    return SimpleNamespace(**base)


def sample_findings() -> list[SimpleNamespace]:
    return [
        _finding(
            tool="semgrep", severity="high", title="SQL injection in UserServlet.find",
            cwe=89, file_path="src/main/java/com/example/UserServlet.java", line=42,
            hash_code="h-sqli",
            flags_now={
                "description": "User input reaches a SQL statement without parameterisation.",
                "mitigation": "Use a PreparedStatement with bound parameters.",
            },
        ),
        _finding(
            tool="semgrep", severity="critical", title=XSS_TITLE, cwe=79,
            file_path="web/render.js", line=7, hash_code="h-xss",
            flags_now={"description": "Output is written to the page unescaped: " + XSS_PAYLOAD},
        ),
        _finding(
            tool="semgrep", severity="medium", title="Hard-coded password", cwe=798,
            file_path="app/settings.py", line=12, hash_code="h-pw",
        ),
        _finding(
            tool="gitleaks", severity="high", title="Generic API key in config.yaml",
            cwe=798, file_path="deploy/config.yaml", line=3, hash_code="h-key",
            flags_now={"description": "Secret: sk_live_THIS_MUST_NOT_APPEAR"},
        ),
        _finding(
            tool="grype", severity="high", title="CVE-2021-44228 in log4j-core 2.14.1",
            cve="CVE-2021-44228", cvss=10.0, component="log4j-core", component_version="2.14.1",
            cwe=502, hash_code="h-log4j",
        ),
        _finding(
            tool="grype", severity="low", title="CVE-2020-0001 in libexample 1.0",
            cve="CVE-2020-0001", component="libexample", component_version="1.0",
            hash_code="h-lib",
        ),
        _finding(
            tool="sonarqube", severity="info", title="Remove this unused import",
            file_path="app/util.py", line=1, hash_code="h-import",
        ),
        _finding(
            tool="semgrep", severity="medium", title="Weak hash algorithm MD5", cwe=327,
            file_path="app/crypto.py", line=30, hash_code="h-md5",
            state_at_scan="open", state_now="false_positive",
        ),
    ]


def sample_jobs() -> list[SimpleNamespace]:
    def job(tool: str, **values: Any) -> SimpleNamespace:
        base: dict[str, Any] = {
            "tool": tool, "state": "completed", "import_state": "imported", "partial": False,
            "tool_version": "1.0.0", "image": f"example/{tool}",
            "image_digest": "sha256:" + "ab" * 32,
            "content_versions": {}, "outcome_reason": None, "coverage_note": None,
            "applied_exclusions": [], "options": {},
        }
        base.update(values)
        return SimpleNamespace(**base)

    return [
        job("semgrep", tool_version="1.179.0", content_versions={"semgrep_rules": "2026-10-03"}),
        job(
            "sonarqube", tool_version="26.9.0",
            options={
                "quality_gate": {
                    "status": "ERROR",
                    "conditions": [
                        {"metric": "new_vulnerabilities", "status": "ERROR", "actual": "2",
                         "threshold": "0"}
                    ],
                },
                "measures": {"bugs": 3, "vulnerabilities": 2, "code_smells": 41, "coverage": 63.5},
            },
        ),
        job("gitleaks", tool_version="8.30.1"),
        job("syft", tool_version="1.54.0", options={"component_count": 187}),
        job(
            "grype", tool_version="0.120.0", content_versions={"grype_db": "v6.0.3"},
            state="completed_partial", partial=True,
            outcome_reason="The vulnerability database is 9 days old.",
        ),
    ]


def sample_snapshot(kind: str = "application") -> Snapshot:
    """A complete snapshot of the given report kind (``application`` or ``vendor``)."""
    vendor_kind = kind == "vendor"
    application = SimpleNamespace(
        name="Payroll Portal", type="vendor" if vendor_kind else "internal",
        criticality="high", data_classification="confidential",
        vendor_product="Payroll Suite", hosting="deployable",
    )
    version = SimpleNamespace(label="v2.4.0", label_kind="release", commit_sha="0123abcd" * 5)
    scan = SimpleNamespace(
        id="00000000-0000-0000-0000-000000000001", kind="sast", mode=None,
        profile_name="code-standard", profile_version=3, verdict="fail",
        verdict_detail={}, commit_sha="0123abcd" * 5, source_ref="main", source_digest=None,
        coverage_notes=["Dependency-Check was not requested for this scan."],
        requested_tools=["semgrep", "sonarqube", "gitleaks", "syft", "grype", "dependency-check"],
        started_at=SAMPLE_TIME, finished_at=SAMPLE_TIME, created_at=SAMPLE_TIME,
    )
    vendor = SimpleNamespace(
        name="Example Software Ltd", contact_name="A. Contact",
        contact_email="security@example.invalid", risk_tier="high",
    )
    previous = PreviousReport(
        ref="SSR-20260901-ABC123", scan_date="2026-09-01T08:00:00Z", version_label="v2.3.0",
        findings={
            "h-sqli": BriefFinding(
                key="h-sqli", severity="high", severity_label="High", title="SQL injection",
                tool="Semgrep CE",
            ),
            "h-gone": BriefFinding(
                key="h-gone", severity="medium", severity_label="Medium",
                title="Open redirect", tool="Semgrep CE", location="web/redirect.js:9",
            ),
        },
    )
    review = None
    if vendor_kind:
        review = ReviewInput(
            state="reviewed", reviewer="Analyst Example", reviewed_at=SAMPLE_TIME,
            proposed_verdict="fail", verdict="conditional", overridden=True,
            override_reason="The Critical finding is a false positive in a test-only file.",
            conditions=[
                {"finding_hash": "h-sqli", "deadline": "2026-12-01"},
                {"finding_hash": "h-log4j", "deadline": "2026-11-15"},
            ],
            internal_notes="Discussed with the vendor on a call.",
        )
    return build_snapshot(
        kind=kind, application=application, version=version, scan=scan, jobs=sample_jobs(),
        findings=sample_findings(), vendor=vendor if vendor_kind else None,
        template_name="Sample template", template_version=1,
        report_ref="SSR-20261007-SAMPLE1", generated_at=SAMPLE_TIME, previous=previous,
        sbom_artifacts=[
            SimpleNamespace(id="11111111-1111-1111-1111-111111111111", filename="sbom.cdx.json",
                            sha256="cd" * 32, size_bytes=48213)
        ],
        sbom_component_count=187, review=review,
    )
