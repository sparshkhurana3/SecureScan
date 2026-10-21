"""Contract test: DefectDojo accepts every fixture report and yields findings (plan 1.5 and M4).

Run before every DefectDojo or scanner image upgrade, against a running DefectDojo::

    SECURESCAN_INTEGRATION=1 \\
    DD_URL=http://127.0.0.1:8080 DD_ADMIN_USER=admin DD_ADMIN_PASSWORD=<password> \\
    python scripts/dev.py test contract

(``DD_ADMIN_PASSWORD_FILE`` works too. The test logs in as the admin of a throw-away DefectDojo; do not
point it at the production instance.) Each report in ``backend/tests/fixtures/reports/`` is imported
with the scan type the scanner catalogue names for that file, into the product ``securescan-contract``.
The test then checks that

* the import succeeds and the Test holds at least one finding (or the ``min_findings`` of the optional
  ``expected.json`` next to the reports),
* the severities listed in ``expected.json`` are present, for example
  ``{"semgrep.json": {"min_findings": 2, "severities": ["High"]}}``,
* every finding converts into a history row (``history_values``),
* importing the same file again creates no finding and closes none (deduplication works).

The fixture reports are produced in M1 (spike S7) by running each pinned image against the planted
sample apps, and refreshed whenever an image is bumped. With no report present the test skips.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from securescan.integrations.defectdojo.client import DefectDojoClient, ReimportRequest
from securescan.integrations.defectdojo.findings import history_values, severity_counts, severity_of
from securescan.integrations.defectdojo.mapping import content_type_for

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("SECURESCAN_INTEGRATION") != "1",
        reason="set SECURESCAN_INTEGRATION=1 and point DD_URL at a throw-away DefectDojo",
    ),
]

REPORTS = Path(__file__).resolve().parents[1] / "fixtures" / "reports"

# File name -> DefectDojo scan type, used where the catalogue does not name the file.
FALLBACK_SCAN_TYPES = {
    "semgrep.json": "Semgrep JSON Report",
    "gitleaks.json": "Gitleaks Scan",
    "grype.json": "Anchore Grype",
    "zap.xml": "ZAP Scan",
    "nuclei.json": "Nuclei Scan",
    "spotbugs.xml": "SpotBugs Scan",
}


def scan_types() -> dict[str, str]:
    """The scan type for each report file: the catalogue's ``defectdojo_scan_type`` first."""
    types = dict(FALLBACK_SCAN_TYPES)
    try:
        from securescan.runner.catalogue import load_catalogue

        for entry in load_catalogue().values():
            if entry.defectdojo_file and entry.defectdojo_scan_type:
                types[entry.defectdojo_file] = entry.defectdojo_scan_type
    except Exception:  # noqa: BLE001, S110 - the fallback table is enough when the catalogue is absent
        pass
    return types


def expectations() -> dict[str, Any]:
    path = REPORTS / "expected.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def fixture_reports() -> list[Path]:
    if not REPORTS.is_dir():
        return []
    known = scan_types()
    return sorted(p for p in REPORTS.iterdir() if p.is_file() and p.name in known)


def credentials() -> tuple[str, str, str]:
    base = os.environ.get("DD_URL") or os.environ.get("SECURESCAN_DEFECTDOJO_URL") or "http://127.0.0.1:8080"
    user = os.environ.get("DD_ADMIN_USER", "admin")
    password = os.environ.get("DD_ADMIN_PASSWORD", "")
    password_file = os.environ.get("DD_ADMIN_PASSWORD_FILE")
    if not password and password_file:
        password = Path(password_file).read_text(encoding="utf-8").strip()
    if not password:
        pytest.skip("set DD_ADMIN_PASSWORD (or DD_ADMIN_PASSWORD_FILE) for the throw-away DefectDojo")
    return base, user, password


CASES = fixture_reports()


@pytest.mark.parametrize("report", CASES or [None], ids=[p.name for p in CASES] or ["no-reports"])
async def test_fixture_report_imports_and_deduplicates(report: Path | None) -> None:
    if report is None:
        pytest.skip("no fixture reports in backend/tests/fixtures/reports (spike S7 produces them)")
    base, user, password = credentials()
    scan_type = scan_types()[report.name]
    token = await DefectDojoClient.obtain_token(base, user, password)
    stamp = f"contract-{uuid.uuid4().hex[:8]}"
    request = ReimportRequest(
        file_path=report,
        file_name=report.name,
        scan_type=scan_type,
        product_type_name="Contract Tests",
        product_name="securescan-contract",
        engagement_name=stamp,
        test_title=f"{report.stem}:{stamp}",
        version=stamp,
        tags=("securescan-contract",),
        scan_date=date.today(),
        content_type=content_type_for(report.name),
    )
    async with DefectDojoClient(base, token, import_timeout=900.0) as client:
        first = await client.reimport_scan(request)
        findings = await client.list_findings(first.test_id, include_inactive=True)
        want = expectations().get(report.name, {})
        assert findings, f"{report.name} as '{scan_type}' produced no findings"
        assert len(findings) >= int(want.get("min_findings", 1))
        present = {severity_of(f).value for f in findings}
        for severity in want.get("severities", []):
            assert severity.lower() in present, f"{report.name}: no {severity} finding (has {sorted(present)})"
        for finding in findings:
            values = history_values(finding)  # every finding must fit a history row
            assert values["title"]
        before = severity_counts(findings)

        second = await client.reimport_scan(request)
        assert second.test_id == first.test_id
        again = await client.list_findings(first.test_id, include_inactive=True)
        assert len(again) == len(findings), "re-importing the same report created or removed findings"
        assert severity_counts(again) == before, "re-importing the same report changed the open counts"
