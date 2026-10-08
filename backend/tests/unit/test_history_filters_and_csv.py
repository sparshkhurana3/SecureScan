"""History filters (SQL they produce), query-parameter validation, CSV escaping and streaming."""

from __future__ import annotations

import csv
import io
import json
import types
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from securescan.api import history as history_api
from securescan.api.problems import BadRequest
from securescan.db.models.enums import AppType, ScanKind, ScanState, Severity, Verdict
from securescan.db.models.history import FindingHistory
from securescan.db.models.scans import Scan
from securescan.domain.history import (
    FindingFilters,
    ScanFilters,
    finding_conditions,
    scan_conditions,
)
from securescan.security.csv_safe import csv_line, csv_safe_cell, csv_safe_row, iter_csv

UTC = timezone.utc


def compiled(conditions: list[Any], entity: Any = FindingHistory) -> tuple[str, dict[str, Any]]:
    statement = select(entity.id).where(*conditions)
    result = statement.compile(dialect=postgresql.dialect())
    return str(result), dict(result.params)


# --- finding filters ----------------------------------------------------------------------------------------------


def test_no_filter_no_condition() -> None:
    assert finding_conditions(FindingFilters()) == []
    assert scan_conditions(ScanFilters()) == []


def test_every_finding_filter_adds_exactly_one_condition() -> None:
    uid = uuid.uuid4()
    filters = FindingFilters(
        application_id=uid,
        version_id=uid,
        vendor_id=uid,
        app_type=AppType.VENDOR,
        source="zip",
        tools=["semgrep", "gitleaks"],
        severities=[Severity.CRITICAL, Severity.HIGH],
        cwe=79,
        cve="CVE-2021-44228",
        state_then=["open"],
        state_now=["false_positive", "mitigated"],
        scanned_from=datetime(2026, 1, 1, tzinfo=UTC),
        scanned_to=datetime(2026, 12, 31, tzinfo=UTC),
        started_by_id=uid,
        scan_id=uid,
        q="inject",
    )
    assert len(finding_conditions(filters)) == 16
    sql, params = compiled(finding_conditions(filters))
    for fragment in (
        "finding_history.application_id =",
        "finding_history.version_id =",
        "finding_history.vendor_id =",
        "finding_history.source_kind =",
        "finding_history.tool IN",
        "finding_history.severity IN",
        "finding_history.cwe =",
        "lower(finding_history.cve) =",
        "finding_history.state_at_scan IN",
        "finding_history.state_now IN",
        "finding_history.scanned_at >=",
        "finding_history.scanned_at <=",
        "finding_history.started_by_id =",
        "finding_history.scan_id =",
        "ILIKE",
    ):
        assert fragment in sql, fragment
    assert "applications.type" in sql  # internal/vendor goes through the application
    assert "cve-2021-44228" in params.values()  # compared lower-case on both sides


def test_title_search_escapes_wildcards() -> None:
    sql, params = compiled(finding_conditions(FindingFilters(q="100%_done")))
    assert "ESCAPE" in sql
    assert "%100\\%\\_done%" in params.values()


def test_filters_are_anded() -> None:
    sql, _ = compiled(finding_conditions(FindingFilters(tools=["semgrep"], cwe=79)))
    assert " AND " in sql


def test_filter_detail_is_json_for_the_audit_event() -> None:
    uid = uuid.uuid4()
    detail = FindingFilters(
        application_id=uid,
        severities=[Severity.HIGH],
        app_type=AppType.INTERNAL,
        scanned_from=datetime(2026, 1, 1, tzinfo=UTC),
        cwe=89,
    ).as_detail()
    json.dumps(detail)  # must serialise
    assert detail["severities"] == ["high"]
    assert detail["app_type"] == "internal"
    assert detail["cwe"] == "89"
    assert detail["application_id"] == str(uid)
    assert FindingFilters().as_detail() == {}


# --- scan filters -----------------------------------------------------------------------------------------------------


def test_scan_filters() -> None:
    uid = uuid.uuid4()
    filters = ScanFilters(
        application_id=uid,
        version_id=uid,
        vendor_id=uid,
        app_type=AppType.INTERNAL,
        kind=ScanKind.SAST,
        tools=["semgrep"],
        states=[ScanState.COMPLETED],
        verdicts=[Verdict.FAIL, Verdict.CONDITIONAL],
        started_by_id=uid,
        date_from=datetime(2026, 1, 1, tzinfo=UTC),
        date_to=datetime(2026, 12, 1, tzinfo=UTC),
    )
    conditions = scan_conditions(filters)
    assert len(conditions) == 11
    sql, _ = compiled(conditions, Scan)
    assert "scans.application_id =" in sql
    assert "scan_jobs.tool IN" in sql
    assert "scans.verdict IN" in sql
    assert "scans.state IN" in sql
    assert "applications.vendor_id" in sql


# --- query parameter validation -------------------------------------------------------------------------------------------


def test_finding_filters_parse_and_validate_query_values() -> None:
    parsed = history_api.finding_filters(
        severity=["High", " CRITICAL "],
        state_then=["Open"],
        state_now=["false_positive"],
        tool=["semgrep"],
        app_type=AppType.VENDOR,
    )
    assert parsed.severities == [Severity.HIGH, Severity.CRITICAL]
    assert parsed.state_then == ["open"]
    assert parsed.tools == ["semgrep"]
    assert parsed.app_type == AppType.VENDOR
    with pytest.raises(BadRequest) as bad_severity:
        history_api.finding_filters(severity=["urgent"])
    assert bad_severity.value.code == "history.invalid_severity"
    with pytest.raises(BadRequest) as bad_state:
        history_api.finding_filters(state_now=["maybe"])
    assert bad_state.value.code == "history.invalid_state"


# --- csv_safe ---------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("starter", ["=", "+", "-", "@", "\t", "\r"])
def test_formula_starters_get_a_quote_prefix(starter: str) -> None:
    assert csv_safe_cell(f"{starter}SUM(1+1)") == f"'{starter}SUM(1+1)"


def test_ordinary_cells_are_untouched() -> None:
    assert csv_safe_cell("SQL injection") == "SQL injection"
    assert csv_safe_cell("a=b") == "a=b"
    assert csv_safe_cell(None) == ""
    assert csv_safe_cell(42) == "42"
    assert csv_safe_cell(9.8) == "9.8"
    assert csv_safe_row(["=x", None, 3]) == ["'=x", "", "3"]


def test_csv_line_quotes_and_escapes() -> None:
    line = csv_line(['say "hi", ok', "=HYPERLINK(\"http://evil\")", "multi\nline"])
    assert line.endswith("\r\n")
    row = next(csv.reader(io.StringIO(line)))
    assert row == ['say "hi", ok', "'=HYPERLINK(\"http://evil\")", "multi\nline"]
    assert list(iter_csv(["a", "-b"], [[1, "=2"]])) == ["a,'-b\r\n", "1,'=2\r\n"]


# --- finding CSV rows and streaming ---------------------------------------------------------------------------------------------------


def history_row(**overrides: Any) -> FindingHistory:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "scan_id": uuid.uuid4(),
        "job_id": uuid.uuid4(),
        "application_id": uuid.UUID(int=1),
        "version_id": uuid.UUID(int=2),
        "vendor_id": None,
        "tool": "semgrep",
        "dd_finding_id": 5,
        "severity": Severity.HIGH,
        "title": "SQL injection",
        "state_at_scan": "open",
        "state_now": "open",
        "scanned_at": datetime(2026, 10, 7, 12, 0, tzinfo=UTC),
    }
    values.update(overrides)
    return FindingHistory(**values)


def names() -> history_api.Names:
    n = history_api.Names()
    n.applications = {uuid.UUID(int=1): ("js-planted", AppType.INTERNAL)}
    n.versions = {uuid.UUID(int=2): "main"}
    return n


def test_csv_row_columns_match_the_header() -> None:
    row = history_api.finding_csv_row(history_row(cwe=89, line=12, file_path="src/a.py"), names())
    assert len(row) == len(history_api.CSV_HEADER)
    by_name = dict(zip(history_api.CSV_HEADER, row, strict=True))
    assert by_name["application"] == "js-planted"
    assert by_name["application_type"] == "internal"
    assert by_name["version"] == "main"
    assert by_name["severity"] == "high"
    assert by_name["cwe"] == 89
    assert by_name["file"] == "src/a.py"
    assert by_name["defectdojo_link"].endswith("/finding/5")


def test_hostile_cells_are_neutralised_in_the_csv_line() -> None:
    hostile = history_row(
        title="=cmd|' /C calc'!A0",
        file_path="+SUM(A1)",
        component="-2+3",
        url="@import",
        cve="\t=1",
    )
    line = csv_line(history_api.finding_csv_row(hostile, names()))
    cells = next(csv.reader(io.StringIO(line)))
    by_name = dict(zip(history_api.CSV_HEADER, cells, strict=True))
    assert by_name["title"] == "'=cmd|' /C calc'!A0"
    assert by_name["file"] == "'+SUM(A1)"
    assert by_name["component"] == "'-2+3"
    assert by_name["url"] == "'@import"
    assert by_name["cve"] == "'\t=1"
    for value in by_name.values():
        assert not value.startswith(("=", "+", "@"))


class Batches:
    """A fake ``session_scope`` that serves the rows in fixed batches."""

    def __init__(self, batches: list[list[FindingHistory]]) -> None:
        self._batches = batches
        self.sessions = 0

    @asynccontextmanager
    async def __call__(self) -> Any:
        self.sessions += 1
        batch = self._batches.pop(0) if self._batches else []

        class Scalars:
            def all(self) -> list[FindingHistory]:
                return batch

        async def scalars(stmt: Any) -> Scalars:
            return Scalars()

        yield types.SimpleNamespace(scalars=scalars)


async def test_the_csv_streams_every_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [history_row(dd_finding_id=i, title=f"finding {i}") for i in range(5)]
    rows[3].title = "=evil()"
    fake = Batches([rows[:2], rows[2:4], rows[4:]])
    monkeypatch.setattr(history_api, "session_scope", fake)
    monkeypatch.setattr(history_api, "CSV_BATCH", 2)

    async def fake_names(db: Any, batch: Any) -> history_api.Names:
        return names()

    monkeypatch.setattr(history_api, "_finding_names", fake_names)
    chunks = [c async for c in history_api.stream_findings_csv(FindingFilters())]
    text = "".join(chunks)
    assert text.startswith("\ufeff")  # BOM for spreadsheet programs
    parsed = list(csv.reader(io.StringIO(text.lstrip("\ufeff"))))
    assert parsed[0] == history_api.CSV_HEADER
    assert len(parsed) == 6  # header + 5 findings
    titles = [r[history_api.CSV_HEADER.index("title")] for r in parsed[1:]]
    assert titles == ["finding 0", "finding 1", "finding 2", "'=evil()", "finding 4"]
    assert fake.sessions == 3  # a short last batch ends the stream without another query


async def test_an_empty_result_is_just_the_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history_api, "session_scope", Batches([[]]))
    chunks = [c async for c in history_api.stream_findings_csv(FindingFilters())]
    assert len(chunks) == 1
    assert chunks[0].lstrip("\ufeff").strip().split(",")[0] == "scanned_at"
