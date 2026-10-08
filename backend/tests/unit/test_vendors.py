"""Vendor assessments (M10): hosting rule, delta, conditions, vendor copy, intake and the API.

No database and no network: the domain functions take plain rows, the API tests run a small FastAPI
app over a fake session (see ``tests/unit/conftest.py``).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from securescan.api import vendor_assessments as api
from securescan.api.problems import (
    Conflict,
    NotFound,
    UnprocessableEntity,
    install_problem_handlers,
)
from securescan.auth.roles import CurrentUser, current_user
from securescan.db.models.applications import Application
from securescan.db.models.artifacts import Artifact
from securescan.db.models.audit import AuditEvent
from securescan.db.models.enums import (
    AppType,
    ArtifactKind,
    ReportKind,
    ReviewState,
    ScanKind,
    ScanState,
    TargetEnvironment,
    TargetKind,
    UserRole,
)
from securescan.db.models.scans import Scan
from securescan.db.models.targets import Target
from securescan.db.models.vendors import Vendor
from securescan.db.models.versions import ApplicationVersion
from securescan.db.session import get_session
from securescan.domain import reports as report_service
from securescan.domain import scans as scan_service
from securescan.domain import vendors
from securescan.reports import renderer
from securescan.reports import snapshot as snap
from securescan.reports.sample import sample_snapshot
from securescan.storage.artifacts import save_bytes
from securescan.util import utcnow
from tests.unit.conftest import FakeScalars, FakeSession
from tests.unit.test_reports_api import blank_pdf, future, make_report, make_user, store_files
from tests.unit.test_reports_render import assert_outline, render_text

HASH = "0123456789abcdef" * 4
TODAY = date(2026, 10, 7)
NOW = datetime(2026, 10, 7, 9, 30, tzinfo=timezone.utc)

UAT = TargetEnvironment.UAT
PROD = TargetEnvironment.PRODUCTION


# --------------------------------------------------------------------------- helpers


def row(title: str = "Finding", **values: Any) -> SimpleNamespace:
    """A finding-history row with the attributes the delta reads."""
    base: dict[str, Any] = {
        "tool": "semgrep",
        "severity": "high",
        "title": title,
        "cwe": None,
        "cve": None,
        "cvss": None,
        "component": None,
        "component_version": None,
        "file_path": "src/app.py",
        "line": 10,
        "url": None,
        "hash_code": f"h-{title}",
        "state_at_scan": "open",
        "state_now": "open",
    }
    base.update(values)
    return SimpleNamespace(**base)


def keys(items: list[vendors.DeltaFinding]) -> list[str]:
    return sorted(i.key for i in items)


def job(tool: str, state: str = "completed", imported: str = "imported", **kw: Any) -> Any:
    return SimpleNamespace(tool=tool, state=state, import_state=imported, partial=False, **kw)


# --------------------------------------------------------------------------- authorization record


def auth(**overrides: Any) -> str:
    values: dict[str, Any] = {
        "artifact_id": uuid.uuid4(),
        "authorized_from": NOW - timedelta(days=1),
        "authorized_until": NOW + timedelta(days=5),
        "contact": "Jo Vendor, +1 555 0100",
        "now": NOW,
    }
    values.update(overrides)
    return vendors.authorization_state(**values)


def test_authorization_states() -> None:
    assert auth() == vendors.AUTH_VALID
    assert auth(artifact_id=None, authorized_from=None, authorized_until=None, contact=None) == (
        vendors.AUTH_MISSING
    )
    assert auth(artifact_id=None) == vendors.AUTH_INCOMPLETE  # no written authorization
    assert auth(contact="  ") == vendors.AUTH_INCOMPLETE
    assert auth(authorized_until=None) == vendors.AUTH_INCOMPLETE
    assert auth(authorized_from=NOW + timedelta(hours=1)) == vendors.AUTH_NOT_STARTED
    assert auth(authorized_until=NOW - timedelta(seconds=1)) == vendors.AUTH_EXPIRED
    assert auth(authorized_until=NOW) == vendors.AUTH_VALID  # the end of the window is inclusive


def test_authorization_accepts_naive_datetimes_as_utc() -> None:
    naive_from = datetime(2026, 10, 1)
    naive_until = datetime(2026, 10, 31)
    assert auth(authorized_from=naive_from, authorized_until=naive_until) == vendors.AUTH_VALID


def test_target_authorization_state_reads_the_target_columns() -> None:
    target = SimpleNamespace(
        vendor_authorization_artifact_id=uuid.uuid4(),
        vendor_authorized_from=NOW - timedelta(days=1),
        vendor_authorized_until=NOW + timedelta(days=1),
        vendor_contact="Jo",
    )
    assert vendors.target_authorization_state(target, NOW) == vendors.AUTH_VALID
    target.vendor_contact = None
    assert vendors.target_authorization_state(target, NOW) == vendors.AUTH_INCOMPLETE


# --------------------------------------------------------------------------- hosting rule table

V = vendors
HOSTING_TABLE = [
    # hosting, tag, authorization, mode, expected environment or refusal code
    ("deployable", UAT, V.AUTH_MISSING, "full", UAT),
    ("deployable", UAT, V.AUTH_MISSING, "api", UAT),
    ("deployable", UAT, V.AUTH_MISSING, "baseline", UAT),
    ("deployable", PROD, V.AUTH_MISSING, "baseline", PROD),
    ("deployable", PROD, V.AUTH_MISSING, "full", "dast.production_baseline_only"),
    ("saas", PROD, V.AUTH_VALID, "baseline", PROD),
    ("saas", PROD, V.AUTH_VALID, "full", "dast.production_baseline_only"),
    ("saas", UAT, V.AUTH_VALID, "full", UAT),  # the vendor provided and authorized a UAT instance
    ("saas", UAT, V.AUTH_VALID, "baseline", UAT),
    ("saas", PROD, V.AUTH_MISSING, "baseline", "vendor.authorization_required"),
    ("saas", UAT, V.AUTH_MISSING, "full", "vendor.authorization_required"),
    ("saas", UAT, V.AUTH_MISSING, "baseline", "vendor.authorization_required"),
    ("saas", PROD, V.AUTH_INCOMPLETE, "baseline", "vendor.authorization_incomplete"),
    ("saas", UAT, V.AUTH_NOT_STARTED, "full", "vendor.authorization_not_started"),
    ("saas", UAT, V.AUTH_EXPIRED, "full", "vendor.authorization_expired"),
    (None, PROD, V.AUTH_VALID, "baseline", PROD),  # unset hosting is treated as SaaS
    (None, UAT, V.AUTH_VALID, "full", UAT),
    (None, UAT, V.AUTH_MISSING, "full", "vendor.authorization_required"),
]


@pytest.mark.parametrize(("hosting", "tag", "state", "mode", "expected"), HOSTING_TABLE)
def test_hosting_rule_table(
    hosting: str | None, tag: TargetEnvironment, state: str, mode: str, expected: Any
) -> None:
    kwargs: dict[str, Any] = {
        "app_type": AppType.VENDOR,
        "hosting": hosting,
        "tagged_environment": tag,
        "mode": mode,
        "authorization": state,
    }
    if not isinstance(expected, TargetEnvironment):
        with pytest.raises(UnprocessableEntity) as raised:
            vendors.check_vendor_dast(**kwargs)
        assert raised.value.code == expected
        return
    decision = vendors.check_vendor_dast(**kwargs)
    assert decision is not None and decision.environment == expected


def test_a_saas_target_tagged_uat_without_authorization_counts_as_production() -> None:
    decision = vendors.vendor_hosting_decision(
        hosting="saas", tagged_environment=UAT, authorization=vendors.AUTH_MISSING
    )
    assert decision.environment == PROD
    assert decision.authorization_required and not decision.full_scans_allowed
    authorized = vendors.vendor_hosting_decision(
        hosting="saas", tagged_environment=UAT, authorization=vendors.AUTH_VALID
    )
    assert authorized.environment == UAT and authorized.full_scans_allowed


def test_a_deployable_product_needs_no_vendor_authorization() -> None:
    decision = vendors.vendor_hosting_decision(
        hosting="deployable", tagged_environment=UAT, authorization=vendors.AUTH_MISSING
    )
    assert not decision.authorization_required
    assert decision.authorization == vendors.AUTH_NOT_REQUIRED
    assert decision.full_scans_allowed


def test_internal_applications_are_not_touched_by_the_vendor_rule() -> None:
    assert (
        vendors.check_vendor_dast(
            app_type=AppType.INTERNAL,
            hosting=None,
            tagged_environment=PROD,
            mode="full",
            authorization=vendors.AUTH_MISSING,
        )
        is None
    )


def check_context(
    *, kind: str = "dast", mode: str = "baseline", hosting: str | None = "saas", **target: Any
) -> Any:
    target_values: dict[str, Any] = {
        "environment": PROD,
        "vendor_authorization_artifact_id": None,
        "vendor_authorized_from": None,
        "vendor_authorized_until": None,
        "vendor_contact": None,
    }
    target_values.update(target)
    return SimpleNamespace(
        doc=SimpleNamespace(kind=kind, mode=mode),
        application=SimpleNamespace(type=AppType.VENDOR, hosting=hosting),
        target=SimpleNamespace(**target_values),
    )


def test_the_scan_check_is_registered_and_refuses_dast_without_authorization() -> None:
    assert vendors.vendor_scan_check in scan_service._EXTRA_CHECKS
    with pytest.raises(UnprocessableEntity) as raised:
        vendors.vendor_scan_check(check_context())
    assert raised.value.code == "vendor.authorization_required"


def test_the_scan_check_lets_an_authorized_baseline_scan_through() -> None:
    now = utcnow()
    context = check_context(
        vendor_authorization_artifact_id=uuid.uuid4(),
        vendor_authorized_from=now - timedelta(hours=1),
        vendor_authorized_until=now + timedelta(hours=1),
        vendor_contact="Jo",
    )
    vendors.vendor_scan_check(context)  # no problem
    full = check_context(
        mode="full",
        vendor_authorization_artifact_id=uuid.uuid4(),
        vendor_authorized_from=now - timedelta(hours=1),
        vendor_authorized_until=now + timedelta(hours=1),
        vendor_contact="Jo",
    )
    with pytest.raises(UnprocessableEntity) as raised:
        vendors.vendor_scan_check(full)  # still production: baseline only
    assert raised.value.code == "dast.production_baseline_only"


def test_the_scan_check_ignores_code_scans_and_internal_applications() -> None:
    vendors.vendor_scan_check(check_context(kind="sast"))
    internal = check_context()
    internal.application.type = AppType.INTERNAL
    vendors.vendor_scan_check(internal)


# --------------------------------------------------------------------------- delta


def test_delta_lists_the_fixed_remaining_and_new_findings() -> None:
    """The acceptance scenario: a second version with one issue fixed and one added."""
    previous = [
        row("SQL injection", severity="high", hash_code="h1"),
        row("Reflected XSS", severity="medium", hash_code="h2", file_path="web/a.js"),
        row("Hard-coded password", severity="low", hash_code="h3", file_path="cfg.py"),
    ]
    current = [
        row("Reflected XSS", severity="medium", hash_code="h2", file_path="web/a.js"),
        row("Hard-coded password", severity="low", hash_code="h3", file_path="cfg.py"),
        row("Path traversal", severity="high", hash_code="h4", file_path="files.py"),
    ]
    result = vendors.compute_delta(previous, current)
    assert keys(result.fixed) == ["h1"]
    assert keys(result.remaining) == ["h2", "h3"]
    assert keys(result.new) == ["h4"]
    assert result.reopened == [] and result.triaged == []
    assert result.counts() == {"fixed": 1, "remaining": 2, "new": 1, "reopened": 0, "triaged": 0}
    assert result.open_now() == 3
    assert result.fixed[0].title == "SQL injection"
    assert result.new[0].location == "files.py:10"


def test_delta_is_ordered_by_severity_then_title() -> None:
    result = vendors.compute_delta(
        [],
        [
            row("b low", severity="low", hash_code="a"),
            row("z critical", severity="critical", hash_code="b"),
            row("a high", severity="high", hash_code="c"),
            row("b high", severity="high", hash_code="d"),
        ],
    )
    assert [f.title for f in result.new] == ["z critical", "a high", "b high", "b low"]


def test_duplicate_rows_with_the_same_hash_count_once() -> None:
    previous = [row("A", hash_code="h1"), row("A", hash_code="h1", line=20)]
    current = [
        row("A", hash_code="h1"),
        row("A", hash_code="h1", line=30),
        row("A", hash_code="h1", line=40),
        row("B", hash_code="h2"),
    ]
    result = vendors.compute_delta(previous, current)
    assert keys(result.remaining) == ["h1"] and result.remaining[0].rows == 3
    assert keys(result.new) == ["h2"]
    assert result.duplicate_rows_previous == 1 and result.duplicate_rows_current == 2


def test_a_finding_is_open_when_any_of_its_duplicate_rows_is_open() -> None:
    previous = [row("A", hash_code="h1", state_now="false_positive"), row("A", hash_code="h1")]
    current = [row("A", hash_code="h1", state_now="false_positive"), row("A", hash_code="h1")]
    result = vendors.compute_delta(previous, current)
    assert keys(result.remaining) == ["h1"]
    assert result.fixed == [] and result.triaged == []


def test_the_most_severe_duplicate_represents_the_finding() -> None:
    result = vendors.compute_delta(
        [], [row("A", hash_code="h1", severity="low"), row("A", hash_code="h1", severity="high")]
    )
    assert [f.severity for f in result.new] == ["high"]


@pytest.mark.parametrize("old_state", ["mitigated", "closed", "false_positive", "risk_accepted"])
def test_a_finding_that_was_closed_or_triaged_before_and_is_open_now_is_reopened(
    old_state: str,
) -> None:
    previous = [row("A", hash_code="h1", state_now=old_state)]
    current = [row("A", hash_code="h1")]
    result = vendors.compute_delta(previous, current)
    assert keys(result.reopened) == ["h1"]
    assert result.reopened[0].previous_state == old_state
    assert result.new == [] and result.remaining == [] and result.fixed == []


def test_a_finding_that_an_analyst_triaged_away_is_not_counted_as_fixed() -> None:
    previous = [row("A", hash_code="h1"), row("B", hash_code="h2"), row("C", hash_code="h3")]
    current = [
        row("A", hash_code="h1", state_now="false_positive"),
        row("B", hash_code="h2", state_now="mitigated"),
    ]
    result = vendors.compute_delta(previous, current)
    assert keys(result.triaged) == ["h1"] and result.triaged[0].state == "false_positive"
    assert keys(result.fixed) == ["h2", "h3"]  # mitigated in DefectDojo, or gone
    assert result.remaining == [] and result.new == []


def test_findings_closed_in_both_scans_are_ignored() -> None:
    result = vendors.compute_delta(
        [row("A", hash_code="h1", state_now="false_positive")],
        [row("A", hash_code="h1", state_now="false_positive")],
    )
    assert result.counts() == {"fixed": 0, "remaining": 0, "new": 0, "reopened": 0, "triaged": 0}


def test_state_at_scan_is_used_when_state_now_is_missing() -> None:
    result = vendors.compute_delta(
        [row("A", hash_code="h1", state_now=None, state_at_scan="open")], []
    )
    assert keys(result.fixed) == ["h1"]


def test_rows_without_a_hash_code_are_matched_by_their_fields() -> None:
    previous = [row("SQL injection", hash_code=None, cwe=89, file_path="a.py", line=5)]
    current = [row("SQL injection", hash_code=None, cwe="CWE-89", file_path="a.py", line=99)]
    result = vendors.compute_delta(previous, current)
    assert len(result.remaining) == 1 and result.fixed == [] and result.new == []
    assert result.remaining[0].key.startswith("x")


def test_the_delta_key_is_the_key_the_report_snapshot_uses() -> None:
    for item in (
        row("With hash", hash_code="abc123"),
        row("Without hash", hash_code=None, cwe=79, file_path="x.js"),
        row("Component", hash_code=None, tool="grype", cve="CVE-2021-44228", component="log4j"),
        row("", hash_code=None),
    ):
        assert vendors.row_key(item) == snap._finding_item(item, 0, "").key  # noqa: SLF001


def test_only_the_tools_that_ran_in_both_scans_are_compared() -> None:
    previous = [row("A", hash_code="h1"), row("Secret", hash_code="h9", tool="gitleaks")]
    current = [row("A", hash_code="h1"), row("Lib", hash_code="h7", tool="grype")]
    everything = vendors.compute_delta(previous, current)
    assert keys(everything.fixed) == ["h9"] and keys(everything.new) == ["h7"]
    result = vendors.compute_delta(previous, current, compared_tools=["semgrep"])
    assert keys(result.remaining) == ["h1"]
    assert result.fixed == [] and result.new == []
    assert result.compared_tools == ["semgrep"]


def test_compare_tools_needs_a_finished_and_imported_job_in_both_scans() -> None:
    older = [job("semgrep"), job("gitleaks"), job("syft", imported="failed")]
    newer = [job("semgrep", state="completed_partial"), job("grype"), job("syft")]
    comparison = vendors.compare_tools(older, newer)
    assert comparison.compared == ["semgrep"]
    assert comparison.skipped == ["gitleaks", "grype", "syft"]
    assert comparison.partial == ["semgrep"]
    text = " ".join(comparison.notes)
    assert "Gitleaks ran in the previous assessment only" in text
    assert "Grype ran only in this assessment" in text
    assert "Syft did not finish or was not imported" in text
    assert "Semgrep CE was partial" in text


def test_compare_tools_without_any_common_tool() -> None:
    comparison = vendors.compare_tools([job("semgrep")], [job("grype")])
    assert comparison.compared == [] and comparison.skipped == ["grype", "semgrep"]


def test_the_snapshot_delta_has_exact_counts_and_capped_lists() -> None:
    result = vendors.compute_delta(
        [
            row("Gone", hash_code="g1", severity="medium"),
            row("Back", hash_code="b1", state_now="closed"),
        ],
        [row(f"New {i}", hash_code=f"n{i}") for i in range(150)] + [row("Back", hash_code="b1")],
        compared_tools=["semgrep"],
    )
    result.skipped_tools = ["gitleaks"]
    result.notes = ["Gitleaks ran in the previous assessment only and is not compared."]
    delta = vendors.to_snapshot_delta(
        result,
        previous_ref="SSR-20260901-ABC123",
        previous_scan_date="2026-09-01T08:00:00Z",
        previous_version_label="v1.0",
    )
    assert delta.new == 150 and len(delta.new_findings) == snap.MAX_DELTA_ROWS
    assert delta.fixed == 1 and delta.fixed_findings[0].title == "Gone"
    assert delta.fixed_findings[0].severity_label == "Medium"
    assert delta.reopened == 1 and delta.reopened_findings[0].note.startswith("Was closed")
    assert delta.remaining == 0 and delta.triaged == 0
    assert delta.compared_tools == ["Semgrep CE"] and delta.skipped_tools == ["Gitleaks"]
    assert delta.previous_ref == "SSR-20260901-ABC123" and delta.previous_version_label == "v1.0"
    assert delta.new_findings[0].tool == "Semgrep CE"


def test_the_snapshot_delta_mentions_collapsed_duplicates() -> None:
    result = vendors.compute_delta([row("A", hash_code="h")], [row("A", hash_code="h")] * 2)
    delta = vendors.to_snapshot_delta(
        result, previous_ref="x", previous_scan_date="", previous_version_label=""
    )
    assert any("counted once" in note for note in delta.notes)


def test_findings_of_a_snapshot_are_marked_against_the_delta() -> None:
    snapshot = sample_snapshot("vendor")
    by_key = {f.key: f for f in snapshot.findings}
    result = vendors.DeltaResult(
        remaining=[vendors.DeltaFinding("h-sqli", "high", "t", "semgrep", "")],
        new=[vendors.DeltaFinding("h-xss", "critical", "t", "semgrep", "")],
        reopened=[vendors.DeltaFinding("h-pw", "medium", "t", "semgrep", "")],
    )
    vendors.mark_findings_against(snapshot, result)
    assert by_key["h-sqli"].vs_previous == "remaining"
    assert by_key["h-xss"].vs_previous == "new"
    assert by_key["h-pw"].vs_previous == "reopened"
    assert by_key["h-key"].vs_previous == ""


# ------------------------------------------------------------------------ delta from the database


class TypedFakeSession(FakeSession):
    """A fake session that answers by the entity of the statement or the model of ``get``."""

    def __init__(self, rows: list[Any] | None = None, scalar_value: Any = None) -> None:
        super().__init__(rows)
        self.scalar_value = scalar_value

    async def scalars(self, stmt: Any) -> FakeScalars:
        entity = stmt.column_descriptions[0]["entity"]
        return FakeScalars([r for r in [*self.added, *self.rows] if isinstance(r, entity)])

    async def scalar(self, stmt: Any) -> Any:
        if self.scalar_value is not None:
            return self.scalar_value
        entity = stmt.column_descriptions[0]["entity"]
        for found in [*self.added, *self.rows]:
            if isinstance(found, entity):
                return found
        return None

    async def get(self, model: Any, ident: Any) -> Any:
        for obj in [*self.added, *self.rows]:
            if isinstance(obj, model) and getattr(obj, "id", None) == ident:
                return obj
        return None


def make_scan(**overrides: Any) -> Scan:
    now = utcnow()
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "application_id": uuid.uuid4(),
        "version_id": uuid.uuid4(),
        "target_id": None,
        "kind": ScanKind.SAST,
        "state": ScanState.COMPLETED,
        "created_at": now,
        "started_at": now,
        "finished_at": now,
    }
    values.update(overrides)
    return Scan(**values)


async def test_compute_scan_delta_reads_the_history_of_both_scans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    older = make_scan()
    newer = make_scan(application_id=older.application_id)
    history = {
        older.id: [row("Fixed one", hash_code="f1"), row("Stays", hash_code="s1")],
        newer.id: [row("Stays", hash_code="s1"), row("Added", hash_code="a1")],
    }
    jobs = {
        older.id: [job("semgrep"), job("gitleaks")],
        newer.id: [job("semgrep")],
    }

    async def fake_findings(session: Any, scan_id: Any, include_inactive: bool = False) -> Any:
        assert include_inactive is True
        return history[scan_id]

    async def fake_jobs(session: Any, scan_id: Any) -> Any:
        return jobs[scan_id]

    monkeypatch.setattr("securescan.domain.history.scan_findings", fake_findings)
    monkeypatch.setattr(vendors, "_jobs_of_scan", fake_jobs)
    delta = await vendors.compute_scan_delta(TypedFakeSession(), newer, older)  # type: ignore[arg-type]
    assert delta is not None and delta.previous is older
    assert keys(delta.result.fixed) == ["f1"]
    assert keys(delta.result.remaining) == ["s1"]
    assert keys(delta.result.new) == ["a1"]
    assert delta.result.compared_tools == ["semgrep"] and delta.result.skipped_tools == ["gitleaks"]


async def test_compute_scan_delta_without_an_earlier_scan_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def nothing(session: Any, scan: Any) -> None:
        return None

    monkeypatch.setattr(vendors, "find_previous_scan", nothing)
    assert await vendors.compute_scan_delta(TypedFakeSession(), make_scan()) is None  # type: ignore[arg-type]


async def test_apply_vendor_context_sets_scope_delta_and_marks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = sample_snapshot("vendor")
    older = make_scan(
        version_id=uuid.uuid4(), finished_at=datetime(2026, 9, 1, 8, tzinfo=timezone.utc)
    )
    newer = make_scan(application_id=older.application_id, target_id=None)
    previous_version = ApplicationVersion(
        id=older.version_id,
        application_id=older.application_id,
        label="v2.3.0",
        label_kind="release",
    )
    result = vendors.compute_delta(
        [row("Old", hash_code="h-old"), row("SQL", hash_code="h-sqli")],
        [row("SQL", hash_code="h-sqli"), row("Cross-site", hash_code="h-xss", severity="critical")],
        compared_tools=["semgrep"],
    )

    async def fake_delta(session: Any, scan: Any, previous: Any = None) -> Any:
        return vendors.ScanDelta(result=result, current=newer, previous=older)

    monkeypatch.setattr(vendors, "compute_scan_delta", fake_delta)
    application = SimpleNamespace(type=AppType.VENDOR, hosting="deployable")
    session = TypedFakeSession(rows=[previous_version], scalar_value="SSR-20260901-PREV01")
    delta = await vendors.apply_vendor_context(session, snapshot, newer, application)  # type: ignore[arg-type]
    assert delta is not None
    assert snapshot.vendor_scope is not None and snapshot.vendor_scope.hosting == "deployable"
    block = snapshot.summary.delta
    assert block is not None
    assert (block.fixed, block.remaining, block.new) == (1, 1, 1)
    assert block.previous_ref == "SSR-20260901-PREV01" and block.previous_version_label == "v2.3.0"
    assert block.previous_scan_date == "2026-09-01T08:00:00Z"
    marks = {f.key: f.vs_previous for f in snapshot.findings}
    assert marks["h-sqli"] == "remaining" and marks["h-xss"] == "new" and marks["h-key"] == ""


async def test_apply_vendor_context_keeps_the_builders_delta_when_nothing_compares(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = sample_snapshot("vendor")
    before = snapshot.summary.delta.model_dump() if snapshot.summary.delta else None
    result = vendors.DeltaResult(notes=["No tool finished and was imported in both scans."])

    async def fake_delta(session: Any, scan: Any, previous: Any = None) -> Any:
        return vendors.ScanDelta(result=result, current=make_scan(), previous=make_scan())

    monkeypatch.setattr(vendors, "compute_scan_delta", fake_delta)
    await vendors.apply_vendor_context(
        TypedFakeSession(), snapshot, make_scan(), SimpleNamespace(hosting="saas")  # type: ignore[arg-type]
    )
    after = snapshot.summary.delta.model_dump() if snapshot.summary.delta else None
    assert after == before
    assert "No tool finished and was imported in both scans." in snapshot.coverage.notes


# --------------------------------------------------------------------------- the vendor scope


def web_target(**overrides: Any) -> Any:
    values: dict[str, Any] = {
        "kind": "url",
        "name": "Portal",
        "locator": "https://portal.vendor.example",
        "environment": UAT,
        "vendor_authorization_artifact_id": uuid.uuid4(),
        "vendor_authorized_from": NOW - timedelta(days=1),
        "vendor_authorized_until": NOW + timedelta(days=2),
        "vendor_contact": "Jo Vendor, jo@vendor.example",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_scope_of_an_authorized_saas_uat_instance() -> None:
    scope = vendors.build_vendor_scope(
        application=SimpleNamespace(hosting="saas"), target=web_target(), now=NOW
    )
    assert scope.hosting == "saas" and scope.hosting_label == "SaaS, hosted by the vendor"
    assert scope.environment == "uat" and scope.environment_label == "UAT"
    assert scope.authorization_required and scope.authorization_state == "Authorized"
    assert scope.authorization_contact == "Jo Vendor, jo@vendor.example"
    assert scope.artefacts == ["Web application: https://portal.vendor.example"]
    assert "authorized it in writing" in scope.rule


def test_scope_of_a_saas_target_without_authorization_is_production() -> None:
    target = web_target(vendor_authorization_artifact_id=None, vendor_contact=None)
    scope = vendors.build_vendor_scope(
        application=SimpleNamespace(hosting="saas"), target=target, now=NOW
    )
    assert scope.environment == "production" and scope.environment_label == "Production"
    assert scope.authorization_state == "Authorization record incomplete"


def test_scope_of_a_deployable_source_scan() -> None:
    target = SimpleNamespace(
        kind="image", name=None, locator="registry.vendor.example/app:1.4", environment=None
    )
    scope = vendors.build_vendor_scope(
        application=SimpleNamespace(hosting="deployable"), target=target, now=NOW
    )
    assert scope.artefacts == ["Container image: registry.vendor.example/app:1.4"]
    assert scope.environment == "" and not scope.authorization_required
    assert scope.hosting == "deployable"


def test_scope_without_a_recorded_hosting_says_so() -> None:
    scope = vendors.build_vendor_scope(
        application=SimpleNamespace(hosting=None), target=None, now=NOW
    )
    assert scope.hosting == "" and "treated as SaaS" in scope.hosting_label
    assert scope.artefacts == []


def test_the_scope_and_delta_details_are_drawn_in_the_vendor_report() -> None:
    snapshot = sample_snapshot("vendor")
    assert "Scope of the assessment" not in render_text(snapshot)  # nothing extra without data
    assert "Delta details" not in render_text(snapshot)

    snapshot.vendor_scope = vendors.build_vendor_scope(
        application=SimpleNamespace(hosting="saas"), target=web_target(), now=NOW
    )
    result = vendors.compute_delta(
        [
            row("Stays", hash_code="s1"),
            row("Triaged", hash_code="t1", severity="medium"),
            row("Back", hash_code="b1", state_now="closed"),
        ],
        [
            row("Stays", hash_code="s1"),
            row("Triaged", hash_code="t1", severity="medium", state_now="false_positive"),
            row("Back", hash_code="b1"),
        ],
        compared_tools=["semgrep"],
    )
    result.skipped_tools = ["gitleaks"]
    result.notes = ["Gitleaks ran in the previous assessment only and is not compared."]
    snapshot.summary.delta = vendors.to_snapshot_delta(
        result, previous_ref="SSR-1", previous_scan_date="2026-09-01T08:00:00Z",
        previous_version_label="v1",
    )
    text = render_text(snapshot)
    assert_outline(
        text,
        [
            "Executive summary",
            "Delta from the last assessment Compared with SSR-1",
            "Scope of the assessment",
            "Hosting SaaS, hosted by the vendor",
            "Supplied for testing Web application: https://portal.vendor.example",
            "Web scan environment UAT",
            "Vendor authorization Authorized",
            "Vendor contact Jo Vendor, jo@vendor.example",
            "Delta details",
            "Compared tools: Semgrep CE.",
            "Gitleaks ran in the previous assessment only and is not compared.",
            "Remaining findings Severity Finding Tool Location High Stays",
            "Reopened findings",
            "Back Semgrep CE src/app.py:10 Was closed in the previous assessment",
            "Triaged out since the previous assessment",
            "Triaged Semgrep CE src/app.py:10 Now false positive",
            "Findings by tool",
        ],
    )


def test_the_application_report_never_draws_the_vendor_blocks() -> None:
    snapshot = sample_snapshot("application")
    snapshot.vendor_scope = vendors.build_vendor_scope(
        application=SimpleNamespace(hosting="saas"), target=web_target(), now=NOW
    )
    assert "Scope of the assessment" not in render_text(snapshot)


def test_the_default_template_check_still_passes_with_the_vendor_partial() -> None:
    problems = renderer.static_problems(renderer.DEFAULT_TEMPLATE_DIR)
    assert problems == []


# --------------------------------------------------------------------------- conditions


def findings() -> list[snap.FindingItem]:
    return sample_snapshot("vendor").findings


def cond(key: str, deadline: Any) -> dict[str, Any]:
    return {"finding_hash": key, "deadline": deadline}


def days(n: int) -> date:
    return TODAY + timedelta(days=n)


def test_conditions_for_open_high_findings_with_future_deadlines_are_accepted() -> None:
    cleaned = vendors.validate_vendor_conditions(
        [cond("h-sqli", days(30)), cond("h-log4j", days(60).isoformat())],
        findings(),
        "conditional",
        TODAY,
    )
    assert cleaned == [
        {"finding_hash": "h-sqli", "deadline": "2026-11-06"},
        {"finding_hash": "h-log4j", "deadline": "2026-12-06"},
    ]


def test_a_deadline_may_be_a_datetime_and_may_be_tomorrow_or_a_year_away() -> None:
    cleaned = vendors.validate_vendor_conditions(
        [
            cond("h-sqli", datetime(2026, 10, 8, 12, 0)),
            cond("h-log4j", days(vendors.MAX_DEADLINE_DAYS)),
        ],
        findings(),
        "conditional",
        TODAY,
    )
    assert [c["deadline"] for c in cleaned] == ["2026-10-08", days(365).isoformat()]


def errors_of(
    conditions: list[dict[str, Any]], verdict: str = "conditional"
) -> list[dict[str, Any]]:
    with pytest.raises(UnprocessableEntity) as raised:
        vendors.validate_vendor_conditions(conditions, findings(), verdict, TODAY)
    assert raised.value.code == "report.invalid_conditions"
    return list(raised.value.errors or [])


@pytest.mark.parametrize(
    "deadline",
    [TODAY, days(-1), "2001-01-01", days(366), "2999-01-01", "soon", None, ""],
)
def test_a_deadline_must_be_after_today_and_within_a_year(deadline: Any) -> None:
    errors = errors_of([cond("h-sqli", deadline)])
    assert [e["field"] for e in errors] == ["conditions.0.deadline"]


def test_a_condition_must_name_an_open_finding_of_the_report() -> None:
    errors = errors_of([cond("no-such-finding", days(10))])
    assert errors[0]["field"] == "conditions.0.finding_hash"
    assert "not an open finding" in errors[0]["message"]


@pytest.mark.parametrize("key", ["h-xss", "h-pw", "h-import", "h-lib"])
def test_only_high_findings_can_carry_a_condition(key: str) -> None:
    """h-xss is Critical, h-pw Medium, h-lib Low, h-import Info."""
    errors = errors_of([cond(key, days(10))])
    assert errors[0]["field"] == "conditions.0.finding_hash"
    assert "only open High findings" in errors[0]["message"]


def test_a_finding_triaged_out_cannot_carry_a_condition() -> None:
    errors = errors_of([cond("h-md5", days(10))])  # false positive: not among the open findings
    assert "not an open finding" in errors[0]["message"]


def test_a_finding_is_listed_once() -> None:
    errors = errors_of([cond("h-sqli", days(10)), cond("h-sqli", days(20))])
    assert errors == [{"field": "conditions.1.finding_hash", "message": "listed twice"}]


def test_every_problem_is_reported_with_its_position() -> None:
    errors = errors_of([cond("h-sqli", "2001-01-01"), cond("h-pw", days(10)), cond("zzz", None)])
    assert [e["field"] for e in errors] == [
        "conditions.0.deadline",
        "conditions.1.finding_hash",
        "conditions.2.finding_hash",
        "conditions.2.deadline",
    ]


@pytest.mark.parametrize("verdict", ["pass", "fail", "pending"])
def test_conditions_need_a_conditional_verdict(verdict: str) -> None:
    with pytest.raises(UnprocessableEntity) as raised:
        vendors.validate_vendor_conditions(
            [cond("h-sqli", days(10))], findings(), verdict, TODAY
        )
    assert raised.value.code == "vendor.conditions_need_conditional_verdict"


@pytest.mark.parametrize("verdict", ["pass", "conditional", "fail"])
def test_no_conditions_is_always_valid(verdict: str) -> None:
    assert vendors.validate_vendor_conditions([], findings(), verdict, TODAY) == []


def test_single_condition_problems_are_reported_before_the_verdict_problem() -> None:
    with pytest.raises(UnprocessableEntity) as raised:
        vendors.validate_vendor_conditions(
            [cond("zzz", days(10))], findings(), "fail", TODAY
        )
    assert raised.value.code == "report.invalid_conditions"


def test_high_findings_without_a_condition_are_listed() -> None:
    missing = vendors.findings_without_condition(
        findings(), [{"finding_hash": "h-sqli", "deadline": "2026-12-01"}]
    )
    assert sorted(f.key for f in missing) == ["h-key", "h-log4j"]


# ------------------------------------------------------------------------ the review applies them


async def reviewed_report() -> tuple[FakeSession, Any]:
    db = FakeSession()
    report = make_report()  # a vendor report; the stored snapshot is the sample vendor snapshot
    await store_files(db, report)
    db.rows.append(report)
    return db, report


async def apply(db: FakeSession, report: Any, **request: Any) -> Any:
    user = SimpleNamespace(id=uuid.uuid4(), name="A. Analyst", email=None, oid="o")
    return await report_service.apply_review(
        db,  # type: ignore[arg-type]
        report,
        user,
        report_service.ReviewRequest(**request),
    )


async def test_a_vendor_review_refuses_conditions_on_a_failing_verdict() -> None:
    db, report = await reviewed_report()
    with pytest.raises(UnprocessableEntity) as raised:
        await apply(
            db,
            report,
            decision="confirm",
            conditions=[{"finding_hash": "h-sqli", "deadline": future(30)}],
        )
    assert raised.value.code == "vendor.conditions_need_conditional_verdict"
    assert report.review_state == ReviewState.AUTOMATIC


async def test_a_vendor_review_refuses_a_condition_on_a_critical_finding() -> None:
    db, report = await reviewed_report()
    with pytest.raises(UnprocessableEntity) as raised:
        await apply(
            db,
            report,
            decision="override",
            verdict="conditional",
            reason="The Critical finding is in a test-only file",
            conditions=[{"finding_hash": "h-xss", "deadline": future(30)}],
        )
    assert raised.value.code == "report.invalid_conditions"


async def test_a_vendor_review_records_conditions_of_a_conditional_pass() -> None:
    db, report = await reviewed_report()
    snapshot = await apply(
        db,
        report,
        decision="override",
        verdict="conditional",
        reason="Agreed with the vendor on 7 October",
        conditions=[
            {"finding_hash": "h-sqli", "deadline": future(30)},
            {"finding_hash": "h-key", "deadline": future(45)},
            {"finding_hash": "h-log4j", "deadline": future(60)},
        ],
        internal_notes="private",
    )
    assert report.review_state == ReviewState.REVIEWED
    assert [c["finding_hash"] for c in report.conditions] == ["h-sqli", "h-key", "h-log4j"]
    assert [c.deadline for c in snapshot.review.conditions] == [
        future(30), future(45), future(60)
    ]
    assert snapshot.summary.verdict == "conditional"


async def test_an_application_report_keeps_the_general_condition_rules() -> None:
    db = FakeSession()
    report = make_report(kind=ReportKind.APPLICATION)
    await store_files(db, report)
    db.rows.append(report)
    snapshot = await apply(
        db,
        report,
        decision="confirm",
        conditions=[{"finding_hash": "h-pw", "deadline": future(10)}],
    )
    assert [c.finding_hash for c in snapshot.review.conditions] == ["h-pw"]


# --------------------------------------------------------------------------- vendor copy


def test_a_vendor_copy_has_no_internal_notes() -> None:
    snapshot = sample_snapshot("vendor")
    assert snapshot.review.internal_notes == "Discussed with the vendor on a call."
    copy = vendors.vendor_copy_snapshot(snapshot)
    assert copy.vendor_copy is True
    assert copy.review.internal_notes == ""
    assert snapshot.review.internal_notes != ""  # the original is untouched
    assert snapshot.vendor_copy is False
    assert "Discussed with the vendor" not in snap.canonical_json(copy).decode("utf-8")


def test_a_vendor_copy_drops_the_companys_own_ratings_and_keeps_the_verdict() -> None:
    snapshot = sample_snapshot("vendor")
    assert snapshot.vendor is not None and snapshot.vendor.risk_tier == "high"
    assert snapshot.header.criticality == "high"
    copy = vendors.vendor_copy_snapshot(snapshot)
    assert copy.vendor is not None and copy.vendor.risk_tier is None
    assert copy.header.criticality is None
    assert copy.vendor.name == "Example Software Ltd"
    assert copy.summary.verdict == "conditional"
    assert copy.review.override_reason == snapshot.review.override_reason
    assert [c.finding_hash for c in copy.review.conditions] == ["h-sqli", "h-log4j"]
    assert len(copy.findings) == len(snapshot.findings)


def test_the_rendered_vendor_copy_omits_the_notes_and_the_ratings() -> None:
    full = render_text(sample_snapshot("vendor"))
    assert "Internal notes Discussed with the vendor on a call." in full
    assert "(criticality: high)" in full
    copy = render_text(vendors.vendor_copy_snapshot(sample_snapshot("vendor")))
    assert "Internal notes" not in copy
    assert "Discussed with the vendor" not in copy
    assert "criticality" not in copy
    assert "Reason for override The Critical finding is a false positive" in copy
    assert "Verdict decision Conditional pass (overridden)" in copy


def test_the_copy_is_stored_under_the_name_of_its_own_hash() -> None:
    report = make_report(ref="SSR-20261007-ABC123")
    html_name, pdf_name = vendors.vendor_copy_filenames(report, "ab" * 32)
    assert html_name == "SSR-20261007-ABC123-vendor-copy-abababababab.html"
    assert pdf_name == "SSR-20261007-ABC123-vendor-copy-abababababab.pdf"


def test_a_vendor_copy_needs_a_ready_reviewed_vendor_report() -> None:
    reviewed = make_report(review_state=ReviewState.REVIEWED)
    vendors.require_copy_ready(reviewed)  # no problem
    with pytest.raises(UnprocessableEntity) as wrong_kind:
        vendors.require_copy_ready(make_report(kind=ReportKind.APPLICATION))
    assert wrong_kind.value.code == "vendor.copy_not_available"
    with pytest.raises(Conflict) as pending:
        vendors.require_copy_ready(make_report(status="pending"))
    assert pending.value.code == "report.not_ready"
    with pytest.raises(Conflict) as unreviewed:
        vendors.require_copy_ready(make_report())
    assert unreviewed.value.code == "vendor.copy_needs_review"


# --------------------------------------------------------------------------- intake


@pytest.fixture
def repositories(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The lookups the intake uses, answered from a dict instead of a database."""
    found: dict[str, Any] = {"vendor": None, "application": None, "version": None}

    async def vendor_by_name(session: Any, name: str, exclude_id: Any = None) -> Any:
        return found["vendor"]

    async def application_by_name(session: Any, name: str, exclude_id: Any = None) -> Any:
        return found["application"]

    async def version_by_label(session: Any, application_id: Any, label: str) -> Any:
        return found["version"]

    module = "securescan.db.repositories.applications"
    monkeypatch.setattr(f"{module}.find_vendor_by_name", vendor_by_name)
    monkeypatch.setattr(f"{module}.find_application_by_name", application_by_name)
    monkeypatch.setattr(f"{module}.find_version_by_label", version_by_label)
    return found


def make_vendor(name: str = "Example Software Ltd") -> Vendor:
    return Vendor(id=uuid.uuid4(), name=name, created_at=utcnow(), updated_at=utcnow())


def make_application(vendor: Vendor, **overrides: Any) -> Application:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "name": "Payroll Suite",
        "type": AppType.VENDOR,
        "vendor_id": vendor.id,
        "vendor_product": "Payroll Suite",
        "hosting": "saas",
        "tags": [],
        "confirmed": True,
        "automatic": False,
        "cached_counts": {},
        "created_at": utcnow(),
        "updated_at": utcnow(),
    }
    values.update(overrides)
    return Application(**values)


async def intake(session: FakeSession, **overrides: Any) -> vendors.VendorIntake:
    values: dict[str, Any] = {
        "user": SimpleNamespace(id=uuid.uuid4()),
        "vendor_id": None,
        "vendor_name": "Example Software Ltd",
        "product": "Payroll Suite",
        "version_label": "2.4.0",
        "version_kind": "release",
        "hosting": "saas",
    }
    values.update(overrides)
    return await vendors.get_or_create_vendor_product(session, **values)  # type: ignore[arg-type]


async def test_intake_creates_the_vendor_the_product_and_the_version(
    repositories: dict[str, Any],
) -> None:
    session = FakeSession()
    result = await intake(
        session, risk_tier="high", contact_email="sec@vendor.example", criticality="high"
    )
    assert result.vendor_created and result.application_created and result.version_created
    assert result.vendor.name == "Example Software Ltd" and result.vendor.risk_tier == "high"
    app_row = result.application
    assert app_row.type == AppType.VENDOR and app_row.vendor_id == result.vendor.id
    assert app_row.name == "Payroll Suite" and app_row.vendor_product == "Payroll Suite"
    assert app_row.hosting == "saas" and app_row.criticality == "high"
    assert result.version.application_id == app_row.id
    assert result.version.label == "2.4.0" and result.version.label_kind == "release"
    assert len(session.added) == 3


async def test_intake_reuses_what_exists_and_adds_the_new_version(
    repositories: dict[str, Any],
) -> None:
    vendor = make_vendor()
    application = make_application(vendor)
    repositories.update(vendor=vendor, application=application)
    session = FakeSession()
    result = await intake(session, version_label="2.5.0")
    assert not result.vendor_created and not result.application_created
    assert result.version_created and result.application is application
    assert [type(o).__name__ for o in session.added] == ["ApplicationVersion"]


async def test_intake_by_vendor_id_and_an_existing_version(
    repositories: dict[str, Any],
) -> None:
    vendor = make_vendor()
    application = make_application(vendor)
    version = ApplicationVersion(
        id=uuid.uuid4(), application_id=application.id, label="2.4.0", label_kind="release"
    )
    repositories.update(application=application, version=version)
    session = FakeSession(rows=[vendor])
    result = await intake(session, vendor_id=vendor.id, vendor_name=None)
    assert result.vendor is vendor and result.version is version
    assert session.added == []


async def test_intake_cannot_change_the_recorded_hosting(repositories: dict[str, Any]) -> None:
    vendor = make_vendor()
    repositories.update(vendor=vendor, application=make_application(vendor, hosting="saas"))
    with pytest.raises(Conflict) as raised:
        await intake(FakeSession(), hosting="deployable")
    assert raised.value.code == "vendor.hosting_mismatch"


async def test_intake_records_the_hosting_of_a_product_that_has_none(
    repositories: dict[str, Any],
) -> None:
    vendor = make_vendor()
    application = make_application(vendor, hosting=None)
    repositories.update(vendor=vendor, application=application)
    await intake(FakeSession(), hosting="deployable")
    assert application.hosting == "deployable"


async def test_intake_refuses_a_product_name_used_by_another_vendor_or_an_internal_app(
    repositories: dict[str, Any],
) -> None:
    vendor = make_vendor()
    other = make_vendor("Other Ltd")
    repositories.update(vendor=vendor, application=make_application(other))
    with pytest.raises(Conflict) as raised:
        await intake(FakeSession())
    assert raised.value.code == "application.duplicate_name"
    repositories.update(application=make_application(vendor, type=AppType.INTERNAL))
    with pytest.raises(Conflict):
        await intake(FakeSession())


async def test_intake_needs_a_vendor_and_a_hosting(repositories: dict[str, Any]) -> None:
    with pytest.raises(UnprocessableEntity) as no_vendor:
        await intake(FakeSession(), vendor_name="  ")
    assert no_vendor.value.code == "vendor.vendor_required"
    with pytest.raises(UnprocessableEntity) as no_hosting:
        await intake(FakeSession(), hosting="on-prem")
    assert no_hosting.value.code == "vendor.hosting_required"
    with pytest.raises(NotFound) as unknown:
        await intake(FakeSession(), vendor_id=uuid.uuid4(), vendor_name=None)
    assert unknown.value.code == "vendor.not_found"


async def test_intake_refuses_an_archived_vendor(repositories: dict[str, Any]) -> None:
    vendor = make_vendor()
    vendor.archived_at = utcnow()
    repositories["vendor"] = vendor
    with pytest.raises(UnprocessableEntity) as raised:
        await intake(FakeSession())
    assert raised.value.code == "vendor.archived"


# --------------------------------------------------------------------------- API


def build_client(db: FakeSession, user: CurrentUser | None = None) -> TestClient:
    app = FastAPI()
    install_problem_handlers(app)
    app.include_router(api.router, prefix="/api/v1")

    async def session() -> AsyncIterator[FakeSession]:
        yield db

    app.dependency_overrides[get_session] = session
    app.dependency_overrides[current_user] = lambda: user or make_user(UserRole.ANALYST)
    return TestClient(app)


def audit_actions(db: FakeSession) -> list[str]:
    return [e.action for e in db.added if isinstance(e, AuditEvent)]


def api_world() -> tuple[TypedFakeSession, Vendor, Application, ApplicationVersion, Any]:
    vendor = make_vendor()
    application = make_application(vendor)
    version = ApplicationVersion(
        id=uuid.uuid4(), application_id=application.id, label="2.4.0", label_kind="release"
    )
    report = make_report(application_id=application.id, version_id=version.id)
    db = TypedFakeSession(rows=[report, vendor, application, version])
    return db, vendor, application, version, report


def test_the_route_order_keeps_the_fixed_paths_before_the_report_id() -> None:
    paths = [route.path for route in api.router.routes]  # type: ignore[attr-defined]
    parameter = paths.index("/vendor-assessments/{report_id}")
    assert paths.index("/vendor-assessments/delta") < parameter
    assert paths.index("/vendor-assessments/intake") < parameter


def test_intake_endpoint_creates_the_rows_and_audits_them(
    repositories: dict[str, Any],
) -> None:
    db = TypedFakeSession()
    response = build_client(db).post(
        "/api/v1/vendor-assessments/intake",
        json={
            "vendor_name": "Example Software Ltd",
            "product": "Payroll Suite",
            "version": "2.4.0",
            "hosting": "saas",
            "risk_tier": "high",
        },
    )
    assert response.status_code == 201, response.text
    data = response.json()
    assert data["vendor"]["name"] == "Example Software Ltd"
    assert data["application"]["type"] == "vendor" and data["application"]["hosting"] == "saas"
    assert data["version"]["label"] == "2.4.0"
    assert data["vendor_created"] and data["application_created"] and data["version_created"]
    assert any("written authorization" in step for step in data["next_steps"])
    assert audit_actions(db) == [
        "vendor.create",
        "application.create",
        "version.create",
        "vendor.intake",
    ]
    assert db.commits == 1


def test_intake_endpoint_validates_the_form(repositories: dict[str, Any]) -> None:
    client = build_client(TypedFakeSession())
    url = "/api/v1/vendor-assessments/intake"
    base = {"product": "P", "version": "1", "hosting": "saas"}
    assert client.post(url, json=base).status_code == 422  # no vendor
    named = {**base, "vendor_name": "V"}
    assert client.post(url, json={**named, "hosting": "cloud"}).status_code == 422
    no_hosting = {"vendor_name": "V", "product": "P", "version": "1"}
    assert client.post(url, json=no_hosting).status_code == 422


def test_listing_shows_vendor_product_and_version_names() -> None:
    db, vendor, application, version, report = api_world()
    response = build_client(db).get("/api/v1/vendor-assessments")
    assert response.status_code == 200, response.text
    item = response.json()["items"][0]
    assert item["id"] == str(report.id) and item["kind"] == "vendor"
    assert item["vendor_name"] == "Example Software Ltd" and item["product"] == "Payroll Suite"
    assert item["hosting"] == "saas" and item["version_label"] == "2.4.0"


async def test_detail_shows_the_delta_scope_and_the_conditions_still_to_set() -> None:
    db, vendor, application, version, report = api_world()
    await store_files(db, report)  # stores the sample vendor snapshot
    report.conditions = [{"finding_hash": "h-sqli", "deadline": "2999-01-01"}]
    response = build_client(db).get(f"/api/v1/vendor-assessments/{report.id}")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["counts"]["high"] == 3 and data["counts"]["critical"] == 1
    assert data["delta"]["fixed"] == 1 and data["delta"]["new"] == 6
    assert sorted(c["key"] for c in data["condition_candidates"]) == ["h-key", "h-log4j", "h-sqli"]
    assert sorted(c["key"] for c in data["missing_conditions"]) == ["h-key", "h-log4j"]
    rules = data["condition_rules"]
    assert rules["severity"] == "high" and rules["verdict"] == "conditional"
    assert date.fromisoformat(rules["earliest_deadline"]) == utcnow().date() + timedelta(days=1)
    assert data["review"]["verdict"] == "conditional"


def test_detail_of_a_pending_assessment_has_no_snapshot_parts() -> None:
    db, vendor, application, version, report = api_world()
    report.status = "pending"
    report.snapshot_artifact_id = None
    data = build_client(db).get(f"/api/v1/vendor-assessments/{report.id}").json()
    assert data["delta"] is None and data["counts"] is None and data["condition_candidates"] == []


def test_an_application_report_is_not_an_assessment() -> None:
    db, vendor, application, version, report = api_world()
    report.kind = ReportKind.APPLICATION
    response = build_client(db).get(f"/api/v1/vendor-assessments/{report.id}")
    assert response.status_code == 404
    assert response.json()["code"] == "vendor.not_an_assessment"


def test_creating_an_assessment_needs_a_vendor_application() -> None:
    internal = Application(
        id=uuid.uuid4(), name="Intranet", type=AppType.INTERNAL, tags=[], cached_counts={}
    )
    scan = make_scan(application_id=internal.id)
    db = TypedFakeSession(rows=[scan, internal])
    response = build_client(db).post("/api/v1/vendor-assessments", json={"scan_id": str(scan.id)})
    assert response.status_code == 422
    assert response.json()["code"] == "vendor.not_a_vendor_application"
    assert audit_actions(db) == []


def test_creating_an_assessment_needs_exactly_one_of_scan_or_version() -> None:
    client = build_client(TypedFakeSession())
    assert client.post("/api/v1/vendor-assessments", json={}).status_code == 422
    both = {"scan_id": str(uuid.uuid4()), "version_id": str(uuid.uuid4())}
    assert client.post("/api/v1/vendor-assessments", json=both).status_code == 422


def test_creating_an_assessment_for_an_unfinished_scan_is_refused() -> None:
    scan = make_scan(state=ScanState.RUNNING)
    db = TypedFakeSession(rows=[scan])
    response = build_client(db).post("/api/v1/vendor-assessments", json={"scan_id": str(scan.id)})
    assert response.status_code == 409
    assert response.json()["code"] == "report.scan_not_finished"


def test_creating_an_assessment_queues_a_vendor_report(monkeypatch: pytest.MonkeyPatch) -> None:
    db, vendor, application, version, _ = api_world()
    scan = make_scan(application_id=application.id, version_id=version.id)
    db.rows.append(scan)
    template = SimpleNamespace(id=uuid.uuid4(), version=1, name="default-sonacomstar")
    queued: list[Any] = []

    async def default_template(session: Any, kind: Any) -> Any:
        assert kind == ReportKind.VENDOR
        return template

    async def fake_defer(task: Any, **kwargs: Any) -> int:
        queued.append(kwargs)
        return 1

    monkeypatch.setattr(report_service, "get_default_template", default_template)
    monkeypatch.setattr(api, "defer", fake_defer)
    response = build_client(db).post(
        "/api/v1/vendor-assessments", json={"scan_id": str(scan.id), "vendor_copy": True}
    )
    assert response.status_code == 202, response.text
    data = response.json()
    assert data["kind"] == "vendor" and data["status"] == "pending" and data["vendor_copy"]
    assert data["vendor_name"] == "Example Software Ltd"
    assert queued == [{"report_id": data["id"]}]
    assert audit_actions(db) == ["vendor_assessment.create"]


def test_the_delta_endpoint_compares_two_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    older = make_scan()
    newer = make_scan(application_id=older.application_id)
    db = TypedFakeSession(rows=[older, newer])
    result = vendors.compute_delta(
        [row("Gone", hash_code="g"), row("Stays", hash_code="s")],
        [row("Stays", hash_code="s"), row("Added", hash_code="a")],
        compared_tools=["semgrep"],
    )
    result.notes = ["a note"]
    calls: list[Any] = []

    async def fake_delta(session: Any, scan: Any, previous: Any = None) -> Any:
        calls.append((scan, previous))
        return vendors.ScanDelta(result=result, current=scan, previous=older)

    monkeypatch.setattr(vendors, "compute_scan_delta", fake_delta)
    response = build_client(db).get(
        "/api/v1/vendor-assessments/delta",
        params={"scan_id": str(newer.id), "previous_scan_id": str(older.id)},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["counts"] == {"fixed": 1, "remaining": 1, "new": 1, "reopened": 0, "triaged": 0}
    assert [f["title"] for f in data["fixed"]] == ["Gone"]
    assert [f["title"] for f in data["new"]] == ["Added"]
    assert data["compared_tools"] == ["Semgrep CE"] and data["notes"] == ["a note"]
    assert data["scan_id"] == str(newer.id) and data["previous_scan_id"] == str(older.id)
    assert data["truncated"] is False
    assert calls == [(newer, older)]


def test_the_delta_endpoint_compares_two_versions(monkeypatch: pytest.MonkeyPatch) -> None:
    app_id = uuid.uuid4()
    old_version, new_version = uuid.uuid4(), uuid.uuid4()
    older = make_scan(application_id=app_id, version_id=old_version)
    newer = make_scan(application_id=app_id, version_id=new_version)

    class VersionScans(TypedFakeSession):
        def __init__(self) -> None:
            super().__init__(rows=[older, newer])
            self.queue = [newer, older]

        async def scalar(self, stmt: Any) -> Any:
            return self.queue.pop(0)

    seen: list[Any] = []

    async def fake_delta(session: Any, scan: Any, previous: Any = None) -> Any:
        seen.append((scan, previous))
        return vendors.ScanDelta(result=vendors.DeltaResult(), current=scan, previous=previous)

    monkeypatch.setattr(vendors, "compute_scan_delta", fake_delta)
    response = build_client(VersionScans()).get(
        "/api/v1/vendor-assessments/delta",
        params={"version_id": str(new_version), "against_version_id": str(old_version)},
    )
    assert response.status_code == 200, response.text
    assert seen == [(newer, older)]
    assert response.json()["version_id"] == str(new_version)
    assert response.json()["previous_version_id"] == str(old_version)


def test_the_delta_endpoint_needs_its_inputs_and_a_previous_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = build_client(TypedFakeSession())
    assert client.get("/api/v1/vendor-assessments/delta").status_code == 422
    only_version = client.get(
        "/api/v1/vendor-assessments/delta", params={"version_id": str(uuid.uuid4())}
    )
    assert only_version.json()["code"] == "vendor.delta_input"

    scan = make_scan()
    other = make_scan()
    mismatch = build_client(TypedFakeSession(rows=[scan, other])).get(
        "/api/v1/vendor-assessments/delta",
        params={"scan_id": str(scan.id), "previous_scan_id": str(other.id)},
    )
    assert mismatch.json()["code"] == "vendor.delta_applications"

    async def nothing(session: Any, scan: Any, previous: Any = None) -> None:
        return None

    monkeypatch.setattr(vendors, "compute_scan_delta", nothing)
    first = build_client(TypedFakeSession(rows=[scan])).get(
        "/api/v1/vendor-assessments/delta", params={"scan_id": str(scan.id)}
    )
    assert first.status_code == 404 and first.json()["code"] == "vendor.no_previous_scan"


def test_the_hosting_endpoint_reports_the_rule_for_a_target() -> None:
    db, vendor, application, version, _ = api_world()
    row_target = Target(
        id=uuid.uuid4(),
        version_id=version.id,
        kind=TargetKind.URL,
        locator="https://portal.vendor.example",
        environment=PROD,
        host_approved=False,
    )
    db.rows.append(row_target)
    url = f"/api/v1/vendor-assessments/targets/{row_target.id}/hosting"
    data = build_client(db).get(url).json()
    assert data["hosting"] == "saas" and data["effective_environment"] == "production"
    assert data["authorization_required"] and data["authorization"] == "missing"
    assert data["authorization_label"] == "No authorization record"
    assert data["full_scans_allowed"] is False


# ------------------------------------------------------------------- the vendor copy over the API


async def copy_world(**report_values: Any) -> tuple[TypedFakeSession, Any, vendors.VendorCopyFiles]:
    db, vendor, application, version, report = api_world()
    report.review_state = ReviewState.REVIEWED
    for name, value in report_values.items():
        setattr(report, name, value)
    html = await save_bytes(
        db,  # type: ignore[arg-type]
        kind=ArtifactKind.REPORT_FILE,
        data=b"<html><body>copy</body></html>",
        filename="copy.html",
        content_type="text/html",
        owner_type="report",
        owner_id=report.id,
    )
    pdf = await save_bytes(
        db,  # type: ignore[arg-type]
        kind=ArtifactKind.REPORT_FILE,
        data=blank_pdf(),
        filename="copy.pdf",
        content_type="application/pdf",
        owner_type="report",
        owner_id=report.id,
    )
    assert isinstance(html, Artifact)
    return db, report, vendors.VendorCopyFiles(html=html, pdf=pdf, sha256="c" * 64, created=True)


async def test_the_vendor_copy_html_is_served_with_the_strict_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db, report, files = await copy_world()

    async def fake_render(session: Any, rep: Any) -> Any:
        return files

    monkeypatch.setattr(vendors, "render_vendor_copy", fake_render)
    response = build_client(db).get(f"/api/v1/vendor-assessments/{report.id}/html?copy=vendor")
    assert response.status_code == 200, response.text
    assert response.content == b"<html><body>copy</body></html>"
    assert response.headers["content-security-policy"].startswith("default-src 'none'")
    assert response.headers["x-frame-options"] == "SAMEORIGIN"
    event = next(e for e in db.added if isinstance(e, AuditEvent))
    assert event.action == "report.vendor_copy_view" and event.detail["copy_sha256"] == "c" * 64


async def test_the_vendor_copy_pdf_is_stamped_and_audited(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.reports.watermark import pdf_text

    db, report, files = await copy_world()

    async def fake_render(session: Any, rep: Any) -> Any:
        return files

    monkeypatch.setattr(vendors, "render_vendor_copy", fake_render)
    response = build_client(db, make_user()).get(
        f"/api/v1/vendor-assessments/{report.id}/pdf?copy=vendor"
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/pdf"
    assert "vendor-copy.pdf" in response.headers["content-disposition"]
    assert "Test User" in pdf_text(response.content)
    assert "report.vendor_copy_download" in audit_actions(db)


async def test_the_vendor_copy_needs_the_copy_parameter_and_a_reviewed_report() -> None:
    db, report, files = await copy_world(review_state=ReviewState.AUTOMATIC)
    client = build_client(db)
    assert client.get(f"/api/v1/vendor-assessments/{report.id}/html").status_code == 422
    assert client.get(f"/api/v1/vendor-assessments/{report.id}/html?copy=other").status_code == 422
    refused = client.get(f"/api/v1/vendor-assessments/{report.id}/pdf?copy=vendor")
    assert refused.status_code == 409 and refused.json()["code"] == "vendor.copy_needs_review"
    assert audit_actions(db) == []
