"""M4 against a real database: history append and refresh, history API and CSV, results, policies,
accounts (DefectDojo itself is replaced by small fakes; the real thing is covered by the contract test)."""

from __future__ import annotations

import csv
import io
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select

from securescan.api import history as history_api
from securescan.db.models.applications import Application
from securescan.db.models.audit import AuditEvent
from securescan.db.models.enums import (
    AppType,
    ImportState,
    JobState,
    ScanKind,
    ScanState,
    ScanTrigger,
    UserRole,
    Verdict,
)
from securescan.db.models.jobs import ScanJob
from securescan.db.models.scans import Scan
from securescan.db.models.users import User
from securescan.db.models.versions import ApplicationVersion
from securescan.db.session import session_scope
from securescan.domain.accounts import ensure_account
from securescan.domain.history import (
    append_job_history,
    refresh_finding_states,
    scan_findings,
)
from securescan.domain.policy import evaluate_scan
from securescan.util import new_id, utcnow
from tests.unit.test_dd_accounts import FakeDD

pytestmark = pytest.mark.integration

Login = Callable[[UserRole], Awaitable[httpx.AsyncClient]]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


def finding(finding_id: int, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": finding_id,
        "title": f"Finding {finding_id}",
        "severity": SEVERITIES[finding_id % 5],
        "active": True,
        "verified": False,
        "duplicate": False,
        "false_p": False,
        "out_of_scope": False,
        "is_mitigated": False,
        "risk_accepted": False,
        "cwe": 79,
        "file_path": f"src/file{finding_id % 7}.js",
        "line": finding_id,
        "hash_code": f"{finding_id:064d}",
    }
    base.update(overrides)
    return base


async def seed(
    db: Any, *, job_state: JobState = JobState.COMPLETED, import_state: ImportState = ImportState.IMPORTED
) -> tuple[Application, ApplicationVersion, Scan, ScanJob]:
    application = Application(id=new_id(), name=f"js-planted-{new_id()}", type=AppType.INTERNAL)
    db.add(application)
    await db.flush()
    version = ApplicationVersion(
        id=new_id(), application_id=application.id, label="main", label_kind="branch"
    )
    db.add(version)
    await db.flush()
    scan = Scan(
        id=new_id(),
        application_id=application.id,
        version_id=version.id,
        profile_name="code-standard",
        profile_version=1,
        kind=ScanKind.SAST,
        trigger=ScanTrigger.USER,
        state=ScanState.COMPLETED,
        finished_at=utcnow(),
    )
    db.add(scan)
    await db.flush()
    job = ScanJob(
        id=new_id(),
        scan_id=scan.id,
        tool="semgrep",
        state=job_state,
        import_state=import_state,
        dd_test_id=11,
        dd_imported_at=utcnow(),
        finished_at=utcnow(),
        counts={"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0, "total": 2},
    )
    db.add(job)
    await db.flush()
    return application, version, scan, job


# --- history append, filters, CSV --------------------------------------------------------------------------------------


async def test_history_append_is_idempotent_and_the_csv_streams_every_row(
    api_as: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = await api_as(UserRole.ANALYST)
    total = 1200
    findings = [finding(i) for i in range(1, total + 1)]
    findings.append(finding(total + 1, title="=cmd|' /C calc'!A0", severity="High"))
    async with session_scope() as db:
        application, version, scan, job = await seed(db)
        first = await append_job_history(
            db, job=job, scan=scan, application=application, target_kind="zip",
            findings=findings, scanned_at=utcnow(),
        )
        again = await append_job_history(
            db, job=job, scan=scan, application=application, target_kind="zip",
            findings=findings, scanned_at=utcnow(),
        )
    assert first == total + 1
    assert again == 0  # (job_id, dd_finding_id) is unique

    page = await client.get("/api/v1/history/findings", params={"severity": "high", "limit": 5})
    assert page.status_code == 200, page.text
    assert len(page.json()["items"]) == 5
    assert page.json()["next_cursor"]
    assert page.json()["items"][0]["severity"] == "high"

    monkeypatch.setattr(history_api, "CSV_BATCH", 100)  # force several keyset batches
    response = await client.get("/api/v1/history/findings.csv", params={"severity": "high"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(response.text.lstrip("\ufeff"))))
    expected_high = sum(1 for f in findings if f["severity"] == "High")
    assert len(rows) == expected_high + 1  # header + every matching row, however many batches
    titles = [r[history_api.CSV_HEADER.index("title")] for r in rows[1:]]
    assert "'=cmd|' /C calc'!A0" in titles
    assert not any(t.startswith("=") for t in titles)

    async with session_scope() as db:
        exported = await db.scalar(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "export.history_csv")
        )
    assert exported == 1


async def test_history_filters_narrow_the_result(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    async with session_scope() as db:
        application, _, scan, job = await seed(db)
        await append_job_history(
            db, job=job, scan=scan, application=application, target_kind="github_repo",
            findings=[
                finding(1, severity="Critical", cwe=89),
                finding(2, severity="High", cwe=79),
                finding(3, severity="High", active=False, false_p=True),
            ],
            scanned_at=utcnow(),
        )
        app_id = application.id
    base = "/api/v1/history/findings"
    assert len((await client.get(base, params={"application_id": str(app_id)})).json()["items"]) == 3
    assert len((await client.get(base, params={"cwe": 89})).json()["items"]) == 1
    assert len((await client.get(base, params={"state_then": "false_positive"})).json()["items"]) == 1
    assert len((await client.get(base, params={"source": "github_repo", "tool": "semgrep"})).json()["items"]) == 3
    assert len((await client.get(base, params={"source": "zip"})).json()["items"]) == 0
    assert (await client.get(base, params={"severity": "urgent"})).status_code == 400
    scans = (await client.get("/api/v1/history/scans", params={"tool": "semgrep"})).json()
    assert len(scans["items"]) == 1
    assert scans["items"][0]["tools"] == ["semgrep"]


# --- state refresh, per-scan reads ---------------------------------------------------------------------------------------------


class RefreshClient:
    async def get_findings_by_ids(self, ids: Any) -> dict[int, dict[str, Any]]:
        # 1 was marked false positive in DefectDojo, 2 is unchanged, 3 no longer exists
        return {
            1: finding(1, active=False, false_p=True),
            2: finding(2),
        }


async def test_state_now_is_refreshed_and_history_is_otherwise_untouched() -> None:
    async with session_scope() as db:
        application, _, scan, job = await seed(db)
        await append_job_history(
            db, job=job, scan=scan, application=application, target_kind="zip",
            findings=[finding(1), finding(2), finding(3)], scanned_at=utcnow(),
        )
        scan_id = scan.id
    async with session_scope() as db:
        stats = await refresh_finding_states(db, RefreshClient(), [1, 2, 3])  # type: ignore[arg-type]
        assert stats.checked == 3 and stats.missing == 1
    async with session_scope() as db:
        rows = {r.dd_finding_id: r for r in (await scan_findings(db, scan_id, include_inactive=True))}
        assert rows[1].state_at_scan == "open" and rows[1].state_now == "false_positive"
        assert rows[2].state_now == "open"
        assert rows[3].state_at_scan == "open" and rows[3].state_now == "deleted"
        assert rows[1].flags_now["false_p"] is True
        assert rows[1].flags_at_scan["false_p"] is False  # the copy at scan time never changes
        still_open = await scan_findings(db, scan_id)
        assert [r.dd_finding_id for r in still_open] == [2]


async def test_scan_findings_lists_critical_first() -> None:
    async with session_scope() as db:
        application, _, scan, job = await seed(db)
        await append_job_history(
            db, job=job, scan=scan, application=application, target_kind="zip",
            findings=[finding(4, severity="Low"), finding(5, severity="Critical"), finding(6, severity="High")],
            scanned_at=utcnow(),
        )
        rows = await scan_findings(db, scan.id)
        assert [r.severity.value for r in rows] == ["critical", "high", "low"]


# --- results, summary, verdict -------------------------------------------------------------------------------------------------


async def test_results_and_summary_reflect_the_verdict(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    async with session_scope() as db:
        application, version, scan, job = await seed(db)
        scan_id, app_id = scan.id, application.id
        verdict = await evaluate_scan(db, scan.id)
    assert verdict == "conditional"  # 2 High

    results = await client.get(f"/api/v1/scans/{scan_id}/results")
    assert results.status_code == 200, results.text
    body = results.json()
    assert body["verdict"] == "conditional"
    assert body["counts"]["high"] == 2
    assert body["import_state"] == "imported"
    assert body["jobs"][0]["defectdojo_url"].endswith("/test/11")

    app_results = await client.get(f"/api/v1/applications/{app_id}/results")
    assert app_results.status_code == 200, app_results.text
    assert app_results.json()["last_verdict"] == "conditional"
    assert app_results.json()["versions"][0]["latest_scan_id"] == str(scan_id)

    summary = await client.get("/api/v1/summary")
    assert summary.status_code == 200, summary.text
    assert summary.json()["latest"][0]["scan_id"] == str(scan_id)
    assert summary.json()["import_queue"]["dead_letters"] == 0


async def test_a_scan_with_an_unimported_job_stays_pending() -> None:
    async with session_scope() as db:
        _, _, scan, job = await seed(db, import_state=ImportState.PENDING)
        assert await evaluate_scan(db, scan.id) == "pending"
        assert scan.verdict == Verdict.PENDING


# --- policies --------------------------------------------------------------------------------------------------------------------------


async def test_policies_are_admin_only_and_change_the_verdict(api_as: Login) -> None:
    analyst = await api_as(UserRole.ANALYST)
    assert (await analyst.get("/api/v1/policies")).status_code == 403
    admin = await api_as(UserRole.ADMIN)
    created = await admin.post(
        "/api/v1/policies",
        json={
            "name": "Strict default",
            "is_default": True,
            "thresholds": {"fail": {"high": 2}, "conditional": {"medium": 1}},
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["version"] == 1
    clash = await admin.post(
        "/api/v1/policies",
        json={"name": "bad", "is_default": True, "data_classification": "public"},
    )
    assert clash.status_code == 422  # exactly one scope
    async with session_scope() as db:
        _, _, scan, _ = await seed(db)
        assert await evaluate_scan(db, scan.id) == "fail"  # 2 High reach the strict limit
        assert scan.verdict_detail["policy"]["name"] == "Strict default"
    changed = await admin.patch(
        f"/api/v1/policies/{created.json()['id']}",
        json={"thresholds": {"fail": {"high": 3}, "conditional": {"high": 1}}},
    )
    assert changed.json()["version"] == 2


# --- accounts ------------------------------------------------------------------------------------------------------------------------------


async def test_first_provisioning_shows_the_password_once(api_as: Login) -> None:
    client = await api_as(UserRole.ANALYST)
    dd = FakeDD()
    async with session_scope() as db:
        user = (await db.scalars(select(User))).one()
        user.upn = "test.analyst@sona.example"
        assert await ensure_account(db, dd, user) is True  # type: ignore[arg-type]
    first = (await client.get("/api/v1/me/defectdojo-account")).json()
    assert first["status"] == "ready"
    assert first["username"] == "test.analyst"
    assert first["initial_password"] == dd.created[0]["password"]
    second = (await client.get("/api/v1/me/defectdojo-account")).json()
    assert second["initial_password"] is None
    assert second["password_shown"] is True
    async with session_scope() as db:
        shown = await db.scalar(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "defectdojo_account.password_shown")
        )
    assert shown == 1
