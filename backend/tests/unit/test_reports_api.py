from __future__ import annotations

import csv
import io
import uuid
from collections.abc import AsyncIterator
from datetime import date, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pypdf import PdfWriter

from securescan.api import reports as reports_api
from securescan.api.problems import UnprocessableEntity, install_problem_handlers
from securescan.auth.roles import CurrentUser, current_user
from securescan.db.models.audit import AuditEvent
from securescan.db.models.enums import ArtifactKind, ReportKind, ReviewState, UserRole, Verdict
from securescan.db.models.reports import Report
from securescan.db.session import get_session
from securescan.domain import reports as report_service
from securescan.reports.sample import sample_snapshot
from securescan.reports.snapshot import canonical_json
from securescan.reports.watermark import pdf_text
from securescan.storage.artifacts import read_bytes, save_bytes
from securescan.util import utcnow
from tests.unit.conftest import FakeSession


def make_user(role: UserRole = UserRole.ANALYST) -> CurrentUser:
    return CurrentUser(
        id=uuid.uuid4(),
        oid="oid-1",
        name="Test User",
        email="test@example.com",
        role=role,
        session_id=uuid.uuid4(),
        csrf_token="csrf",
    )


def blank_pdf() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=595, height=842)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def make_report(**overrides: Any) -> Report:
    now = utcnow()
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "application_id": uuid.uuid4(),
        "version_id": uuid.uuid4(),
        "scan_id": uuid.uuid4(),
        "kind": ReportKind.VENDOR,
        "ref": "SSR-20261007-ABC123",
        "title": "Payroll Portal v2.4.0 - vendor assessment",
        "template_id": None,
        "template_version": 1,
        "snapshot_artifact_id": None,
        "snapshot_sha256": "a" * 64,
        "html_artifact_id": None,
        "pdf_artifact_id": None,
        "status": "ready",
        "error": None,
        "review_state": ReviewState.AUTOMATIC,
        "proposed_verdict": Verdict.FAIL,
        "verdict": Verdict.FAIL,
        "verdict_overridden": False,
        "override_reason": None,
        "reviewer_id": None,
        "reviewed_at": None,
        "conditions": [],
        "vendor_copy": False,
        "internal_notes": None,
        "mapping_versions": {},
        "previous_report_id": None,
        "generated_by_id": None,
        "created_at": now,
        "updated_at": now,
    }
    values.update(overrides)
    return Report(**values)


async def store_files(db: FakeSession, report: Report) -> dict[str, bytes]:
    """Give the report an HTML, a PDF and a snapshot artifact; return their bytes."""
    html = b"<!doctype html><html><body><p>report</p></body></html>"
    pdf = blank_pdf()
    snapshot = canonical_json(sample_snapshot("vendor"))
    files = {"html": html, "pdf": pdf, "snapshot": snapshot}
    kinds = {
        "html": (ArtifactKind.REPORT_FILE, "r.html", "text/html"),
        "pdf": (ArtifactKind.REPORT_FILE, "r.pdf", "application/pdf"),
        "snapshot": (ArtifactKind.SNAPSHOT, "r.json", "application/json"),
    }
    for name, data in files.items():
        kind, filename, content_type = kinds[name]
        artifact = await save_bytes(
            db,  # type: ignore[arg-type]
            kind=kind,
            data=data,
            filename=f"{name}-{report.id}-{filename}",
            content_type=content_type,
            owner_type="report",
            owner_id=report.id,
        )
        setattr(report, f"{name}_artifact_id", artifact.id)
    return files


def build_client(db: FakeSession, user: CurrentUser | None = None) -> TestClient:
    app = FastAPI()
    install_problem_handlers(app)
    app.include_router(reports_api.router, prefix="/api/v1")

    async def session() -> AsyncIterator[FakeSession]:
        yield db

    app.dependency_overrides[get_session] = session
    if user is not None:
        app.dependency_overrides[current_user] = lambda: user
    return TestClient(app)


def audit_actions(db: FakeSession) -> list[str]:
    return [e.action for e in db.added if isinstance(e, AuditEvent)]


def test_the_html_is_served_under_the_strict_csp_headers() -> None:
    import asyncio

    db = FakeSession()
    report = make_report()
    files = asyncio.run(store_files(db, report))
    db.rows.append(report)
    response = build_client(db, make_user()).get(f"/api/v1/reports/{report.id}/html")
    assert response.status_code == 200
    assert response.content == files["html"]
    assert response.headers["content-type"].startswith("text/html")
    assert (
        response.headers["content-security-policy"]
        == "default-src 'none'; img-src data:; style-src 'unsafe-inline'"
    )
    assert response.headers["x-frame-options"] == "SAMEORIGIN"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "no-store" in response.headers["cache-control"]
    assert audit_actions(db) == ["report.view"]
    assert db.commits == 1


def test_the_csp_constant_is_the_plans_policy() -> None:
    assert reports_api.HTML_CSP == "default-src 'none'; img-src data:; style-src 'unsafe-inline'"
    assert reports_api.HTML_HEADERS["X-Frame-Options"] == "SAMEORIGIN"


def test_the_pdf_download_is_stamped_and_the_stored_pdf_is_not() -> None:
    import asyncio

    db = FakeSession()
    report = make_report()
    files = asyncio.run(store_files(db, report))
    db.rows.append(report)
    response = build_client(db, make_user()).get(f"/api/v1/reports/{report.id}/pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert 'filename="SSR-20261007-ABC123.pdf"' in response.headers["content-disposition"]
    text = " ".join(pdf_text(response.content).split())
    assert "Downloaded by Test User (test@example.com) on " in text
    assert text.endswith("UTC")
    stored = next(a for a in db.added if a.id == report.pdf_artifact_id)
    assert asyncio.run(read_bytes(stored)) == files["pdf"]
    assert "Downloaded by" not in pdf_text(files["pdf"])
    assert audit_actions(db) == ["report.download"]
    event = next(e for e in db.added if isinstance(e, AuditEvent))
    assert event.detail["format"] == "pdf" and event.object_id == str(report.id)


def test_the_csv_download_is_escaped_and_audited() -> None:
    import asyncio

    db = FakeSession()
    report = make_report()
    asyncio.run(store_files(db, report))
    db.rows.append(report)
    response = build_client(db, make_user()).get(f"/api/v1/reports/{report.id}/findings.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    text = response.content.decode("utf-8")
    assert text.startswith("﻿")
    rows = list(csv.reader(io.StringIO(text.lstrip("﻿"))))
    assert rows[0][0] == "Report" and len(rows) == 1 + 7 + 1
    assert audit_actions(db) == ["export.report_csv"]


def test_a_report_that_is_not_ready_is_a_conflict() -> None:
    db = FakeSession()
    report = make_report(status="pending")
    db.rows.append(report)
    client = build_client(db, make_user())
    for suffix in ("html", "pdf", "findings.csv", "snapshot"):
        response = client.get(f"/api/v1/reports/{report.id}/{suffix}")
        assert response.status_code == 409
        assert response.json()["code"] == "report.not_ready"


def test_an_unknown_report_is_a_404_problem() -> None:
    response = build_client(FakeSession(), make_user()).get(f"/api/v1/reports/{uuid.uuid4()}/html")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")


def test_reports_need_a_signed_in_user() -> None:
    response = build_client(FakeSession()).get(f"/api/v1/reports/{uuid.uuid4()}/html")
    assert response.status_code == 401


def test_a_missing_file_on_disk_is_reported_not_crashed(tmp_path: Any) -> None:
    import asyncio

    db = FakeSession()
    report = make_report()
    asyncio.run(store_files(db, report))
    db.rows.append(report)
    stored = next(a for a in db.added if a.id == report.html_artifact_id)
    (tmp_path / "artifacts" / stored.storage_key).unlink()
    response = build_client(db, make_user()).get(f"/api/v1/reports/{report.id}/html")
    assert response.status_code == 404
    assert response.json()["code"] == "report.file_missing"


# --------------------------------------------------------------------------- review


def review_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"decision": "confirm"}
    body.update(overrides)
    return body


def future(days: int = 30) -> str:
    return (date.today() + timedelta(days=days)).isoformat()


@pytest.fixture
def reviewable() -> tuple[FakeSession, Report]:
    import asyncio

    db = FakeSession()
    report = make_report()
    asyncio.run(store_files(db, report))
    db.rows.append(report)
    return db, report


def test_review_confirm_with_two_conditions_is_recorded_and_audited(
    reviewable: tuple[FakeSession, Report], monkeypatch: pytest.MonkeyPatch
) -> None:
    db, report = reviewable
    rendered: list[Any] = []

    async def fake_rerender(session: Any, rep: Report, snapshot: Any) -> None:
        rendered.append(snapshot)

    monkeypatch.setattr(report_service, "rerender", fake_rerender)
    user = make_user()
    body = review_body(
        decision="override",
        verdict="conditional",
        reason="The remaining findings are agreed with the vendor",
        conditions=[
            {"finding_hash": "h-sqli", "deadline": future(30)},
            {"finding_hash": "h-log4j", "deadline": future(60)},
        ],
        internal_notes="agreed on a call",
    )
    response = build_client(db, user).post(f"/api/v1/reports/{report.id}/review", json=body)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["review_state"] == "reviewed"
    # M10: conditions belong to a conditional pass, so the review overrides the proposed fail
    assert data["verdict"] == "conditional" and data["verdict_overridden"] is True
    assert [c["finding_hash"] for c in data["conditions"]] == ["h-sqli", "h-log4j"]
    assert report.reviewer_id == user.id and report.reviewed_at is not None

    event = next(e for e in db.added if isinstance(e, AuditEvent))
    assert event.action == "report.review"
    assert event.actor_id == user.id
    assert event.detail["verdict"] == "conditional" and event.detail["decision"] == "override"
    assert [c["finding_hash"] for c in event.detail["conditions"]] == ["h-sqli", "h-log4j"]

    reviewed = rendered[0]
    assert reviewed.header.review_state == "reviewed"
    assert reviewed.review.reviewer == "Test User"
    assert [c.finding_hash for c in reviewed.review.conditions] == ["h-sqli", "h-log4j"]
    assert reviewed.review.conditions[0].finding_title == "SQL injection in UserServlet.find"


def test_review_override_needs_a_verdict_and_a_reason(
    reviewable: tuple[FakeSession, Report], monkeypatch: pytest.MonkeyPatch
) -> None:
    db, report = reviewable

    async def fake_rerender(session: Any, rep: Report, snapshot: Any) -> None:
        return None

    monkeypatch.setattr(report_service, "rerender", fake_rerender)
    client = build_client(db, make_user())
    url = f"/api/v1/reports/{report.id}/review"
    no_verdict = client.post(
        url, json=review_body(decision="override", reason="long enough reason")
    )
    assert no_verdict.status_code == 422 and no_verdict.json()["code"] == "report.invalid_verdict"
    no_reason = client.post(url, json=review_body(decision="override", verdict="pass"))
    assert no_reason.status_code == 422
    assert no_reason.json()["code"] == "report.override_reason_required"
    same = client.post(url, json=review_body(decision="override", verdict="fail", reason="because"))
    assert same.json()["code"] == "report.not_an_override"
    assert report.review_state == ReviewState.AUTOMATIC

    ok = client.post(
        url, json=review_body(decision="override", verdict="conditional", reason="Test-only file")
    )
    assert ok.status_code == 200
    assert ok.json()["verdict"] == "conditional" and ok.json()["verdict_overridden"] is True
    assert ok.json()["proposed_verdict"] == "fail"
    assert ok.json()["override_reason"] == "Test-only file"


@pytest.mark.parametrize(
    ("conditions", "field"),
    [
        (
            [{"finding_hash": "no-such-finding", "deadline": "2999-01-01"}],
            "conditions.0.finding_hash",
        ),
        ([{"finding_hash": "h-sqli", "deadline": "2001-01-01"}], "conditions.0.deadline"),
        (
            [
                {"finding_hash": "h-sqli", "deadline": "2999-01-01"},
                {"finding_hash": "h-sqli", "deadline": "2999-02-01"},
            ],
            "conditions.1.finding_hash",
        ),
    ],
)
def test_review_validates_conditions(
    reviewable: tuple[FakeSession, Report], conditions: list[dict[str, str]], field: str
) -> None:
    db, report = reviewable
    response = build_client(db, make_user()).post(
        f"/api/v1/reports/{report.id}/review", json=review_body(conditions=conditions)
    )
    assert response.status_code == 422
    assert response.json()["code"] == "report.invalid_conditions"
    assert field in [e["field"] for e in response.json()["errors"]]
    assert report.review_state == ReviewState.AUTOMATIC
    assert audit_actions(db) == []


def test_a_passing_verdict_has_no_conditions(reviewable: tuple[FakeSession, Report]) -> None:
    db, report = reviewable
    response = build_client(db, make_user()).post(
        f"/api/v1/reports/{report.id}/review",
        json=review_body(
            decision="override",
            verdict="pass",
            reason="accepted by security board",
            conditions=[{"finding_hash": "h-sqli", "deadline": future()}],
        ),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "report.conditions_not_allowed"


def test_a_pending_report_cannot_be_reviewed() -> None:
    db = FakeSession()
    report = make_report(status="pending")
    db.rows.append(report)
    response = build_client(db, make_user()).post(
        f"/api/v1/reports/{report.id}/review", json=review_body()
    )
    assert response.status_code == 409


async def test_apply_review_returns_the_reviewed_snapshot() -> None:
    db = FakeSession()
    report = make_report()
    await store_files(db, report)
    db.rows.append(report)
    user = SimpleNamespace(id=uuid.uuid4(), name=None, email="a@example.com", oid="o")
    request = report_service.ReviewRequest(
        decision="override", verdict="pass", reason="false positives", vendor_copy=True,
        internal_notes="private",
    )
    snapshot = await report_service.apply_review(
        db,  # type: ignore[arg-type]
        report,
        user,
        request,
    )
    assert snapshot.review.reviewer == "a@example.com"
    assert snapshot.summary.verdict == "pass" and snapshot.vendor_copy
    assert snapshot.review.internal_notes == ""  # a vendor copy never carries the notes
    assert report.internal_notes == "private"  # but the row keeps them
    assert report.vendor_copy is True


def test_validate_conditions_accepts_dates_and_text() -> None:
    cleaned = report_service.validate_conditions(
        [
            {"finding_hash": "a", "deadline": date(2999, 1, 1)},
            {"finding_hash": "b", "deadline": "2999-02-03"},
        ],
        {"a", "b"},
        date(2026, 10, 7),
    )
    assert cleaned == [
        {"finding_hash": "a", "deadline": "2999-01-01"},
        {"finding_hash": "b", "deadline": "2999-02-03"},
    ]
    with pytest.raises(UnprocessableEntity):
        report_service.validate_conditions(
            [{"finding_hash": "a", "deadline": "soon"}], {"a"}, date(2026, 1, 1)
        )


def test_report_helpers() -> None:
    created = utcnow().replace(year=2026, month=10, day=7)
    ident = uuid.UUID("0199aaaa-bbbb-7ccc-8ddd-eeeeeeabcdef")
    assert report_service.report_ref(ident, created) == "SSR-20261007-ABCDEF"
    assert report_service.sbom_component_count(b'{"components": [1, 2, 3]}') == 3
    assert report_service.sbom_component_count(b'{"artifacts": [1]}') == 1
    assert report_service.sbom_component_count(b"not json") is None
    assert report_service.sbom_component_count(b"{}") is None
    assert report_service.verdict_of("conditional") == Verdict.CONDITIONAL
    assert report_service.verdict_of("nonsense") == Verdict.PENDING
