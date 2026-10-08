"""The DAST endpoints (target check, options, Start wrapper, login profiles) without a database."""

from __future__ import annotations

import types
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from securescan.api import dast as dast_api
from securescan.api.problems import Forbidden, install_problem_handlers
from securescan.auth.roles import CurrentUser, current_user
from securescan.config import get_settings
from securescan.db.models.credentials import Credential
from securescan.db.models.enums import CredentialKind, ScanTrigger, TargetEnvironment, TargetKind, UserRole
from securescan.db.session import get_session
from securescan.domain.scans import ScanCreation
from securescan.runner.catalogue import clear_catalogue_cache
from securescan.runner.profiles import parse_profile_yaml, profile_body
from securescan.util import utcnow
from tests.unit.conftest import FakeScalars, FakeSession
from tests.unit.runner_helpers import REPO_SCANNERS

PASSWORD = "Very-Secret-Pa55word"
VERSION_ID = uuid.uuid4()


class DastSession(FakeSession):
    """FakeSession whose ``scalars`` answers the profile query."""

    def __init__(self, rows: list[Any] | None = None, profiles: list[Any] | None = None) -> None:
        super().__init__(rows)
        self.profiles = profiles or []

    async def scalars(self, stmt: Any) -> FakeScalars:
        return FakeScalars(self.profiles)


def make_user(role: UserRole = UserRole.ANALYST) -> CurrentUser:
    return CurrentUser(
        id=uuid.uuid4(), oid="oid", name="Tester", email="tester@example.com", role=role,
        session_id=uuid.uuid4(), csrf_token="csrf",
    )  # fmt: skip


def build_app(session: FakeSession | None = None) -> tuple[TestClient, FakeSession]:
    app = FastAPI()
    install_problem_handlers(app)
    app.include_router(dast_api.router, prefix="/api/v1")
    fake = session or FakeSession()
    user = make_user()

    async def db() -> AsyncIterator[FakeSession]:
        yield fake

    app.dependency_overrides[get_session] = db
    app.dependency_overrides[current_user] = lambda: user
    return TestClient(app), fake


@pytest.fixture(autouse=True)
def dast_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_DAST_ALLOWED_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("SECURESCAN_SCANNERS_DIR", str(REPO_SCANNERS))
    get_settings.cache_clear()
    clear_catalogue_cache()


def make_url_target(environment: TargetEnvironment | None = TargetEnvironment.UAT, **overrides: Any) -> Any:
    values: dict[str, Any] = {
        "id": uuid.uuid4(), "version_id": VERSION_ID, "kind": TargetKind.URL, "name": "Shop", "environment": environment,
        "locator": "http://10.20.30.40:8080/", "login_profile_id": None, "host_approved": False, "blackout_windows": [],
        "api_spec_type": None, "api_spec_locator": None, "api_spec_artifact_id": None, "rate_limit_rps": None,
        "vendor_authorization_artifact_id": None, "vendor_authorized_from": None, "vendor_authorized_until": None,
        "vendor_contact": None,
    }  # fmt: skip
    values.update(overrides)
    return types.SimpleNamespace(**values)


# --------------------------------------------------------------------------- target check
def test_check_accepts_an_allowlisted_target(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolved(hosts: Any, timeout: float = 5.0) -> dict[str, list[str]]:
        return {"shop.uat.example": ["10.1.2.3"]}

    monkeypatch.setattr(dast_api, "resolve_hosts", resolved)
    client, _ = build_app()
    response = client.post(
        "/api/v1/dast/targets/check",
        json={"locator": "https://shop.uat.example/app", "environment": "uat"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["allowed"] is True and body["code"] is None and body["allowlist_configured"] is True
    assert body["hosts"] == [{"host": "shop.uat.example", "port": 443, "scheme": "https", "addresses": ["10.1.2.3"]}]
    assert body["modes"] == ["baseline", "full", "api", "nuclei"]


def test_check_explains_why_a_target_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolved(hosts: Any, timeout: float = 5.0) -> dict[str, list[str]]:
        return {"public.example": ["93.184.216.34"]}

    monkeypatch.setattr(dast_api, "resolve_hosts", resolved)
    client, _ = build_app()
    refused = client.post("/api/v1/dast/targets/check", json={"locator": "https://public.example/", "environment": "production"})
    body = refused.json()
    assert refused.status_code == 200 and body["allowed"] is False and body["code"] == "dast.host_not_allowlisted"
    assert "93.184.216.34" in body["reason"] and body["modes"] == ["baseline"]
    approved = client.post(
        "/api/v1/dast/targets/check", json={"locator": "https://public.example/", "environment": "uat", "host_approved": True}
    ).json()
    assert approved["allowed"] is True
    login = client.post(
        "/api/v1/dast/targets/check",
        json={"locator": "https://public.example/", "environment": "production", "host_approved": True, "has_login_profile": True},
    ).json()
    assert login["modes"] == []  # production cannot use a login profile: no mode is left
    blocked = client.post(
        "/api/v1/dast/targets/check", json={"locator": "http://169.254.169.254/", "environment": "uat", "host_approved": True}
    ).json()
    assert blocked["allowed"] is False and blocked["code"] == "dast.host_blocked"


@pytest.mark.parametrize("locator", ["ftp://example.com/", "example.com", "http://user:pw@example.com/", "http://exa mple.com/"])
def test_check_rejects_unusable_addresses(locator: str) -> None:
    client, _ = build_app()
    response = client.post("/api/v1/dast/targets/check", json={"locator": locator})
    assert response.status_code == 422 and response.json()["code"] == "target.invalid_url"


# --------------------------------------------------------------------------- options
def dast_profile_rows() -> list[Any]:
    rows = []
    for name in ("dast-baseline", "dast-full", "dast-api"):
        text = (REPO_SCANNERS / "profiles" / f"{name}.yaml").read_text(encoding="utf-8")
        doc = parse_profile_yaml(text)
        rows.append(types.SimpleNamespace(id=uuid.uuid4(), name=name, version=1, body=profile_body(doc, 1), kind="dast", active=True))
    return rows


def options_world(environment: TargetEnvironment | None, **target_overrides: Any) -> tuple[TestClient, Any]:
    target = make_url_target(environment, **target_overrides)
    version = types.SimpleNamespace(id=VERSION_ID, application_id=uuid.uuid4())
    application = types.SimpleNamespace(id=version.application_id, type="internal", hosting=None)
    session = DastSession(rows=[target, version, application], profiles=dast_profile_rows())
    client, _ = build_app(session)
    return client, target


def test_options_for_a_uat_target() -> None:
    client, target = options_world(TargetEnvironment.UAT)
    response = client.get(f"/api/v1/dast/targets/{target.id}/options")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["default_profile"] == "dast-full" and body["environment"] == "uat"
    options = {o["profile"]: o for o in body["options"]}
    assert options["dast-baseline"]["allowed"] is True and options["dast-baseline"]["mode"] == "baseline"
    assert options["dast-full"]["allowed"] is True and options["dast-full"]["tools"] == ["zap", "nuclei"]
    assert options["dast-api"]["allowed"] is False and options["dast-api"]["code"] == "dast.api_spec_required"


def test_options_for_a_production_target_name_the_rule() -> None:
    client, target = options_world(TargetEnvironment.PRODUCTION)
    body = client.get(f"/api/v1/dast/targets/{target.id}/options").json()
    assert body["default_profile"] == "dast-baseline"
    options = {o["profile"]: o for o in body["options"]}
    assert options["dast-baseline"]["allowed"] is True
    for name in ("dast-full", "dast-api"):
        assert options[name]["allowed"] is False and options[name]["code"] == "dast.production_baseline_only"
        assert "baseline" in options[name]["reason"]


def test_options_of_a_missing_or_wrong_target() -> None:
    client, _ = options_world(TargetEnvironment.UAT)
    assert client.get(f"/api/v1/dast/targets/{uuid.uuid4()}/options").status_code == 404
    client, target = options_world(TargetEnvironment.UAT, kind=TargetKind.ZIP)
    response = client.get(f"/api/v1/dast/targets/{target.id}/options")
    assert response.status_code == 422 and response.json()["code"] == "scan.target_kind_mismatch"


# --------------------------------------------------------------------------- start
def start_world(monkeypatch: pytest.MonkeyPatch, environment: TargetEnvironment | None) -> tuple[TestClient, Any, dict[str, Any]]:
    target = make_url_target(environment)
    version = types.SimpleNamespace(id=VERSION_ID, application_id=uuid.uuid4())
    application = types.SimpleNamespace(id=version.application_id, type="internal", hosting=None)
    client, _ = build_app(FakeSession(rows=[target, version, application]))
    captured: dict[str, Any] = {}

    async def fake_create(db: Any, **kwargs: Any) -> ScanCreation:
        captured.update(kwargs)
        if kwargs["profile_name"] != "dast-baseline" and environment == TargetEnvironment.PRODUCTION:
            raise Forbidden("Production targets accept the unauthenticated ZAP baseline scan only.", code="dast.production_baseline_only")
        return ScanCreation(scan=types.SimpleNamespace(id=uuid.uuid4()), jobs=[], created=True)  # type: ignore[arg-type]

    async def fake_detail(db: Any, scan: Any, replayed: bool = False, collapsed: bool = False) -> Any:
        from tests.unit.test_scans_api import make_detail

        return make_detail(scan.id, kind="dast", mode="baseline", profile_name=captured["profile_name"], requested_tools=["zap"])

    monkeypatch.setattr(dast_api, "create_scan_result", fake_create)
    monkeypatch.setattr(dast_api, "load_detail", fake_detail)
    return client, target, captured


def test_start_uses_the_default_profile_of_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    client, target, captured = start_world(monkeypatch, TargetEnvironment.UAT)
    response = client.post(f"/api/v1/dast/targets/{target.id}/scans", json={}, headers={"Idempotency-Key": "k-1"})
    assert response.status_code == 202, response.text
    assert captured["profile_name"] == "dast-full" and captured["version_id"] == VERSION_ID
    assert captured["target_ids"] == [target.id] and captured["trigger"] == ScanTrigger.USER
    assert captured["idempotency_key"].endswith(":k-1")
    prod_client, prod_target, prod_captured = start_world(monkeypatch, TargetEnvironment.PRODUCTION)
    assert prod_client.post(f"/api/v1/dast/targets/{prod_target.id}/scans", json={}).status_code == 202
    assert prod_captured["profile_name"] == "dast-baseline"


def test_start_of_a_forbidden_profile_is_a_403_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    client, target, captured = start_world(monkeypatch, TargetEnvironment.PRODUCTION)
    response = client.post(f"/api/v1/dast/targets/{target.id}/scans", json={"profile": "dast-full"})
    assert response.status_code == 403
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "dast.production_baseline_only" and "baseline" in response.json()["detail"]
    assert captured["profile_name"] == "dast-full"


def test_start_needs_an_environment_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    client, target, captured = start_world(monkeypatch, None)
    response = client.post(f"/api/v1/dast/targets/{target.id}/scans", json={})
    assert response.status_code == 422 and response.json()["code"] == "target.environment_required" and captured == {}


# --------------------------------------------------------------------------- login profiles
def form_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "UAT analyst login",
        "settings": {
            "method": "form",
            "login_page_url": "http://10.20.30.40:8080/login",
            "login_request_url": "http://10.20.30.40:8080/login",
            "login_request_body": "user={%username%}&pass={%password%}",
            "logged_in_regex": "\\QSign out\\E",
        },
        "username": "analyst",
        "password": PASSWORD,
    }
    body.update(overrides)
    return body


def test_a_login_profile_is_stored_encrypted_and_never_returned(master_key: str) -> None:
    client, session = build_app()
    response = client.post("/api/v1/dast/login-profiles", json=form_body())
    assert response.status_code == 201, response.text
    assert PASSWORD not in response.text and "analyst" not in response.text.replace("UAT analyst login", "")
    body = response.json()
    assert body["method"] == "form" and body["verification_method"] == "response" and body["revoked_at"] is None
    credential = next(row for row in session.added if isinstance(row, Credential))
    assert credential.kind == CredentialKind.DAST_LOGIN and credential.ciphertext.startswith("ss1:")
    assert PASSWORD not in credential.ciphertext and PASSWORD not in str(credential.extra)
    assert credential.extra["method"] == "form" and credential.extra["logged_in_regex"] == "\\QSign out\\E"
    from securescan.domain.credentials import reveal_secret

    assert PASSWORD in reveal_secret(credential)
    audit = [row for row in session.added if type(row).__name__ == "AuditEvent"]
    assert audit and audit[0].action == "dast_login.create" and PASSWORD not in str(audit[0].detail)
    assert session.commits == 1


@pytest.mark.parametrize(
    "overrides, code",
    [
        ({"password": None}, "dast_login.secret_incomplete"),
        ({"username": None}, "dast_login.secret_incomplete"),
        ({"expires_at": "2000-01-01T00:00:00Z"}, "dast_login.expired"),
    ],
)
def test_incomplete_login_profiles_are_refused(master_key: str, overrides: dict[str, Any], code: str) -> None:
    client, session = build_app()
    response = client.post("/api/v1/dast/login-profiles", json=form_body(**overrides))
    assert response.status_code == 422 and response.json()["code"] == code
    assert not [row for row in session.added if isinstance(row, Credential)]


def test_a_login_without_verification_is_refused_by_validation(master_key: str) -> None:
    client, _ = build_app()
    body = form_body()
    del body["settings"]["logged_in_regex"]
    response = client.post("/api/v1/dast/login-profiles", json=body)
    assert response.status_code == 422 and PASSWORD not in response.text
    body = form_body()
    body["settings"]["logged_in_regex"] = "${ZAP_AUTH_PASSWORD}"
    assert client.post("/api/v1/dast/login-profiles", json=body).status_code == 422


def test_a_header_login_needs_its_token(master_key: str) -> None:
    client, session = build_app()
    settings = {"method": "header", "header_name": "Authorization", "poll_url": "http://10.20.30.40:8080/api/me"}
    missing = client.post("/api/v1/dast/login-profiles", json={"name": "token login", "settings": settings})
    assert missing.status_code == 422 and missing.json()["code"] == "dast_login.secret_incomplete"
    created = client.post(
        "/api/v1/dast/login-profiles", json={"name": "token login", "settings": settings, "header_value": "Bearer abc.def.ghi"}
    )
    assert created.status_code == 201 and "abc.def.ghi" not in created.text


def test_revoking_a_login_profile(master_key: str) -> None:
    client, session = build_app()
    created = client.post("/api/v1/dast/login-profiles", json=form_body()).json()
    revoked = client.delete(f"/api/v1/dast/login-profiles/{created['id']}")
    assert revoked.status_code == 200 and revoked.json()["revoked_at"] is not None
    credential = next(row for row in session.added if isinstance(row, Credential))
    assert credential.revoked_at is not None and credential.revoked_at <= utcnow()
    again = client.delete(f"/api/v1/dast/login-profiles/{created['id']}")
    assert again.status_code == 200  # revoking twice changes nothing
    assert client.delete(f"/api/v1/dast/login-profiles/{uuid.uuid4()}").status_code == 404
    other = Credential(id=uuid.uuid4(), kind=CredentialKind.VENDOR_TOKEN, name="x", ciphertext="y", key_id="k", extra={}, created_at=utcnow())
    session.added.append(other)
    assert client.delete(f"/api/v1/dast/login-profiles/{other.id}").status_code == 404  # not a login profile


def test_profile_yaml_files_in_the_repository_are_valid_scan_profiles() -> None:
    for name in ("dast-baseline", "dast-full", "dast-api"):
        data = yaml.safe_load((REPO_SCANNERS / "profiles" / f"{name}.yaml").read_text(encoding="utf-8"))
        assert data["kind"] == "dast" and data["profile"] == name
