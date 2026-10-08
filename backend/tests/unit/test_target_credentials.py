"""A target may carry only a credential of its own kind, application and target (security review)."""

from __future__ import annotations

import types
import uuid
from typing import Any

import pytest

from securescan.api import versions_targets as vt
from securescan.api.problems import Forbidden, UnprocessableEntity
from securescan.db.models.enums import CredentialKind, TargetKind
from tests.unit.conftest import FakeSession

APPLICATION = uuid.uuid4()
VERSION = uuid.uuid4()
TARGET = uuid.uuid4()


def credential(kind: CredentialKind, **changes: Any) -> types.SimpleNamespace:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "kind": kind,
        "application_id": APPLICATION,
        "version_id": VERSION,
        "extra": {"target_id": str(TARGET)},
        "revoked_at": None,
    }
    values.update(changes)
    return types.SimpleNamespace(**values)


async def check(
    row: types.SimpleNamespace,
    target_kind: TargetKind,
    *,
    is_admin: bool = False,
    target_id: uuid.UUID | None = TARGET,
    field: str = "credential_id",
) -> None:
    await vt._check_references(
        FakeSession(rows=[row]),  # type: ignore[arg-type]
        {field: row.id},
        target_kind=target_kind,
        application_id=APPLICATION,
        version_id=VERSION,
        is_admin=is_admin,
        target_id=target_id,
    )


@pytest.mark.parametrize(
    "kind",
    [
        CredentialKind.NVD_KEY,
        CredentialKind.GITHUB_APP_KEY,
        CredentialKind.DEFECTDOJO_TOKEN,
        CredentialKind.DEFECTDOJO_ADMIN_TOKEN,
        CredentialKind.SONARQUBE_TOKEN,
        CredentialKind.DAST_LOGIN,
    ],
)
@pytest.mark.parametrize("target_kind", [TargetKind.VENDOR_REPO, TargetKind.IMAGE, TargetKind.GITHUB_REPO])
async def test_admin_only_secrets_cannot_be_attached_to_a_target(kind: CredentialKind, target_kind: TargetKind) -> None:
    with pytest.raises(UnprocessableEntity) as caught:
        await check(credential(kind), target_kind)
    assert caught.value.code == "target.credential_kind"


async def test_each_target_kind_accepts_only_its_own_credential_kinds() -> None:
    await check(credential(CredentialKind.DEPLOY_KEY), TargetKind.VENDOR_REPO)
    await check(credential(CredentialKind.VENDOR_TOKEN), TargetKind.VENDOR_REPO)
    await check(credential(CredentialKind.REGISTRY, extra={}), TargetKind.IMAGE)
    for kind, target_kind in (
        (CredentialKind.REGISTRY, TargetKind.VENDOR_REPO),
        (CredentialKind.VENDOR_TOKEN, TargetKind.IMAGE),
        (CredentialKind.VENDOR_TOKEN, TargetKind.GITHUB_REPO),
        (CredentialKind.DEPLOY_KEY, TargetKind.URL),
        (CredentialKind.DEPLOY_KEY, TargetKind.ZIP),
    ):
        with pytest.raises(UnprocessableEntity):
            await check(credential(kind), target_kind)


async def test_a_credential_of_another_application_version_or_target_is_refused() -> None:
    other = uuid.uuid4()
    for changes in (
        {"application_id": other},
        {"version_id": other},
        {"extra": {"target_id": str(other)}},
    ):
        with pytest.raises(UnprocessableEntity) as caught:
            await check(credential(CredentialKind.VENDOR_TOKEN, **changes), TargetKind.VENDOR_REPO)
        assert caught.value.code == "target.credential_scope"
    # a credential bound to a target cannot be attached to a target that does not exist yet
    with pytest.raises(UnprocessableEntity):
        await check(credential(CredentialKind.VENDOR_TOKEN), TargetKind.VENDOR_REPO, target_id=None)


async def test_a_shared_registry_login_needs_an_admin() -> None:
    shared = credential(CredentialKind.REGISTRY, application_id=None, version_id=None, extra={})
    with pytest.raises(Forbidden):
        await check(shared, TargetKind.IMAGE, is_admin=False)
    await check(shared, TargetKind.IMAGE, is_admin=True)


async def test_a_revoked_or_unknown_credential_is_refused() -> None:
    from securescan.util import utcnow

    revoked = credential(CredentialKind.DEPLOY_KEY, revoked_at=utcnow())
    with pytest.raises(UnprocessableEntity) as caught:
        await check(revoked, TargetKind.VENDOR_REPO)
    assert caught.value.code == "target.credential_id_unknown"
    with pytest.raises(UnprocessableEntity):
        await vt._check_references(
            FakeSession(),  # type: ignore[arg-type]
            {"credential_id": uuid.uuid4()},
            target_kind=TargetKind.VENDOR_REPO,
            application_id=APPLICATION,
            version_id=VERSION,
            is_admin=True,
        )


async def test_a_login_profile_of_another_application_is_refused() -> None:
    ok = credential(CredentialKind.DAST_LOGIN, extra={})
    await check(ok, TargetKind.URL, field="login_profile_id")
    foreign = credential(CredentialKind.DAST_LOGIN, application_id=uuid.uuid4(), extra={})
    with pytest.raises(UnprocessableEntity) as caught:
        await check(foreign, TargetKind.URL, field="login_profile_id")
    assert caught.value.code == "target.credential_scope"
    unscoped = credential(CredentialKind.DAST_LOGIN, application_id=None, version_id=None, extra={})
    await check(unscoped, TargetKind.URL, field="login_profile_id")


def test_the_host_signature_ignores_paths_and_changes_with_the_host() -> None:
    first = vt._host_signature("https://app.uat.example.com/login", None)
    assert first == vt._host_signature("https://app.uat.example.com/other/path", None)
    assert first != vt._host_signature("https://evil.example.org/", None)
    with_spec = vt._host_signature("https://app.uat.example.com/", "https://specs.example.org/openapi.json")
    assert with_spec is not None and first is not None and not with_spec <= first
    assert vt._host_signature("not a url", None) is None
