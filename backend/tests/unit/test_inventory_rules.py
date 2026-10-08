from __future__ import annotations

import uuid

import pytest

from securescan.api.problems import UnprocessableEntity
from securescan.db.models.enums import AppType, TargetEnvironment, TargetKind
from securescan.domain.inventory import (
    normalise_tags,
    validate_application_rules,
    validate_cron,
    validate_scope_patterns,
    validate_target_rules,
)


def test_application_rules() -> None:
    validate_application_rules(AppType.INTERNAL, None)
    validate_application_rules(AppType.VENDOR, uuid.uuid4())
    with pytest.raises(UnprocessableEntity):
        validate_application_rules(AppType.INTERNAL, uuid.uuid4())
    with pytest.raises(UnprocessableEntity):
        validate_application_rules(AppType.VENDOR, None)


def test_tags_are_trimmed_and_deduplicated() -> None:
    assert normalise_tags([" a ", "b", "a", ""]) == ["a", "b"]
    with pytest.raises(UnprocessableEntity):
        normalise_tags(["x" * 65])
    with pytest.raises(UnprocessableEntity):
        normalise_tags([str(i) for i in range(51)])


@pytest.mark.parametrize("expr", ["0 2 * * 0", "*/10 * * * *", "30 7 * * 1-5", "0 3 1,15 * *"])
def test_valid_cron(expr: str) -> None:
    assert validate_cron(expr) == expr


@pytest.mark.parametrize("expr", ["", "* * * *", "0 2 * * * *", "rm -rf /", "0 2 * * ;"])
def test_invalid_cron(expr: str) -> None:
    with pytest.raises(UnprocessableEntity):
        validate_cron(expr)


def test_scope_patterns_must_compile() -> None:
    assert validate_scope_patterns([r"https://app\.example\.com/.*"]) == [r"https://app\.example\.com/.*"]
    with pytest.raises(UnprocessableEntity):
        validate_scope_patterns(["(unclosed"])


def test_url_target_needs_an_environment() -> None:
    with pytest.raises(UnprocessableEntity) as info:
        validate_target_rules(
            kind=TargetKind.URL,
            locator="https://app.example.com",
            environment=None,
            application_type=AppType.INTERNAL,
        )
    assert info.value.code == "target.environment_required"


def test_url_target_accepts_http_urls_only() -> None:
    ok = validate_target_rules(
        kind=TargetKind.URL,
        locator=" https://uat.example.com/app ",
        environment=TargetEnvironment.UAT,
        application_type=AppType.INTERNAL,
    )
    assert ok == "https://uat.example.com/app"
    for bad in ("ftp://x.example.com", "not a url", "https://user:pw@host.example.com", ""):
        with pytest.raises(UnprocessableEntity):
            validate_target_rules(
                kind=TargetKind.URL,
                locator=bad,
                environment=TargetEnvironment.UAT,
                application_type=AppType.INTERNAL,
            )


def test_login_profile_is_refused_on_production() -> None:
    with pytest.raises(UnprocessableEntity) as info:
        validate_target_rules(
            kind=TargetKind.URL,
            locator="https://app.example.com",
            environment=TargetEnvironment.PRODUCTION,
            application_type=AppType.INTERNAL,
            login_profile_id=uuid.uuid4(),
        )
    assert info.value.code == "target.login_profile_production"
    validate_target_rules(
        kind=TargetKind.URL,
        locator="https://uat.example.com",
        environment=TargetEnvironment.UAT,
        application_type=AppType.INTERNAL,
        login_profile_id=uuid.uuid4(),
    )


def test_only_url_targets_carry_environment_or_login_profile() -> None:
    with pytest.raises(UnprocessableEntity):
        validate_target_rules(
            kind=TargetKind.GITHUB_REPO,
            locator="org/repo",
            environment=TargetEnvironment.UAT,
            application_type=AppType.INTERNAL,
        )
    with pytest.raises(UnprocessableEntity):
        validate_target_rules(
            kind=TargetKind.IMAGE,
            locator="registry.example.com/app:1",
            environment=None,
            application_type=AppType.INTERNAL,
            login_profile_id=uuid.uuid4(),
        )


def test_zip_target_needs_an_upload_and_gets_its_locator() -> None:
    artifact_id = uuid.uuid4()
    assert (
        validate_target_rules(
            kind=TargetKind.ZIP,
            locator=None,
            environment=None,
            application_type=AppType.VENDOR,
            upload_artifact_id=artifact_id,
        )
        == f"upload:{artifact_id}"
    )
    with pytest.raises(UnprocessableEntity):
        validate_target_rules(
            kind=TargetKind.ZIP, locator=None, environment=None, application_type=AppType.VENDOR
        )


def test_vendor_repo_belongs_to_vendor_applications() -> None:
    with pytest.raises(UnprocessableEntity):
        validate_target_rules(
            kind=TargetKind.VENDOR_REPO,
            locator="git@github.com:vendor/repo.git",
            environment=None,
            application_type=AppType.INTERNAL,
        )
    assert (
        validate_target_rules(
            kind=TargetKind.VENDOR_REPO,
            locator="git@github.com:vendor/repo.git",
            environment=None,
            application_type=AppType.VENDOR,
        )
        == "git@github.com:vendor/repo.git"
    )
