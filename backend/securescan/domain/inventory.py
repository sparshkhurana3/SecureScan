"""Business rules for the inventory: applications, versions, targets, vendors.

Pure functions raise ``Problem`` subclasses with stable ``code`` values; routers call them before
writing. Rules that belong to later milestones (DAST modes per environment at scan time, the vendor
authorization record for SaaS targets) are enforced where scans are created.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from securescan.api.problems import UnprocessableEntity
from securescan.db.models.enums import AppType, TargetEnvironment, TargetKind

_CRON_FIELD = re.compile(r"^[0-9A-Za-z*/,\-?]+$")
_NO_SPACE = re.compile(r"^\S+$")
MAX_TAGS = 50
MAX_TAG_LENGTH = 64


def validate_cron(expression: str) -> str:
    """Accept a standard five-field cron expression (evaluated in UTC)."""
    parts = expression.split()
    if len(parts) != 5 or not all(_CRON_FIELD.match(p) for p in parts):
        raise UnprocessableEntity(
            "A cron expression has five fields: minute hour day-of-month month day-of-week",
            code="schedule.invalid_cron",
        )
    return " ".join(parts)


def normalise_tags(tags: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for tag in tags:
        clean = tag.strip()
        if not clean:
            continue
        if len(clean) > MAX_TAG_LENGTH:
            raise UnprocessableEntity(f"A tag is longer than {MAX_TAG_LENGTH} characters", code="tags.too_long")
        if clean not in seen:
            seen.append(clean)
    if len(seen) > MAX_TAGS:
        raise UnprocessableEntity(f"At most {MAX_TAGS} tags are allowed", code="tags.too_many")
    return seen


def validate_application_rules(app_type: AppType, vendor_id: Any) -> None:
    if app_type == AppType.INTERNAL and vendor_id is not None:
        raise UnprocessableEntity(
            "Internal applications have no vendor", code="application.vendor_not_allowed"
        )
    if app_type == AppType.VENDOR and vendor_id is None:
        raise UnprocessableEntity(
            "Vendor applications must name their vendor", code="application.vendor_required"
        )


def validate_scope_patterns(patterns: Iterable[str]) -> list[str]:
    """DAST in-scope entries are regular expressions; reject ones that do not compile."""
    result: list[str] = []
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise UnprocessableEntity(
                f"Invalid scope pattern {pattern!r}: {exc}", code="target.invalid_scope_pattern"
            ) from exc
        result.append(pattern)
    return result


def validate_url(locator: str) -> str:
    parts = urlsplit(locator.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UnprocessableEntity(
            "A URL target needs an http:// or https:// address", code="target.invalid_url"
        )
    if parts.username or parts.password:
        raise UnprocessableEntity(
            "Do not put credentials in the URL; use a login profile", code="target.url_credentials"
        )
    return locator.strip()


def validate_target_rules(
    *,
    kind: TargetKind,
    locator: str | None,
    environment: TargetEnvironment | None,
    application_type: AppType,
    login_profile_id: Any = None,
    upload_artifact_id: Any = None,
) -> str:
    """Check a target's combination of fields and return the normalised locator."""
    if kind == TargetKind.URL:
        if environment is None:
            raise UnprocessableEntity(
                "URL targets need an environment tag (production or uat)",
                code="target.environment_required",
            )
        if environment == TargetEnvironment.PRODUCTION and login_profile_id is not None:
            raise UnprocessableEntity(
                "Production targets accept unauthenticated baseline scans only; "
                "a login profile is allowed on UAT targets",
                code="target.login_profile_production",
            )
        return validate_url(locator or "")
    if environment is not None:
        raise UnprocessableEntity(
            "Only URL targets carry an environment tag", code="target.environment_not_allowed"
        )
    if login_profile_id is not None:
        raise UnprocessableEntity(
            "Only URL targets can have a login profile", code="target.login_profile_not_allowed"
        )
    if kind == TargetKind.ZIP:
        if upload_artifact_id is None:
            raise UnprocessableEntity(
                "Zip targets need a finished upload", code="target.upload_required"
            )
        return f"upload:{upload_artifact_id}"
    if kind == TargetKind.VENDOR_REPO and application_type != AppType.VENDOR:
        raise UnprocessableEntity(
            "Vendor repositories belong to vendor applications", code="target.vendor_repo_internal"
        )
    value = (locator or "").strip()
    if not value or not _NO_SPACE.match(value) or len(value) > 2000:
        raise UnprocessableEntity(
            "The locator must be a repository, image reference or URL without spaces",
            code="target.invalid_locator",
        )
    return value
