"""Repository discovery: turn the repositories the GitHub App can reach into inventory.

New repositories become ``Application`` rows (``type=internal``, ``confirmed=false``,
``automatic=false``) with a version named after the default branch and a ``github_repo`` target.
Repositories the App no longer lists are flagged (``github_removed_at``), never deleted: history is
kept forever. An analyst confirms an application and decides whether it joins the automatic set.

``run_discovery`` holds the rules and talks to a small store protocol; ``SqlDiscoveryStore`` is the
SQLAlchemy implementation, so the rules can be tested without a database.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.db.models.applications import Application
from securescan.db.models.enums import AppType, TargetKind
from securescan.db.models.targets import Target
from securescan.db.models.versions import ApplicationVersion
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.integrations.github.app import RepositoryInfo
from securescan.logging import get_logger
from securescan.util import utcnow

log = get_logger(__name__)


@dataclass
class KnownApplication:
    """What discovery needs to know about an application that already has a GitHub repository id."""

    id: uuid.UUID
    github_repo_id: int
    full_name: str | None
    default_branch: str | None
    removed_at: datetime | None


@dataclass
class DiscoveryResult:
    seen: int = 0
    created: int = 0
    updated: int = 0
    removed: int = 0
    restored: int = 0
    created_names: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            "%d repositories seen, %d new, %d updated, %d removed, %d restored"
            % (self.seen, self.created, self.updated, self.removed, self.restored)
        )


class DiscoveryStore(Protocol):
    async def known_applications(self) -> list[KnownApplication]: ...

    async def create_application(self, repo: RepositoryInfo) -> uuid.UUID: ...

    async def update_application(
        self, application_id: uuid.UUID, repo: RepositoryInfo, *, restored: bool
    ) -> None: ...

    async def mark_removed(self, application_id: uuid.UUID, when: datetime) -> None: ...

    async def audit(self, action: str, object_id: uuid.UUID, detail: dict[str, object]) -> None: ...


def wants_application(repo: RepositoryInfo) -> bool:
    """Disabled repositories cannot be cloned, so they are not added."""
    return not repo.disabled and bool(repo.full_name)


async def run_discovery(
    repositories: Sequence[RepositoryInfo],
    store: DiscoveryStore,
    *,
    now: datetime | None = None,
) -> DiscoveryResult:
    """Apply ``repositories`` (the complete list the App can reach) to the inventory."""
    moment = now or utcnow()
    result = DiscoveryResult(seen=len(repositories))
    known = {k.github_repo_id: k for k in await store.known_applications()}
    present: set[int] = set()
    for repo in repositories:
        present.add(repo.id)
        existing = known.get(repo.id)
        if existing is None:
            if not wants_application(repo):
                continue
            application_id = await store.create_application(repo)
            result.created += 1
            result.created_names.append(repo.full_name)
            await store.audit(
                "application.discovered",
                application_id,
                {"repository": repo.full_name, "default_branch": repo.default_branch},
            )
            continue
        restored = existing.removed_at is not None
        changed = (
            restored
            or existing.full_name != repo.full_name
            or existing.default_branch != repo.default_branch
        )
        if changed:
            await store.update_application(existing.id, repo, restored=restored)
            result.updated += 1
            if restored:
                result.restored += 1
            await store.audit(
                "application.github_update",
                existing.id,
                {
                    "repository": repo.full_name,
                    "default_branch": repo.default_branch,
                    "restored": restored,
                },
            )
    for repo_id, existing in known.items():
        if repo_id not in present and existing.removed_at is None:
            await store.mark_removed(existing.id, moment)
            result.removed += 1
            await store.audit(
                "application.github_removed", existing.id, {"repository": existing.full_name}
            )
    log.info(
        "github_discovery_done",
        seen=result.seen,
        created=result.created,
        updated=result.updated,
        removed=result.removed,
        restored=result.restored,
    )
    return result


# ------------------------------------------------------------------------------ SQL implementation


async def ensure_default_version(
    session: AsyncSession, application: Application
) -> tuple[ApplicationVersion, Target] | None:
    """The version named after the default branch and its ``github_repo`` target, created if missing.

    None when the application has no repository or its default-branch version is archived.
    """
    if not application.github_full_name or not application.default_branch:
        return None
    version = await session.scalar(
        select(ApplicationVersion).where(
            ApplicationVersion.application_id == application.id,
            ApplicationVersion.label == application.default_branch,
        )
    )
    now = utcnow()
    if version is None:
        version = ApplicationVersion(
            application_id=application.id,
            label=application.default_branch,
            label_kind="branch",
            description="Default branch (created by GitHub discovery)",
            created_at=now,
            updated_at=now,
        )
        session.add(version)
        await session.flush()
    elif version.archived_at is not None:
        return None
    target = await session.scalar(
        select(Target).where(
            Target.version_id == version.id,
            Target.kind == TargetKind.GITHUB_REPO,
            Target.archived_at.is_(None),
        )
    )
    if target is None:
        target = Target(
            version_id=version.id,
            kind=TargetKind.GITHUB_REPO,
            locator=application.github_full_name,
            default_branch=application.default_branch,
            created_at=now,
            updated_at=now,
        )
        session.add(target)
        await session.flush()
    elif target.locator != application.github_full_name:
        target.locator = application.github_full_name  # the repository was renamed
        target.default_branch = application.default_branch
        target.updated_at = now
    return version, target


class SqlDiscoveryStore:
    """``DiscoveryStore`` on a SQLAlchemy session. The caller commits."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def known_applications(self) -> list[KnownApplication]:
        rows = await self._session.scalars(
            select(Application).where(Application.github_repo_id.is_not(None))
        )
        return [
            KnownApplication(
                id=a.id,
                github_repo_id=int(a.github_repo_id or 0),
                full_name=a.github_full_name,
                default_branch=a.default_branch,
                removed_at=a.github_removed_at,
            )
            for a in rows.all()
        ]

    async def _unique_name(self, full_name: str, repo_id: int) -> str:
        taken = await self._session.scalar(
            select(func.count())
            .select_from(Application)
            .where(func.lower(Application.name) == full_name.lower())
        )
        name = full_name if not taken else "%s (%d)" % (full_name, repo_id)
        return name[:200]

    async def create_application(self, repo: RepositoryInfo) -> uuid.UUID:
        now = utcnow()
        application = Application(
            name=await self._unique_name(repo.full_name, repo.id),
            type=AppType.INTERNAL,
            confirmed=False,
            automatic=False,
            github_repo_id=repo.id,
            github_full_name=repo.full_name,
            default_branch=repo.default_branch,
            tags=[],
            cached_counts={},
            created_by_id=None,
            created_at=now,
            updated_at=now,
        )
        self._session.add(application)
        await self._session.flush()
        await ensure_default_version(self._session, application)
        return application.id

    async def update_application(
        self, application_id: uuid.UUID, repo: RepositoryInfo, *, restored: bool
    ) -> None:
        application = await self._session.get(Application, application_id)
        if application is None:
            return
        application.github_full_name = repo.full_name
        application.default_branch = repo.default_branch
        if restored:
            application.github_removed_at = None
        application.updated_at = utcnow()
        await ensure_default_version(self._session, application)

    async def mark_removed(self, application_id: uuid.UUID, when: datetime) -> None:
        application = await self._session.get(Application, application_id)
        if application is not None:
            application.github_removed_at = when
            application.updated_at = when

    async def audit(self, action: str, object_id: uuid.UUID, detail: dict[str, object]) -> None:
        await record_audit(
            self._session, SYSTEM_ACTOR, action, "application", object_id, dict(detail)
        )
