"""Types shared by the source handlers (zip, git repository, later image)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from securescan.config import Settings
from securescan.db.models.applications import Application
from securescan.db.models.scans import Scan
from securescan.db.models.targets import Target
from securescan.db.models.versions import ApplicationVersion
from securescan.runner.workspace import Workspace

LogLine = Callable[[str], Awaitable[None]]
ClaimCommit = Callable[[str], Awaitable[str]]


class SourceError(Exception):
    """The source could not be obtained or is not acceptable. ``str(exc)`` is plain language.

    ``code`` is a stable machine-readable value (``zip.path_traversal``, ``git.clone_failed``, ...)
    that the API turns into a problem detail and the job stores as its outcome reason.
    """

    def __init__(self, message: str, code: str = "source.error") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class SourceInfo:
    """What was placed in the workspace's ``src`` directory."""

    kind: str  # zip | git | image
    is_git: bool
    commit_sha: str | None = None
    ref: str | None = None
    description: str = ""
    notes: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceRequest:
    """Everything a handler needs to fill ``workspace.src`` for one job."""

    session: AsyncSession
    scan: Scan
    version: ApplicationVersion
    application: Application
    target: Target
    workspace: Workspace
    settings: Settings
    log: LogLine
    claim_commit: ClaimCommit
