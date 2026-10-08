"""Scanner image updates: monthly proposals, the SonarQube December rule, approval.

The monthly task (``securescan/jobs/image_updates.py``) reads ``deploy/images.lock.yaml``, asks the
registries what each tag points to now and which newer tags exist, and stores what it finds as
``ImageVersion`` rows with ``source = "proposal"``. Nothing changes for scans until an Admin approves a
row (``approve_image_version``): the catalogue loader (``securescan/runner/catalogue.py``) then
overlays the active row on the lock file's digest.

Row life cycle (``image_versions``)::

    proposal, regression_result pending -> testing -> passed | failed | error | skipped
    proposal, passed (or skipped + acknowledged)  --approve-->  active = true, approved_at set
    proposal  --reject-->  source = "rejected"           active row  --deactivate-->  active = false

Scope (``regression_detail["scope"]``): ``runtime`` images are started by the worker (scanners, the
SonarQube server, squid, skopeo), so an approved row takes effect at the next scan. ``release`` images
(PostgreSQL, Python, Node, nginx, the socket proxy, DefectDojo, Valkey) are part of the Compose bundle:
a proposal is only a notice, applied by editing ``deploy/images.lock.yaml`` in the next release.

Everything above the "storing and approving" banner is pure and unit-tested without a database.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from securescan.api.problems import Conflict, UnprocessableEntity
from securescan.db.models.images import ImageVersion
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.integrations.registry import ImageName, RegistryError, parse_image_name, registry_hosts
from securescan.logging import get_logger
from securescan.util import new_id, utcnow

log = get_logger(__name__)

SOURCE_PROPOSAL = "proposal"
SOURCE_REJECTED = "rejected"
SCOPE_RUNTIME = "runtime"
SCOPE_RELEASE = "release"

# Images the Compose bundle starts: a proposal for one of them is a notice, not an overlay.
LOCAL_BUILT = frozenset({"SPOTBUGS_FSB"})  # built from scanners/spotbugs/Dockerfile, not pulled
STATIC_RUNTIME_LOCKS = frozenset(
    {
        "SEMGREP", "GITLEAKS", "SONARQUBE", "SONAR_SCANNER", "SYFT", "GRYPE", "DEPENDENCY_CHECK",
        "ZAP", "NUCLEI", "SKOPEO", "SQUID",
    }
)  # fmt: skip

# How many leading version components a candidate must share with the current tag. Major upgrades of
# these products need a migration runbook, not a digest swap.
KEEP_COMPONENTS: dict[str, int] = {
    "POSTGRES": 1,
    "PYTHON": 2,
    "NODE": 1,
    "DD_DJANGO": 1,
    "DD_NGINX": 1,
    "DD_VALKEY": 1,
}

# Image tool (catalogue tool or lower-cased lock name) -> (scan job tool to run, expectation tool).
# Only images whose digest the scan job records (``scan_jobs.image_digest`` is the image of the job's own catalogue
# entry) can be gated: the gate checks that the job ran the candidate. A tool missing here has no regression: the
# proposal is stored as ``skipped`` and approving needs an acknowledgement. That is the case for the Syft image (it runs
# inside the syft-grype job but is not the job's recorded image), for the SonarQube *server* (created by the lifecycle task,
# not by the job; ``sonarqube-upgrade.md`` is the hand test), squid, skopeo, ZAP and Nuclei.
REGRESSION_TOOLS: dict[str, tuple[str, str]] = {
    "semgrep": ("semgrep", "semgrep"),
    "gitleaks": ("gitleaks", "gitleaks"),
    "syft-grype": ("syft-grype", "grype"),  # the Grype image; also used by grype-db-update and grype-db-status
    "dependency-check": ("dependency-check", "dependency-check"),
    "spotbugs": ("spotbugs", "spotbugs"),
    "sonarqube": ("sonarqube", "sonarqube"),  # the scanner image (sonar-scanner-cli)
}


# ================================================================================ tags (pure)

_TAG = re.compile(
    r"^(?P<prefix>v?)(?P<a>\d+(?:\.\d+)*)(?:_(?P<b>\d+(?:\.\d+)*))?(?P<suffix>-[A-Za-z][A-Za-z0-9._-]*)?$"
)
_SONAR = re.compile(r"^(?P<year>\d{2})\.(?P<month>\d{1,2})\.(?P<patch>\d+)\.(?P<build>\d+)-community$")


@dataclass(frozen=True)
class ParsedTag:
    """A version-like tag: ``v8.30.1``, ``1.179.0-nonroot``, ``26.9.0.129388-community``, ``12.2.0.4256_8.1.0``."""

    raw: str
    prefix: str
    parts: tuple[tuple[int, ...], ...]
    suffix: str

    @property
    def series(self) -> tuple[str, tuple[int, ...], str]:
        """Tags are comparable only inside one series: same prefix, same suffix, same number of components."""
        return (self.prefix, tuple(len(p) for p in self.parts), self.suffix)


def parse_tag(tag: str) -> ParsedTag | None:
    """None for tags that are not versions (``latest``, ``stable``, ``stable-alpine``, ``sha-abc``)."""
    match = _TAG.match(tag.strip())
    if match is None:
        return None
    groups = [match.group("a")] + ([match.group("b")] if match.group("b") else [])
    try:
        parts = tuple(tuple(int(piece) for piece in group.split(".")) for group in groups)
    except ValueError:
        return None
    return ParsedTag(tag.strip(), match.group("prefix"), parts, match.group("suffix") or "")


def newer_tags(current: str, tags: Iterable[str], keep_components: int = 0) -> list[str]:
    """Tags of the same series that are newer than ``current``, newest first.

    ``keep_components`` > 0 requires that many leading components to equal the current tag's (so a
    PostgreSQL 18 image is never offered 19).
    """
    base = parse_tag(current)
    if base is None:
        return []
    found: list[ParsedTag] = []
    seen: set[str] = set()
    for tag in tags:
        parsed = parse_tag(tag)
        if parsed is None or parsed.series != base.series or parsed.parts <= base.parts:
            continue
        if keep_components and parsed.parts[0][:keep_components] != base.parts[0][:keep_components]:
            continue
        if parsed.raw in seen:
            continue
        seen.add(parsed.raw)
        found.append(parsed)
    found.sort(key=lambda p: p.parts, reverse=True)
    return [p.raw for p in found]


# --------------------------------------------------------------------------- SonarQube December rule


@dataclass(frozen=True, order=True)
class SonarVersion:
    """``YY.M.patch.build-community``: ``26.9.0.129388-community`` is the September 2026 build."""

    year: int
    month: int
    patch: int
    build: int


def parse_sonar_tag(tag: str) -> SonarVersion | None:
    match = _SONAR.match(tag.strip())
    if match is None:
        return None
    return SonarVersion(
        int(match.group("year")), int(match.group("month")), int(match.group("patch")), int(match.group("build"))
    )


def sonarqube_candidate_allowed(current_tag: str, candidate_tag: str) -> bool:
    """The December rule of SonarQube Community Build.

    A newer build of the same calendar year is always allowed. A build of the *next* calendar year is
    allowed only when the current build is the December build of its year (Sonar requires every year
    boundary to be crossed through that release). Two years ahead is never allowed: the in-between
    December comes first.
    """
    current = parse_sonar_tag(current_tag)
    candidate = parse_sonar_tag(candidate_tag)
    if current is None or candidate is None or candidate <= current:
        return False
    if candidate.year == current.year:
        return True
    if candidate.year == current.year + 1:
        return current.month == 12
    return False


def is_sonarqube_server(lock_name: str, tool: str) -> bool:
    return lock_name == "SONARQUBE" or tool == "sonarqube-server"


def select_candidate(
    lock_name: str, tool: str, current_tag: str, tags: Iterable[str], keep_components: int | None = None
) -> str | None:
    """The one newer tag to propose for an image, or None."""
    keep = KEEP_COMPONENTS.get(lock_name, 0) if keep_components is None else keep_components
    candidates = newer_tags(current_tag, tags, keep)
    if is_sonarqube_server(lock_name, tool):
        candidates = [c for c in candidates if sonarqube_candidate_allowed(current_tag, c)]
    return candidates[0] if candidates else None


# ================================================================================ lock file


@dataclass(frozen=True)
class LockImage:
    name: str  # NAME in images.lock.yaml, also the SECURESCAN_IMAGE_<NAME> variable
    image: str
    tag: str
    digest: str | None


def lock_file_candidates(scanners_dir: Path | None) -> list[Path]:
    """Where the lock file may be: next to the scanners directory's parent (repository layout, and
    ``/app/deploy`` in the worker container), or inside the scanners directory."""
    paths: list[Path] = []
    if scanners_dir is not None:
        paths.append(scanners_dir.parent / "deploy" / "images.lock.yaml")
        paths.append(scanners_dir / "images.lock.yaml")
    return paths


def parse_lock_file(text: str) -> list[LockImage]:
    data = yaml.safe_load(text) or {}
    items = data.get("images") if isinstance(data, dict) else None
    result: list[LockImage] = []
    for item in items or []:
        if not isinstance(item, dict) or not item.get("name") or not item.get("image") or not item.get("tag"):
            continue
        digest = item.get("digest")
        result.append(
            LockImage(
                name=str(item["name"]),
                image=str(item["image"]),
                tag=str(item["tag"]),
                digest=str(digest) if digest else None,
            )
        )
    return result


def load_lock_images(scanners_dir: Path | None) -> list[LockImage]:
    for path in lock_file_candidates(scanners_dir):
        if path.is_file():
            return parse_lock_file(path.read_text(encoding="utf-8"))
    return []


def lock_yaml_line(row: ImageVersion) -> str:
    """The line for ``deploy/images.lock.yaml`` that records this image in the next release commit."""
    detail = row.regression_detail or {}
    name = str(detail.get("lock_name") or row.tool.upper().replace("-", "_"))
    return '- { name: %s, image: %s, tag: "%s", digest: %s }' % (name, row.image, row.tag or "", row.digest)


# ================================================================================ proposals (pure)


class RegistryLike(Protocol):
    async def manifest_digest(self, image: ImageName, reference: str) -> str | None: ...

    async def list_tags(self, image: ImageName) -> list[str]: ...


@dataclass(frozen=True)
class Current:
    """What is in use for one image now: the active approved row, else the lock file."""

    tag: str
    digest: str | None
    from_override: bool


@dataclass(frozen=True)
class Proposal:
    lock_name: str
    tool: str
    image: str
    tag: str
    digest: str
    reason: str  # rebuild | new_version
    scope: str
    previous_tag: str
    previous_digest: str | None


@dataclass
class PlanOutcome:
    proposals: list[Proposal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # one plain sentence per image that could not be checked


def primary_tool_by_lock(entries: Mapping[str, Any]) -> dict[str, str]:
    """``{lock name: catalogue tool}``. Several entries can share one lock (Grype: the scan, the database update and the
    status entries); the proposal is stored under the entry that scans something (it has target kinds), else the first by
    name. The catalogue overlay applies an approved row to every entry with the same lock."""
    ordered = sorted(entries, key=lambda name: (not getattr(entries[name], "target_kinds", None), name))
    mapping: dict[str, str] = {}
    for name in ordered:
        lock = getattr(entries[name].image, "lock", None)
        if lock and lock not in mapping:
            mapping[lock] = name
    return mapping


def tool_for_lock(lock_name: str, tool_by_lock: Mapping[str, str]) -> str:
    """The ``ImageVersion.tool`` of a lock image: the catalogue tool that uses it, else the lower-cased
    lock name (``SQUID`` -> ``squid``, which ``runner/egress.py`` looks up)."""
    return tool_by_lock.get(lock_name) or lock_name.lower()


def scope_for(lock_name: str, runtime_locks: Iterable[str]) -> str:
    return SCOPE_RUNTIME if lock_name in set(runtime_locks) else SCOPE_RELEASE


async def plan_image(
    lock_image: LockImage,
    current: Current,
    *,
    tool: str,
    scope: str,
    registry: RegistryLike,
) -> PlanOutcome:
    """What to propose for one image: a rebuild of the current tag, and/or one newer tag."""
    outcome = PlanOutcome()
    try:
        name = parse_image_name(lock_image.image)
        proposals: dict[str, Proposal] = {}

        def add(tag: str, digest: str, reason: str) -> None:
            if digest == current.digest or digest in proposals:
                return
            proposals[digest] = Proposal(
                lock_name=lock_image.name, tool=tool, image=lock_image.image, tag=tag, digest=digest,
                reason=reason, scope=scope, previous_tag=current.tag, previous_digest=current.digest,
            )  # fmt: skip

        if current.digest is None:
            outcome.notes.append(
                "%s has no pinned digest yet (run `python scripts/dev.py pin-images`); nothing to compare." % lock_image.name
            )
            return outcome
        now_digest = await registry.manifest_digest(name, current.tag)
        if now_digest is None:
            outcome.notes.append("%s: the tag %s no longer exists in the registry." % (lock_image.name, current.tag))
        else:
            add(current.tag, now_digest, "rebuild")
        if parse_tag(current.tag) is not None:
            tags = await registry.list_tags(name)
            newer = select_candidate(lock_image.name, tool, current.tag, tags)
            if newer is not None:
                digest = await registry.manifest_digest(name, newer)
                if digest is None:
                    outcome.notes.append("%s: the tag %s vanished while it was read." % (lock_image.name, newer))
                else:
                    add(newer, digest, "new_version")
        outcome.proposals.extend(proposals.values())
    except RegistryError as exc:
        outcome.notes.append("%s: %s" % (lock_image.name, exc))
    return outcome


# ================================================================================ storing and approving


@dataclass
class StoredProposal:
    id: Any
    tool: str
    tag: str
    scope: str
    regression_result: str
    job_tool: str | None  # the scan job tool to run for the regression, None when skipped


@dataclass
class ProposalSummary:
    checked: int = 0
    new: list[StoredProposal] = field(default_factory=list)
    already_known: int = 0
    notes: list[str] = field(default_factory=list)


def regression_job_for(tool: str, scope: str) -> str | None:
    """The scan job tool that exercises a candidate of ``tool``, None when no expectations apply."""
    if scope != SCOPE_RUNTIME:
        return None
    mapping = REGRESSION_TOOLS.get(tool)
    return mapping[0] if mapping else None


async def active_rows_by_tool(session: AsyncSession) -> dict[str, ImageVersion]:
    rows = (
        await session.scalars(
            select(ImageVersion).where(ImageVersion.active.is_(True)).order_by(ImageVersion.approved_at)
        )
    ).all()
    return {row.tool: row for row in rows}  # the newest approval wins


def current_for(lock_image: LockImage, tool: str, active: Mapping[str, ImageVersion]) -> Current:
    row = active.get(tool)
    if row is not None and row.tag:
        return Current(tag=row.tag, digest=row.digest, from_override=True)
    return Current(tag=lock_image.tag, digest=lock_image.digest, from_override=False)


async def store_proposals(session: AsyncSession, proposals: Sequence[Proposal]) -> ProposalSummary:
    """Write the proposals that are not known yet (one row per tool and digest, rejected ones stay rejected)."""
    summary = ProposalSummary()
    for proposal in proposals:
        existing = await session.scalar(
            select(ImageVersion).where(
                ImageVersion.tool == proposal.tool, ImageVersion.digest == proposal.digest
            )
        )
        if existing is not None:
            summary.already_known += 1
            continue
        job_tool = regression_job_for(proposal.tool, proposal.scope)
        result = "pending" if job_tool else "skipped"
        reason = (
            "Platform image: applied by editing deploy/images.lock.yaml in the next release."
            if proposal.scope == SCOPE_RELEASE
            else "No regression expectations exist for this tool; approving needs an explicit acknowledgement."
        )
        row = ImageVersion(
            id=new_id(),
            tool=proposal.tool,
            image=proposal.image,
            tag=proposal.tag,
            digest=proposal.digest,
            source=SOURCE_PROPOSAL,
            regression_result=result,
            regression_detail={
                "scope": proposal.scope,
                "reason": proposal.reason,
                "lock_name": proposal.lock_name,
                "previous_tag": proposal.previous_tag,
                "previous_digest": proposal.previous_digest,
                **({"note": reason} if result == "skipped" else {}),
            },
            active=False,
            proposed_at=utcnow(),
            notes=None,
            created_at=utcnow(),
        )
        session.add(row)
        await session.flush()
        await record_audit(
            session, SYSTEM_ACTOR, "image.propose", "image_version", row.id,
            {
                "tool": row.tool, "tag": row.tag, "digest": row.digest, "scope": proposal.scope,
                "reason": proposal.reason, "previous_tag": proposal.previous_tag,
            },
        )  # fmt: skip
        summary.new.append(
            StoredProposal(
                id=row.id, tool=row.tool, tag=row.tag or "", scope=proposal.scope,
                regression_result=result, job_tool=job_tool,
            )
        )  # fmt: skip
    return summary


def public_detail(detail: Mapping[str, Any] | None) -> dict[str, Any]:
    """``regression_detail`` without the candidate token (never leaves the server)."""
    return {k: v for k, v in (detail or {}).items() if k != "candidate_token"}


def _is_pending_proposal(row: ImageVersion) -> bool:
    return row.source == SOURCE_PROPOSAL and row.approved_at is None and not row.active


def check_approvable(row: ImageVersion, *, acknowledge_skipped: bool) -> None:
    """Raise a 409/422 problem unless ``row`` may be approved. Pure: no database access."""
    detail = row.regression_detail or {}
    if not _is_pending_proposal(row):
        raise Conflict("Only a pending proposal can be approved.", code="image.not_pending")
    if detail.get("scope") == SCOPE_RELEASE:
        raise Conflict(
            "This image is part of the platform release. Update deploy/images.lock.yaml in the next "
            "release instead of approving it here.",
            code="image.release_scope",
        )
    result = row.regression_result
    if result == "skipped":
        if not acknowledge_skipped:
            raise UnprocessableEntity(
                "No regression check exists for this image. Confirm that you tested it by hand "
                "(acknowledge_skipped) to approve it.",
                code="image.ack_required",
            )
    elif result != "passed":
        raise Conflict(
            "The regression check is %s. A proposal goes live only after the regression suite passed." % result,
            code="image.regression_not_passed",
        )
    previous = str(detail.get("previous_tag") or "")
    tag = row.tag or ""
    if (
        previous
        and previous != tag
        and parse_sonar_tag(tag) is not None
        and not sonarqube_candidate_allowed(previous, tag)
    ):
        raise Conflict(
            "SonarQube crosses a year boundary only through the December build; "
            "approve the December build of the current year first.",
            code="image.december_rule",
        )


async def approve_image_version(
    session: AsyncSession,
    row: ImageVersion,
    user: Any,
    *,
    acknowledge_skipped: bool = False,
    request: Any = None,
) -> ImageVersion:
    """Make ``row`` the image in use for its tool (audited). The caller commits."""
    check_approvable(row, acknowledge_skipped=acknowledge_skipped)
    now = utcnow()
    previous = (
        await session.scalars(
            select(ImageVersion).where(
                ImageVersion.tool == row.tool, ImageVersion.active.is_(True), ImageVersion.id != row.id
            )
        )
    ).all()
    for old in previous:
        old.active = False
    row.active = True
    row.approved_at = now
    row.approved_by_id = getattr(user, "id", None)
    await session.flush()
    await record_audit(
        session, user, "image.approve", "image_version", row.id,
        {
            "tool": row.tool, "tag": row.tag, "digest": row.digest,
            "regression_result": row.regression_result, "acknowledged_skipped": acknowledge_skipped,
            "replaced": [str(old.id) for old in previous],
        },
        request,
    )  # fmt: skip
    return row


async def reject_image_version(
    session: AsyncSession, row: ImageVersion, user: Any, *, note: str | None = None, request: Any = None
) -> ImageVersion:
    """Mark a pending proposal as rejected so the same digest is not proposed again (audited)."""
    if not _is_pending_proposal(row):
        raise Conflict("Only a pending proposal can be rejected.", code="image.not_pending")
    row.source = SOURCE_REJECTED
    row.notes = (note or "").strip()[:2000] or None
    await session.flush()
    await record_audit(
        session, user, "image.reject", "image_version", row.id,
        {"tool": row.tool, "tag": row.tag, "digest": row.digest}, request,
    )  # fmt: skip
    return row


async def deactivate_image_version(
    session: AsyncSession, row: ImageVersion, user: Any, *, request: Any = None
) -> ImageVersion:
    """Stop using an approved image: the next scan falls back to the lock file's digest (audited)."""
    if not row.active:
        raise Conflict("This image is not in use.", code="image.not_active")
    row.active = False
    await session.flush()
    await record_audit(
        session, user, "image.deactivate", "image_version", row.id,
        {"tool": row.tool, "tag": row.tag, "digest": row.digest}, request,
    )  # fmt: skip
    return row


# ================================================================================ the whole run


async def run_proposals(
    session_scope_factory: Callable[[], Any],
    registry: RegistryLike,
    lock_images: Sequence[LockImage],
    *,
    tool_by_lock: Mapping[str, str],
    runtime_locks: Iterable[str],
    local_built: Iterable[str] = LOCAL_BUILT,
    on_progress: Callable[[str], Awaitable[None]] | None = None,
) -> ProposalSummary:
    """Check every lock image against its registry and store the new proposals.

    ``session_scope_factory`` is ``securescan.db.session.session_scope`` (an async context manager that
    commits). The registry is read first (no transaction held open), the rows are written at the end.
    """
    runtime = set(runtime_locks)
    skip = set(local_built)
    async with session_scope_factory() as session:
        active = await active_rows_by_tool(session)
    summary = ProposalSummary()
    collected: list[Proposal] = []
    for lock_image in lock_images:
        if lock_image.name in skip:
            summary.notes.append("%s is built locally; rebuild it from new SpotBugs and Find Security Bugs releases." % lock_image.name)
            continue
        tool = tool_for_lock(lock_image.name, tool_by_lock)
        current = current_for(lock_image, tool, active)
        outcome = await plan_image(
            lock_image, current, tool=tool, scope=scope_for(lock_image.name, runtime), registry=registry
        )
        summary.checked += 1
        summary.notes.extend(outcome.notes)
        collected.extend(outcome.proposals)
        if on_progress is not None:
            await on_progress(lock_image.name)
    async with session_scope_factory() as session:
        stored = await store_proposals(session, collected)
    stored.checked = summary.checked
    stored.notes = summary.notes + stored.notes
    return stored


def egress_hosts_for(lock_images: Iterable[LockImage], local_built: Iterable[str] = LOCAL_BUILT) -> set[str]:
    """Registry hosts the egress proxy must allow for a run over these images."""
    skip = set(local_built)
    hosts: set[str] = set()
    for item in lock_images:
        if item.name in skip:
            continue
        try:
            hosts |= registry_hosts(parse_image_name(item.image))
        except RegistryError:
            continue
    return hosts


def when(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


# ================================================================================ command line


async def active_references() -> list[str]:
    """``image@digest`` of every approved, active row: what ``dev.py pull-images`` must also pull."""
    from securescan.db.session import session_scope

    async with session_scope() as session:
        rows = (
            await session.scalars(
                select(ImageVersion)
                .where(ImageVersion.active.is_(True), ImageVersion.approved_at.is_not(None))
                .order_by(ImageVersion.tool)
            )
        ).all()
    return ["%s@%s" % (row.image, row.digest) for row in rows]


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m securescan.domain.image_updates active``: print the references of the approved images.

    The worker may not pull images, so after an approval pull them from the host::

        sc exec -T api python -m securescan.domain.image_updates active | while read ref; do docker pull "$ref"; done
    """
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(prog="securescan.domain.image_updates")
    parser.add_argument("command", choices=["active"], help="active: the image@digest of every approved image")
    parser.parse_args(list(argv) if argv is not None else None)
    for reference in asyncio.run(active_references()):
        print(reference)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
