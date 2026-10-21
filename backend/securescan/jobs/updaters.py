"""Content updaters (plan M8 tasks 2, 3, 6): Grype database, Semgrep rules, Nuclei templates.

Scan containers never download anything; these updaters do, on a schedule, through the shared egress proxy
(``runner/egress.py``) and in containers built from catalogue entries. Each update ends in a ``ContentVersion``
row and a metric; a failed update keeps the previous version active and sets
``securescan_content_update_failed{feed}`` (alert metric).

=========================  ==========================  ==============================================================
Periodic task              Feed                        What it does
=========================  ==========================  ==============================================================
``grype_db_update`` 07:30  ``grype_db``                ``grype db update`` (single writer), ``grype db status`` for the
                                                       build date; no regression gate (data, not logic)
``rules_and_templates_     ``semgrep_rules``,          clone ``semgrep-rules`` at the pinned commit (``content/
update`` Sat 03:00         ``nuclei_templates``        semgrep-rules.lock``), licence filter, regression gate, symlink
                                                       switch; Nuclei templates into a dated directory, same gate
=========================  ==========================  ==============================================================

Manual start: task ``content_update(feed)`` (``POST /api/v1/content-versions/updates``). At worker start-up the
first update of every empty feed is queued (``SECURESCAN_CONTENT_BOOTSTRAP``).

The regression gate is ``run_regression(kind)`` (async; returns True when the candidate may be promoted). Its
minimal form: Semgrep rules must run on the planted sample apps without rule errors and must still produce every
``verified: true`` expectation of ``expected-findings.yaml``; Nuclei templates must pass ``nuclei -validate``.
M11 extends it (image bumps, the Juice Shop run). The first installation of a feed has nothing to regress against
and is promoted without the Semgrep gate.

One worker process is assumed (as for the egress proxy): updates are serialised by in-process locks.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select, update

from securescan.config import Settings, get_settings
from securescan.db.models.content import ContentVersion
from securescan.db.models.enums import ContentFeed
from securescan.db.session import session_scope
from securescan.domain.audit import SYSTEM_ACTOR, record_audit
from securescan.jobs.app import app
from securescan.jobs.enqueue import defer
from securescan.jobs.hooks import periodic_hook, worker_startup_hook
from securescan.jobs.scanner_health import (
    ALL_FEEDS,
    active_versions,
    feed_value,
    record_feed_clock,
    record_update_result,
    reference_time,
)
from securescan.logging import get_logger, scrub
from securescan.runner.catalogue import (
    CatalogueEntry,
    ResolvedImage,
    find_scanners_dir,
    get_entry,
    resolve_image_with_override,
)
from securescan.runner.egress import EgressError, egress_lease
from securescan.runner.sources.base import SourceError
from securescan.runner.sources.github import CloneAuth, GitRunner, base_git_args, clone_repository, git_environment
from securescan.runner.specs import ContainerResult, ContainerSpec
from securescan.runner.tools._support import (
    content_dir,
    egress_network,
    proxy_env,
    spec_from_entry,
)
from securescan.runner.tools.base import LABEL_MANAGED, LABEL_TOOL
from securescan.runner.workspace import Workspace
from securescan.util import new_id, utcnow

log = get_logger(__name__)

GRYPE_HOSTS = ("grype.anchore.io", "toolbox-data.anchore.io")
GITHUB_HOSTS = ("github.com", "codeload.github.com")
NUCLEI_HOSTS = (
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "api.pdtm.sh",
)
RULES_PREFIX = "rules-"
RULES_LINK = "rules"
TEMPLATES_PREFIX = "nuclei-templates-"
TEMPLATES_LINK = "nuclei-templates"
BUNDLE_INFO = "BUNDLE.info"
GRYPE_DB_DIRECTORY = "grype-db"
MIN_TEMPLATE_FILES = 200
NOTICE_PREFIXES = ("LICENSE", "LICENCE", "NOTICE", "COPYING")
YAML_SUFFIXES = (".yaml", ".yml")

_FEED_LOCKS: dict[str, asyncio.Lock] = {}


def feed_lock(feed: ContentFeed | str) -> asyncio.Lock:
    return _FEED_LOCKS.setdefault(feed_value(feed), asyncio.Lock())


@dataclass
class UpdateOutcome:
    feed: str
    ok: bool
    changed: bool = False
    version: str | None = None
    message: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


# =============================================================================================== helpers
def utc_stamp(moment: datetime | None = None) -> str:
    return (moment or utcnow()).strftime("%Y%m%d")


def parse_timestamp(value: Any) -> datetime | None:
    """An ISO 8601 time (``...Z`` or with an offset) as an aware UTC datetime; None when unreadable."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def switch_symlink(link: Path, target_name: str) -> None:
    """Point ``link`` at ``target_name`` (a sibling directory) atomically.

    A relative link is created beside the old one and renamed over it, so a scan that resolves the link sees
    either the old or the new directory, never neither. A real directory in the link's place (put there by hand
    or by spike S7) is moved aside first.
    """
    if "/" in target_name or target_name in ("", ".", ".."):
        raise ValueError(f"unsafe link target {target_name!r}")
    if not (link.parent / target_name).is_dir():
        raise FileNotFoundError(f"{target_name} does not exist beside {link.name}")
    temporary = link.with_name(link.name + ".new")
    if os.path.lexists(temporary):
        os.unlink(temporary)
    os.symlink(target_name, temporary)
    if os.path.lexists(link) and not os.path.islink(link):
        os.replace(link, link.with_name(f"{link.name}.previous-{int(time.time())}"))
    os.replace(temporary, link)


def prune_directories(parent: Path, prefix: str, keep: int, protect: Iterable[str] = ()) -> list[str]:
    """Remove the oldest directories ``parent/<prefix>*`` beyond ``keep``, never one in ``protect``."""
    protected = set(protect)
    candidates = [
        p
        for p in parent.iterdir()
        if p.is_dir() and not p.is_symlink() and p.name.startswith(prefix) and p.name not in protected
    ]
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    removed: list[str] = []
    for old in candidates[max(0, keep) :]:
        shutil.rmtree(old, ignore_errors=True)
        removed.append(old.name)
    return removed


def tail(text: str, limit: int = 400) -> str:
    stripped = scrub(text.strip())
    return stripped[-limit:]


async def record_version(
    session: Any,
    feed: ContentFeed,
    version: str,
    *,
    path: str | None = None,
    source_commit: str | None = None,
    built_at: datetime | None = None,
    regression_result: str = "passed",
    regression_detail: Mapping[str, Any] | None = None,
    activate: bool = True,
) -> ContentVersion:
    """Add or refresh the ``ContentVersion`` row (feed, version) and, when ``activate``, make it the only active one."""
    now = utcnow()
    if activate:
        await session.execute(
            update(ContentVersion)
            .where(ContentVersion.feed == feed, ContentVersion.active.is_(True), ContentVersion.version != version)
            .values(active=False)
        )
        await session.flush()
    row = await session.scalar(
        select(ContentVersion).where(ContentVersion.feed == feed, ContentVersion.version == version)
    )
    if row is None:
        row = ContentVersion(id=new_id(), feed=feed, version=version, created_at=now)
        session.add(row)
    row.path = path
    row.source_commit = source_commit
    row.built_at = built_at
    row.fetched_at = now
    row.regression_result = regression_result
    row.regression_detail = dict(regression_detail or {})
    if activate and not row.active:
        row.activated_at = now
    row.active = activate
    await session.flush()
    return row


async def touch_active(session: Any, feed: ContentFeed) -> ContentVersion | None:
    """A successful check that found nothing new: the active version counts as fetched now."""
    row = await session.scalar(
        select(ContentVersion).where(ContentVersion.feed == feed, ContentVersion.active.is_(True))
    )
    if row is not None:
        row.fetched_at = utcnow()
        await session.flush()
    return row


async def finish(outcome: UpdateOutcome, feed: ContentFeed, row_id: Any = None) -> UpdateOutcome:
    """Metrics, feed clock, audit and log line of an update result."""
    record_update_result(feed, outcome.ok)
    async with session_scope() as db:
        if outcome.ok:
            active = (await active_versions(db)).get(feed.value)
            if active is not None:
                record_feed_clock(feed, reference_time(feed, active))
        await record_audit(
            db,
            SYSTEM_ACTOR,
            "content.update" if outcome.ok else "content.update_failed",
            "content_version",
            row_id or feed.value,
            {"feed": feed.value, "version": outcome.version, "changed": outcome.changed, "message": outcome.message[:300]},
        )
    if outcome.ok:
        log.info("content_updated", feed=feed.value, version=outcome.version, changed=outcome.changed)
    else:
        log.error("content_update_failed", feed=feed.value, message=outcome.message[:300])
    return outcome


async def run_updater_container(
    entry: CatalogueEntry,
    *,
    name: str,
    binds: Sequence[tuple[str, str, bool]],
    env: Mapping[str, str] | None = None,
    network: str = "none",
    command: Sequence[str] | None = None,
    settings: Settings | None = None,
) -> ContainerResult:
    """Run one container of a catalogue entry to its end (kill on timeout, remove afterwards)."""
    from securescan.runner.launcher import get_launcher

    cfg = settings or get_settings()
    async with session_scope() as db:
        image = await resolve_image_with_override(db, entry, cfg)
    spec = spec_from_entry(
        entry,
        image,
        name=name,
        binds=list(binds),
        env=env,
        network=network,
        labels={LABEL_MANAGED: "true", LABEL_TOOL: entry.tool},
        command=command,
    )
    return await get_launcher().run(spec, entry.timeout_seconds)


# =============================================================================================== Grype
def parse_grype_status(logs: str) -> dict[str, Any] | None:
    """The JSON object of ``grype db status -o json`` out of the container output."""
    start = logs.find("{")
    end = logs.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(logs[start : end + 1])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def grype_version_label(status: Mapping[str, Any], built: datetime | None) -> str:
    schema = status.get("schemaVersion") or status.get("schema")
    stamp = built.strftime("%Y%m%dT%H%M%SZ") if built is not None else utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"v{schema}-{stamp}" if schema is not None else f"db-{stamp}"


async def update_grype_db(settings: Settings | None = None) -> UpdateOutcome:
    """Daily: ``grype db update`` with egress to ``grype.anchore.io``; the build date comes from ``db status``."""
    cfg = settings or get_settings()
    feed = ContentFeed.GRYPE_DB
    async with feed_lock(feed):
        directory = content_dir(cfg, GRYPE_DB_DIRECTORY)
        update_entry = get_entry("grype-db-update")
        status_entry = get_entry("grype-db-status")
        try:
            async with egress_lease(GRYPE_HOSTS) as proxy_url:
                result = await run_updater_container(
                    update_entry,
                    name="securescan-updater-grype-db",
                    binds=[(str(directory), update_entry.mount_target("out"), False)],
                    env=proxy_env(proxy_url),
                    network=egress_network(cfg),
                    settings=cfg,
                )
        except EgressError as exc:
            return await finish(UpdateOutcome(feed.value, False, message=str(exc)), feed)
        if result.timed_out or result.exit_code != 0:
            reason = "timed out" if result.timed_out else f"exit code {result.exit_code}"
            return await finish(
                UpdateOutcome(feed.value, False, message=f"grype db update failed ({reason}): {tail(result.logs)}"),
                feed,
            )
        status_result = await run_updater_container(
            status_entry,
            name="securescan-updater-grype-status",
            binds=[(str(directory), status_entry.mount_target("content"), True)],
            network="none",
            settings=cfg,
        )
        status = parse_grype_status(status_result.logs) if status_result.exit_code == 0 else None
        if status is not None and status.get("valid") is False:
            return await finish(
                UpdateOutcome(feed.value, False, message=f"the database is not valid: {tail(str(status.get('error') or ''))}"),
                feed,
            )
        built = parse_timestamp((status or {}).get("built"))
        if status is None:
            log.warning("grype_status_unreadable", tail=tail(status_result.logs, 200))
        version = grype_version_label(status or {}, built)
        async with session_scope() as db:
            previous = (await active_versions(db)).get(feed.value)
            row = await record_version(
                db, feed, version, path=GRYPE_DB_DIRECTORY, built_at=built,
                regression_result="skipped", regression_detail={"reason": "data feed, no regression gate"},
            )  # fmt: skip
            row_id = row.id
            changed = previous is None or previous.version != version
        return await finish(UpdateOutcome(feed.value, True, changed, version, "updated"), feed, row_id)


# =============================================================================================== Semgrep rules
@dataclass
class RulesLock:
    repository: str = "https://github.com/semgrep/semgrep-rules"
    commit: str = ""
    auto: bool = True
    allowed_licenses: list[str] = field(default_factory=lambda: ["Semgrep Rules License v1.0"])
    deny_licenses: list[str] = field(default_factory=lambda: ["agpl", "gpl-3", "gpl-2", "lgpl", "commons clause", "proprietary", "unknown"])
    missing_license: str = "allow"
    drop_directories: list[str] = field(
        default_factory=lambda: ["stats", ".github", ".git", ".circleci", "scripts", "tests", "target", "node_modules"]
    )


def find_lock_file(settings: Settings) -> Path | None:
    candidates: list[Path] = []
    if settings.semgrep_rules_lock_file:
        candidates.append(Path(settings.semgrep_rules_lock_file))
    scanners = find_scanners_dir(settings)
    if scanners is not None:
        candidates.append(scanners.parent / "content" / "semgrep-rules.lock")
    candidates += [Path("/app/content/semgrep-rules.lock"), Path(settings.content_root) / "semgrep-rules.lock"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def parse_rules_lock(text: str) -> RulesLock:
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("semgrep-rules.lock must be a YAML mapping")
    lock = RulesLock()

    def strings(key: str, default: list[str]) -> list[str]:
        value = data.get(key)
        if value is None:
            return default
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError(f"semgrep-rules.lock: {key} must be a list of strings")
        return [v for v in value if v]

    repository = data.get("repository")
    if isinstance(repository, str) and repository.startswith("https://"):
        lock.repository = repository
    commit = str(data.get("commit") or "").strip()
    if commit and not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
        raise ValueError("semgrep-rules.lock: commit must be a hexadecimal commit id")
    lock.commit = commit
    lock.auto = bool(data.get("auto", True))
    lock.allowed_licenses = strings("allowed_licenses", lock.allowed_licenses)
    lock.deny_licenses = strings("deny_licenses", lock.deny_licenses)
    missing = str(data.get("missing_license", "allow")).lower()
    if missing not in ("allow", "drop"):
        raise ValueError("semgrep-rules.lock: missing_license must be allow or drop")
    lock.missing_license = missing
    lock.drop_directories = strings("drop_directories", lock.drop_directories)
    return lock


def load_rules_lock(settings: Settings) -> RulesLock:
    path = find_lock_file(settings)
    if path is None:
        log.warning("semgrep_rules_lock_not_found")
        return RulesLock()
    return parse_rules_lock(path.read_text(encoding="utf-8"))


def wanted_commit(settings: Settings, lock: RulesLock) -> str | None:
    """The commit to fetch: the environment pin, else the lock's pin unless ``auto``; None means the newest."""
    if settings.semgrep_rules_commit.strip():
        return settings.semgrep_rules_commit.strip()
    if lock.commit and not lock.auto:
        return lock.commit
    return None


def license_problem(value: Any, lock: RulesLock) -> str | None:
    """None when a rule with ``metadata.license == value`` may be kept, else the reason."""
    text = "" if value is None else str(value).strip()
    if not text:
        return None if lock.missing_license == "allow" else "no licence stated"
    lowered = text.lower()
    for denied in lock.deny_licenses:
        if denied.lower() in lowered:
            return f"licence not allowed: {text[:80]}"
    if text.lower() in {a.lower() for a in lock.allowed_licenses}:
        return None
    return f"licence not on the allowlist: {text[:80]}"


@dataclass
class FilterReport:
    files_seen: int = 0
    files_kept: int = 0
    rules_kept: int = 0
    dropped: dict[str, int] = field(default_factory=dict)
    examples: dict[str, list[str]] = field(default_factory=dict)

    def drop(self, reason: str, path: str) -> None:
        key = reason.split(":")[0]
        self.dropped[key] = self.dropped.get(key, 0) + 1
        bucket = self.examples.setdefault(key, [])
        if len(bucket) < 5:
            bucket.append(f"{path} ({reason})")

    def as_dict(self) -> dict[str, Any]:
        return {
            "files_seen": self.files_seen,
            "files_kept": self.files_kept,
            "rules_kept": self.rules_kept,
            "dropped": dict(self.dropped),
            "examples": {k: list(v) for k, v in self.examples.items()},
        }


def _yaml_loader() -> Any:
    return getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def rule_file_verdict(text: str, lock: RulesLock) -> tuple[int, str | None]:
    """``(number of rules, None)`` when the file is a rule file whose rules all pass the licence policy,
    else ``(0, reason)``. A rule file is a YAML mapping with a ``rules`` list of mappings that have an ``id``."""
    try:
        data = yaml.load(text, Loader=_yaml_loader())  # noqa: S506 - a safe loader
    except yaml.YAMLError:
        return 0, "unreadable yaml"
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list) or not data["rules"]:
        return 0, "not a rule file"
    count = 0
    for rule in data["rules"]:
        if not isinstance(rule, dict) or not rule.get("id"):
            return 0, "not a rule file"
        metadata = rule.get("metadata")
        value = metadata.get("license") if isinstance(metadata, dict) else None
        problem = license_problem(value, lock)
        if problem is not None:
            return 0, problem
        count += 1
    return count, None


def filter_rules(source: Path, destination: Path, lock: RulesLock) -> FilterReport:
    """Copy the rule files of a ``semgrep-rules`` checkout that pass the filter into ``destination``.

    Kept: ``.yaml``/``.yml`` files that are rule files with every rule's licence accepted (see
    ``scanners``-side ``content/semgrep-rules.lock``). Dropped: everything else. The directory layout is kept
    (rule ids come from it); licence notices (``LICENSE*``, ``NOTICE*``, ``COPYING*``) at the top are copied.
    """
    report = FilterReport()
    drop_dirs = {d.lower() for d in lock.drop_directories}
    destination.mkdir(parents=True, exist_ok=True)
    os.chmod(destination, 0o755)
    for current, dirs, files in os.walk(source, followlinks=False):
        relative_dir = os.path.relpath(current, source).replace(os.sep, "/")
        at_top = relative_dir == "."
        dirs[:] = sorted(
            d for d in dirs
            if not (at_top and d.lower() in drop_dirs) and d != ".git" and not os.path.islink(os.path.join(current, d))
        )  # fmt: skip
        for name in sorted(files):
            full = os.path.join(current, name)
            relative = name if at_top else f"{relative_dir}/{name}"
            if at_top and name.upper().startswith(NOTICE_PREFIXES) and os.path.isfile(full):
                shutil.copyfile(full, destination / name)
                continue
            lowered = name.lower()
            if not lowered.endswith(YAML_SUFFIXES):
                continue
            report.files_seen += 1
            if os.path.islink(full) or name.startswith(".") or lowered.endswith((".test.yaml", ".test.yml")):
                report.drop("not a rule file", relative)
                continue
            try:
                with open(full, encoding="utf-8") as handle:
                    text = handle.read()
            except (OSError, UnicodeDecodeError):
                report.drop("unreadable file", relative)
                continue
            count, reason = rule_file_verdict(text, lock)
            if reason is not None:
                report.drop(reason, relative)
                continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(full, target)
            os.chmod(target, 0o644)
            report.files_kept += 1
            report.rules_kept += count
    for path, _dirs, _files in os.walk(destination):
        os.chmod(path, 0o755)
    return report


async def _commit_date(runner: GitRunner, repo: Path) -> datetime | None:
    try:
        out = await runner.run([*base_git_args(), "log", "-1", "--format=%cI"], cwd=repo, what="Reading the commit date")
    except SourceError:
        return None
    return parse_timestamp(out.strip())


async def update_semgrep_rules(settings: Settings | None = None) -> UpdateOutcome:
    """Weekly: clone, filter, regression gate, promote (see the module docstring)."""
    cfg = settings or get_settings()
    feed = ContentFeed.SEMGREP_RULES
    async with feed_lock(feed):
        lock = load_rules_lock(cfg)
        wanted = wanted_commit(cfg, lock)
        base = content_dir(cfg, "semgrep")
        scratch = Path(tempfile.mkdtemp(prefix=".clone-", dir=str(base)))
        os.chmod(scratch, 0o755)
        clone_dir = scratch / "repo"
        clone_dir.mkdir()
        staging: Path | None = None
        try:
            try:
                async with egress_lease(GITHUB_HOSTS) as proxy_url:
                    result = await clone_repository(
                        lock.repository,
                        clone_dir,
                        auth=CloneAuth(),
                        auth_dir=scratch,
                        commit=wanted,
                        proxy_url=proxy_url or None,
                        timeout_s=float(cfg.git_clone_timeout_seconds),
                    )
            except (SourceError, EgressError) as exc:
                return await finish(UpdateOutcome(feed.value, False, message=f"fetching semgrep-rules failed: {exc}"), feed)
            sha = result.commit_sha
            version = f"{RULES_PREFIX}{sha}"
            async with session_scope() as db:
                active = (await active_versions(db)).get(feed.value)
            final = base / version
            if active is not None and active.version == version and final.is_dir():
                async with session_scope() as db:
                    row = await touch_active(db, feed)
                return await finish(
                    UpdateOutcome(feed.value, True, False, version, "already at the newest commit"), feed, row.id if row else None
                )
            commit_date = await _commit_date(GitRunner(git_environment(str(scratch))), clone_dir)
            staging = base / f".staging-{sha}"
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
            report = await asyncio.to_thread(filter_rules, clone_dir, staging, lock)
            if report.rules_kept == 0:
                return await finish(
                    UpdateOutcome(feed.value, False, message="the licence filter left no rules", detail=report.as_dict()), feed
                )
            info = {"commit": sha, "repository": lock.repository, "committed_at": commit_date.isoformat() if commit_date else None, **report.as_dict()}
            (staging / BUNDLE_INFO).write_text(json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.chmod(staging / BUNDLE_INFO, 0o644)
            if active is None:
                gate_ok, gate_result, gate_detail = True, "skipped", {"reason": "first installation: nothing to regress against"}
            else:
                outcome = await run_regression_detailed("semgrep", staging, settings=cfg)
                gate_ok, gate_result, gate_detail = outcome.passed, outcome.result, outcome.detail
            gate_detail = {**gate_detail, "filter": report.as_dict()}
            if not gate_ok:
                rejected = base / f"{version}.rejected"
                if rejected.exists():
                    shutil.rmtree(rejected, ignore_errors=True)
                os.replace(staging, rejected)
                staging = None
                async with session_scope() as db:
                    row = await record_version(
                        db, feed, version, path=f"semgrep/{rejected.name}", source_commit=sha, built_at=commit_date,
                        regression_result="failed", regression_detail=gate_detail, activate=False,
                    )  # fmt: skip
                    row_id = row.id
                prune_directories(base, RULES_PREFIX, cfg.content_keep_versions, protect=[active.version] if active else [])
                return await finish(
                    UpdateOutcome(
                        feed.value, False, message=f"the regression gate rejected the rules at {sha[:12]}; the previous version stays active",
                        version=version, detail=gate_detail,
                    ),
                    feed, row_id,
                )  # fmt: skip
            if final.exists():
                shutil.rmtree(final, ignore_errors=True)
            os.replace(staging, final)
            staging = None
            switch_symlink(base / RULES_LINK, final.name)
            async with session_scope() as db:
                row = await record_version(
                    db, feed, version, path=f"semgrep/{version}", source_commit=sha, built_at=commit_date,
                    regression_result=gate_result, regression_detail=gate_detail,
                )  # fmt: skip
                row_id = row.id
            prune_directories(base, RULES_PREFIX, cfg.content_keep_versions, protect=[version])
            return await finish(
                UpdateOutcome(feed.value, True, True, version, f"{report.rules_kept} rules from {report.files_kept} files", gate_detail),
                feed, row_id,
            )  # fmt: skip
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)


# =============================================================================================== Nuclei templates
def count_template_files(directory: Path, limit: int = 100000) -> int:
    total = 0
    for _current, _dirs, files in os.walk(directory, followlinks=False):
        total += sum(1 for name in files if name.lower().endswith(YAML_SUFFIXES))
        if total >= limit:
            break
    return total


def dated_directory_name(parent: Path, moment: datetime | None = None) -> str:
    """``nuclei-templates-<yyyymmdd>``; a second update on the same day gets ``-2``, ``-3``, ..."""
    base = f"{TEMPLATES_PREFIX}{utc_stamp(moment)}"
    candidate = base
    number = 1
    while (parent / candidate).exists():
        number += 1
        candidate = f"{base}-{number}"
    return candidate


async def update_nuclei_templates(settings: Settings | None = None) -> UpdateOutcome:
    """Weekly: ``nuclei -ut -ud`` into a dated directory, structural check, promote."""
    cfg = settings or get_settings()
    feed = ContentFeed.NUCLEI_TEMPLATES
    async with feed_lock(feed):
        base = content_dir(cfg)
        entry = get_entry("nuclei-templates-update")
        async with session_scope() as db:
            active = (await active_versions(db)).get(feed.value)
        name = dated_directory_name(base)
        staging = base / f".staging-{name}"
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir()
        os.chmod(staging, 0o777)
        promoted = False
        try:
            try:
                async with egress_lease(NUCLEI_HOSTS) as proxy_url:
                    result = await run_updater_container(
                        entry,
                        name="securescan-updater-nuclei",
                        binds=[(str(staging), entry.mount_target("out"), False)],
                        env=proxy_env(proxy_url),
                        network=egress_network(cfg),
                        settings=cfg,
                    )
            except EgressError as exc:
                return await finish(UpdateOutcome(feed.value, False, message=str(exc)), feed)
            if result.timed_out or result.exit_code != 0:
                reason = "timed out" if result.timed_out else f"exit code {result.exit_code}"
                return await finish(
                    UpdateOutcome(feed.value, False, message=f"the template fetch failed ({reason}): {tail(result.logs)}"), feed
                )
            templates = await asyncio.to_thread(count_template_files, staging)
            if templates < MIN_TEMPLATE_FILES:
                return await finish(
                    UpdateOutcome(feed.value, False, message=f"the fetch produced only {templates} templates; expected at least {MIN_TEMPLATE_FILES}"),
                    feed,
                )
            outcome = await run_regression_detailed("nuclei", staging, settings=cfg)
            detail = {**outcome.detail, "templates": templates}
            if not outcome.passed:
                rejected = base / f"{name}.rejected"
                if rejected.exists():
                    shutil.rmtree(rejected, ignore_errors=True)
                os.replace(staging, rejected)
                async with session_scope() as db:
                    row = await record_version(
                        db, feed, name, path=rejected.name, regression_result="failed", regression_detail=detail, activate=False,
                    )  # fmt: skip
                    row_id = row.id
                return await finish(
                    UpdateOutcome(feed.value, False, message="the template check failed; the previous version stays active", version=name, detail=detail),
                    feed, row_id,
                )  # fmt: skip
            final = base / name
            os.replace(staging, final)
            promoted = True
            os.chmod(final, 0o755)
            switch_symlink(base / TEMPLATES_LINK, final.name)
            now = utcnow()
            async with session_scope() as db:
                row = await record_version(
                    db, feed, name, path=name, built_at=now, regression_result=outcome.result, regression_detail=detail,
                )  # fmt: skip
                row_id = row.id
            prune_directories(base, TEMPLATES_PREFIX, cfg.content_keep_versions, protect=[name, active.version if active else ""])
            return await finish(UpdateOutcome(feed.value, True, True, name, f"{templates} templates", detail), feed, row_id)
        finally:
            if not promoted and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)


# =============================================================================================== regression
@dataclass
class RegressionOutcome:
    passed: bool
    result: str  # passed | failed | skipped
    detail: dict[str, Any] = field(default_factory=dict)


def find_regression_apps(settings: Settings) -> Path | None:
    """The directory with the planted sample apps (``<app>/expected-findings.yaml``)."""
    candidates: list[Path] = []
    if settings.regression_apps_dir:
        candidates.append(Path(settings.regression_apps_dir))
    scanners = find_scanners_dir(settings)
    if scanners is not None:
        candidates.append(scanners.parent / "backend" / "tests" / "fixtures" / "sample-apps")
        candidates.append(scanners / "regression" / "apps")
    candidates += [Path("/app/tests/fixtures/sample-apps"), Path.cwd() / "tests" / "fixtures" / "sample-apps"]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def load_expectations(path: Path, tool: str) -> list[dict[str, Any]]:
    """The entries of ``tools.<tool>`` of an ``expected-findings.yaml`` (format: scanners/regression/README.md)."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    tools = data.get("tools") if isinstance(data, dict) else None
    entries = tools.get(tool) if isinstance(tools, dict) else None
    return [e for e in entries or [] if isinstance(e, dict)]


def expectation_met(entry: Mapping[str, Any], results: Sequence[Mapping[str, Any]]) -> bool:
    """Whether a Semgrep raw result list satisfies one ``verified`` expectation.

    There is one matcher for expectations, ``securescan.domain.regression.match_expectation``; this function only
    adapts the raw results of the candidate-rules run to it. When the expectation names a file, only results in a
    file of that name are considered. The raw report is read only to gate a content update (the candidate rules
    are not yet imported anywhere); findings of real scans are DefectDojo's business (docs/decisions.md).
    """
    from securescan.domain.regression import ExpectedFinding, ObservedFinding, match_expectation

    wanted_file = str(entry.get("file") or "")
    observed: list[ObservedFinding] = []
    for result in results:
        path = str(result.get("path") or "")
        if wanted_file and not path.endswith(wanted_file.split("/")[-1]):
            continue
        extra = result.get("extra")
        message = str(extra.get("message") or "") if isinstance(extra, dict) else ""
        start = result.get("start")
        line = start.get("line") if isinstance(start, dict) else None
        observed.append(
            ObservedFinding(
                tool="semgrep",
                title=(str(result.get("check_id") or "") + " " + message).strip(),
                file_path=path or None,
                line=line if isinstance(line, int) else None,
            )
        )
    expected = ExpectedFinding(
        id=str(entry.get("id") or entry.get("expect_category") or "?")[:100],
        expect_category=str(entry.get("expect_category") or ""),
        file=wanted_file or None,
        verified=True,
        rule_id=str(entry.get("rule_id") or "") or None,
        vulnerability_id=str(entry.get("vulnerability_id") or "") or None,
    )
    return match_expectation(expected, observed) is not None


def missing_expectations(entries: Sequence[Mapping[str, Any]], results: Sequence[Mapping[str, Any]]) -> list[str]:
    """Ids of ``verified: true`` entries that the results do not satisfy."""
    return [
        str(entry.get("id") or entry.get("expect_category") or "?")
        for entry in entries
        if entry.get("verified") is True and not expectation_met(entry, results)
    ]


def rule_errors(report: Mapping[str, Any]) -> list[str]:
    """Rule-level errors of a Semgrep JSON report (an invalid rule makes the whole candidate unusable)."""
    found: list[str] = []
    for error in report.get("errors") or []:
        if not isinstance(error, dict):
            continue
        kind = error.get("type")
        text = " ".join(str(k) for k in kind) if isinstance(kind, list) else str(kind or "")
        if "rule" in text.lower() and error.get("level", "error") == "error":
            found.append(text[:100])
    return found


async def _semgrep_on_app(
    settings: Settings, entry: CatalogueEntry, image: ResolvedImage, app_dir: Path, rules: Path
) -> tuple[ContainerResult, dict[str, Any] | None]:
    from securescan.runner.launcher import get_launcher

    workspace = await asyncio.to_thread(Workspace.create, new_id())
    try:
        await asyncio.to_thread(shutil.copytree, app_dir, workspace.src, dirs_exist_ok=True)
        spec: ContainerSpec = spec_from_entry(
            entry,
            image,
            name=f"securescan-regression-{workspace.job_id}",
            binds=[
                (str(workspace.src), entry.mount_target("src"), True),
                (str(workspace.out), entry.mount_target("out"), False),
                (str(rules), entry.mount_target("content"), True),
            ],
            network="none",
            labels={LABEL_MANAGED: "true", LABEL_TOOL: entry.tool},
        )
        result = await get_launcher().run(spec, entry.timeout_seconds)
        report_path = workspace.out / "semgrep.json"
        report: dict[str, Any] | None = None
        if report_path.is_file():
            try:
                loaded = json.loads(report_path.read_text(encoding="utf-8"))
                report = loaded if isinstance(loaded, dict) else None
            except ValueError:
                report = None
        return result, report
    finally:
        await asyncio.to_thread(workspace.cleanup)


async def _regression_semgrep(settings: Settings, candidate: Path) -> RegressionOutcome:
    apps = find_regression_apps(settings)
    if apps is None:
        return RegressionOutcome(False, "failed", {"reason": "the planted sample apps were not found (SECURESCAN_REGRESSION_APPS_DIR)"})
    entry = get_entry("semgrep")
    async with session_scope() as db:
        image = await resolve_image_with_override(db, entry, settings)
    detail: dict[str, Any] = {"apps": {}, "candidate": candidate.name}
    total_results = 0
    verified = 0
    failures: list[str] = []
    for app_dir in sorted(p for p in apps.iterdir() if p.is_dir() and (p / "expected-findings.yaml").is_file()):
        entries = load_expectations(app_dir / "expected-findings.yaml", "semgrep")
        result, report = await _semgrep_on_app(settings, entry, image, app_dir, candidate)
        app_detail: dict[str, Any] = {"exit_code": result.exit_code}
        detail["apps"][app_dir.name] = app_detail
        if result.timed_out or result.exit_code not in (0, 1) or report is None:
            app_detail["problem"] = "semgrep did not complete with the candidate rules"
            app_detail["output"] = tail(result.logs, 300)
            failures.append(f"{app_dir.name}: semgrep failed")
            continue
        errors = rule_errors(report)
        if errors:
            app_detail["rule_errors"] = errors[:5]
            failures.append(f"{app_dir.name}: rule errors")
        results = [r for r in report.get("results") or [] if isinstance(r, dict)]
        total_results += len(results)
        verified += sum(1 for e in entries if e.get("verified") is True)
        missing = missing_expectations(entries, results)
        app_detail.update({"results": len(results), "missing": missing})
        if missing:
            failures.append(f"{app_dir.name}: {len(missing)} expected finding(s) disappeared")
    detail["verified_expectations"] = verified
    detail["total_results"] = total_results
    if not detail["apps"]:
        return RegressionOutcome(False, "failed", {**detail, "reason": "no sample app has an expected-findings.yaml"})
    if not failures and verified == 0 and total_results == 0:
        failures.append("the candidate rules found nothing in the planted apps")
    detail["failures"] = failures
    return RegressionOutcome(not failures, "failed" if failures else "passed", detail)


async def _regression_nuclei(settings: Settings, candidate: Path) -> RegressionOutcome:
    templates = await asyncio.to_thread(count_template_files, candidate)
    detail: dict[str, Any] = {"templates": templates, "candidate": candidate.name}
    if templates < MIN_TEMPLATE_FILES:
        return RegressionOutcome(False, "failed", {**detail, "reason": f"fewer than {MIN_TEMPLATE_FILES} templates"})
    entry = get_entry("nuclei-templates-validate")
    result = await run_updater_container(
        entry,
        name="securescan-regression-nuclei",
        binds=[(str(candidate), entry.mount_target("content"), True)],
        network="none",
        settings=settings,
    )
    detail["exit_code"] = result.exit_code
    if result.timed_out or result.exit_code != 0:
        detail["output"] = tail(result.logs, 400)
        return RegressionOutcome(False, "failed", detail)
    return RegressionOutcome(True, "passed", detail)


async def run_regression_detailed(
    kind: str, candidate: Path | None = None, *, settings: Settings | None = None
) -> RegressionOutcome:
    """Run the regression gate for ``kind`` (``semgrep`` or ``nuclei``) against ``candidate``.

    Without a candidate the currently active content is checked. Anything that goes wrong inside the gate counts as
    a failed gate (fail closed).
    """
    cfg = settings or get_settings()
    try:
        if kind == "semgrep":
            chosen = candidate or Path(cfg.content_root) / "semgrep" / RULES_LINK
            return await _regression_semgrep(cfg, chosen.resolve())
        if kind == "nuclei":
            chosen = candidate or Path(cfg.content_root) / TEMPLATES_LINK
            return await _regression_nuclei(cfg, chosen.resolve())
    except Exception as exc:  # noqa: BLE001 - fail closed, with the reason in the detail
        log.exception("regression_error", kind=kind)
        return RegressionOutcome(False, "failed", {"reason": f"the regression run failed: {type(exc).__name__}"})
    raise ValueError(f"unknown regression kind {kind!r}")


async def run_regression(kind: str, candidate: Path | None = None) -> bool:
    """True when the candidate content of ``kind`` passes the regression gate (see the module docstring)."""
    return (await run_regression_detailed(kind, candidate)).passed


# =============================================================================================== wiring
UPDATERS = {
    ContentFeed.GRYPE_DB.value: update_grype_db,
    ContentFeed.SEMGREP_RULES.value: update_semgrep_rules,
    ContentFeed.NUCLEI_TEMPLATES.value: update_nuclei_templates,
}


async def update_feed(feed: ContentFeed | str) -> UpdateOutcome:
    """Run the updater of ``feed``; never raises (a crash is recorded as a failed update)."""
    name = feed_value(feed)
    updater = UPDATERS.get(name)
    if updater is None:
        raise ValueError(f"unknown content feed {name!r}")
    try:
        return await updater()
    except Exception as exc:  # noqa: BLE001 - recorded, the previous version stays active
        log.exception("content_update_crashed", feed=name)
        record_update_result(name, False)
        return UpdateOutcome(name, False, message=f"the update crashed ({type(exc).__name__})")


@periodic_hook("grype_db_update")
async def grype_db_update_hook(timestamp: int) -> None:
    await update_feed(ContentFeed.GRYPE_DB)


@periodic_hook("rules_and_templates_update")
async def rules_and_templates_hook(timestamp: int) -> None:
    await update_feed(ContentFeed.SEMGREP_RULES)
    await update_feed(ContentFeed.NUCLEI_TEMPLATES)


@app.task(name="content_update", queue="maintenance")
async def content_update(feed: str) -> None:
    """Update one feed now (Settings, Content, and the start-up bootstrap). Idempotent."""
    outcome = await update_feed(feed)
    log.info("content_update_task_done", feed=feed, ok=outcome.ok, message=outcome.message[:200])


@worker_startup_hook
async def bootstrap_content() -> None:
    """Queue the first update of every feed that has no active version (``SECURESCAN_CONTENT_BOOTSTRAP``)."""
    cfg = get_settings()
    if not cfg.content_bootstrap:
        return
    try:
        async with session_scope() as db:
            active = await active_versions(db)
        for feed in ALL_FEEDS:
            if feed.value in active:
                continue
            job_id = await defer(content_update, queueing_lock=f"content_update:{feed.value}", feed=feed.value)
            log.info("content_bootstrap_queued", feed=feed.value, job_id=job_id)
    except Exception as exc:  # noqa: BLE001 - never block worker start-up
        log.warning("content_bootstrap_failed", error=type(exc).__name__)
