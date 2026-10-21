"""The regression suite: do the scanners still report what the planted applications contain?

The suite answers one question for every change to scanner content or a scanner image: for each
planted application and tool, are the expected findings still reported? It is the gate of the weekly
Semgrep rules and Nuclei templates update (M8) and of the monthly image-update proposals (M11).

How a run works (``run_regression``):

1. The expectations are read from ``backend/tests/fixtures/sample-apps/<app>/expected-findings.yaml``
   (and ``scanners/regression/<app>.yaml`` for the optional Juice Shop and WebGoat); the format is
   described in ``scanners/regression/README.md``.
2. Each planted application is zipped (deterministically), stored as an upload artifact and scanned
   through the **normal scan path** (``create_scan_result`` with the ``code-standard`` profile, queue,
   worker, DefectDojo import, history). The suite reads the findings back from the history rows of
   that scan. SecureScan does not parse any scanner report here: DefectDojo did.
3. ``evaluate_tool`` (pure) compares the observed findings with the expectations.

Results per (application, tool): ``passed`` (all verified expectations matched), ``failed`` (a verified
expectation is missing), ``error`` (the job failed, timed out, the scan could not run or the candidate
image was not the one that ran), ``unasserted`` (no verified expectation yet: the entries are still
``verified: false``, see the README), ``skipped``. Overall: ``failed`` if any tool failed or errored,
``passed`` if at least one tool passed, otherwise ``unasserted``. An ``unasserted`` suite proves
nothing: the monthly image gate stores it as ``skipped`` and approving needs an explicit acknowledgement.

Command line (inside the worker container, which has Docker access, the database and the queue)::

    docker compose ... exec worker python -m securescan.domain.regression run --kind all
    python -m securescan.domain.regression check        # parse the expectation files only (no database)
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import math
import re
import secrets
import sys
import time
import zipfile
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from securescan.config import Settings, get_settings
from securescan.logging import get_logger
from securescan.util import utcnow

log = get_logger(__name__)

APP_PREFIX = "regression-"
EXPECTATIONS_FILE = "expected-findings.yaml"
STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_ERROR = "error"
STATUS_UNASSERTED = "unasserted"
STATUS_SKIPPED = "skipped"
BAD_JOB_STATES = frozenset({"failed", "timed_out", "cancelled"})
FIXTURE_ZIP_EXCLUDES = frozenset({"__pycache__", ".git", "node_modules", ".venv", EXPECTATIONS_FILE})
MAX_REPORTED = 50

# job tool name -> the tool key used in the expectation files
TOOL_ALIASES: dict[str, str] = {"syft-grype": "grype", "syft": "grype"}
# expectation tool key -> the scan job tool to request
JOB_TOOL_FOR_KEY: dict[str, str] = {"grype": "syft-grype"}

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_WORD = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    "the and with from into that this for not are was were has have its via use used using built "
    "known vulnerability vulnerabilities vulnerable hard coded hardcoded secret enabled bound all "
    "request input response string".split()
)


class RegressionConfigError(Exception):
    """An expectation or suite file is invalid (the message names the file and the problem)."""


# ================================================================================ configuration files


class ExpectedFinding(BaseModel):
    """One planted weakness (``scanners/regression/README.md``)."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1, max_length=100)
    expect_category: str = ""
    file: str | None = None
    line: int | None = None
    verified: bool = False
    note: str | None = None
    rule_id: str | None = None
    vulnerability_id: str | None = None


class ExpectationFile(BaseModel):
    model_config = ConfigDict(extra="ignore")

    app: str = Field(min_length=1)
    schema_version: int = 1
    tools: dict[str, list[ExpectedFinding]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _unique_ids(self) -> ExpectationFile:
        for tool, entries in self.tools.items():
            seen: set[str] = set()
            for entry in entries:
                if entry.id in seen:
                    raise ValueError("duplicate id %r under tool %r" % (entry.id, tool))
                seen.add(entry.id)
        if self.schema_version != 1:
            raise ValueError("unsupported schema_version %r (this version reads 1)" % self.schema_version)
        return self


class KindConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    apps: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    profile: str | None = None
    external: bool = False  # apps that must be cloned by hand (Juice Shop, WebGoat): skipped when absent


class SuiteConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: int = 1
    profile: str = "code-standard"
    kinds: dict[str, KindConfig] = Field(default_factory=dict)


DEFAULT_SUITE = SuiteConfig(
    profile="code-standard",
    kinds={
        "content": KindConfig(
            apps=["java-planted", "js-planted", "python-planted", "csharp-planted"], tools=["semgrep"]
        ),
        "image": KindConfig(
            apps=["java-planted", "js-planted", "python-planted", "csharp-planted"],
            tools=["semgrep", "gitleaks", "grype", "spotbugs"],
        ),
        "external": KindConfig(apps=["juice-shop", "webgoat"], tools=["semgrep"], external=True),
        "dast": KindConfig(apps=["juice-shop"], tools=["nuclei"], profile="nuclei-uat", external=True),
    },
)


def canonical_tool(tool: str) -> str:
    return TOOL_ALIASES.get(tool, tool)


def load_expectation_file(path: Path) -> ExpectationFile:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return ExpectationFile.model_validate(data)
    except (OSError, yaml.YAMLError) as exc:
        raise RegressionConfigError("%s: cannot be read (%s)" % (path, exc)) from exc
    except ValidationError as exc:
        problems = "; ".join(
            "%s: %s" % (".".join(str(p) for p in err["loc"]) or "file", err["msg"]) for err in exc.errors()
        )
        raise RegressionConfigError("%s: %s" % (path, problems[:500])) from exc


def load_suite(regression_dir: Path | None) -> SuiteConfig:
    """``scanners/regression/suite.yaml``, or the built-in default when the file is missing."""
    if regression_dir is None or not (regression_dir / "suite.yaml").is_file():
        return DEFAULT_SUITE
    path = regression_dir / "suite.yaml"
    try:
        return SuiteConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise RegressionConfigError("%s: %s" % (path, str(exc)[:400])) from exc


def find_fixtures_dir(settings: Settings | None = None) -> Path | None:
    """The directory holding the planted applications."""
    cfg = settings or get_settings()
    candidates: list[Path] = []
    for configured in (cfg.regression_fixtures_dir, cfg.regression_apps_dir):  # the second is the content updaters' setting
        if configured:
            candidates.append(Path(configured))
    scanners = find_regression_root(cfg)
    if scanners is not None:
        candidates += [
            scanners.parent / "backend" / "tests" / "fixtures" / "sample-apps",
            scanners.parent / "regression" / "sample-apps",
        ]
    candidates.append(Path("/app/regression/sample-apps"))
    candidates.append(Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "sample-apps")
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def find_regression_root(settings: Settings | None = None) -> Path | None:
    """The ``scanners`` directory (its ``regression`` sub-directory holds the suite files)."""
    from securescan.runner.catalogue import find_scanners_dir

    return find_scanners_dir(settings or get_settings())


def find_regression_dir(settings: Settings | None = None) -> Path | None:
    root = find_regression_root(settings)
    if root is not None and (root / "regression").is_dir():
        return root / "regression"
    return None


def load_expectations(
    apps: Iterable[str], fixtures_dir: Path | None, regression_dir: Path | None
) -> dict[str, ExpectationFile]:
    """Expectations by application name; an application without a file is left out."""
    found: dict[str, ExpectationFile] = {}
    for app in apps:
        for path in (
            (fixtures_dir / app / EXPECTATIONS_FILE) if fixtures_dir else None,
            (regression_dir / ("%s.yaml" % app)) if regression_dir else None,
        ):
            if path is not None and path.is_file():
                found[app] = load_expectation_file(path)
                break
    return found


# ================================================================================ comparing (pure)


@dataclass(frozen=True)
class ObservedFinding:
    """What a tool reported, as read back from the history rows of the scan."""

    tool: str
    title: str
    severity: str = "info"
    cwe: int | None = None
    cve: str | None = None
    file_path: str | None = None
    line: int | None = None
    component: str | None = None


def tokens(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def keywords(category: str) -> list[str]:
    """The words of an ``expect_category`` that say what the weakness is."""
    seen: list[str] = []
    for word in tokens(category):
        if len(word) >= 3 and word not in _STOPWORDS and not word.isdigit() and word not in seen:
            seen.append(word)
    return seen


def _word_hits(word: str, haystack: Iterable[str]) -> bool:
    stem = word[:5]
    for token in haystack:
        if token == word or (len(token) >= 4 and (token.startswith(stem) or word.startswith(token[:5]))):
            return True
    return False


def keyword_score(category: str, observed: ObservedFinding) -> float:
    words = keywords(category)
    if not words:
        return 0.0
    haystack = tokens(observed.title) + tokens(observed.component or "")
    return sum(1 for word in words if _word_hits(word, haystack)) / len(words)


def _norm_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./").lower()


def file_matches(expected_file: str | None, observed_path: str | None) -> bool:
    if not expected_file or not observed_path:
        return False
    want, got = _norm_path(expected_file), _norm_path(observed_path)
    return got.endswith(want) or want.endswith(got) or got.rsplit("/", 1)[-1] == want.rsplit("/", 1)[-1]


@dataclass(frozen=True)
class Match:
    finding: ObservedFinding
    how: str  # rule_id | vulnerability_id | keywords | keywords+file
    score: float


def rule_in_title(rule: str, title: str) -> bool:
    """Whether ``rule`` is a whole rule id inside ``title`` (``sql-string`` is not in ``tainted-sql-string``)."""
    pattern = r"(?<![A-Za-z0-9_-])" + re.escape(rule.lower()) + r"(?![A-Za-z0-9_-])"
    return re.search(pattern, title.lower()) is not None


def match_expectation(entry: ExpectedFinding, observed: Sequence[ObservedFinding]) -> Match | None:
    """The best observed finding for one expected finding, or None.

    1. ``rule_id`` (filled from a real report): a whole rule id inside the title, case-insensitive.
    2. ``vulnerability_id`` (or a CVE named in the category): equals the CVE or is contained in the title.
    3. Otherwise the key words of ``expect_category``: at least 60 percent of them in the title, or
       34 percent when the finding is in the expected file.
    """
    if entry.rule_id:
        rule = entry.rule_id.lower()
        for finding in observed:
            if rule_in_title(rule, finding.title):
                return Match(finding, "rule_id", 1.0)
        return None
    cve_in_text = _CVE.search(entry.expect_category)
    vuln = entry.vulnerability_id or (cve_in_text.group(0) if cve_in_text else None)
    if vuln:
        wanted = vuln.lower()
        for finding in observed:
            if (finding.cve or "").lower() == wanted or wanted in finding.title.lower():
                return Match(finding, "vulnerability_id", 1.0)
        return None
    best: Match | None = None
    for finding in observed:
        score = keyword_score(entry.expect_category, finding)
        with_file = file_matches(entry.file, finding.file_path)
        if score >= 0.6 or (with_file and score >= 0.34):
            how = "keywords+file" if with_file else "keywords"
            rank = score + (0.5 if with_file else 0.0)
            if best is None or rank > best.score:
                best = Match(finding, how, rank)
    return best


@dataclass
class EntryResult:
    id: str
    verified: bool
    status: str  # matched | missing | seen | not_seen
    matched_title: str | None = None
    how: str | None = None


@dataclass
class ToolResult:
    app: str
    tool: str
    status: str
    reason: str | None = None
    entries: list[EntryResult] = field(default_factory=list)
    observed_count: int = 0
    titles: list[str] = field(default_factory=list)
    unexpected_titles: list[str] = field(default_factory=list)
    removed_vs_baseline: list[str] = field(default_factory=list)
    job_state: str | None = None
    image_digest: str | None = None

    @property
    def missing(self) -> list[str]:
        return [e.id for e in self.entries if e.status == "missing"]

    @property
    def newly_seen(self) -> list[str]:
        """Unverified entries a real run did report: candidates for ``verified: true``."""
        return [e.id for e in self.entries if e.status == "seen"]


def evaluate_tool(
    app: str,
    tool: str,
    expected: Sequence[ExpectedFinding],
    observed: Sequence[ObservedFinding],
    *,
    job_state: str | None,
    job_reason: str | None = None,
    image_digest: str | None = None,
    baseline_titles: Iterable[str] | None = None,
) -> ToolResult:
    """Compare one tool's findings with its expectations. Pure."""
    result = ToolResult(app=app, tool=tool, status=STATUS_PASSED, job_state=job_state, image_digest=image_digest)
    titles = sorted({f.title for f in observed})
    result.observed_count = len(observed)
    result.titles = titles[:200]
    if baseline_titles is not None:
        result.removed_vs_baseline = sorted(set(baseline_titles) - set(titles))[:MAX_REPORTED]
    if job_state is None:
        result.status = STATUS_SKIPPED
        result.reason = "the tool did not take part in the scan"
        return result
    if job_state in BAD_JOB_STATES:
        result.status = STATUS_ERROR
        result.reason = "job %s: %s" % (job_state, job_reason or "no reason recorded")
        return result
    covered: set[ObservedFinding] = set()
    for entry in expected:
        match = match_expectation(entry, observed)
        if match is not None:
            covered.add(match.finding)
        if entry.verified:
            status = "matched" if match else "missing"
        else:
            status = "seen" if match else "not_seen"
        result.entries.append(
            EntryResult(entry.id, entry.verified, status, match.finding.title if match else None, match.how if match else None)
        )
    result.unexpected_titles = sorted({f.title for f in observed if f not in covered})[:MAX_REPORTED]
    verified = [e for e in result.entries if e.verified]
    if not verified:
        result.status = STATUS_UNASSERTED
        result.reason = "no verified expectation for this tool yet"
    elif result.missing:
        result.status = STATUS_FAILED
        result.reason = "missing: " + ", ".join(result.missing)
    return result


def compare_title_sets(before: Iterable[str], after: Iterable[str]) -> tuple[list[str], list[str]]:
    """``(removed, added)`` finding titles between two runs (the rules-update acceptance compares title sets)."""
    old, new = set(before), set(after)
    return sorted(old - new), sorted(new - old)


@dataclass
class RegressionReport:
    kind: str
    started_at: datetime
    finished_at: datetime | None = None
    results: list[ToolResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def outcome(self) -> str:
        statuses = {r.status for r in self.results}
        if statuses & {STATUS_FAILED, STATUS_ERROR}:
            return STATUS_FAILED
        if STATUS_PASSED in statuses:
            return STATUS_PASSED
        return STATUS_UNASSERTED

    @property
    def passed(self) -> bool:
        return self.outcome == STATUS_PASSED

    @property
    def failed(self) -> bool:
        return self.outcome == STATUS_FAILED

    def titles_by_tool(self) -> dict[str, list[str]]:
        """``{"<app>/<tool>": [titles]}``: store it and pass it back as ``baseline_titles`` next time."""
        return {"%s/%s" % (r.app, r.tool): list(r.titles) for r in self.results if r.titles}

    def to_detail(self) -> dict[str, Any]:
        """A compact JSON document for ``regression_detail`` columns."""
        return {
            "kind": self.kind,
            "outcome": self.outcome,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "notes": self.notes[:MAX_REPORTED],
            "results": [
                {
                    "app": r.app,
                    "tool": r.tool,
                    "status": r.status,
                    "reason": r.reason,
                    "job_state": r.job_state,
                    "image_digest": r.image_digest,
                    "observed": r.observed_count,
                    "missing": r.missing,
                    "newly_seen": r.newly_seen,
                    "unexpected": r.unexpected_titles[:10],
                    "removed_vs_baseline": r.removed_vs_baseline[:10],
                }
                for r in self.results
            ],
        }

    def summary_lines(self) -> list[str]:
        lines = ["regression %s: %s" % (self.kind, self.outcome.upper())]
        for r in self.results:
            extra = " (%s)" % r.reason if r.reason else ""
            lines.append("  %-18s %-17s %-10s observed=%d%s" % (r.app, r.tool, r.status, r.observed_count, extra))
            if r.newly_seen:
                lines.append("      reported, not yet verified: " + ", ".join(r.newly_seen))
            if r.removed_vs_baseline:
                lines.append("      titles gone since the baseline: %d" % len(r.removed_vs_baseline))
        for note in self.notes:
            lines.append("  note: " + note)
        if self.outcome == STATUS_UNASSERTED:
            lines.append("  NOTHING WAS ASSERTED: no expectation is verified yet (see scanners/regression/README.md).")
        return lines


# ================================================================================ running


@dataclass
class JobOutcome:
    tool: str  # the scan job tool (syft-grype)
    state: str  # completed | completed_partial | failed | timed_out | cancelled
    reason: str | None = None
    image_digest: str | None = None
    findings: list[ObservedFinding] = field(default_factory=list)


@dataclass
class AppRun:
    app: str
    scan_id: str | None = None
    jobs: dict[str, JobOutcome] = field(default_factory=dict)
    error: str | None = None  # the scan could not be created, or did not finish in time


@dataclass(frozen=True)
class AppSource:
    """What to scan: a directory (zipped and uploaded) or, for the DAST regression, a UAT URL."""

    app: str
    path: Path | None = None
    url: str | None = None


@dataclass(frozen=True)
class CandidateImage:
    """An image proposal under test: its row, its secret token and the digest that must run."""

    tool: str  # the image tool (catalogue tool or lower-cased lock name)
    image_version_id: str
    token: str
    digest: str


class RegressionRunner(Protocol):
    async def run_app(
        self,
        source: AppSource,
        job_tools: Sequence[str],
        *,
        profile: str,
        options: Mapping[str, Any],
        wait_seconds: float,
    ) -> AppRun: ...


def scan_options_with_candidates(
    base: Mapping[str, Any] | None, candidates: Mapping[str, CandidateImage] | None
) -> dict[str, Any]:
    """Scan options; every candidate is attached to the job tool that exercises it."""
    from securescan.domain.image_updates import REGRESSION_TOOLS

    options: dict[str, Any] = {k: v for k, v in (base or {}).items()}
    tool_options: dict[str, Any] = {k: dict(v) for k, v in (options.get("tool_options") or {}).items()}
    for image_tool, candidate in (candidates or {}).items():
        mapping = REGRESSION_TOOLS.get(image_tool)
        job_tool = mapping[0] if mapping else image_tool
        per_tool = tool_options.setdefault(job_tool, {})
        per_tool.setdefault("image_candidates", {})[image_tool] = {
            "id": candidate.image_version_id,
            "token": candidate.token,
        }
    if tool_options:
        options["tool_options"] = tool_options
    return options


def new_candidate_token() -> str:
    return secrets.token_urlsafe(24)


def digest_matches(ran: str | None, wanted: str) -> bool:
    """``ran`` may be ``sha256:...`` or ``name@sha256:...``."""
    if not ran:
        return False
    return ran.rsplit("@", 1)[-1].strip() == wanted.rsplit("@", 1)[-1].strip()


async def run_regression(
    kind: str = "content",
    *,
    apps: Sequence[str] | None = None,
    tools: Sequence[str] | None = None,
    scan_options: Mapping[str, Any] | None = None,
    candidates: Mapping[str, CandidateImage] | None = None,
    baseline_titles: Mapping[str, Sequence[str]] | None = None,
    runner: RegressionRunner | None = None,
    settings: Settings | None = None,
    fixtures_dir: Path | None = None,
    regression_dir: Path | None = None,
) -> RegressionReport:
    """Run one kind of regression (``content``, ``image``, ``external``, ``dast``, or ``all``: ``image`` and ``external``).

    ``apps`` and ``tools`` narrow the selection (tools are expectation keys: ``semgrep``, ``grype``...).
    ``scan_options`` is merged into every scan's options (per-job settings go under ``tool_options``).
    ``candidates`` maps an image tool to the proposal under test; the run fails if a job did not run
    that digest. ``baseline_titles`` (``RegressionReport.titles_by_tool()`` of an earlier run) adds the
    list of titles that disappeared. ``runner`` is injectable (tests); the default scans through the
    queue and the database.
    """
    cfg = settings or get_settings()
    report = RegressionReport(kind=kind, started_at=utcnow())
    regression_dir = regression_dir or find_regression_dir(cfg)
    fixtures_dir = fixtures_dir or find_fixtures_dir(cfg)
    suite = load_suite(regression_dir)
    if kind == "all":
        # `content` is a subset of `image` (same planted apps, Semgrep only): scanning it twice would double the work
        kind_names = [name for name in suite.kinds if name not in ("dast", "content")]
    elif kind in suite.kinds:
        kind_names = [kind]
    else:
        raise RegressionConfigError("unknown regression kind %r (known: %s, all)" % (kind, ", ".join(sorted(suite.kinds))))
    active_runner = runner or DatabaseRegressionRunner(cfg)
    options = scan_options_with_candidates(scan_options, candidates)
    deadline_seconds = float(cfg.regression_wait_minutes) * 60.0
    done: set[tuple[str, str]] = set()

    for name in kind_names:
        config = suite.kinds[name]
        wanted_apps = [a for a in config.apps if apps is None or a in apps]
        wanted_tools = [t for t in config.tools if tools is None or canonical_tool(t) in {canonical_tool(x) for x in tools}]
        expectations = load_expectations(wanted_apps, fixtures_dir, regression_dir)
        for app in wanted_apps:
            if (name, app) in done:
                continue
            done.add((name, app))
            sources = _source_for(name, config, app, fixtures_dir, cfg, report)
            if sources is None:
                continue
            exp = expectations.get(app)
            if exp is None:
                report.notes.append("%s: no expectation file; skipped" % app)
                continue
            keys = [canonical_tool(t) for t in wanted_tools if canonical_tool(t) in exp.tools or name == "dast"]
            if not keys:
                report.notes.append("%s: none of the selected tools has expectations; skipped" % app)
                continue
            job_tools = []
            for key in keys:
                job = JOB_TOOL_FOR_KEY.get(key, key)
                if job not in job_tools:
                    job_tools.append(job)
            run = await active_runner.run_app(
                sources, job_tools, profile=config.profile or suite.profile, options=options, wait_seconds=deadline_seconds
            )
            report.results.extend(_results_for(app, keys, exp, run, candidates, baseline_titles))
    report.finished_at = utcnow()
    return report


def _source_for(
    kind: str, config: KindConfig, app: str, fixtures_dir: Path | None, cfg: Settings, report: RegressionReport
) -> AppSource | None:
    if kind == "dast":
        if not cfg.regression_dast_url:
            report.notes.append("%s: DAST regression skipped (SECURESCAN_REGRESSION_DAST_URL is empty)" % app)
            return None
        return AppSource(app=app, url=cfg.regression_dast_url)
    path = (fixtures_dir / app) if fixtures_dir else None
    if path is None or not path.is_dir():
        text = "%s: application directory not found" % app
        if config.external:
            text += " (clone it into the fixtures directory, see scanners/regression/README.md)"
        report.notes.append(text + "; skipped")
        return None
    return AppSource(app=app, path=path)


def _results_for(
    app: str,
    keys: Sequence[str],
    exp: ExpectationFile,
    run: AppRun,
    candidates: Mapping[str, CandidateImage] | None,
    baseline_titles: Mapping[str, Sequence[str]] | None,
) -> list[ToolResult]:
    results: list[ToolResult] = []
    for key in keys:
        expected = exp.tools.get(key, [])
        jobs = [job for job in run.jobs.values() if canonical_tool(job.tool) == key]
        if run.error and not jobs:
            results.append(ToolResult(app=app, tool=key, status=STATUS_ERROR, reason=run.error))
            continue
        if not jobs:
            results.append(evaluate_tool(app, key, expected, [], job_state=None))
            continue
        job = jobs[0]
        observed = [f for j in jobs for f in j.findings]
        result = evaluate_tool(
            app, key, expected, observed, job_state=job.state, job_reason=job.reason,
            image_digest=job.image_digest,
            baseline_titles=(baseline_titles or {}).get("%s/%s" % (app, key)),
        )  # fmt: skip
        for image_tool, candidate in (candidates or {}).items():
            from securescan.domain.image_updates import REGRESSION_TOOLS

            mapping = REGRESSION_TOOLS.get(image_tool)
            if (mapping[1] if mapping else image_tool) != key:
                continue
            if job.state not in BAD_JOB_STATES and not digest_matches(job.image_digest, candidate.digest):
                result.status = STATUS_ERROR
                result.reason = "the candidate image was not the one that ran (job used %s)" % (job.image_digest or "an unknown image")
        results.append(result)
    return results


# ================================================================================ the database runner


def zip_directory(root: Path) -> bytes:
    """A deterministic zip of a directory (sorted entries, fixed timestamps) so equal content gives an equal hash."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if any(part in FIXTURE_ZIP_EXCLUDES for part in relative.parts) or not path.is_file():
                continue
            info = zipfile.ZipInfo(relative.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
    return buffer.getvalue()


class DatabaseRegressionRunner:
    """Scans an application through the normal path: queue, worker, DefectDojo import, history."""

    def __init__(self, settings: Settings | None = None, *, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:
        self.settings = settings or get_settings()
        self._sleep = sleep

    async def run_app(
        self,
        source: AppSource,
        job_tools: Sequence[str],
        *,
        profile: str,
        options: Mapping[str, Any],
        wait_seconds: float,
    ) -> AppRun:
        from securescan.api.problems import Problem
        from securescan.db.session import session_scope
        from securescan.domain.scans import create_scan_result, get_profile

        run = AppRun(app=source.app)
        try:
            async with session_scope() as db:
                _row, doc = await get_profile(db, profile)
                usable = [t for t in job_tools if t in doc.tools]
                dropped = [t for t in job_tools if t not in doc.tools]
                if not usable:
                    run.error = "the profile %s has none of the tools %s" % (profile, ", ".join(job_tools))
                    return run
                version, target = await self._ensure_target(db, source)
                creation = await create_scan_result(
                    db,
                    version_id=version.id,
                    profile_name=profile,
                    trigger=_regression_trigger(),
                    requested_by="system",
                    target_ids=[target.id],
                    options={**options, "trigger_detail": "regression"},
                    tools=usable,
                )
                scan_id = creation.scan.id
            run.scan_id = str(scan_id)
            # leaving session_scope committed the rows; the queue entries follow the commit
            if dropped:
                log.info("regression_tools_not_in_profile", app=source.app, tools=dropped)
            await self._wait(scan_id, wait_seconds, run)
        except Problem as exc:
            run.error = "the scan could not be started: %s" % str(exc)
        except Exception as exc:  # noqa: BLE001 - one application must not stop the whole suite
            log.warning("regression_app_failed", app=source.app, error=type(exc).__name__)
            run.error = "the scan could not be run (%s)" % type(exc).__name__
        return run

    async def _ensure_target(self, db: Any, source: AppSource) -> tuple[Any, Any]:
        from sqlalchemy import select

        from securescan.db.models.applications import Application
        from securescan.db.models.enums import AppType, ArtifactKind, TargetEnvironment, TargetKind
        from securescan.db.models.targets import Target
        from securescan.db.models.versions import ApplicationVersion
        from securescan.domain.inventory import validate_target_rules
        from securescan.storage.artifacts import save_bytes
        from securescan.util import new_id, sha256_hex

        name = APP_PREFIX + source.app
        now = utcnow()
        application = await db.scalar(select(Application).where(Application.name == name))
        if application is None:
            application = Application(
                id=new_id(), name=name, type=AppType.INTERNAL,
                description="Created by the regression suite (planted application %s). Not a real application." % source.app,
                criticality="low", data_classification="internal", tags=["regression"], confirmed=True,
                automatic=False, cached_counts={}, created_at=now, updated_at=now,
            )  # fmt: skip
            db.add(application)
            await db.flush()
        if source.url is not None:
            label, kind = "dast-" + sha256_hex(source.url.encode("utf-8"))[:12], "release"
            payload = None
        else:
            assert source.path is not None  # noqa: S101
            payload = await asyncio.to_thread(zip_directory, source.path)
            label, kind = "fixture-" + sha256_hex(payload)[:12], "upload"
        version = await db.scalar(
            select(ApplicationVersion).where(
                ApplicationVersion.application_id == application.id, ApplicationVersion.label == label
            )
        )
        if version is None:
            version = ApplicationVersion(
                id=new_id(), application_id=application.id, label=label, label_kind=kind,
                description="Regression fixture", created_at=now, updated_at=now,
            )  # fmt: skip
            db.add(version)
            await db.flush()
        target = await db.scalar(
            select(Target).where(Target.version_id == version.id, Target.archived_at.is_(None)).limit(1)
        )
        if target is None:
            if payload is not None:
                artifact = await save_bytes(
                    db, kind=ArtifactKind.UPLOAD, data=payload, filename="%s.zip" % source.app,
                    content_type="application/zip",
                )  # fmt: skip
                locator = validate_target_rules(
                    kind=TargetKind.ZIP, locator=None, environment=None,
                    application_type=AppType.INTERNAL, upload_artifact_id=artifact.id,
                )  # fmt: skip
                target = Target(
                    id=new_id(), version_id=version.id, kind=TargetKind.ZIP, name=source.app, locator=locator,
                    upload_artifact_id=artifact.id, created_at=now, updated_at=now,
                )  # fmt: skip
            else:
                locator = validate_target_rules(
                    kind=TargetKind.URL, locator=source.url, environment=TargetEnvironment.UAT,
                    application_type=AppType.INTERNAL,
                )  # fmt: skip
                target = Target(
                    id=new_id(), version_id=version.id, kind=TargetKind.URL, name=source.app, locator=locator,
                    environment=TargetEnvironment.UAT, environment_set_at=now, host_approved=True,
                    created_at=now, updated_at=now,
                )  # fmt: skip
            db.add(target)
            await db.flush()
        return version, target

    async def _wait(self, scan_id: Any, wait_seconds: float, run: AppRun) -> None:
        from sqlalchemy import select

        from securescan.db.models.enums import ImportState, JobState, ScanState
        from securescan.db.models.jobs import ScanJob
        from securescan.db.models.scans import Scan
        from securescan.db.session import session_scope
        from securescan.domain.history import scan_findings

        final_scan = {ScanState.COMPLETED, ScanState.COMPLETED_PARTIAL, ScanState.FAILED, ScanState.CANCELLED}
        final_job = {
            JobState.COMPLETED, JobState.COMPLETED_PARTIAL, JobState.FAILED, JobState.CANCELLED, JobState.TIMED_OUT
        }
        started = time.monotonic()
        poll = max(1.0, float(self.settings.regression_poll_seconds))
        while True:
            async with session_scope() as db:
                scan = await db.get(Scan, scan_id)
                jobs = list((await db.scalars(select(ScanJob).where(ScanJob.scan_id == scan_id))).all())
                settled = scan is not None and scan.state in final_scan and all(
                    j.state in final_job
                    and (
                        j.state not in (JobState.COMPLETED, JobState.COMPLETED_PARTIAL)
                        or j.import_state in (ImportState.IMPORTED, ImportState.FAILED)
                    )
                    for j in jobs
                )
                if settled:
                    rows = await scan_findings(db, scan_id, include_inactive=True)
                    for job in jobs:
                        mine = [r for r in rows if r.job_id == job.id]
                        reason = job.outcome_reason
                        state = job.state.value
                        if job.import_state == ImportState.FAILED and state in ("completed", "completed_partial"):
                            state, reason = "failed", "the report could not be imported into DefectDojo"
                        run.jobs[job.tool] = JobOutcome(
                            tool=job.tool, state=state, reason=reason, image_digest=job.image_digest,
                            findings=[
                                ObservedFinding(
                                    tool=job.tool, title=r.title, severity=r.severity.value, cwe=r.cwe, cve=r.cve,
                                    file_path=r.file_path, line=r.line, component=r.component,
                                )
                                for r in mine
                            ],
                        )  # fmt: skip
                    return
            if time.monotonic() - started > wait_seconds:
                run.error = "the scan did not finish within %d minutes" % math.ceil(wait_seconds / 60.0)
                return
            await self._sleep(poll)


def _regression_trigger() -> Any:
    from securescan.db.models.enums import ScanTrigger

    return ScanTrigger.SCHEDULE


# ================================================================================ command line


def _check(fixtures_dir: Path | None, regression_dir: Path | None) -> int:
    """Parse every expectation file and report counts. No database, no Docker."""
    suite = load_suite(regression_dir)
    status = 0
    names: list[str] = sorted({a for cfg in suite.kinds.values() for a in cfg.apps})
    for app in names:
        try:
            found = load_expectations([app], fixtures_dir, regression_dir)
        except RegressionConfigError as exc:
            print("INVALID  %s" % exc)
            status = 1
            continue
        if app not in found:
            print("absent   %s (no expectation file)" % app)
            continue
        counts = {t: (len(v), sum(1 for e in v if e.verified)) for t, v in found[app].tools.items()}
        shown = ", ".join("%s %d/%d verified" % (t, c[1], c[0]) for t, c in sorted(counts.items()) if c[0])
        print("ok       %-16s %s" % (app, shown or "no entries"))
    return status


async def _run_cli(kind: str, apps: list[str], tools: list[str], as_json: bool, allow_unasserted: bool) -> int:
    from securescan.jobs.app import app as queue_app
    from securescan.jobs.app import load_tasks

    load_tasks()
    async with queue_app.open_async():
        report = await run_regression(kind, apps=apps or None, tools=tools or None)
    print("\n".join(report.summary_lines()))
    if as_json:
        print(json.dumps(report.to_detail(), indent=2, sort_keys=True))
    if report.failed:
        return 1
    if report.outcome == STATUS_UNASSERTED and not allow_unasserted:
        return 2
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securescan.domain.regression", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run", help="scan the planted applications and compare with the expectations")
    run_p.add_argument("--kind", default="all", help="content | image | external | dast | all (default all)")
    run_p.add_argument("--app", action="append", default=[], help="only this application (repeatable)")
    run_p.add_argument("--tool", action="append", default=[], help="only this tool (repeatable)")
    run_p.add_argument("--json", action="store_true", help="also print the result as JSON")
    run_p.add_argument("--allow-unasserted", action="store_true", help="exit 0 when no expectation is verified yet")
    sub.add_parser("check", help="parse the expectation files only (no database)")
    args = parser.parse_args(list(argv) if argv is not None else None)
    settings = get_settings()
    from securescan.logging import configure_logging

    configure_logging(settings.log_level)
    try:
        if args.command == "check":
            return _check(find_fixtures_dir(settings), find_regression_dir(settings))
        return asyncio.run(_run_cli(args.kind, args.app, args.tool, args.json, args.allow_unasserted))
    except RegressionConfigError as exc:
        print("regression: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
