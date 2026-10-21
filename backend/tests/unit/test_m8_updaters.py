"""The content updaters: licence filter, symlink switch, regression gate, and each feed's update flow (no Docker)."""

from __future__ import annotations

import os
import types
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from securescan.config import Settings, get_settings
from securescan.db.models.enums import ContentFeed
from securescan.jobs import scanner_health, updaters
from securescan.jobs.updaters import (
    FilterReport,
    RegressionOutcome,
    RulesLock,
    UpdateOutcome,
    count_template_files,
    dated_directory_name,
    expectation_met,
    filter_rules,
    grype_version_label,
    license_problem,
    load_expectations,
    missing_expectations,
    parse_grype_status,
    parse_rules_lock,
    parse_timestamp,
    prune_directories,
    rule_errors,
    rule_file_verdict,
    switch_symlink,
    wanted_commit,
)
from securescan.runner.catalogue import clear_catalogue_cache
from securescan.runner.specs import ContainerResult
from tests.unit.conftest import FakeSession
from tests.unit.m8_helpers import PROXY, lease_factory, put_file, set_pin
from tests.unit.runner_helpers import REPO_SCANNERS, SAMPLE_APPS

SHA = "0123456789abcdef0123456789abcdef01234567"
NEW = f"rules-{SHA}"
needs_links = pytest.mark.skipif(os.name == "nt", reason="atomic symbolic link replacement needs POSIX")

RULE_OK = """rules:
- id: sql-injection
  languages: [java]
  message: SQL built from input
  severity: ERROR
  pattern: foo(...)
  metadata:
    license: Semgrep Rules License v1.0
    cwe: CWE-89
"""
RULE_NOLICENCE = RULE_OK.replace("    license: Semgrep Rules License v1.0\n", "")
RULE_AGPL = RULE_OK.replace("Semgrep Rules License v1.0", "AGPL-3.0 license")
LOCK = RulesLock()
ORIGINAL_DETAILED = updaters.run_regression_detailed


# =============================================================================================== the rules lock
def test_the_shipped_lock_file_parses_and_pins_nothing() -> None:
    lock = parse_rules_lock((REPO_SCANNERS.parent / "content" / "semgrep-rules.lock").read_text(encoding="utf-8"))
    assert lock.commit == "" and lock.auto is True and lock.repository == "https://github.com/semgrep/semgrep-rules"
    assert lock.allowed_licenses == ["Semgrep Rules License v1.0"] and "agpl" in lock.deny_licenses
    assert "stats" in lock.drop_directories and ".github" in lock.drop_directories and lock.missing_license == "allow"


@pytest.mark.parametrize("text", ["commit: nothex", "missing_license: maybe", "allowed_licenses: notalist", "- a\n- b", "deny_licenses: [1, 2]"])
def test_a_broken_lock_file_is_refused(text: str) -> None:
    with pytest.raises(ValueError):
        parse_rules_lock(text)


def test_which_commit_is_fetched() -> None:
    env_pin = Settings(semgrep_rules_commit=" deadbee ")  # type: ignore[call-arg]
    plain = Settings()
    pinned = parse_rules_lock("commit: abcdef1\nauto: false\n")
    auto = parse_rules_lock("commit: abcdef1\nauto: true\n")
    assert wanted_commit(plain, parse_rules_lock("")) is None
    assert wanted_commit(plain, pinned) == "abcdef1"
    assert wanted_commit(plain, auto) is None, "auto means the newest commit"
    assert wanted_commit(env_pin, auto) == "deadbee" and wanted_commit(env_pin, pinned) == "deadbee"


# =============================================================================================== the licence filter
def test_licence_policy() -> None:
    assert license_problem("Semgrep Rules License v1.0", LOCK) is None
    assert license_problem("semgrep rules license v1.0", LOCK) is None
    assert license_problem(None, LOCK) is None and license_problem("  ", LOCK) is None
    assert "licence not allowed" in (license_problem("AGPL-3.0 license", LOCK) or "")
    assert "licence not allowed" in (license_problem("Commons Clause License Condition v1.0[LGPL-2.1-only]", LOCK) or "")
    assert "not on the allowlist" in (license_problem("MIT", LOCK) or "")
    assert license_problem("MIT", parse_rules_lock("allowed_licenses: [Semgrep Rules License v1.0, MIT]")) is None
    assert license_problem(None, parse_rules_lock("missing_license: drop")) == "no licence stated"
    assert license_problem("MIT-AGPL-3.0", parse_rules_lock("allowed_licenses: [MIT-AGPL-3.0]")) is not None, "a denied word wins over the allowlist"


def test_rule_file_verdicts() -> None:
    assert rule_file_verdict(RULE_OK, LOCK) == (1, None)
    assert rule_file_verdict(RULE_NOLICENCE, LOCK) == (1, None)
    assert rule_file_verdict(RULE_AGPL, LOCK)[0] == 0
    mixed = RULE_OK + RULE_AGPL.split("rules:\n", 1)[1].replace("sql-injection", "other")
    assert rule_file_verdict(mixed, LOCK)[0] == 0, "one refused rule drops the whole file"
    assert rule_file_verdict("just: data\n", LOCK) == (0, "not a rule file")
    assert rule_file_verdict("rules: []\n", LOCK) == (0, "not a rule file")
    assert rule_file_verdict("rules: [1, 2]\n", LOCK) == (0, "not a rule file")
    assert rule_file_verdict("rules:\n- message: no id\n", LOCK) == (0, "not a rule file")
    assert rule_file_verdict("a: [unclosed\n", LOCK) == (0, "unreadable yaml")


def test_the_filter_keeps_licensed_rule_files_only_with_their_layout(tmp_path: Path) -> None:
    clone = tmp_path / "clone"
    put_file(clone, "LICENSE", b"Semgrep Rules License v1.0")
    put_file(clone, "README.md", b"readme")
    put_file(clone, "java/security/sqli.yaml", RULE_OK.encode())
    put_file(clone, "java/security/sqli.java", b"// ruleid: sql-injection")
    put_file(clone, "java/security/sqli.test.yaml", RULE_OK.encode())
    put_file(clone, "python/lang/nolicence.yaml", RULE_NOLICENCE.encode())
    put_file(clone, "trailofbits/go/agpl.yaml", RULE_AGPL.encode())
    put_file(clone, "stats/rules.yaml", RULE_OK.encode())
    put_file(clone, ".github/workflows/ci.yaml", b"name: ci\njobs: {}\n")
    put_file(clone, "generic/config.yaml", b"settings: {a: 1}\n")
    put_file(clone, "python/.hidden.yaml", RULE_OK.encode())
    put_file(clone, "deep/er/ok.yml", RULE_OK.encode())
    put_file(clone, ".git/config", b"x")
    bundle = tmp_path / "bundle"
    report = filter_rules(clone, bundle, LOCK)
    kept = sorted(str(p.relative_to(bundle)).replace(os.sep, "/") for p in bundle.rglob("*") if p.is_file())
    assert kept == ["LICENSE", "deep/er/ok.yml", "java/security/sqli.yaml", "python/lang/nolicence.yaml"]
    assert (bundle / "java/security/sqli.yaml").read_text(encoding="utf-8") == RULE_OK, "the file is copied unchanged"
    assert (report.files_kept, report.rules_kept) == (3, 3)
    assert report.dropped["licence not allowed"] == 1 and report.dropped["not a rule file"] == 3
    assert any("trailofbits/go/agpl.yaml" in example for example in report.examples["licence not allowed"])
    assert FilterReport().as_dict()["files_kept"] == 0


def test_a_company_approved_licence_can_be_allowed(tmp_path: Path) -> None:
    clone = tmp_path / "clone"
    put_file(clone, "a/mit.yaml", RULE_OK.replace("Semgrep Rules License v1.0", "MIT").encode())
    strict = filter_rules(clone, tmp_path / "strict", LOCK)
    relaxed = filter_rules(clone, tmp_path / "relaxed", parse_rules_lock("allowed_licenses: [MIT]"))
    assert strict.files_kept == 0 and relaxed.files_kept == 1


# =============================================================================================== symlinks, pruning, names
@needs_links
def test_the_symlink_is_switched_atomically(tmp_path: Path) -> None:
    base = tmp_path / "semgrep"
    (base / "rules-aaa").mkdir(parents=True)
    (base / "rules-bbb").mkdir()
    switch_symlink(base / "rules", "rules-aaa")
    assert os.readlink(base / "rules") == "rules-aaa", "a relative link"
    switch_symlink(base / "rules", "rules-bbb")
    assert os.readlink(base / "rules") == "rules-bbb" and not os.path.lexists(base / "rules.new")
    assert (base / "rules").resolve().name == "rules-bbb"


@needs_links
def test_a_real_directory_in_the_links_place_is_moved_aside(tmp_path: Path) -> None:
    base = tmp_path / "semgrep"
    (base / "rules-aaa").mkdir(parents=True)
    (base / "rules").mkdir()
    (base / "rules" / "f").write_text("x")
    switch_symlink(base / "rules", "rules-aaa")
    assert os.path.islink(base / "rules")
    assert any(p.name.startswith("rules.previous-") and (p / "f").exists() for p in base.iterdir())


def test_the_symlink_target_must_be_a_sibling_directory(tmp_path: Path) -> None:
    (tmp_path / "x").mkdir()
    for bad in ("../x", "a/b", "", ".", ".."):
        with pytest.raises(ValueError):
            switch_symlink(tmp_path / "link", bad)
    with pytest.raises(FileNotFoundError):
        switch_symlink(tmp_path / "link", "missing")


def test_old_directories_are_pruned_but_never_the_protected_ones(tmp_path: Path) -> None:
    for index, name in enumerate(["rules-1", "rules-2", "rules-3", "rules-4", "other"]):
        directory = tmp_path / name
        directory.mkdir()
        os.utime(directory, (1000 + index, 1000 + index))
    removed = prune_directories(tmp_path, "rules-", keep=1, protect=["rules-1"])
    assert sorted(removed) == ["rules-2", "rules-3"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["other", "rules-1", "rules-4"]


def test_dated_directories_and_template_counts(tmp_path: Path) -> None:
    moment = datetime(2026, 10, 7, tzinfo=timezone.utc)
    assert dated_directory_name(tmp_path, moment) == "nuclei-templates-20261007"
    (tmp_path / "nuclei-templates-20261007").mkdir()
    assert dated_directory_name(tmp_path, moment) == "nuclei-templates-20261007-2"
    (tmp_path / "nuclei-templates-20261007-2").mkdir()
    assert dated_directory_name(tmp_path, moment) == "nuclei-templates-20261007-3"
    put_file(tmp_path, "t/a.yaml")
    put_file(tmp_path, "t/sub/b.yml")
    put_file(tmp_path, "t/c.txt")
    assert count_template_files(tmp_path / "t") == 2


def test_grype_status_and_timestamps() -> None:
    output = 'time=x level=info msg="hi"\n{"schemaVersion": 6, "from": "https://x", "built": "2026-10-07T01:30:03Z", "valid": true}\n'
    status = parse_grype_status(output)
    assert status is not None and status["schemaVersion"] == 6 and status["valid"] is True
    built = parse_timestamp(status["built"])
    assert built == datetime(2026, 10, 7, 1, 30, 3, tzinfo=timezone.utc)
    assert grype_version_label(status, built) == "v6-20261007T013003Z" and grype_version_label({}, built) == "db-20261007T013003Z"
    assert parse_grype_status("no json here") is None and parse_grype_status("{broken") is None and parse_grype_status("[1]") is None
    assert parse_timestamp("2026-10-05T12:34:56+02:00") == datetime(2026, 10, 5, 10, 34, 56, tzinfo=timezone.utc)
    assert parse_timestamp("") is None and parse_timestamp("yesterday") is None and parse_timestamp(5) is None


# =============================================================================================== expectations
RESULTS = [
    {"check_id": "java.lang.security.audit.sqli.tainted-sql-string", "path": "/src/src/main/java/com/x/UserServlet.java",
     "start": {"line": 25}, "extra": {"message": "SQL injection: query built by string concatenation"}},
    {"check_id": "javascript.express.xss.direct-response-write", "path": "/src/server.js", "start": {"line": 5},
     "extra": {"message": "Cross-site scripting through direct response write"}},
]  # fmt: skip


def test_expectations_are_matched_by_rule_id_or_by_category_words() -> None:
    assert expectation_met({"id": "e1", "rule_id": "tainted-sql-string"}, RESULTS)
    assert expectation_met({"id": "e1", "rule_id": "java.lang.security.audit.sqli.tainted-sql-string"}, RESULTS)
    assert not expectation_met({"id": "e2", "rule_id": "sql-string"}, RESULTS), "a rule id matches whole dotted parts"
    fuzzy = {"id": "e3", "expect_category": "SQL injection: query built by string concatenation with request input", "file": "UserServlet.java"}
    assert expectation_met(fuzzy, RESULTS) and not expectation_met({**fuzzy, "file": "Other.java"}, RESULTS)
    assert not expectation_met({"id": "e4", "expect_category": "Hard-coded credential in source"}, RESULTS)


def test_only_verified_expectations_can_go_missing() -> None:
    entries = [
        {"id": "ok", "rule_id": "tainted-sql-string", "verified": True},
        {"id": "gone", "rule_id": "other-rule", "verified": True},
        {"id": "not-yet", "rule_id": "nope", "verified": False},
    ]
    assert missing_expectations(entries, RESULTS) == ["gone"]
    assert missing_expectations([], RESULTS) == []


def test_rule_errors_of_a_report() -> None:
    report = {"errors": [{"type": ["InvalidRuleSchemaError", "x"], "level": "error"}, {"type": "PartialParsing", "level": "warn"}]}
    assert rule_errors(report) == ["InvalidRuleSchemaError x"] and rule_errors({"errors": []}) == [] and rule_errors({}) == []


def test_the_shipped_expected_findings_load() -> None:
    apps = [p for p in SAMPLE_APPS.iterdir() if (p / "expected-findings.yaml").is_file()]
    assert apps
    for app in apps:
        entries = load_expectations(app / "expected-findings.yaml", "semgrep")
        assert all(isinstance(e, dict) for e in entries), app.name
        assert load_expectations(app / "expected-findings.yaml", "no-such-tool") == []


# =============================================================================================== flows with fakes
class Env:
    """Everything the updaters reach through module-level names, replaced by recorders."""

    def __init__(self) -> None:
        self.db = FakeSession()
        self.active: dict[str, Any] = {}
        self.versions: list[dict[str, Any]] = []
        self.touched: list[str] = []
        self.containers: list[dict[str, Any]] = []
        self.script: dict[str, Callable[[dict[str, Any]], ContainerResult]] = {}
        self.hosts: list[Any] = []
        self.regression: list[tuple[str, Path]] = []
        self.gate = RegressionOutcome(True, "passed", {"apps": {}})


def result(code: int = 0, logs: str = "", timed_out: bool = False) -> ContainerResult:
    return ContainerResult("c" * 12, code, timed_out, logs)


@pytest.fixture
def catalogue_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_SCANNERS_DIR", str(REPO_SCANNERS))
    get_settings.cache_clear()
    clear_catalogue_cache()


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, catalogue_env: None) -> Env:
    state = Env()

    class Scope:
        async def __aenter__(self) -> FakeSession:
            return state.db

        async def __aexit__(self, *_a: object) -> None:
            return None

    async def active_versions(_session: Any) -> dict[str, Any]:
        return dict(state.active)

    async def record_version(_session: Any, feed: ContentFeed, version: str, **kwargs: Any) -> Any:
        state.versions.append({"feed": feed, "version": version, **kwargs})
        if kwargs.get("activate", True):
            state.active[feed.value] = types.SimpleNamespace(
                version=version, built_at=kwargs.get("built_at"), fetched_at=datetime.now(timezone.utc), source_commit=kwargs.get("source_commit"),
            )  # fmt: skip
        return types.SimpleNamespace(id=uuid.uuid4())

    async def touch_active(_session: Any, feed: ContentFeed) -> Any:
        state.touched.append(feed.value)
        return types.SimpleNamespace(id=uuid.uuid4())

    async def run_container(entry: Any, **kwargs: Any) -> ContainerResult:
        call = {"tool": entry.tool, **kwargs}
        state.containers.append(call)
        return state.script[entry.tool](call)

    async def regression(kind: str, candidate: Path | None = None, *, settings: Any = None) -> RegressionOutcome:
        state.regression.append((kind, candidate))  # type: ignore[arg-type]
        return state.gate

    monkeypatch.setattr(updaters, "session_scope", lambda: Scope())
    monkeypatch.setattr(updaters, "active_versions", active_versions)
    monkeypatch.setattr(updaters, "record_version", record_version)
    monkeypatch.setattr(updaters, "touch_active", touch_active)
    monkeypatch.setattr(updaters, "run_updater_container", run_container)
    monkeypatch.setattr(updaters, "run_regression_detailed", regression)
    monkeypatch.setattr(updaters, "egress_lease", lease_factory(PROXY, state.hosts))
    scanner_health._failed.clear()
    return state


def content_root() -> Path:
    return Path(Settings().content_root)


# ----------------------------------------------------------------------------------------------- Grype
STATUS = '{"schemaVersion": 6, "from": "https://grype.anchore.io/databases", "built": "2026-10-07T01:30:03Z", "valid": true}'


async def test_the_grype_database_update_records_the_build_date(env: Env) -> None:
    env.script["grype-db-update"] = lambda call: result(0, "no update available")
    env.script["grype-db-status"] = lambda call: result(0, STATUS)
    outcome = await updaters.update_grype_db(Settings())
    assert outcome.ok and outcome.changed and outcome.version == "v6-20261007T013003Z"
    update, status = env.containers
    assert update["tool"] == "grype-db-update" and update["network"] == Settings().network_backend
    assert update["env"]["HTTPS_PROXY"] == PROXY and env.hosts == [["grype.anchore.io", "toolbox-data.anchore.io"]]
    database = content_root() / "grype-db"
    assert update["binds"] == [(str(database), "/content/grype-db", False)], "the single writer"
    assert status["network"] == "none" and status["binds"] == [(str(database), "/content/grype-db", True)]
    recorded = env.versions[0]
    assert recorded["feed"] == ContentFeed.GRYPE_DB and recorded["built_at"] == datetime(2026, 10, 7, 1, 30, 3, tzinfo=timezone.utc)
    assert recorded["path"] == "grype-db" and recorded["regression_result"] == "skipped"
    assert scanner_health._failed[ContentFeed.GRYPE_DB.value] is False


async def test_an_unchanged_database_is_not_a_change(env: Env) -> None:
    env.script["grype-db-update"] = lambda call: result(0)
    env.script["grype-db-status"] = lambda call: result(0, STATUS)
    env.active[ContentFeed.GRYPE_DB.value] = types.SimpleNamespace(version="v6-20261007T013003Z", built_at=None, fetched_at=None)
    outcome = await updaters.update_grype_db(Settings())
    assert outcome.ok and outcome.changed is False


async def test_a_failed_grype_update_keeps_the_old_database_and_raises_the_alert(env: Env) -> None:
    env.active[ContentFeed.GRYPE_DB.value] = types.SimpleNamespace(version="old", built_at=None, fetched_at=datetime.now(timezone.utc))
    env.script["grype-db-update"] = lambda call: result(1, "error: could not reach grype.anchore.io")
    outcome = await updaters.update_grype_db(Settings())
    assert not outcome.ok and "grype db update failed (exit code 1)" in outcome.message and "could not reach" in outcome.message
    assert env.versions == [] and env.active[ContentFeed.GRYPE_DB.value].version == "old"
    assert scanner_health._failed[ContentFeed.GRYPE_DB.value] is True


async def test_an_invalid_grype_database_is_a_failure(env: Env) -> None:
    env.script["grype-db-update"] = lambda call: result(0)
    env.script["grype-db-status"] = lambda call: result(0, '{"schemaVersion": 6, "valid": false, "error": "checksum mismatch"}')
    outcome = await updaters.update_grype_db(Settings())
    assert not outcome.ok and "not valid" in outcome.message and env.versions == []


async def test_a_timeout_is_a_failure_and_a_proxy_problem_too(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    env.script["grype-db-update"] = lambda call: result(0, "", timed_out=True)
    assert "timed out" in (await updaters.update_grype_db(Settings())).message
    from securescan.runner.egress import EgressError

    def broken(_hosts: Any) -> Any:
        raise EgressError("The egress proxy did not become ready in 30 seconds.")

    monkeypatch.setattr(updaters, "egress_lease", broken)
    outcome = await updaters.update_grype_db(Settings())
    assert not outcome.ok and "egress proxy did not become ready" in outcome.message


# ----------------------------------------------------------------------------------------------- Semgrep rules
@pytest.fixture
def rules_env(env: Env, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Env:
    lock = tmp_path / "semgrep-rules.lock"
    lock.write_text("commit: ''\nauto: true\n", encoding="utf-8")
    monkeypatch.setenv("SECURESCAN_SEMGREP_RULES_LOCK_FILE", str(lock))
    clones: list[dict[str, Any]] = []
    files: dict[str, bytes] = {"java/security/sqli.yaml": RULE_OK.encode(), "LICENSE": b"licence text"}

    async def clone_repository(url: str, dest: Path, **kwargs: Any) -> Any:
        clones.append({"url": url, "proxy": kwargs.get("proxy_url"), "commit": kwargs.get("commit")})
        for relative, data in files.items():
            put_file(dest, relative, data)
        return types.SimpleNamespace(commit_sha=SHA, branches=1, tags=0)

    class Runner:
        def __init__(self, _env: Any, _secrets: Any = ()) -> None:
            pass

        async def run(self, *_a: Any, **_k: Any) -> str:
            return "2026-10-05T12:00:00+00:00\n"

    monkeypatch.setattr(updaters, "clone_repository", clone_repository)
    monkeypatch.setattr(updaters, "GitRunner", Runner)
    env.clones = clones  # type: ignore[attr-defined]
    env.clone_files = files  # type: ignore[attr-defined]
    return env


@needs_links
async def test_the_first_installation_is_promoted_without_the_gate(rules_env: Env) -> None:
    outcome = await updaters.update_semgrep_rules(Settings())
    base = content_root() / "semgrep"
    assert outcome.ok and outcome.changed and outcome.version == NEW
    assert os.readlink(base / "rules") == NEW
    assert (base / NEW / "java/security/sqli.yaml").read_text(encoding="utf-8") == RULE_OK
    assert (base / NEW / "LICENSE").is_file() and (base / NEW / "BUNDLE.info").is_file()
    assert rules_env.regression == [], "nothing to regress against"
    recorded = rules_env.versions[0]
    assert recorded["regression_result"] == "skipped" and recorded["source_commit"] == SHA and recorded["path"] == f"semgrep/{NEW}"
    assert recorded["built_at"] == datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
    assert sorted(p.name for p in base.iterdir()) == ["rules", NEW], "no staging or clone leftovers"
    assert rules_env.clones[0]["url"] == "https://github.com/semgrep/semgrep-rules"  # type: ignore[attr-defined]
    assert rules_env.clones[0]["proxy"] == PROXY and rules_env.clones[0]["commit"] is None  # type: ignore[attr-defined]
    assert rules_env.hosts == [["codeload.github.com", "github.com"]]


@needs_links
async def test_a_new_version_is_promoted_after_the_gate_passes(rules_env: Env) -> None:
    base = content_root() / "semgrep"
    (base / "rules-old").mkdir(parents=True)
    os.symlink("rules-old", base / "rules")
    rules_env.active[ContentFeed.SEMGREP_RULES.value] = types.SimpleNamespace(version="rules-old", built_at=None, fetched_at=None)
    outcome = await updaters.update_semgrep_rules(Settings())
    assert outcome.ok and os.readlink(base / "rules") == NEW and (base / "rules-old").is_dir(), "the previous version is kept"
    kind, candidate = rules_env.regression[0]
    assert kind == "semgrep" and candidate is not None and candidate.name == f".staging-{SHA}"
    assert rules_env.versions[0]["regression_result"] == "passed"
    assert "filter" in rules_env.versions[0]["regression_detail"]


@needs_links
async def test_rules_that_fail_the_gate_are_rejected_and_the_old_ones_stay(rules_env: Env) -> None:
    base = content_root() / "semgrep"
    (base / "rules-old").mkdir(parents=True)
    os.symlink("rules-old", base / "rules")
    rules_env.active[ContentFeed.SEMGREP_RULES.value] = types.SimpleNamespace(version="rules-old", built_at=None, fetched_at=None)
    rules_env.gate = RegressionOutcome(False, "failed", {"failures": ["java-planted: 1 expected finding(s) disappeared"]})
    outcome = await updaters.update_semgrep_rules(Settings())
    assert not outcome.ok and "regression gate rejected" in outcome.message and outcome.version == NEW
    assert os.readlink(base / "rules") == "rules-old", "the active version did not change"
    assert (base / f"{NEW}.rejected").is_dir() and not (base / NEW).exists()
    recorded = rules_env.versions[0]
    assert recorded["activate"] is False and recorded["regression_result"] == "failed"
    assert recorded["regression_detail"]["failures"] == ["java-planted: 1 expected finding(s) disappeared"]
    assert rules_env.active[ContentFeed.SEMGREP_RULES.value].version == "rules-old"
    assert scanner_health._failed[ContentFeed.SEMGREP_RULES.value] is True
    assert sorted(p.name for p in base.iterdir() if p.name.startswith(".")) == [], "no staging leftovers"


@needs_links
async def test_the_same_commit_is_only_rechecked(rules_env: Env) -> None:
    base = content_root() / "semgrep"
    (base / NEW).mkdir(parents=True)
    os.symlink(NEW, base / "rules")
    rules_env.active[ContentFeed.SEMGREP_RULES.value] = types.SimpleNamespace(version=NEW, built_at=None, fetched_at=None)
    outcome = await updaters.update_semgrep_rules(Settings())
    assert outcome.ok and outcome.changed is False and rules_env.touched == [ContentFeed.SEMGREP_RULES.value]
    assert rules_env.versions == [] and rules_env.regression == []


async def test_a_clone_that_has_only_refused_licences_is_not_promoted(rules_env: Env) -> None:
    rules_env.clone_files.clear()  # type: ignore[attr-defined]
    rules_env.clone_files["trailofbits/go/agpl.yaml"] = RULE_AGPL.encode()  # type: ignore[attr-defined]
    outcome = await updaters.update_semgrep_rules(Settings())
    assert not outcome.ok and "licence filter left no rules" in outcome.message and rules_env.versions == []
    assert not (content_root() / "semgrep" / NEW).exists()


async def test_a_failing_clone_is_a_failed_update(rules_env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.runner.sources.base import SourceError

    async def broken(*_a: Any, **_k: Any) -> Any:
        raise SourceError("Cloning the repository: git could not reach the repository host.")

    monkeypatch.setattr(updaters, "clone_repository", broken)
    outcome = await updaters.update_semgrep_rules(Settings())
    assert not outcome.ok and "fetching semgrep-rules failed" in outcome.message
    assert rules_env.versions == []


# ----------------------------------------------------------------------------------------------- Nuclei templates
def fetch_templates(count: int) -> Callable[[dict[str, Any]], ContainerResult]:
    def run(call: dict[str, Any]) -> ContainerResult:
        staging = Path(call["binds"][0][0])
        for index in range(count):
            put_file(staging, f"http/cves/t{index}.yaml", b"id: t")
        return result(0, "templates updated")

    return run


@needs_links
async def test_templates_go_into_a_dated_directory_behind_a_symlink(env: Env) -> None:
    env.script["nuclei-templates-update"] = fetch_templates(MIN := 250)
    root = content_root()
    old = root / "nuclei-templates-20250101"
    old.mkdir(parents=True)
    os.symlink(old.name, root / "nuclei-templates")
    env.active[ContentFeed.NUCLEI_TEMPLATES.value] = types.SimpleNamespace(version=old.name, built_at=None, fetched_at=None)
    outcome = await updaters.update_nuclei_templates(Settings())
    assert outcome.ok and outcome.version is not None and outcome.version.startswith("nuclei-templates-")
    assert os.readlink(root / "nuclei-templates") == outcome.version
    assert count_template_files(root / outcome.version) == MIN and old.is_dir(), "the previous directory is kept"
    call = env.containers[0]
    assert call["network"] == Settings().network_backend and call["env"]["HTTPS_PROXY"] == PROXY
    assert call["binds"][0][1] == "/templates" and call["binds"][0][2] is False
    assert env.regression[0][0] == "nuclei" and env.versions[0]["feed"] == ContentFeed.NUCLEI_TEMPLATES
    assert not any(p.name.startswith(".staging") for p in root.iterdir())
    assert "api.pdtm.sh" in env.hosts[0] and "github.com" in env.hosts[0]


@needs_links
async def test_templates_that_fail_the_check_are_rejected(env: Env) -> None:
    env.script["nuclei-templates-update"] = fetch_templates(250)
    env.gate = RegressionOutcome(False, "failed", {"exit_code": 1})
    root = content_root()
    (root / "nuclei-templates-20250101").mkdir(parents=True)
    os.symlink("nuclei-templates-20250101", root / "nuclei-templates")
    outcome = await updaters.update_nuclei_templates(Settings())
    assert not outcome.ok and os.readlink(root / "nuclei-templates") == "nuclei-templates-20250101"
    assert any(p.name.endswith(".rejected") for p in root.iterdir())
    assert env.versions[0]["activate"] is False


async def test_a_fetch_with_too_few_templates_is_refused(env: Env) -> None:
    env.script["nuclei-templates-update"] = fetch_templates(5)
    outcome = await updaters.update_nuclei_templates(Settings())
    assert not outcome.ok and "only 5 templates" in outcome.message and env.regression == []


# =============================================================================================== the regression gate
APP_EXPECTATIONS = """app: python-planted
schema_version: 1
tools:
  semgrep:
    - {id: sqli, expect_category: "SQL injection: query built by string concatenation", file: UserServlet.java, verified: VERIFIED, rule_id: tainted-sql-string}
  gitleaks: []
"""


@pytest.fixture
def gate_env(env: Env, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Env:
    from securescan.runner.catalogue import ResolvedImage

    apps = tmp_path / "apps"
    state: dict[str, Any] = {"report": {"results": [], "errors": []}, "exit": 0, "verified": "true"}

    def write_app() -> None:
        put_file(apps, "python-planted/app.py", b"print(1)")
        put_file(apps, "python-planted/expected-findings.yaml", APP_EXPECTATIONS.replace("VERIFIED", state["verified"]).encode())

    write_app()

    async def on_app(settings: Any, entry: Any, image: Any, app_dir: Path, rules: Path) -> Any:
        state.setdefault("runs", []).append((app_dir.name, rules))
        return result(state["exit"]), state["report"]

    async def resolve(_session: Any, _entry: Any, _settings: Any = None) -> Any:
        return ResolvedImage("semgrep/semgrep@sha256:" + "a" * 64, "semgrep/semgrep", "1", "sha256:" + "a" * 64, "env")

    monkeypatch.setattr(updaters, "find_regression_apps", lambda settings: apps)
    monkeypatch.setattr(updaters, "_semgrep_on_app", on_app)
    monkeypatch.setattr(updaters, "resolve_image_with_override", resolve)
    env.state = state  # type: ignore[attr-defined]
    return env


async def semgrep_gate(candidate: Path) -> RegressionOutcome:
    return await updaters._regression_semgrep(Settings(), candidate)  # type: ignore[attr-defined,no-any-return]


async def test_the_gate_passes_when_every_verified_expectation_is_still_found(gate_env: Env, tmp_path: Path) -> None:
    gate_env.state["report"] = {"results": [RESULTS[0]], "errors": []}  # type: ignore[attr-defined]
    outcome = await semgrep_gate(tmp_path / "candidate")
    assert outcome.passed and outcome.result == "passed"
    assert outcome.detail["verified_expectations"] == 1 and outcome.detail["apps"]["python-planted"]["missing"] == []


async def test_the_gate_rejects_rules_that_lost_a_verified_finding(gate_env: Env, tmp_path: Path) -> None:
    gate_env.state["report"] = {"results": [RESULTS[1]], "errors": []}  # type: ignore[attr-defined]
    outcome = await semgrep_gate(tmp_path / "candidate")
    assert not outcome.passed and outcome.result == "failed"
    assert outcome.detail["apps"]["python-planted"]["missing"] == ["sqli"]
    assert "disappeared" in outcome.detail["failures"][0]


async def test_the_gate_rejects_an_invalid_rule(gate_env: Env, tmp_path: Path) -> None:
    gate_env.state["report"] = {"results": [RESULTS[0]], "errors": [{"type": ["InvalidRuleSchemaError", "x"], "level": "error"}]}  # type: ignore[attr-defined]
    outcome = await semgrep_gate(tmp_path / "candidate")
    assert not outcome.passed and outcome.detail["apps"]["python-planted"]["rule_errors"] == ["InvalidRuleSchemaError x"]


async def test_the_gate_rejects_rules_semgrep_cannot_run(gate_env: Env, tmp_path: Path) -> None:
    gate_env.state["exit"] = 7  # type: ignore[attr-defined]
    outcome = await semgrep_gate(tmp_path / "candidate")
    assert not outcome.passed and "semgrep did not complete" in outcome.detail["apps"]["python-planted"]["problem"]


async def test_without_verified_expectations_the_candidate_must_still_find_something(gate_env: Env, tmp_path: Path) -> None:
    gate_env.state["verified"] = "false"  # type: ignore[attr-defined]
    put_file(tmp_path / "apps", "python-planted/expected-findings.yaml", APP_EXPECTATIONS.replace("VERIFIED", "false").encode())
    gate_env.state["report"] = {"results": [], "errors": []}  # type: ignore[attr-defined]
    empty = await semgrep_gate(tmp_path / "candidate")
    assert not empty.passed and "found nothing" in empty.detail["failures"][0]
    gate_env.state["report"] = {"results": [RESULTS[0]], "errors": []}  # type: ignore[attr-defined]
    found = await semgrep_gate(tmp_path / "candidate")
    assert found.passed and found.detail["verified_expectations"] == 0


async def test_the_gate_fails_closed_without_sample_apps(gate_env: Env, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(updaters, "find_regression_apps", lambda settings: None)
    outcome = await semgrep_gate(tmp_path / "candidate")
    assert not outcome.passed and "sample apps were not found" in outcome.detail["reason"]
    empty = tmp_path / "empty-apps"
    empty.mkdir()
    monkeypatch.setattr(updaters, "find_regression_apps", lambda settings: empty)
    assert "no sample app has" in (await semgrep_gate(tmp_path / "candidate")).detail["reason"]


async def test_nuclei_templates_are_checked_structurally(env: Env, tmp_path: Path) -> None:
    module = updaters

    candidate = tmp_path / "templates"
    for index in range(250):
        put_file(candidate, f"t{index}.yaml", b"id: x")
    env.script["nuclei-templates-validate"] = lambda call: result(0, "All templates validated successfully")
    passed = await module._regression_nuclei(Settings(), candidate)  # type: ignore[attr-defined]
    assert passed.passed and passed.detail["templates"] == 250
    call = env.containers[0]
    assert call["network"] == "none" and call["binds"] == [(str(candidate), "/templates", True)]
    env.script["nuclei-templates-validate"] = lambda call: result(1, "[ERR] could not parse template")
    failed = await module._regression_nuclei(Settings(), candidate)  # type: ignore[attr-defined]
    assert not failed.passed and "could not parse" in failed.detail["output"]
    few = tmp_path / "few"
    put_file(few, "a.yaml")
    assert not (await module._regression_nuclei(Settings(), few)).passed  # type: ignore[attr-defined]


async def test_run_regression_returns_a_bool(env: Env) -> None:
    assert await updaters.run_regression("semgrep") is True
    env.gate = RegressionOutcome(False, "failed", {})
    assert await updaters.run_regression("nuclei") is False
    assert [kind for kind, _ in env.regression] == ["semgrep", "nuclei"]


async def test_the_real_gate_rejects_unknown_kinds_and_fails_closed_on_errors(monkeypatch: pytest.MonkeyPatch, catalogue_env: None) -> None:
    with pytest.raises(ValueError):
        await ORIGINAL_DETAILED("nothing")

    async def broken(_settings: Any, _candidate: Path) -> RegressionOutcome:
        raise RuntimeError("docker is gone")

    monkeypatch.setattr(updaters, "_regression_semgrep", broken)
    outcome = await ORIGINAL_DETAILED("semgrep", Path("."))
    assert not outcome.passed and outcome.result == "failed" and "RuntimeError" in outcome.detail["reason"]


# =============================================================================================== wiring
async def test_update_feed_dispatches_and_never_raises(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(settings: Any = None) -> UpdateOutcome:
        raise RuntimeError("disk full")

    monkeypatch.setitem(updaters.UPDATERS, ContentFeed.GRYPE_DB.value, boom)
    outcome = await updaters.update_feed(ContentFeed.GRYPE_DB)
    assert not outcome.ok and "crashed" in outcome.message and "disk full" not in outcome.message
    assert scanner_health._failed[ContentFeed.GRYPE_DB.value] is True
    with pytest.raises(ValueError):
        await updaters.update_feed("nope")


def test_the_periodic_hooks_and_the_task_are_registered() -> None:
    from securescan.jobs.app import app
    from securescan.jobs.hooks import has_periodic_hook

    for name in ("grype_db_update", "rules_and_templates_update"):
        assert has_periodic_hook(name), name
    assert "content_update" in app.tasks


async def test_the_weekly_hook_runs_rules_then_templates_even_when_the_first_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []

    async def fake_update(feed: Any) -> UpdateOutcome:
        order.append(feed_name := scanner_health.feed_value(feed))
        return UpdateOutcome(feed_name, feed_name != "semgrep_rules")

    monkeypatch.setattr(updaters, "update_feed", fake_update)
    await updaters.rules_and_templates_hook(0)
    assert order == ["semgrep_rules", "nuclei_templates"]


async def test_the_bootstrap_queues_the_first_update_of_every_empty_feed(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    queued: list[tuple[str, dict[str, Any]]] = []

    async def defer(task: Any, *, queueing_lock: str | None = None, **kwargs: Any) -> int:
        queued.append((queueing_lock or "", kwargs))
        return 1

    monkeypatch.setattr(updaters, "defer", defer)
    env.active[ContentFeed.GRYPE_DB.value] = types.SimpleNamespace(version="v6-x", built_at=None, fetched_at=None)
    await updaters.bootstrap_content()
    assert sorted(q[0] for q in queued) == ["content_update:nuclei_templates", "content_update:semgrep_rules"]
    assert {q[1]["feed"] for q in queued} == {"nuclei_templates", "semgrep_rules"}, "grype has a version"


async def test_the_bootstrap_can_be_switched_off_and_never_blocks_start_up(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    async def defer(*_a: Any, **_k: Any) -> int:
        raise RuntimeError("queue is down")

    monkeypatch.setattr(updaters, "defer", defer)
    await updaters.bootstrap_content()  # logs, does not raise
    monkeypatch.setenv("SECURESCAN_CONTENT_BOOTSTRAP", "false")
    get_settings.cache_clear()
    await updaters.bootstrap_content()
