"""The regression suite: expectation files, matching, evaluation, the run with a fake runner."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml

from securescan.config import get_settings
from securescan.domain.regression import (
    DEFAULT_SUITE,
    AppRun,
    AppSource,
    CandidateImage,
    ExpectedFinding,
    JobOutcome,
    ObservedFinding,
    RegressionConfigError,
    RegressionReport,
    ToolResult,
    canonical_tool,
    compare_title_sets,
    digest_matches,
    evaluate_tool,
    file_matches,
    keyword_score,
    keywords,
    load_expectation_file,
    load_expectations,
    load_suite,
    match_expectation,
    run_regression,
    scan_options_with_candidates,
    zip_directory,
)
from securescan.util import utcnow
from tests.unit.runner_helpers import REPO_SCANNERS, SAMPLE_APPS

D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64


def finding(title: str, tool: str = "semgrep", **changes: Any) -> ObservedFinding:
    return ObservedFinding(tool=tool, title=title, **changes)


def entry(**changes: Any) -> ExpectedFinding:
    values: dict[str, Any] = {"id": "e1", "expect_category": "", "verified": True}
    values.update(changes)
    return ExpectedFinding(**values)


# --------------------------------------------------------------------------- the real expectation files
@pytest.mark.parametrize("app", ["java-planted", "js-planted", "python-planted", "csharp-planted"])
def test_the_planted_apps_have_valid_expectations(app: str) -> None:
    loaded = load_expectation_file(SAMPLE_APPS / app / "expected-findings.yaml")
    assert loaded.app == app and loaded.tools
    assert all(not e.verified for entries in loaded.tools.values() for e in entries)  # nothing verified before a real run


@pytest.mark.parametrize("name", ["juice-shop", "webgoat"])
def test_the_external_apps_have_valid_expectations(name: str) -> None:
    loaded = load_expectation_file(REPO_SCANNERS / "regression" / ("%s.yaml" % name))
    assert loaded.app == name and loaded.tools["semgrep"]


def test_the_suite_file_matches_the_built_in_default() -> None:
    suite = load_suite(REPO_SCANNERS / "regression")
    assert suite.profile == "code-standard"
    assert set(suite.kinds) == set(DEFAULT_SUITE.kinds)
    for name, config in DEFAULT_SUITE.kinds.items():
        assert suite.kinds[name].apps == config.apps and suite.kinds[name].tools == config.tools


def test_the_broken_rule_files_exist_for_the_drill() -> None:
    folder = REPO_SCANNERS / "regression" / "broken-rules"
    never = yaml.safe_load((folder / "never-matches.yaml").read_text(encoding="utf-8"))
    assert never["rules"][0]["id"].startswith("securescan-regression")
    with pytest.raises(yaml.YAMLError):  # invalid on purpose
        yaml.safe_load((folder / "invalid-rule.yaml").read_text(encoding="utf-8"))


def test_unsuitable_expectation_files_are_refused(tmp_path: Path) -> None:
    duplicate = tmp_path / "a.yaml"
    duplicate.write_text("app: x\ntools:\n  semgrep:\n    - {id: a}\n    - {id: a}\n", encoding="utf-8")
    with pytest.raises(RegressionConfigError, match="duplicate id"):
        load_expectation_file(duplicate)
    future = tmp_path / "b.yaml"
    future.write_text("app: x\nschema_version: 2\ntools: {}\n", encoding="utf-8")
    with pytest.raises(RegressionConfigError, match="schema_version"):
        load_expectation_file(future)
    broken = tmp_path / "c.yaml"
    broken.write_text("app: [unclosed", encoding="utf-8")
    with pytest.raises(RegressionConfigError):
        load_expectation_file(broken)
    with pytest.raises(RegressionConfigError):
        load_expectation_file(tmp_path / "missing.yaml")


def test_load_expectations_reads_the_fixture_directory_first_then_the_regression_directory(tmp_path: Path) -> None:
    fixtures, regression = tmp_path / "fixtures", tmp_path / "regression"
    (fixtures / "app-a").mkdir(parents=True)
    regression.mkdir()
    (fixtures / "app-a" / "expected-findings.yaml").write_text("app: app-a\ntools: {semgrep: []}\n", encoding="utf-8")
    (regression / "app-b.yaml").write_text("app: app-b\ntools: {semgrep: []}\n", encoding="utf-8")
    found = load_expectations(["app-a", "app-b", "app-c"], fixtures, regression)
    assert sorted(found) == ["app-a", "app-b"]


# --------------------------------------------------------------------------- matching
def test_keywords_drop_stop_words_and_duplicates() -> None:
    assert keywords("SQL injection: query built by string concatenation with request input") == [
        "sql", "injection", "query", "concatenation",
    ]  # fmt: skip
    assert keywords("known vulnerabilities in flask 0.12") == ["flask"]


def test_keyword_score_uses_word_prefixes() -> None:
    f = finding("python.flask.security.injection.tainted-sql-string.tainted-sql-string")
    assert keyword_score("SQL injection with concatenation", f) == pytest.approx(2 / 3)
    assert keyword_score("SQL injection", finding("some.injected.rule")) == pytest.approx(0.5)


def test_file_matches_compares_suffixes_and_names() -> None:
    assert file_matches("src/main/java/UserServlet.java", "/src/main/java/UserServlet.java")
    assert file_matches("app.py", "sub/app.py")
    assert file_matches("a/b/App.py", "app.py")
    assert not file_matches("app.py", "other.py")
    assert not file_matches(None, "app.py") and not file_matches("app.py", None)


def test_match_by_rule_id_is_exact_substring_of_the_title() -> None:
    e = entry(rule_id="subprocess-shell-true")
    hit = match_expectation(e, [finding("x"), finding("python.lang.security.audit.subprocess-shell-true.subprocess-shell-true")])
    assert hit is not None and hit.how == "rule_id"
    assert match_expectation(entry(rule_id="nothing"), [finding("python.x")]) is None
    # a rule id is a whole dotted part, not any substring of the title
    assert match_expectation(entry(rule_id="sql-string"), [finding("java.sqli.tainted-sql-string")]) is None
    assert match_expectation(entry(rule_id="tainted-sql-string"), [finding("java.sqli.tainted-sql-string")]) is not None


def test_match_by_vulnerability_id_or_a_cve_in_the_category() -> None:
    log4shell = finding("CVE-2021-44228 in log4j-core:2.14.1", tool="grype", cve="CVE-2021-44228")
    assert match_expectation(entry(vulnerability_id="CVE-2021-44228"), [log4shell]).how == "vulnerability_id"  # type: ignore[union-attr]
    named = entry(expect_category="known vulnerability: log4j-core 2.14.1 (Log4Shell, CVE-2021-44228)")
    assert match_expectation(named, [log4shell]) is not None
    assert match_expectation(named, [finding("CVE-2020-1 in flask", cve="CVE-2020-1")]) is None


def test_match_by_keywords_needs_most_words_or_the_expected_file() -> None:
    e = entry(expect_category="command injection: subprocess with shell=True", file="app.py")
    assert match_expectation(e, [finding("subprocess shell true injection command")]) is not None
    weak = finding("subprocess shell audit", file_path="src/app.py")  # 2 of 5 words: enough only inside the expected file
    assert match_expectation(e, [weak]) is not None and match_expectation(e, [weak]).how == "keywords+file"  # type: ignore[union-attr]
    assert match_expectation(e, [finding("subprocess shell audit", file_path="src/other.py")]) is None
    assert match_expectation(entry(expect_category="the and with"), [finding("anything")]) is None


# --------------------------------------------------------------------------- evaluating
def test_a_verified_entry_that_matches_passes() -> None:
    result = evaluate_tool("app", "semgrep", [entry(rule_id="sqli")], [finding("x.sqli.y")], job_state="completed")
    assert result.status == "passed" and result.entries[0].status == "matched" and result.missing == []


def test_a_verified_entry_that_disappeared_fails() -> None:
    result = evaluate_tool("app", "semgrep", [entry(id="gone", rule_id="sqli"), entry(id="here", rule_id="xss")],
                           [finding("a.xss.b")], job_state="completed")  # fmt: skip
    assert result.status == "failed" and result.missing == ["gone"] and "gone" in (result.reason or "")


def test_a_broken_rule_set_fails_the_suite() -> None:
    # the acceptance check: a rule file that stops matching makes the verified expectations disappear
    result = evaluate_tool("app", "semgrep", [entry(rule_id="sqli")], [], job_state="completed")
    assert result.status == "failed"


def test_unverified_entries_never_fail_and_the_tool_is_unasserted() -> None:
    unverified = entry(verified=False, rule_id="sqli")
    seen = evaluate_tool("app", "semgrep", [unverified], [finding("x.sqli.y")], job_state="completed")
    assert seen.status == "unasserted" and seen.newly_seen == ["e1"]
    not_seen = evaluate_tool("app", "semgrep", [unverified], [], job_state="completed")
    assert not_seen.status == "unasserted" and not_seen.newly_seen == [] and not_seen.entries[0].status == "not_seen"


def test_a_failed_job_is_an_error_whatever_the_expectations_say() -> None:
    for state in ("failed", "timed_out", "cancelled"):
        result = evaluate_tool("app", "semgrep", [], [], job_state=state, job_reason="boom")
        assert result.status == "error" and "boom" in (result.reason or "")


def test_a_tool_without_a_job_is_skipped() -> None:
    assert evaluate_tool("app", "spotbugs", [], [], job_state=None).status == "skipped"


def test_unexpected_titles_and_baseline_differences_are_reported() -> None:
    observed = [finding("covered.sqli"), finding("new.rule")]
    result = evaluate_tool("app", "semgrep", [entry(rule_id="sqli")], observed, job_state="completed",
                           baseline_titles=["covered.sqli", "old.rule"])  # fmt: skip
    assert result.unexpected_titles == ["new.rule"]
    assert result.removed_vs_baseline == ["old.rule"] and result.status == "passed"


def test_compare_title_sets() -> None:
    assert compare_title_sets(["a", "b"], ["b", "c"]) == (["a"], ["c"])


def test_aliases_map_the_syft_grype_job_to_the_grype_key() -> None:
    assert canonical_tool("syft-grype") == "grype" and canonical_tool("semgrep") == "semgrep"


def report_of(*statuses: str) -> RegressionReport:
    report = RegressionReport(kind="image", started_at=utcnow())
    for index, status in enumerate(statuses):
        report.results.append(ToolResult(app="a", tool="t%d" % index, status=status))
    return report


def test_report_outcome_rules() -> None:
    assert report_of("passed", "unasserted").outcome == "passed"
    assert report_of("passed", "failed").outcome == "failed"
    assert report_of("passed", "error").outcome == "failed"
    assert report_of("unasserted", "skipped").outcome == "unasserted"
    assert report_of().outcome == "unasserted"
    assert report_of("passed").passed and report_of("failed").failed


def test_report_detail_is_json_friendly_and_lists_the_lines() -> None:
    report = report_of("failed", "unasserted")
    report.results[0].reason = "missing: x"
    detail = report.to_detail()
    assert detail["outcome"] == "failed" and detail["results"][0]["status"] == "failed"
    assert any("failed" in line for line in report.summary_lines())
    assert "NOTHING WAS ASSERTED" in "\n".join(report_of("unasserted").summary_lines())


# --------------------------------------------------------------------------- candidates and options
def test_scan_options_attach_the_candidate_to_the_job_tool_that_exercises_it() -> None:
    candidate = CandidateImage("syft-grype", "row-1", "tok", D2)
    options = scan_options_with_candidates({"ref": "main", "tool_options": {"semgrep": {"exclude": ["x"]}}}, {"syft-grype": candidate})
    assert options["ref"] == "main"
    assert options["tool_options"]["semgrep"] == {"exclude": ["x"]}
    assert options["tool_options"]["syft-grype"] == {"image_candidates": {"syft-grype": {"id": "row-1", "token": "tok"}}}
    assert scan_options_with_candidates(None, None) == {}


def test_digest_matches_accepts_both_forms() -> None:
    assert digest_matches("repo/name@" + D1, D1) and digest_matches(D1, "repo/name@" + D1)
    assert not digest_matches(D2, D1) and not digest_matches(None, D1)


# --------------------------------------------------------------------------- the run, with a fake runner
class FakeRunner:
    def __init__(self, jobs: Mapping[str, JobOutcome] | None = None, error: str | None = None) -> None:
        self.jobs = dict(jobs or {})
        self.error = error
        self.calls: list[dict[str, Any]] = []

    async def run_app(
        self, source: AppSource, job_tools: Sequence[str], *, profile: str, options: Mapping[str, Any], wait_seconds: float
    ) -> AppRun:
        self.calls.append({"app": source.app, "tools": list(job_tools), "profile": profile, "options": dict(options)})
        return AppRun(app=source.app, scan_id="s1", jobs=dict(self.jobs), error=self.error)


def make_fixtures(tmp_path: Path, verified: bool = True) -> Path:
    fixtures = tmp_path / "sample-apps"
    app = fixtures / "java-planted"
    app.mkdir(parents=True)
    (app / "App.java").write_text("class App {}", encoding="utf-8")
    (app / "expected-findings.yaml").write_text(
        yaml.safe_dump(
            {"app": "java-planted", "tools": {
                "semgrep": [{"id": "sqli", "rule_id": "sqli", "verified": verified}],
                "grype": [{"id": "log4shell", "vulnerability_id": "CVE-2021-44228", "verified": verified}],
            }}
        ),
        encoding="utf-8",
    )  # fmt: skip
    return fixtures


async def run_with(runner: FakeRunner, tmp_path: Path, **kwargs: Any) -> RegressionReport:
    fixtures = make_fixtures(tmp_path, kwargs.pop("verified", True))
    return await run_regression(
        kwargs.pop("kind", "image"), runner=runner, fixtures_dir=fixtures, regression_dir=tmp_path / "none",
        settings=get_settings(), apps=["java-planted"], **kwargs,
    )  # fmt: skip


async def test_run_passes_when_every_verified_expectation_is_reported(tmp_path: Path) -> None:
    runner = FakeRunner({
        "semgrep": JobOutcome("semgrep", "completed", findings=[finding("a.sqli.b")]),
        "syft-grype": JobOutcome("syft-grype", "completed", findings=[finding("CVE-2021-44228 in log4j-core", tool="syft-grype", cve="CVE-2021-44228")]),
    })  # fmt: skip
    report = await run_with(runner, tmp_path, tools=["semgrep", "grype"])
    assert report.outcome == "passed", report.summary_lines()
    assert runner.calls[0]["tools"] == ["semgrep", "syft-grype"]  # the grype key runs the syft-grype job
    assert runner.calls[0]["profile"] == "code-standard"


async def test_run_fails_when_a_tool_lost_a_finding(tmp_path: Path) -> None:
    runner = FakeRunner({"semgrep": JobOutcome("semgrep", "completed", findings=[])})
    report = await run_with(runner, tmp_path, tools=["semgrep"])
    assert report.outcome == "failed" and report.results[0].missing == ["sqli"]


async def test_run_is_unasserted_while_nothing_is_verified(tmp_path: Path) -> None:
    runner = FakeRunner({"semgrep": JobOutcome("semgrep", "completed", findings=[finding("a.sqli.b")])})
    report = await run_with(runner, tmp_path, tools=["semgrep"], verified=False)
    assert report.outcome == "unasserted" and report.results[0].newly_seen == ["sqli"]


async def test_run_reports_a_scan_that_could_not_run(tmp_path: Path) -> None:
    report = await run_with(FakeRunner(error="the scan did not finish within 120 minutes"), tmp_path, tools=["semgrep"])
    assert report.outcome == "failed" and report.results[0].status == "error"
    assert "did not finish" in (report.results[0].reason or "")


async def test_run_checks_that_the_candidate_image_really_ran(tmp_path: Path) -> None:
    candidate = {"semgrep": CandidateImage("semgrep", "row-1", "tok", D2)}
    ran_other = FakeRunner({"semgrep": JobOutcome("semgrep", "completed", image_digest=D1, findings=[finding("a.sqli.b")])})
    report = await run_with(ran_other, tmp_path, tools=["semgrep"], candidates=candidate)
    assert report.results[0].status == "error" and "candidate image was not the one that ran" in (report.results[0].reason or "")
    assert ran_other.calls[0]["options"]["tool_options"]["semgrep"]["image_candidates"]["semgrep"]["token"] == "tok"
    ran_it = FakeRunner({"semgrep": JobOutcome("semgrep", "completed", image_digest="semgrep/semgrep@" + D2, findings=[finding("a.sqli.b")])})
    assert (await run_with(ran_it, tmp_path, tools=["semgrep"], candidates=candidate)).outcome == "passed"


async def test_run_skips_missing_applications_with_a_note(tmp_path: Path) -> None:
    fixtures = make_fixtures(tmp_path)
    report = await run_regression("external", runner=FakeRunner(), fixtures_dir=fixtures, regression_dir=tmp_path / "none", settings=get_settings())
    assert report.results == [] and any("juice-shop" in n for n in report.notes)
    assert report.outcome == "unasserted"


async def test_run_rejects_an_unknown_kind(tmp_path: Path) -> None:
    with pytest.raises(RegressionConfigError, match="unknown regression kind"):
        await run_regression("nope", runner=FakeRunner(), fixtures_dir=make_fixtures(tmp_path), regression_dir=tmp_path / "none", settings=get_settings())


async def test_the_dast_kind_is_skipped_without_a_target_url(tmp_path: Path) -> None:
    report = await run_regression("dast", runner=FakeRunner(), fixtures_dir=make_fixtures(tmp_path), regression_dir=tmp_path / "none", settings=get_settings())
    assert report.results == [] and any("DAST regression skipped" in n for n in report.notes)


async def test_baseline_titles_flow_into_the_results(tmp_path: Path) -> None:
    runner = FakeRunner({"semgrep": JobOutcome("semgrep", "completed", findings=[finding("a.sqli.b")])})
    report = await run_with(runner, tmp_path, tools=["semgrep"], baseline_titles={"java-planted/semgrep": ["a.sqli.b", "old.title"]})
    assert report.results[0].removed_vs_baseline == ["old.title"]
    assert report.titles_by_tool() == {"java-planted/semgrep": ["a.sqli.b"]}


# --------------------------------------------------------------------------- the zip of a planted app
def test_zip_directory_is_deterministic_and_leaves_the_expectations_out(tmp_path: Path) -> None:
    app = tmp_path / "app"
    (app / "src").mkdir(parents=True)
    (app / "src" / "a.py").write_text("print(1)", encoding="utf-8")
    (app / "b.txt").write_text("b", encoding="utf-8")
    (app / "expected-findings.yaml").write_text("app: x", encoding="utf-8")
    (app / "__pycache__").mkdir()
    (app / "__pycache__" / "x.pyc").write_bytes(b"x")
    first, second = zip_directory(app), zip_directory(app)
    assert first == second
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        assert archive.namelist() == ["b.txt", "src/a.py"]


def test_zip_directory_of_the_real_planted_apps_is_not_empty() -> None:
    for app in ("python-planted", "js-planted"):
        with zipfile.ZipFile(io.BytesIO(zip_directory(SAMPLE_APPS / app))) as archive:
            assert archive.namelist() and "expected-findings.yaml" not in archive.namelist()
