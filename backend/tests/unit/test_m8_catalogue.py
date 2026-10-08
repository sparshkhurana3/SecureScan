"""The M8 catalogue entries, the extended code-standard profile and the registered builders."""

from __future__ import annotations

import pytest
import yaml

from securescan.runner.catalogue import clear_catalogue_cache
from securescan.runner.profiles import parse_profile_yaml, validate_profile_yaml
from securescan.runner.tools import get_builder, registered_tools
from tests.unit.runner_helpers import REPO_SCANNERS, real_catalogue

JOB_TOOLS = ("semgrep", "gitleaks", "syft-grype", "dependency-check", "spotbugs", "sonarqube")
HELPER_TOOLS = (
    "syft",
    "grype-db-update",
    "grype-db-status",
    "odc-update",
    "sonarqube-server",
    "skopeo",
    "nuclei-templates-update",
    "nuclei-templates-validate",
)
SECRET_WORDS = ("token", "password", "secret", "api_key", "apikey", "nvd")


@pytest.fixture
def catalogue_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.config import get_settings

    monkeypatch.setenv("SECURESCAN_SCANNERS_DIR", str(REPO_SCANNERS))
    get_settings.cache_clear()
    clear_catalogue_cache()


def test_every_m8_entry_is_in_the_catalogue_and_valid() -> None:
    catalogue = real_catalogue()  # raises when any entry of catalogue.d is invalid or duplicated
    for tool in (*JOB_TOOLS, *HELPER_TOOLS):
        assert tool in catalogue, tool


def test_concurrency_caps_follow_the_plan() -> None:
    catalogue = real_catalogue()
    assert catalogue["sonarqube"].max_parallel == 1
    assert catalogue["spotbugs"].max_parallel == 1
    assert catalogue["dependency-check"].max_parallel == 1
    assert catalogue["semgrep"].max_parallel == 2
    assert catalogue["odc-update"].max_parallel == 1 and catalogue["grype-db-update"].max_parallel == 1


def test_no_catalogue_entry_carries_a_secret_or_an_unpinned_image() -> None:
    for tool, entry in real_catalogue().items():
        for key, value in entry.env.items():
            lowered = key.lower()
            assert not any(word in lowered for word in SECRET_WORDS), (tool, key)
            assert "token" not in str(value).lower() or key == "SONAR_USER_HOME", (tool, key)
        assert entry.image.tag is None or entry.image.tag.lower() != "latest", tool
        assert entry.image.lock, f"{tool}: images are resolved through their lock name"
        assert all(not part.startswith("--password") for part in entry.command), tool


def test_scan_containers_have_the_network_the_plan_gives_them() -> None:
    catalogue = real_catalogue()
    for tool in ("semgrep", "gitleaks", "syft-grype", "spotbugs", "syft", "grype-db-status", "nuclei-templates-validate"):
        assert catalogue[tool].network == "none", tool
    assert catalogue["sonarqube"].network == "sonarqube"
    assert catalogue["sonarqube-server"].network == "sonarqube"
    # Dependency-Check, the updaters and the image intake start with no network; the builders add the egress network.
    assert catalogue["dependency-check"].network == "none"


def test_defectdojo_scan_types_and_files() -> None:
    catalogue = real_catalogue()
    expected = {
        "syft-grype": ("Anchore Grype", "grype.json"),
        "dependency-check": ("Dependency Check Scan", "dependency-check-report.xml"),
        "spotbugs": ("SpotBugs Scan", "spotbugs.xml"),
        "sonarqube": ("SonarQube Scan", "sonarqube-issues.zip"),
    }
    for tool, (scan_type, filename) in expected.items():
        assert (catalogue[tool].defectdojo_scan_type, catalogue[tool].defectdojo_file) == (scan_type, filename)
    for tool in ("syft", "skopeo", "odc-update", "grype-db-update"):
        assert catalogue[tool].defectdojo_scan_type is None, f"{tool} is not imported"


def test_helper_entries_are_not_job_tools() -> None:
    catalogue = real_catalogue()
    for tool in HELPER_TOOLS:
        assert catalogue[tool].target_kinds == [], tool
    for tool in JOB_TOOLS:
        assert catalogue[tool].target_kinds, tool


def test_the_sonarqube_issues_zip_is_produced_after_the_container() -> None:
    entry = real_catalogue()["sonarqube"]
    output = entry.output("sonarqube-issues.zip")
    assert output is not None and output.required is False and output.format == "none"


def test_exit_code_mappings() -> None:
    catalogue = real_catalogue()
    odc = catalogue["dependency-check"]
    assert [odc.outcome_for(code) for code in (0, 14, 1, 2, None)] == [
        "completed", "completed_partial", "failed", "failed", "failed",
    ]  # fmt: skip
    for tool in ("syft-grype", "spotbugs", "sonarqube"):
        assert [catalogue[tool].outcome_for(code) for code in (0, 1, 2, None)] == ["completed", "failed", "failed", "failed"], tool


def test_code_standard_profile_v2_lists_every_code_tool() -> None:
    text = (REPO_SCANNERS / "profiles" / "code-standard.yaml").read_text(encoding="utf-8")
    parsed = parse_profile_yaml(text)
    assert parsed.profile == "code-standard" and parsed.version == 2 and parsed.kind == "sast"
    assert parsed.tools == list(JOB_TOOLS)
    assert parsed.verdict is not None and parsed.verdict.fail_on == {"critical": 1, "high": 5}
    for tool in JOB_TOOLS:
        job = parsed.job(tool)
        assert job is not None and job.timeout_min and job.limits is not None, tool


def test_code_standard_profile_passes_the_catalogue_check(catalogue_env: None) -> None:
    text = (REPO_SCANNERS / "profiles" / "code-standard.yaml").read_text(encoding="utf-8")
    assert validate_profile_yaml(text).tools == list(JOB_TOOLS)


def test_builders_exist_for_every_job_tool() -> None:
    registered = set(registered_tools())
    assert set(JOB_TOOLS) <= registered
    for tool in ("syft-grype", "dependency-check", "spotbugs", "sonarqube"):
        assert get_builder(tool).tool == tool
    for helper in HELPER_TOOLS:
        assert helper not in registered, f"{helper} is not a job tool"


def test_dependency_check_settings_file_is_a_tool_settings_file_not_a_profile() -> None:
    data = yaml.safe_load((REPO_SCANNERS / "profiles" / "dependency-check.yaml").read_text(encoding="utf-8"))
    assert data["tool"] == "dependency-check" and "profile" not in data
    assert data["analyzers"]["ossindex"] is False and data["analyzers"]["npm_audit"] is False
    assert data["no_disclosure_for_application_types"] == ["vendor"]


def test_the_rules_lock_file_is_valid_yaml_with_the_agpl_filter() -> None:
    from pathlib import Path

    lock = yaml.safe_load((Path(REPO_SCANNERS).parent / "content" / "semgrep-rules.lock").read_text(encoding="utf-8"))
    assert lock["repository"].startswith("https://github.com/semgrep/")
    assert lock["commit"] == "" and lock["auto"] is True, "no commit may be invented"
    assert "agpl" in [x.lower() for x in lock["deny_licenses"]]
    assert lock["allowed_licenses"] == ["Semgrep Rules License v1.0"]
