"""Profile YAML validation, tool settings files and the seeding used by ``migrate``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from securescan.db.models.profiles import ScanProfile
from securescan.runner.catalogue import clear_catalogue_cache
from securescan.runner.profiles import (
    ProfileError,
    load_tool_settings,
    parse_profile_yaml,
    profile_body,
    profile_sha256,
    seed_profiles,
    string_list,
    validate_profile_yaml,
)
from tests.unit.conftest import FakeSession
from tests.unit.runner_helpers import REPO_SCANNERS

MINIMAL = """
profile: my-profile
kind: sast
jobs:
  - tool: semgrep
"""


def doc(**changes: Any) -> str:
    base: dict[str, Any] = {"profile": "my-profile", "kind": "sast", "jobs": [{"tool": "semgrep"}]}
    base.update(changes)
    return yaml.safe_dump(base)


@pytest.fixture
def catalogue_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from securescan.config import get_settings

    monkeypatch.setenv("SECURESCAN_SCANNERS_DIR", str(REPO_SCANNERS))
    get_settings.cache_clear()
    clear_catalogue_cache()


# --------------------------------------------------------------------------- the shipped profile
def test_code_standard_profile_is_valid() -> None:
    text = (REPO_SCANNERS / "profiles" / "code-standard.yaml").read_text(encoding="utf-8")
    parsed = parse_profile_yaml(text)
    assert parsed.profile == "code-standard" and parsed.version == 3 and parsed.kind == "sast"
    # version 1 was Semgrep and Gitleaks only; version 2 added the M8 tools; version 3 drops SonarQube and
    # Dependency-Check for the 4 vCPU / 8 GB sizing (see test_m8_catalogue.py)
    assert parsed.tools == ["semgrep", "gitleaks", "syft-grype", "spotbugs"]
    semgrep = parsed.job("semgrep")
    assert semgrep is not None and semgrep.job_options() == {
        "timeout_minutes": 60,
        "limits": {"cpus": 2.0, "memory": "2560m"},
    }
    assert parsed.verdict is not None and parsed.verdict.fail_on == {"critical": 1, "high": 5}
    assert parsed.job("nope") is None


def test_shipped_profile_passes_the_catalogue_check(catalogue_env: None) -> None:
    text = (REPO_SCANNERS / "profiles" / "code-standard.yaml").read_text(encoding="utf-8")
    assert validate_profile_yaml(text).tools[:2] == ["semgrep", "gitleaks"]


# --------------------------------------------------------------------------- structure
def test_minimal_profile() -> None:
    parsed = parse_profile_yaml(MINIMAL)
    assert parsed.version is None and parsed.mode is None and parsed.verdict is None
    assert parsed.job("semgrep").job_options() == {}  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("- just\n- a list\n", "mapping"),
        ("profile: [unclosed", "YAML"),
        (doc(profile="Bad Name"), "profile"),
        (doc(profile="x"), "profile"),
        (doc(kind="both"), "kind"),
        (doc(jobs=[]), "jobs"),
        (doc(jobs=[{"tool": "semgrep"}, {"tool": "semgrep"}]), "once"),
        (doc(jobs=[{"tool": "Semgrep!"}]), "tool"),
        (doc(kind="dast"), "mode"),
        (doc(mode="baseline"), "mode"),
        (doc(kind="dast", mode="stealth"), "mode"),
        (doc(unknown_key=1), "unknown_key"),
        (doc(jobs=[{"tool": "semgrep", "extra": 1}]), "extra"),
        (doc(jobs=[{"tool": "semgrep", "timeout_min": 0}]), "timeout_min"),
        (doc(jobs=[{"tool": "semgrep", "timeout_min": 100000}]), "timeout_min"),
        (doc(jobs=[{"tool": "semgrep", "limits": {"cpus": 99}}]), "cpus"),
        (doc(jobs=[{"tool": "semgrep", "limits": {"cpus": 0}}]), "cpus"),
        (doc(jobs=[{"tool": "semgrep", "limits": {"memory": "64g"}}]), "memory"),
        (doc(jobs=[{"tool": "semgrep", "limits": {"memory": "lots"}}]), "memory"),
        (doc(jobs=[{"tool": "semgrep", "limits": {"pids": 5}}]), "pids"),
        (doc(jobs=[{"tool": "semgrep", "options": {"bad key!": 1}}]), "option"),
        (doc(verdict={"fail_on": {"urgent": 1}}), "severity"),
        (doc(verdict={"fail_on": {"high": -1}}), "negative"),
        (doc(version=0), "version"),
    ],
)
def test_invalid_profiles_are_refused_with_a_reason(text: str, needle: str) -> None:
    with pytest.raises(ProfileError) as caught:
        parse_profile_yaml(text)
    assert needle.lower() in " ".join(caught.value.errors + [str(caught.value)]).lower()
    assert caught.value.errors


def test_dast_profile_with_a_mode() -> None:
    parsed = parse_profile_yaml(doc(profile="zap-baseline", kind="dast", mode="baseline", jobs=[{"tool": "zap"}]))
    assert parsed.kind == "dast" and parsed.mode == "baseline"


def test_job_overrides_become_the_job_options() -> None:
    parsed = parse_profile_yaml(
        doc(jobs=[{"tool": "semgrep", "timeout_min": 30, "limits": {"memory": "2g"}, "options": {"exclude": ["x"]}}])
    )
    assert parsed.job("semgrep").job_options() == {  # type: ignore[union-attr]
        "exclude": ["x"],
        "timeout_minutes": 30,
        "limits": {"memory": "2g"},
    }


def test_stored_body_round_trips_through_the_model() -> None:
    parsed = parse_profile_yaml(doc(version=3, description="d", verdict={"fail_on": {"high": 2}}))
    body = profile_body(parsed, 3)
    assert body["version"] == 3 and body["profile"] == "my-profile" and "mode" not in body
    from securescan.runner.profiles import ProfileDoc

    assert ProfileDoc.model_validate(body).tools == ["semgrep"]
    assert len(profile_sha256("x")) == 64


# --------------------------------------------------------------------------- against the catalogue
def test_unknown_tools_are_refused_when_a_catalogue_exists(catalogue_env: None) -> None:
    with pytest.raises(ProfileError) as caught:
        validate_profile_yaml(doc(jobs=[{"tool": "semgrep"}, {"tool": "codeql"}]))
    assert "codeql" in str(caught.value) and "catalogue" in str(caught.value)
    validate_profile_yaml(doc(jobs=[{"tool": "gitleaks"}]))


def test_structure_only_check_does_not_need_the_catalogue(catalogue_env: None) -> None:
    validate_profile_yaml(doc(jobs=[{"tool": "codeql"}]), check_catalogue=False)


# --------------------------------------------------------------------------- tool settings
def test_semgrep_settings_file() -> None:
    settings = load_tool_settings("semgrep", REPO_SCANNERS)
    assert settings["tool"] == "semgrep" and "*.map" in settings["exclude"]
    assert load_tool_settings("gitleaks", REPO_SCANNERS) == {}  # no such file
    assert load_tool_settings("semgrep", Path("/nonexistent/scanners")) == {}


def test_a_scan_profile_is_not_a_tool_settings_file(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "semgrep.yaml").write_text(MINIMAL, encoding="utf-8")  # has `profile:` but no `tool:`
    assert load_tool_settings("semgrep", tmp_path) == {}
    (profiles / "broken.yaml").write_text("tool: [", encoding="utf-8")
    with pytest.raises(ProfileError):
        load_tool_settings("broken", tmp_path)


def test_string_list() -> None:
    assert string_list(None, "x") == []
    assert string_list([" a ", "b"], "x") == ["a", "b"]
    for bad in ("text", [1], [""], ["ok", None]):
        with pytest.raises(ProfileError):
            string_list(bad, "x")


# --------------------------------------------------------------------------- seeding
async def test_seeding_inserts_scan_profiles_and_skips_tool_settings() -> None:
    session = FakeSession()
    inserted = await seed_profiles(session, REPO_SCANNERS)  # type: ignore[arg-type]
    assert inserted == ["code-standard@3", "dast-api@2", "dast-baseline@2", "dast-full@2"]
    rows = [r for r in session.added if isinstance(r, ScanProfile)]
    assert len(rows) == 4
    row = next(r for r in rows if r.name == "code-standard")
    assert (row.name, row.version, row.kind, row.active) == ("code-standard", 3, "sast", True)
    text = (REPO_SCANNERS / "profiles" / "code-standard.yaml").read_text(encoding="utf-8")
    assert row.body_yaml == text and row.sha256 == profile_sha256(text)
    assert row.body["jobs"][0]["tool"] == "semgrep" and row.body["version"] == 3


async def test_seeding_is_idempotent_and_never_overwrites() -> None:
    text = (REPO_SCANNERS / "profiles" / "code-standard.yaml").read_text(encoding="utf-8")
    same = ScanProfile(name="code-standard", version=3, sha256=profile_sha256(text))
    assert await seed_profiles(FakeSession(rows=[same]), REPO_SCANNERS) == []  # type: ignore[arg-type]
    edited = ScanProfile(name="code-standard", version=3, sha256="0" * 64)  # an Admin or an older file
    session = FakeSession(rows=[edited])
    assert await seed_profiles(session, REPO_SCANNERS) == []  # type: ignore[arg-type]
    assert edited.sha256 == "0" * 64 and session.added == []


async def test_seeding_ignores_invalid_files(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "bad.yaml").write_text("profile: Bad Name\nkind: sast\njobs: []\n", encoding="utf-8")
    (profiles / "garbage.yaml").write_text(": : :", encoding="utf-8")
    (profiles / "good.yaml").write_text(MINIMAL, encoding="utf-8")
    session = FakeSession()
    assert await seed_profiles(session, tmp_path) == ["my-profile@1"]  # type: ignore[arg-type]
    assert await seed_profiles(FakeSession(), tmp_path / "missing") == []  # type: ignore[arg-type]
