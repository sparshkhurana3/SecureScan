"""Image updates: tag series, planning, storing, approving, the overlay."""

from __future__ import annotations

import types
import uuid
from pathlib import Path
from typing import Any

import pytest

from securescan.api.problems import Conflict, UnprocessableEntity
from securescan.db.models.images import ImageVersion
from securescan.domain.image_updates import (
    SCOPE_RELEASE,
    SCOPE_RUNTIME,
    Current,
    LockImage,
    Proposal,
    approve_image_version,
    check_approvable,
    current_for,
    deactivate_image_version,
    egress_hosts_for,
    load_lock_images,
    lock_yaml_line,
    newer_tags,
    parse_lock_file,
    parse_tag,
    plan_image,
    primary_tool_by_lock,
    public_detail,
    regression_job_for,
    reject_image_version,
    run_proposals,
    select_candidate,
    store_proposals,
    tool_for_lock,
)
from securescan.integrations.registry import ImageName, RegistryError
from securescan.runner.catalogue import (
    CatalogueEntry,
    image_override,
    resolve_image_with_override,
)
from securescan.util import utcnow
from tests.unit.conftest import FakeSession
from tests.unit.runner_helpers import DIGEST, REPO_SCANNERS, entry_dict

D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64


# --------------------------------------------------------------------------- tags
def test_parse_tag_understands_the_tags_of_the_lock_file() -> None:
    assert parse_tag("v8.30.1") is not None and parse_tag("v8.30.1").parts == ((8, 30, 1),)  # type: ignore[union-attr]
    assert parse_tag("1.179.0-nonroot").suffix == "-nonroot"  # type: ignore[union-attr]
    assert parse_tag("26.9.0.129388-community").parts == ((26, 9, 0, 129388),)  # type: ignore[union-attr]
    assert parse_tag("12.2.0.4256_8.1.0").parts == ((12, 2, 0, 4256), (8, 1, 0))  # type: ignore[union-attr]
    assert parse_tag("3.14-slim-trixie").parts == ((3, 14),)  # type: ignore[union-attr]
    for floating in ("latest", "stable", "stable-alpine", "sha-1234abc", ""):
        assert parse_tag(floating) is None


def test_newer_tags_stay_in_their_series_and_sort_newest_first() -> None:
    tags = ["v1.54.0", "v1.54.1", "v1.55.0", "v1.55.0-rc1", "v1.9.0", "1.99.0", "latest", "v1.55.0-alpine", "v1.55"]
    assert newer_tags("v1.54.0", tags) == ["v1.55.0", "v1.54.1"]
    assert newer_tags("v1.55.0", tags) == []
    assert newer_tags("latest", tags) == []


def test_newer_tags_can_keep_the_leading_components() -> None:
    tags = ["18.6", "18.7", "19.0", "17.9"]
    assert newer_tags("18.6", tags) == ["19.0", "18.7"]
    assert newer_tags("18.6", tags, keep_components=1) == ["18.7"]
    assert select_candidate("POSTGRES", "postgres", "18.6", tags) == "18.7"  # the major is locked by policy
    assert select_candidate("PYTHON", "python", "3.14-slim-trixie", ["3.15-slim-trixie", "3.14-slim-trixie"]) is None


def test_two_part_version_tags_compare_part_by_part() -> None:
    tags = ["12.2.0.4256_8.1.0", "12.3.0.4300_8.2.0", "12.3.0.4300_8.1.0", "12.2.0.4256"]
    assert newer_tags("12.2.0.4256_8.1.0", tags)[0] == "12.3.0.4300_8.2.0"


def test_select_candidate_offers_the_newest_tag_of_the_series() -> None:
    assert select_candidate("SYFT", "syft", "v1.0.0", ["v2.0.0", "v1.5.0", "latest"]) == "v2.0.0"
    assert select_candidate("SYFT", "syft", "v2.0.0", ["v1.5.0"]) is None
    assert select_candidate("POSTGRES", "postgres", "18.6", ["18.7", "19.0"]) == "18.7"  # majors need a runbook


# --------------------------------------------------------------------------- lock file
LOCK_TEXT = """
images:
  - { name: SEMGREP, image: semgrep/semgrep, tag: 1.179.0-nonroot, digest: sha256:%s }
  - { name: SQUID, image: ubuntu/squid, tag: latest, digest: null }
  - { name: BROKEN, image: x }
""" % ("a" * 64)


def test_parse_lock_file_skips_incomplete_items() -> None:
    images = parse_lock_file(LOCK_TEXT)
    assert [i.name for i in images] == ["SEMGREP", "SQUID"]
    assert images[0].digest == "sha256:" + "a" * 64 and images[1].digest is None


def test_load_lock_images_finds_the_file_next_to_the_scanners_directory(tmp_path: Path) -> None:
    (tmp_path / "scanners").mkdir()
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "images.lock.yaml").write_text(LOCK_TEXT, encoding="utf-8")
    assert len(load_lock_images(tmp_path / "scanners")) == 2
    assert load_lock_images(None) == []
    assert load_lock_images(tmp_path / "elsewhere") == []


def test_the_real_lock_file_parses_and_names_every_runtime_lock() -> None:
    images = load_lock_images(REPO_SCANNERS)
    names = {i.name for i in images}
    assert {"SEMGREP", "GITLEAKS", "SPOTBUGS_FSB", "SQUID", "POSTGRES"} <= names
    assert not {"SONARQUBE", "SONAR_SCANNER", "DEPENDENCY_CHECK"} & names, "removed for the 4 vCPU / 8 GB sizing"
    hosts = egress_hosts_for(images)
    assert {"registry-1.docker.io", "auth.docker.io", "ghcr.io", "quay.io"} <= hosts


def test_the_primary_tool_of_a_shared_lock_is_the_one_that_scans() -> None:
    from securescan.runner.catalogue import load_catalogue_from

    primary = primary_tool_by_lock(load_catalogue_from(REPO_SCANNERS))
    assert primary["SEMGREP"] == "semgrep" and primary["GITLEAKS"] == "gitleaks"
    assert primary["GRYPE"] == "syft-grype"  # not grype-db-update or grype-db-status, which share the image
    assert primary["NUCLEI"] == "nuclei"  # not nuclei-templates-update or nuclei-templates-validate
    assert primary_tool_by_lock({}) == {}


def test_tool_for_lock_prefers_the_catalogue_tool() -> None:
    assert tool_for_lock("GRYPE", {"GRYPE": "syft-grype"}) == "syft-grype"
    assert tool_for_lock("SQUID", {}) == "squid"  # runner/egress.py looks the proxy image up under this name


# --------------------------------------------------------------------------- planning
class FakeRegistry:
    def __init__(self, digests: dict[str, str | None], tags: list[str] | None = None, fail: bool = False) -> None:
        self.digests = digests
        self.tags = tags or []
        self.fail = fail
        self.digest_calls: list[str] = []

    async def manifest_digest(self, image: ImageName, reference: str) -> str | None:
        if self.fail:
            raise RegistryError("registry unreachable")
        self.digest_calls.append(reference)
        return self.digests.get(reference)

    async def list_tags(self, image: ImageName) -> list[str]:
        if self.fail:
            raise RegistryError("registry unreachable")
        return list(self.tags)


async def test_plan_proposes_a_rebuild_and_a_newer_tag() -> None:
    lock = LockImage("SYFT", "anchore/syft", "v1.54.0", D1)
    registry = FakeRegistry({"v1.54.0": D2, "v1.55.0": D3}, tags=["v1.54.0", "v1.55.0", "v1.55.0-rc1"])
    outcome = await plan_image(lock, Current("v1.54.0", D1, False), tool="syft", scope=SCOPE_RUNTIME, registry=registry)
    assert [(p.tag, p.digest, p.reason) for p in outcome.proposals] == [
        ("v1.54.0", D2, "rebuild"),
        ("v1.55.0", D3, "new_version"),
    ]
    assert outcome.proposals[0].previous_digest == D1 and outcome.proposals[0].previous_tag == "v1.54.0"


async def test_plan_proposes_nothing_when_nothing_changed() -> None:
    lock = LockImage("SYFT", "anchore/syft", "v1.54.0", D1)
    registry = FakeRegistry({"v1.54.0": D1}, tags=["v1.54.0"])
    outcome = await plan_image(lock, Current("v1.54.0", D1, False), tool="syft", scope=SCOPE_RUNTIME, registry=registry)
    assert outcome.proposals == [] and outcome.notes == []


async def test_plan_ignores_a_new_tag_that_points_at_the_current_digest() -> None:
    lock = LockImage("SYFT", "anchore/syft", "v1.54.0", D1)
    registry = FakeRegistry({"v1.54.0": D1, "v1.54.1": D1}, tags=["v1.54.1"])
    outcome = await plan_image(lock, Current("v1.54.0", D1, False), tool="syft", scope=SCOPE_RUNTIME, registry=registry)
    assert outcome.proposals == []


async def test_plan_floating_tags_get_rebuild_proposals_only() -> None:
    lock = LockImage("SQUID", "ubuntu/squid", "latest", D1)
    registry = FakeRegistry({"latest": D2}, tags=["latest", "6.6-24.04_edge"])
    outcome = await plan_image(lock, Current("latest", D1, False), tool="squid", scope=SCOPE_RUNTIME, registry=registry)
    assert [p.reason for p in outcome.proposals] == ["rebuild"]
    assert registry.digest_calls == ["latest"]  # the tag list was never needed


async def test_plan_without_a_pinned_digest_says_so() -> None:
    lock = LockImage("SYFT", "anchore/syft", "v1.54.0", None)
    outcome = await plan_image(lock, Current("v1.54.0", None, False), tool="syft", scope=SCOPE_RUNTIME, registry=FakeRegistry({}))
    assert outcome.proposals == [] and "pin-images" in outcome.notes[0]


async def test_plan_reports_a_registry_failure_instead_of_raising() -> None:
    lock = LockImage("SYFT", "anchore/syft", "v1.54.0", D1)
    outcome = await plan_image(lock, Current("v1.54.0", D1, False), tool="syft", scope=SCOPE_RUNTIME, registry=FakeRegistry({}, fail=True))
    assert outcome.proposals == [] and "unreachable" in outcome.notes[0]


async def test_plan_notes_a_vanished_tag() -> None:
    lock = LockImage("SYFT", "anchore/syft", "v1.54.0", D1)
    outcome = await plan_image(lock, Current("v1.54.0", D1, False), tool="syft", scope=SCOPE_RUNTIME, registry=FakeRegistry({}, tags=[]))
    assert outcome.proposals == [] and "no longer exists" in outcome.notes[0]


def test_current_for_prefers_the_active_override() -> None:
    lock = LockImage("SYFT", "anchore/syft", "v1.54.0", D1)
    row = make_row(tool="syft", tag="v1.55.0", digest=D2, active=True, approved=True)
    assert current_for(lock, "syft", {}) == Current("v1.54.0", D1, False)
    assert current_for(lock, "syft", {"syft": row}) == Current("v1.55.0", D2, True)


def test_regression_job_for_maps_scanners_and_skips_the_rest() -> None:
    assert regression_job_for("syft-grype", SCOPE_RUNTIME) == "syft-grype"
    assert regression_job_for("spotbugs", SCOPE_RUNTIME) == "spotbugs"
    assert regression_job_for("semgrep", SCOPE_RUNTIME) == "semgrep"
    # images the job does not record cannot be gated: they are skipped and need an acknowledgement
    for ungated in ("syft", "squid", "skopeo", "zap", "nuclei"):
        assert regression_job_for(ungated, SCOPE_RUNTIME) is None, ungated
    assert regression_job_for("semgrep", SCOPE_RELEASE) is None


# --------------------------------------------------------------------------- storing
def make_row(**changes: Any) -> ImageVersion:
    values: dict[str, Any] = {
        "id": uuid.uuid4(), "tool": "semgrep", "image": "semgrep/semgrep", "tag": "1.180.0-nonroot", "digest": D2,
        "source": "proposal", "regression_result": "passed",
        "regression_detail": {"scope": "runtime", "reason": "new_version", "lock_name": "SEMGREP",
                              "previous_tag": "1.179.0-nonroot", "previous_digest": D1, "candidate_token": "secret"},
        "active": False, "proposed_at": utcnow(), "approved_by_id": None, "approved_at": None, "notes": None,
        "created_at": utcnow(),
    }  # fmt: skip
    approved = changes.pop("approved", False)
    values.update(changes)
    if approved:
        values["approved_at"] = utcnow()
    return ImageVersion(**values)


class KnownDigestSession(FakeSession):
    """A FakeSession whose ``scalar`` answers the duplicate check of ``store_proposals``."""

    def __init__(self, known: set[tuple[str, str]] | None = None) -> None:
        super().__init__()
        self.known = known or set()

    async def scalar(self, stmt: Any) -> Any:
        compiled = stmt.compile().params
        values = set(compiled.values())
        for tool, digest in self.known:
            if tool in values and digest in values:
                return object()
        return None


def proposal(**changes: Any) -> Proposal:
    values: dict[str, Any] = {
        "lock_name": "SEMGREP", "tool": "semgrep", "image": "semgrep/semgrep", "tag": "1.180.0-nonroot", "digest": D2,
        "reason": "new_version", "scope": SCOPE_RUNTIME, "previous_tag": "1.179.0-nonroot", "previous_digest": D1,
    }  # fmt: skip
    values.update(changes)
    return Proposal(**values)


async def test_store_proposals_writes_rows_audit_events_and_skips_known_digests() -> None:
    session = KnownDigestSession(known={("semgrep", D3)})
    summary = await store_proposals(
        session,  # type: ignore[arg-type]
        [proposal(), proposal(digest=D3), proposal(tool="squid", lock_name="SQUID", digest=D1, tag="latest")],
    )
    rows = [o for o in session.added if isinstance(o, ImageVersion)]
    assert [(r.tool, r.digest) for r in rows] == [("semgrep", D2), ("squid", D1)]
    assert summary.already_known == 1 and len(summary.new) == 2
    assert rows[0].regression_result == "pending" and summary.new[0].job_tool == "semgrep"
    assert rows[1].regression_result == "skipped" and summary.new[1].job_tool is None  # squid has no expectations
    assert rows[0].source == "proposal" and rows[0].active is False and rows[0].approved_at is None
    assert any(getattr(o, "action", None) == "image.propose" for o in session.added)


async def test_store_proposals_marks_platform_images_as_release_scope() -> None:
    session = KnownDigestSession()
    await store_proposals(session, [proposal(tool="postgres", lock_name="POSTGRES", scope=SCOPE_RELEASE)])  # type: ignore[arg-type]
    row = next(o for o in session.added if isinstance(o, ImageVersion))
    assert row.regression_result == "skipped" and row.regression_detail["scope"] == "release"


class Scope:
    """``session_scope()`` stand-in: an async context manager that hands out one session."""

    def __init__(self, session: Any) -> None:
        self.session = session

    def __call__(self) -> Scope:
        return self

    async def __aenter__(self) -> Any:
        return self.session

    async def __aexit__(self, *exc: Any) -> None:
        return None


async def test_run_proposals_checks_every_image_and_stores_the_new_ones() -> None:
    images = [
        LockImage("SYFT", "anchore/syft", "v1.54.0", D1),
        LockImage("SPOTBUGS_FSB", "securescan/spotbugs-fsb", "4.10.4-1.14.0", None),
        LockImage("POSTGRES", "postgres", "18.6", D1),
    ]
    registry = FakeRegistry({"v1.54.0": D2, "18.6": D1}, tags=[])
    session = KnownDigestSession()
    summary = await run_proposals(
        Scope(session), registry, images, tool_by_lock={"SYFT": "syft"}, runtime_locks={"SYFT"}  # type: ignore[arg-type]
    )
    assert summary.checked == 2  # the locally built image is skipped
    assert [n.tool for n in summary.new] == ["syft"]
    assert any("built locally" in n for n in summary.notes)


# --------------------------------------------------------------------------- approving
def test_check_approvable_needs_a_passed_regression() -> None:
    check_approvable(make_row(), acknowledge_skipped=False)
    for result in ("pending", "testing", "failed", "error"):
        with pytest.raises(Conflict) as info:
            check_approvable(make_row(regression_result=result), acknowledge_skipped=True)
        assert info.value.code == "image.regression_not_passed"


def test_check_approvable_skipped_needs_an_acknowledgement() -> None:
    row = make_row(regression_result="skipped")
    with pytest.raises(UnprocessableEntity) as info:
        check_approvable(row, acknowledge_skipped=False)
    assert info.value.code == "image.ack_required"
    check_approvable(row, acknowledge_skipped=True)


def test_check_approvable_refuses_platform_images_and_decided_rows() -> None:
    release = make_row(regression_detail={"scope": "release"}, regression_result="skipped")
    with pytest.raises(Conflict) as info:
        check_approvable(release, acknowledge_skipped=True)
    assert info.value.code == "image.release_scope"
    for row in (make_row(active=True, approved=True), make_row(source="rejected")):
        with pytest.raises(Conflict) as info:
            check_approvable(row, acknowledge_skipped=True)
        assert info.value.code == "image.not_pending"


async def test_approve_activates_the_row_and_replaces_the_previous_one() -> None:
    old = make_row(active=True, approved=True, digest=D1, tag="1.179.0-nonroot")
    session = FakeSession(rows=[old])
    row = make_row()
    user = types.SimpleNamespace(id=uuid.uuid4(), label="admin@example.com")
    result = await approve_image_version(session, row, user)  # type: ignore[arg-type]
    assert result.active is True and result.approved_at is not None and result.approved_by_id == user.id
    assert old.active is False
    audit = [o for o in session.added if getattr(o, "action", None) == "image.approve"]
    assert len(audit) == 1 and audit[0].detail["replaced"] == [str(old.id)]
    assert "candidate_token" not in str(audit[0].detail)


async def test_approve_leaves_a_failed_row_alone() -> None:
    session = FakeSession()
    row = make_row(regression_result="failed")
    with pytest.raises(Conflict):
        await approve_image_version(session, row, types.SimpleNamespace(id=uuid.uuid4()))  # type: ignore[arg-type]
    assert row.active is False and row.approved_at is None and session.added == []


async def test_reject_and_deactivate_are_audited() -> None:
    session = FakeSession()
    user = types.SimpleNamespace(id=uuid.uuid4())
    row = make_row()
    await reject_image_version(session, row, user, note=" not now ")  # type: ignore[arg-type]
    assert row.source == "rejected" and row.notes == "not now"
    with pytest.raises(Conflict):
        await reject_image_version(session, row, user)  # type: ignore[arg-type]
    active = make_row(active=True, approved=True)
    await deactivate_image_version(session, active, user)  # type: ignore[arg-type]
    assert active.active is False
    with pytest.raises(Conflict):
        await deactivate_image_version(session, active, user)  # type: ignore[arg-type]
    assert [o.action for o in session.added if hasattr(o, "action")] == ["image.reject", "image.deactivate"]


def test_public_detail_hides_the_candidate_token() -> None:
    assert "candidate_token" not in public_detail({"candidate_token": "x", "scope": "runtime"})
    assert public_detail(None) == {}


def test_lock_line_names_the_lock_entry() -> None:
    line = lock_yaml_line(make_row())
    assert line == '- { name: SEMGREP, image: semgrep/semgrep, tag: "1.180.0-nonroot", digest: %s }' % D2


# --------------------------------------------------------------------------- the catalogue overlay
def entry_for(tool: str = "semgrep") -> CatalogueEntry:
    return CatalogueEntry.model_validate(entry_dict(tool=tool, image={"name": "semgrep/semgrep", "tag": "1.0", "lock": "SEMGREP"}))


async def test_overlay_returns_none_without_an_active_row() -> None:
    assert await image_override(FakeSession(), entry_for()) is None  # type: ignore[arg-type]


async def test_overlay_uses_the_approved_active_row() -> None:
    row = make_row(active=True, approved=True)
    resolved = await image_override(FakeSession(rows=[row]), entry_for())  # type: ignore[arg-type]
    assert resolved is not None
    assert resolved.reference == "semgrep/semgrep@%s" % D2 and resolved.source == "override" and resolved.pinned


async def test_overlay_wins_over_the_environment_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_IMAGE_SEMGREP", "semgrep/semgrep@" + DIGEST)
    entry = entry_for()
    plain = await resolve_image_with_override(FakeSession(), entry)  # type: ignore[arg-type]
    assert plain.source == "env" and plain.digest == DIGEST
    row = make_row(active=True, approved=True)
    overlaid = await resolve_image_with_override(FakeSession(rows=[row]), entry)  # type: ignore[arg-type]
    assert overlaid.source == "override" and overlaid.digest == D2


async def test_overlay_rejects_a_damaged_digest() -> None:
    from securescan.runner.catalogue import CatalogueError

    row = make_row(active=True, approved=True, digest="not-a-digest")
    with pytest.raises(CatalogueError):
        await image_override(FakeSession(rows=[row]), entry_for())  # type: ignore[arg-type]


def candidate_row(**changes: Any) -> ImageVersion:
    detail = {"scope": "runtime", "candidate_token": "tok-123"}
    values: dict[str, Any] = {"regression_result": "testing", "regression_detail": detail, "digest": D3}
    values.update(changes)
    return make_row(**values)


async def test_a_candidate_runs_only_with_its_token_and_only_while_testing() -> None:
    row = candidate_row()
    session = FakeSession(rows=[row])
    entry = entry_for()
    options = {"image_candidates": {"semgrep": {"id": str(row.id), "token": "tok-123"}}}
    candidate = await image_override(session, entry, options)  # type: ignore[arg-type]
    assert candidate is not None and candidate.source == "candidate" and candidate.digest == D3

    wrong_token = {"image_candidates": {"semgrep": {"id": str(row.id), "token": "guess"}}}
    assert await image_override(FakeSession(rows=[row]), entry, wrong_token) is None  # type: ignore[arg-type]
    no_token = {"image_candidates": {"semgrep": {"id": str(row.id)}}}
    assert await image_override(FakeSession(rows=[row]), entry, no_token) is None  # type: ignore[arg-type]
    other_tool = {"image_candidates": {"gitleaks": {"id": str(row.id), "token": "tok-123"}}}
    assert await image_override(FakeSession(rows=[row]), entry, other_tool) is None  # type: ignore[arg-type]
    row.regression_result = "passed"  # the test is over: the token no longer works
    assert await image_override(FakeSession(rows=[row]), entry, options) is None  # type: ignore[arg-type]
    garbage = {"image_candidates": {"semgrep": {"id": "not-a-uuid", "token": "tok-123"}}}
    assert await image_override(FakeSession(), entry, garbage) is None  # type: ignore[arg-type]


async def test_a_candidate_beats_the_approved_image_for_the_scans_that_carry_its_token() -> None:
    approved = make_row(active=True, approved=True, digest=D1, tag="1.179.0-nonroot")
    row = candidate_row()
    session = FakeSession(rows=[approved, row])
    options = {"image_candidates": {"semgrep": {"id": str(row.id), "token": "tok-123"}}}
    with_token = await image_override(session, entry_for(), options)  # type: ignore[arg-type]
    without = await image_override(session, entry_for())  # type: ignore[arg-type]
    assert with_token is not None and with_token.digest == D3
    assert without is not None and without.digest == D1


async def test_a_job_carrying_a_valid_candidate_token_resolves_the_candidate() -> None:
    row = candidate_row()
    options = {"image_candidates": {"semgrep": {"id": str(row.id), "token": "tok-123"}}}
    resolved = await resolve_image_with_override(FakeSession(rows=[row]), entry_for(), None, options)  # type: ignore[arg-type]
    assert resolved.source == "candidate" and resolved.digest == D3
    bad = {"image_candidates": {"semgrep": {"id": str(row.id), "token": "guess"}}}
    fallback = await resolve_image_with_override(FakeSession(rows=[row]), entry_for(), None, bad)  # type: ignore[arg-type]
    assert fallback.source != "candidate"


def test_the_executor_passes_the_job_options_to_the_image_resolver() -> None:
    from tests.unit.runner_helpers import REPO_ROOT

    source = (REPO_ROOT / "backend" / "securescan" / "runner" / "executor.py").read_text(encoding="utf-8")
    assert "self.entry, self.settings, dict(self.loaded.job.options or {})" in " ".join(source.split())


def test_the_real_catalogue_has_the_scanners_the_regression_gate_maps() -> None:
    from securescan.domain.image_updates import REGRESSION_TOOLS
    from securescan.runner.catalogue import load_catalogue_from

    catalogue = load_catalogue_from(REPO_SCANNERS)
    assert "semgrep" in catalogue and "gitleaks" in catalogue
    assert REGRESSION_TOOLS["semgrep"] == ("semgrep", "semgrep")
    assert REGRESSION_TOOLS["syft-grype"] == ("syft-grype", "grype")  # the expectation key of the syft-grype job


def test_the_executor_hands_the_job_options_to_the_image_resolution() -> None:
    """Without the options a regression scan of an image proposal would run the active image, not the candidate."""
    from pathlib import Path

    source = (Path(__file__).resolve().parents[2] / "securescan" / "runner" / "executor.py").read_text(encoding="utf-8")
    assert "self.loaded.job.options" in source
