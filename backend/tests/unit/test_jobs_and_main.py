from __future__ import annotations

import sys
import types

import pytest

from securescan import __main__ as entry
from securescan.config import Settings
from securescan.jobs import hooks
from securescan.jobs.app import QUEUES, app, load_tasks
from securescan.observability import metrics

# --------------------------------------------------------------------------- Procrastinate app


def test_all_plan_periodic_tasks_are_registered() -> None:
    load_tasks()
    registered = set(app.tasks)
    assert set(hooks.PERIODIC_TASK_NAMES) <= registered
    assert "session_cleanup" in registered


def test_queues_are_the_planned_ones() -> None:
    assert QUEUES == ["scans", "imports", "reports", "maintenance", "github"]


async def test_periodic_skeleton_is_a_noop_until_a_hook_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    # Every planned name has a real hook once load_tasks() has run, so use an empty registry.
    monkeypatch.setattr(hooks, "_PERIODIC", {})
    assert await hooks.run_periodic("grype_db_update", 0) is False


async def test_registered_hook_is_run() -> None:
    calls: list[int] = []

    async def fake(timestamp: int) -> None:
        calls.append(timestamp)

    previous = hooks._PERIODIC.get("nvd_update")
    hooks.periodic_hook("nvd_update")(fake)
    try:
        assert await hooks.run_periodic("nvd_update", 42) is True
        assert calls == [42]
    finally:
        if previous is None:
            hooks._PERIODIC.pop("nvd_update", None)
        else:
            hooks._PERIODIC["nvd_update"] = previous


def test_unknown_periodic_hook_name_is_rejected() -> None:
    with pytest.raises(ValueError):
        hooks.periodic_hook("not_a_task")


async def test_startup_hooks_run_in_order() -> None:
    seen: list[str] = []

    async def first() -> None:
        seen.append("first")

    async def second() -> None:
        seen.append("second")

    before = list(hooks._STARTUP)
    hooks.worker_startup_hook(first)
    hooks.worker_startup_hook(second)
    try:
        await hooks.run_startup_hooks()
        assert seen[-2:] == ["first", "second"]
    finally:
        hooks._STARTUP[:] = before


# --------------------------------------------------------------------------- command dispatch


def test_missing_command_module_is_not_implemented_yet(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(entry.DISPATCH, "ghost", ("securescan.integrations.ghost.init", "run"))
    assert entry.dispatch("ghost") == 0
    assert capsys.readouterr().out.strip() == "ghost: not implemented yet"


def test_existing_command_module_is_run(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("securescan._fake_command")
    module.run = lambda: 7  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "securescan._fake_command", module)
    monkeypatch.setitem(entry.DISPATCH, "fake", ("securescan._fake_command", "run"))
    assert entry.dispatch("fake") == 7


def test_missing_dependency_inside_a_command_is_a_real_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(_name: str) -> types.ModuleType:
        raise ModuleNotFoundError("No module named 'somelib'", name="somelib")

    monkeypatch.setitem(entry.DISPATCH, "broken", ("securescan.db.migrate", "run"))
    monkeypatch.setattr(entry.importlib, "import_module", broken)
    with pytest.raises(ModuleNotFoundError):
        entry.dispatch("broken")


def test_dispatch_table_matches_the_shared_rules() -> None:
    assert entry.DISPATCH["migrate"] == ("securescan.db.migrate", "run")
    assert entry.DISPATCH["worker"] == ("securescan.jobs.worker", "run")
    assert entry.DISPATCH["dojo-init"] == ("securescan.integrations.defectdojo.init", "run")
    assert entry.DISPATCH["sonar-init"] == ("securescan.integrations.sonarqube.init", "run")
    assert entry.COMMANDS[0] == "api"


# --------------------------------------------------------------------------- settings, metrics


def test_settings_defaults_cover_plan_section_7_1() -> None:
    settings = Settings()
    assert settings.worker_concurrency == 4
    assert settings.sonarqube_idle_minutes == 15
    assert settings.egress_idle_minutes == 5
    assert settings.github_poll_interval_minutes == 10
    assert settings.session_idle_hours == 8
    assert settings.cookies_secure is True
    assert "github.com" in settings.updater_hosts
    assert settings.oidc_redirect_uri == (
        "https://securescan.localtest.me:8443/api/v1/auth/callback"
    )


def test_cookie_secure_follows_the_public_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_PUBLIC_URL", "http://localhost:8080")
    assert Settings().cookies_secure is False
    monkeypatch.setenv("SECURESCAN_COOKIE_SECURE", "true")
    assert Settings().cookies_secure is True


def test_metrics_registry_has_the_observability_table() -> None:
    names = {family.name for family in metrics.REGISTRY.collect()}
    for expected in (
        "securescan_queue_depth",
        "securescan_oldest_queued_job_age_seconds",
        "securescan_jobs",
        "securescan_job_duration_seconds",
        "securescan_import_lag_seconds",
        "securescan_import_dead_letters",
        "securescan_github_poll_last_success_timestamp",
        "securescan_sonarqube_start_seconds",
        "securescan_egress_proxy_up",
        "securescan_disk_used_ratio",
        "securescan_feed_age_seconds",
        "securescan_backup_last_success_timestamp",
        "securescan_break_glass_logins",
        "securescan_http_request_duration_seconds",
    ):
        assert expected in names, expected


def test_prometheus_text_and_snapshot() -> None:
    metrics.observe_request("GET", "/api/v1/me", 200, 0.02)
    metrics.QUEUE_DEPTH.labels(queue="scans").set(3)
    assert b"securescan_queue_depth" in metrics.render_prometheus()
    snapshot = metrics.snapshot()
    assert snapshot["securescan_queue_depth"][0]["value"] == 3
    assert all(not name.endswith("_bucket") for name in snapshot)
