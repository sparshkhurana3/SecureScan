"""Guards for the operations files: shell scripts parse, alert rules are well formed and point at real
runbooks, the Compose file keeps the always-on containers hardened, the install guide names every script."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.unit.runner_helpers import REPO_ROOT

SCRIPTS = REPO_ROOT / "scripts"
DOCS = REPO_ROOT / "docs"
SHELL = ["backup.sh", "restore.sh", "check_host.sh"]
RUNBOOKS = [
    "stuck-scan", "defectdojo-unreachable", "content-update-failed", "release-upgrade", "defectdojo-upgrade",
    "sonarqube-upgrade", "restore", "credential-rotation", "github-app-key-rotation", "approving-image-digest",
    "performance",
]  # fmt: skip


# --------------------------------------------------------------------------- shell scripts
@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")
@pytest.mark.parametrize("name", SHELL)
def test_shell_scripts_parse(name: str) -> None:
    result = subprocess.run(["bash", "-n", str(SCRIPTS / name)], capture_output=True, text=True)  # noqa: S603, S607
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("name", SHELL)
def test_shell_scripts_have_lf_endings_and_a_shebang(name: str) -> None:
    data = (SCRIPTS / name).read_bytes()
    assert b"\r" not in data
    assert data.startswith(b"#!/usr/bin/env bash\n")


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")
def test_check_host_version_comparison() -> None:
    script = 'source "%s"; version_ge 2.40.1 2.24 && version_ge v2.24 2.24 && ! version_ge 2.9 2.24 && echo fine' % (
        SCRIPTS / "check_host.sh"
    )
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)  # noqa: S603, S607
    assert result.stdout.strip() == "fine", result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")
@pytest.mark.parametrize("name", ["backup.sh", "restore.sh", "check_host.sh"])
def test_shell_scripts_answer_help_without_touching_anything(name: str) -> None:
    result = subprocess.run(["bash", str(SCRIPTS / name), "--help"], capture_output=True, text=True, cwd=REPO_ROOT)  # noqa: S603, S607
    assert result.returncode == 0 and result.stdout.startswith("#"), result.stderr


def test_backup_and_restore_use_age_and_never_print_the_key() -> None:
    backup = (SCRIPTS / "backup.sh").read_text(encoding="utf-8")
    restore = (SCRIPTS / "restore.sh").read_text(encoding="utf-8")
    assert "age -r" in backup and "age -d -i" in restore
    assert "cat \"$KEY_FILE\"" not in backup and "cat \"$IDENTITY\"" not in restore
    assert "pg_dump" in backup and "--format=custom" in backup
    for volume in ("artifacts", "defectdojo_media", "securescan_data"):
        assert volume in backup and volume in restore
    # a backup that stays on the machine must not count as a success
    assert backup.index("OFFSITE_OK=true") < backup.index("last_success")


# --------------------------------------------------------------------------- alert rules
def alert_rules() -> list[dict[str, Any]]:
    data = yaml.safe_load((REPO_ROOT / "deploy" / "monitoring" / "alerts.yaml").read_text(encoding="utf-8"))
    return [rule for group in data["groups"] for rule in group["rules"]]


def test_alert_rules_are_well_formed() -> None:
    rules = alert_rules()
    assert len(rules) >= 15
    names = [r["alert"] for r in rules]
    assert len(names) == len(set(names))
    for rule in rules:
        assert rule["expr"].strip() and rule["labels"]["severity"] in {"info", "warning", "critical"}
        assert rule["annotations"]["summary"] and rule["annotations"]["description"]


def test_every_alert_the_design_asks_for_exists() -> None:
    exprs = "\n".join(r["expr"] for r in alert_rules())
    for needle in (
        "securescan_oldest_queued_job_age_seconds", "securescan_jobs_total", "securescan_import_lag_seconds",
        "securescan_import_dead_letters", "securescan_github_poll_last_success_timestamp",
        "securescan_sonarqube_start_seconds", "securescan_disk_used_ratio", "securescan_feed_age_seconds",
        "securescan_backup_last_success_timestamp", "securescan_break_glass_logins_total",
        "securescan_http_request_duration_seconds_bucket", "securescan_host_check_ok",
    ):  # fmt: skip
        assert needle in exprs, needle


def test_alert_metrics_exist_in_the_application() -> None:
    from securescan.observability import metrics
    from securescan.runner import host_check  # noqa: F401 - registers securescan_host_check_ok

    registered = {family.name for family in metrics.REGISTRY.collect()}
    used = set(re.findall(r"securescan_[a-z_]+", "\n".join(r["expr"] for r in alert_rules())))
    # histogram and counter series carry suffixes the registry lists without them
    suffixes = ("_bucket", "_count", "_sum", "_total")
    for name in sorted(used):
        base = name
        for suffix in suffixes:
            if base.endswith(suffix):
                base = base[: -len(suffix)]
                break
        assert base in registered or name in registered or base + "_total" in registered, name


def test_alerts_point_at_runbooks_that_exist() -> None:
    text = (REPO_ROOT / "deploy" / "monitoring" / "alerts.yaml").read_text(encoding="utf-8")
    for slug in set(re.findall(r"docs/runbooks/([a-z-]+)\.md", text)):
        assert (DOCS / "runbooks" / ("%s.md" % slug)).is_file(), slug


# --------------------------------------------------------------------------- compose hardening
def compose_services() -> dict[str, dict[str, Any]]:
    data = yaml.safe_load((REPO_ROOT / "deploy" / "compose.yaml").read_text(encoding="utf-8"))
    return data["services"]  # type: ignore[no-any-return]


@pytest.mark.parametrize("name", ["migrate", "api", "worker", "dojo-init", "gateway", "socket-proxy"])
def test_always_on_services_are_hardened(name: str) -> None:
    service = compose_services()[name]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"] and "cap_add" not in service
    assert "no-new-privileges:true" in service["security_opt"]
    assert service.get("pids_limit")
    assert service["deploy"]["resources"]["limits"]["memory"]


def test_the_database_is_the_documented_exception() -> None:
    db = compose_services()["db"]
    assert db.get("read_only") is not True
    assert db["cap_drop"] == ["ALL"] and set(db["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}
    assert "no-new-privileges:true" in db["security_opt"]
    assert db["healthcheck"]


def test_long_running_services_have_health_checks() -> None:
    services = compose_services()
    for name in ("db", "api", "worker", "gateway"):
        assert services[name]["healthcheck"]["test"], name


def test_only_the_gateway_publishes_a_port() -> None:
    published = {name: s["ports"] for name, s in compose_services().items() if s.get("ports")}
    assert list(published) == ["gateway"]


def test_the_worker_is_the_only_service_with_the_docker_proxy_network() -> None:
    services = compose_services()
    on_docker = [n for n, s in services.items() if "docker" in (s.get("networks") or [])]
    assert sorted(on_docker) == ["socket-proxy", "worker"]
    for name, service in services.items():
        for volume in service.get("volumes") or []:
            assert "docker.sock" not in str(volume) or name == "socket-proxy"


def test_the_api_and_worker_see_the_lock_file_and_the_artifacts_volume() -> None:
    services = compose_services()
    for name in ("api", "worker"):
        volumes = " ".join(str(v) for v in services[name]["volumes"])
        assert "images.lock.yaml:/app/deploy/images.lock.yaml:ro" in volumes
        assert "artifacts:/var/lib/securescan/artifacts" in volumes


def compose_document() -> dict[str, Any]:
    return yaml.safe_load((REPO_ROOT / "deploy" / "compose.yaml").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def test_every_network_is_joined_by_a_service_or_created_by_dev_py() -> None:
    """Compose does not create a network that no service joins; the on-demand ones must be external and made by dev.py."""
    document = compose_document()
    used = set()
    for service in document["services"].values():
        networks = service.get("networks") or []
        used.update(networks if isinstance(networks, list) else networks.keys())
    dev_py = (SCRIPTS / "dev.py").read_text(encoding="utf-8")
    for key, network in (document["networks"] or {}).items():
        if key in used:
            continue
        network = network or {}
        assert network.get("external") is True and network.get("name"), key
        assert network["name"] in dev_py, key
    for name in ("sonarqube", "dast", "egress"):
        assert name not in used  # nothing permanent joins them


def test_the_backend_image_is_installed_not_editable() -> None:
    dockerfile = (REPO_ROOT / "deploy" / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "uv sync --frozen --no-dev --no-editable" in dockerfile


def test_the_worker_has_the_sonarqube_secrets_and_the_ssh_known_hosts() -> None:
    document = compose_document()
    worker = document["services"]["worker"]
    for secret in ("sonarqube_db_password", "sonarqube_admin_password"):
        assert secret in worker["secrets"] and secret in document["secrets"]
    env = worker["environment"]
    assert env["SECURESCAN_SONARQUBE_DB_PASSWORD_FILE"] == "/run/secrets/sonarqube_db_password"
    assert env["SECURESCAN_SONARQUBE_ADMIN_PASSWORD_FILE"] == "/run/secrets/sonarqube_admin_password"
    assert env["SECURESCAN_SSH_KNOWN_HOSTS_FILE"] == "/app/deploy/known_hosts"
    volumes = " ".join(str(v) for v in worker["volumes"])
    assert "./known_hosts:/app/deploy/known_hosts:ro" in volumes
    assert "../content/semgrep-rules.lock:/app/content/semgrep-rules.lock:ro" in volumes


def test_the_dast_scope_settings_reach_the_api_and_the_worker() -> None:
    services = compose_services()
    for name in ("api", "worker"):
        env = services[name]["environment"]
        assert "SECURESCAN_DAST_ALLOWED_CIDRS" in env and "SECURESCAN_DAST_MAX_RPS" in env, name
    example = (REPO_ROOT / "deploy" / ".env.example").read_text(encoding="utf-8")
    assert "SECURESCAN_DAST_ALLOWED_CIDRS" in example and "SECURESCAN_DAST_MAX_RPS" in example


def test_the_test_profile_overlay_publishes_the_database_on_loopback_only() -> None:
    overlay = yaml.safe_load((REPO_ROOT / "deploy" / "compose.test.yaml").read_text(encoding="utf-8"))
    assert all(str(p).startswith("127.0.0.1:") for p in overlay["services"]["db"]["ports"])
    assert all(p["host_ip"] == "127.0.0.1" for p in overlay["services"]["nginx"]["ports"])


# --------------------------------------------------------------------------- documents
def test_install_guide_and_runbooks_exist() -> None:
    assert (DOCS / "install.md").is_file() and (DOCS / "security-checklist.md").is_file()
    for slug in RUNBOOKS:
        assert (DOCS / "runbooks" / ("%s.md" % slug)).is_file(), slug


def test_install_guide_names_the_scripts_and_the_settings() -> None:
    text = (DOCS / "install.md").read_text(encoding="utf-8")
    for needle in ("check_host.sh", "backup.sh", "restore.sh", "BACKUP_REMOTE", "SOCKET_PROXY_USER", "pull-images", "vm.max_map_count"):
        assert needle in text, needle


def test_runbooks_do_not_contain_secret_looking_values() -> None:
    pattern = re.compile(r"(AGE-SECRET-KEY-1[A-Z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
    for path in list((DOCS / "runbooks").glob("*.md")) + [DOCS / "install.md", DOCS / "security-checklist.md"]:
        assert not pattern.search(path.read_text(encoding="utf-8")), path
