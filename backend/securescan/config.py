"""Application settings.

Every setting is read from an environment variable with the prefix ``SECURESCAN_``.
Any ``SECURESCAN_<NAME>_FILE`` variable names a file whose content becomes the value of
``<name>`` (Docker secrets). Trailing whitespace and line endings are stripped, because secret
files written on Windows may carry ``\\r\\n``. An explicit ``SECURESCAN_<NAME>`` wins over the file.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PREFIX = "SECURESCAN_"
FILE_SUFFIX = "_FILE"

# Hosts the on-demand egress proxy lets the worker's own updaters reach (plan section 2.4).
DEFAULT_UPDATER_HOSTS = (
    "github.com,api.github.com,codeload.github.com,objects.githubusercontent.com,"
    "raw.githubusercontent.com,grype.anchore.io,toolbox-data.anchore.io,api.pdtm.sh,"
    "registry-1.docker.io,auth.docker.io,ghcr.io,quay.io"
)


def read_secret_file(path: str | Path) -> str:
    """Return the content of a secret file with surrounding whitespace removed."""
    return Path(path).read_text(encoding="utf-8").strip()


def file_backed_values(environ: Mapping[str, str]) -> dict[str, str]:
    """Collect ``SECURESCAN_<NAME>_FILE`` variables into ``{name: file content}``."""
    values: dict[str, str] = {}
    for key, path in environ.items():
        if key.startswith(ENV_PREFIX) and key.endswith(FILE_SUFFIX) and path:
            name = key[len(ENV_PREFIX) : -len(FILE_SUFFIX)].lower()
            values[name] = read_secret_file(path)
    return values


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix=ENV_PREFIX, extra="ignore")

    # --- runtime -------------------------------------------------------------------------
    env: str = "production"  # "production" | "dev" | "test"
    log_level: str = "INFO"
    docs_enabled: bool = False  # serve Swagger UI at /api/v1/docs (dev only)

    # --- database ------------------------------------------------------------------------
    database_url: str = "postgresql+psycopg://securescan@db:5432/securescan"
    database_password: str = ""
    database_pool_size: int = 10

    # --- public URLs, cookies, sessions ----------------------------------------------------
    public_url: str = "https://securescan.localtest.me:8443"
    defectdojo_url: str = "http://nginx:8080"
    defectdojo_public_url: str = "https://dojo.securescan.localtest.me:8443"
    cookie_domain: str = "securescan.localtest.me"
    cookie_secure: bool | None = None  # None: secure when public_url is https
    session_cookie_name: str = "securescan_session"
    csrf_cookie_name: str = "securescan_csrf"
    csrf_header_name: str = "X-CSRF-Token"
    session_idle_hours: int = 8
    session_max_hours: int = 24
    trust_forwarded_for: bool = True  # only the gateway can reach the api container

    # --- identity provider -----------------------------------------------------------------
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_roles_claim: str = "roles"
    oidc_redirect_path: str = "/api/v1/auth/callback"

    # --- secrets store ---------------------------------------------------------------------
    master_key: str = ""
    master_key_previous: str = ""  # during rotation: still decrypts, never encrypts
    credential_expiry_alert_days: int = 14

    # --- docker, volumes, workspaces -----------------------------------------------------------
    docker_host: str = "tcp://socket-proxy:2375"
    data_root: str = "/var/lib/securescan"
    data_host_root: str = ""
    artifacts_root: str = "/var/lib/securescan/artifacts"
    content_root: str = "/var/lib/securescan/content"
    scanners_dir: str = ""  # directory holding catalogue.yaml; empty: find it next to the package
    network_backend: str = "securescan_backend"
    network_dast: str = "securescan_dast"
    network_egress: str = "securescan_egress"

    docker_api_version: str = "1.44"  # explicit: the SDK would otherwise ask the daemon first
    data_volume: str = "securescan_data"  # named volume behind data_root (bind source lookup)
    content_volume: str = "securescan_content"  # named volume behind content_root
    ssh_known_hosts_file: str = ""  # known_hosts for git over SSH (deploy keys); empty: none
    git_clone_timeout_seconds: int = 1800

    # --- scan runner (M3) ----------------------------------------------------------------------
    zip_max_uncompressed_bytes: int = 2 * 1024**3
    zip_max_ratio: int = 100  # uncompressed : compressed
    zip_max_entries: int = 200_000
    job_heartbeat_seconds: int = 20
    job_stale_after_seconds: int = 300  # stalled_jobs re-queues a running job silent this long
    job_queued_grace_seconds: int = 180  # a queued job older than this without a queue entry is re-deferred
    workspace_max_age_hours: int = 24

    # --- worker --------------------------------------------------------------------------------
    worker_concurrency: int = 4
    worker_metrics_host: str = "0.0.0.0"  # noqa: S104 - container-internal, not published
    worker_metrics_port: int = 9100
    github_poll_interval_minutes: int = 10

    # --- uploads -------------------------------------------------------------------------------
    upload_max_bytes: int = 2 * 1024**3
    upload_chunk_bytes: int = 8 * 1024**2
    upload_max_chunk_bytes: int = 32 * 1024**2
    upload_stale_hours: int = 48

    # --- DefectDojo (M4) -----------------------------------------------------------------------
    defectdojo_admin_username: str = "admin"
    defectdojo_admin_password: str = ""
    defectdojo_sync_username: str = "securescan-sync"
    defectdojo_accounts_username: str = "securescan-accounts"
    defectdojo_version: str = "3.4.0"  # image tag the stack was pinned to (status page only)
    defectdojo_timeout_seconds: float = 60.0
    defectdojo_import_timeout_seconds: float = 900.0  # one reimport-scan request (parse + dedupe)
    defectdojo_max_retries: int = 3  # per request, on connection errors and 5xx
    defectdojo_page_size: int = 200
    defectdojo_dedup_recheck_minutes: int = 2  # re-read after deduplication_complete=false
    defectdojo_import_max_age_days: int = 7  # an outbox row older than this becomes a dead letter
    defectdojo_account_expiry_days: int = 90  # unused DefectDojo accounts are disabled
    defectdojo_init_wait_seconds: int = 900  # dojo-init waits this long for DefectDojo

    # --- egress (M7, M8) -------------------------------------------------------------------------
    egress_idle_minutes: int = 5
    egress_proxy_url: str = "http://securescan-egress:3128"
    egress_allow_hosts_updaters: str = DEFAULT_UPDATER_HOSTS

    # --- reports (M5) ----------------------------------------------------------------------------
    report_detail_limit: int = 300  # findings described in full per report; the CSV lists all
    report_template_max_bytes: int = 20 * 1024**2  # size cap of an uploaded template zip
    report_template_check_seconds: int = 90  # wall-clock limit of the sandboxed test render
    egress_enabled: bool = True  # false (dev, tests): the worker connects directly, no proxy container
    egress_image: str = ""  # squid image by digest (compose passes ${IMG_SQUID}); empty: image_versions row "squid"

    # --- GitHub (M7) -----------------------------------------------------------------------------
    github_app_key_1: str = ""  # PEM (GITHUB_APP_KEY_1_FILE); used when no key was uploaded in Settings
    github_app_key_2: str = ""  # second PEM for rotation without downtime
    github_poll_request_budget: int = 1200  # at most this many head lookups per poll run
    github_poll_max_scans_per_run: int = 25  # scans one poll run may enqueue (the rest follow next run)

    # --- operations (M11) ------------------------------------------------------------------------
    host_check: str = "auto"  # auto (enforce in production, warn in dev/test) | enforce | warn | off
    host_min_docker_major: int = 29  # Docker Engine major version the install guide asks for (warning below)
    host_min_docker_api: str = "1.44"  # the API version the launcher speaks (blocking below)
    backup_status_file: str = "/var/lib/securescan/backup/status.json"  # written by scripts/backup.sh
    regression_fixtures_dir: str = ""  # planted apps; empty: search the usual places
    regression_wait_minutes: int = 120  # longest wait for the scans of one regression run
    regression_poll_seconds: int = 10
    regression_dast_url: str = ""  # a UAT Juice Shop for the optional DAST regression; empty: skipped
    image_registry_timeout_seconds: float = 30.0
    image_update_max_tag_pages: int = 30  # registry tag-list pages read per image

    # --- DAST (M9) -------------------------------------------------------------------------------
    dast_allowed_cidrs: str = ""  # comma-separated CIDRs a DAST target must resolve into ("" = approved hosts only)
    dast_max_rps: int = 100  # upper bound for a target's request-rate cap
    dast_proxy_ready_seconds: int = 20  # how long the worker waits for a job's squid to stay up

    # --- code scanners, content and updaters (M8) ----------------------------------------------------
    grype_db_max_age: str = "120h"  # GRYPE_DB_MAX_ALLOWED_BUILT_AGE of scan containers (stale database fails the job)
    grype_db_read_only: bool = False  # mount the Grype database read-only into scans (confirm with spike S7)
    semgrep_rules_commit: str = ""  # pins the semgrep-rules commit (else content/semgrep-rules.lock)
    semgrep_rules_lock_file: str = ""  # path of semgrep-rules.lock; empty: look next to the scanners directory
    content_bootstrap: bool = True  # worker start-up defers the first update of every empty feed
    content_keep_versions: int = 3  # dated rule and template directories kept besides the active one
    egress_client_network: str = ""  # network of containers that use the egress proxy; empty: network_backend
    image_registry_direct_hosts: str = ""  # comma list of registries reached without the proxy (local registry)
    image_max_extracted_bytes: int = 8 * 1024**3  # cap of an extracted image filesystem
    image_max_entries: int = 2_000_000
    regression_apps_dir: str = ""  # planted sample apps for the regression gate; empty: search the usual places
    feed_max_age_days_database: int = 7  # alert threshold for vulnerability databases
    feed_max_age_days_content: int = 30  # alert threshold for rules and templates

    @model_validator(mode="before")
    @classmethod
    def _load_file_backed(cls, data: Any) -> Any:
        merged: dict[str, Any] = dict(data) if isinstance(data, dict) else {}
        for name, value in file_backed_values(os.environ).items():
            merged.setdefault(name, value)
        return merged

    # --- derived values ------------------------------------------------------------------------
    @property
    def cookies_secure(self) -> bool:
        if self.cookie_secure is not None:
            return self.cookie_secure
        return self.public_url.lower().startswith("https://")

    @property
    def is_dev(self) -> bool:
        return self.env in ("dev", "test")

    @property
    def workspaces_root(self) -> str:
        return str(Path(self.data_root) / "workspaces")

    @property
    def updater_hosts(self) -> list[str]:
        return [h.strip() for h in self.egress_allow_hosts_updaters.split(",") if h.strip()]

    @property
    def dast_cidrs(self) -> list[str]:
        return [c.strip() for c in self.dast_allowed_cidrs.split(",") if c.strip()]

    @property
    def oidc_redirect_uri(self) -> str:
        return self.public_url.rstrip("/") + self.oidc_redirect_path


@lru_cache
def get_settings() -> Settings:
    return Settings()
