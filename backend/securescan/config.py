"""Application settings.

Every setting is read from an environment variable with the prefix ``SECURESCAN_``.
Any ``SECURESCAN_<NAME>_FILE`` variable names a file whose content becomes the value of
``<name>`` (Docker secrets). Trailing whitespace and line endings are stripped, because secret
files written on Windows may carry ``\\r\\n``.
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

    database_url: str = "postgresql+psycopg://securescan@db:5432/securescan"
    database_password: str = ""
    public_url: str = "https://securescan.localtest.me:8443"
    defectdojo_url: str = "http://nginx:8080"
    defectdojo_public_url: str = "https://dojo.securescan.localtest.me:8443"
    cookie_domain: str = "securescan.localtest.me"
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    master_key: str = ""
    docker_host: str = "tcp://socket-proxy:2375"
    data_root: str = "/var/lib/securescan"
    data_host_root: str = ""
    artifacts_root: str = "/var/lib/securescan/artifacts"
    worker_concurrency: int = 4
    sonarqube_url: str = "http://sonarqube:9000"
    sonarqube_container: str = "sonarqube"
    sonarqube_idle_minutes: int = 15
    egress_idle_minutes: int = 5
    github_poll_interval_minutes: int = 10
    log_level: str = "INFO"

    @model_validator(mode="before")
    @classmethod
    def _load_file_backed(cls, data: Any) -> Any:
        merged: dict[str, Any] = dict(data) if isinstance(data, dict) else {}
        for name, value in file_backed_values(os.environ).items():
            merged.setdefault(name, value)
        return merged


@lru_cache
def get_settings() -> Settings:
    return Settings()
