from pathlib import Path

import pytest

from securescan.config import Settings, file_backed_values, read_secret_file


def test_read_secret_file_strips_crlf(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_bytes(b"s3cret\r\n")
    assert read_secret_file(secret) == "s3cret"


def test_file_backed_values_maps_names(tmp_path: Path) -> None:
    secret = tmp_path / "pw"
    secret.write_bytes(b"  hunter2 \r\n")
    values = file_backed_values({"SECURESCAN_DATABASE_PASSWORD_FILE": str(secret), "OTHER_FILE": "x"})
    assert values == {"database_password": "hunter2"}


def test_settings_loads_file_variable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "key"
    secret.write_bytes(b"master\r\n")
    monkeypatch.setenv("SECURESCAN_MASTER_KEY_FILE", str(secret))
    assert Settings().master_key == "master"


def test_explicit_env_wins_over_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "key"
    secret.write_text("from-file")
    monkeypatch.setenv("SECURESCAN_MASTER_KEY_FILE", str(secret))
    monkeypatch.setenv("SECURESCAN_MASTER_KEY", "from-env")
    assert Settings().master_key == "from-env"
