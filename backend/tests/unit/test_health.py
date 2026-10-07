from fastapi.testclient import TestClient

from securescan.main import create_app


def test_healthz_is_ok() -> None:
    client = TestClient(create_app())
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_reports_unavailable_without_database(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", "postgresql+psycopg://nobody@127.0.0.1:1/none")
    from securescan.config import get_settings

    get_settings.cache_clear()
    client = TestClient(create_app())
    response = client.get("/readyz")
    assert response.status_code == 503
    get_settings.cache_clear()
