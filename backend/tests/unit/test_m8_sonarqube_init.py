"""The first-time SonarQube setup against a scripted server: admin password, service user, token, mode."""

from __future__ import annotations

import base64
from collections.abc import Callable
from urllib.parse import parse_qs

import httpx
import pytest

from securescan.config import Settings
from securescan.db.models.enums import CredentialKind
from securescan.domain.credentials import reveal_secret
from securescan.integrations.sonarqube import init as sonar_init
from securescan.integrations.sonarqube.init import (
    SonarInitError,
    ensure_admin_password,
    ensure_standard_experience,
    initialise,
    needs_initialisation,
    stored_service_token,
)
from securescan.integrations.sonarqube.client import SonarQubeClient
from tests.unit.conftest import FakeSession

ADMIN_PASSWORD = "Str0ng-admin-password!"


class Server:
    """Just enough of SonarQube's API: basic authentication, users, permissions, tokens and settings."""

    def __init__(self, admin_password: str = "admin") -> None:
        self.admin_password = admin_password
        self.users: set[str] = set()
        self.permissions: list[tuple[str, str]] = []
        self.tokens: dict[str, str] = {}  # token -> login
        self.settings: dict[str, str] = {"sonar.multi-quality-mode.enabled": "true"}
        self.requests: list[tuple[str, str]] = []
        self.refuse_mode_setting = False
        self.counter = 0

    def credentials(self, request: httpx.Request) -> tuple[str, str]:
        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return "", ""
        user, _, password = base64.b64decode(header[6:]).decode().partition(":")
        return user, password

    def is_admin(self, user: str, password: str) -> bool:
        return user == "admin" and password == self.admin_password

    def __call__(self, request: httpx.Request) -> httpx.Response:
        user, password = self.credentials(request)
        path = request.url.path
        self.requests.append((request.method, path))
        if path == "/api/authentication/validate":
            valid = self.is_admin(user, password) or (user in self.tokens and password == "")
            return httpx.Response(200, json={"valid": valid})
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if path == "/api/users/change_password":
            if form["previousPassword"] != self.admin_password:
                return httpx.Response(400, json={"errors": [{"msg": "Incorrect password"}]})
            self.admin_password = form["password"]
            return httpx.Response(204)
        if not self.is_admin(user, password):
            return httpx.Response(401, json={"errors": [{"msg": "Unauthorized"}]})
        if path == "/api/users/search":
            q = request.url.params.get("q", "")
            return httpx.Response(200, json={"users": [{"login": u} for u in sorted(self.users) if q in u]})
        if path == "/api/users/create":
            self.users.add(form["login"])
            assert form["local"] == "true" and len(form["password"]) >= 12
            return httpx.Response(200, json={"user": {"login": form["login"]}})
        if path == "/api/permissions/add_user":
            entry = (form["login"], form["permission"])
            if entry in self.permissions:
                return httpx.Response(400, json={"errors": [{"msg": "Permission already granted"}]})
            self.permissions.append(entry)
            return httpx.Response(204)
        if path == "/api/user_tokens/generate":
            self.counter += 1
            token = f"squ_token_{self.counter}"
            self.tokens[token] = form["login"]
            assert form["type"] == "USER_TOKEN"
            return httpx.Response(200, json={"login": form["login"], "name": form["name"], "token": token})
        if path == "/api/settings/values":
            key = request.url.params.get("keys", "")
            return httpx.Response(200, json={"settings": [{"key": key, "value": self.settings[key]}] if key in self.settings else []})
        if path == "/api/settings/set":
            if self.refuse_mode_setting:
                return httpx.Response(400, json={"errors": [{"msg": "Setting does not exist"}]})
            self.settings[form["key"]] = form["value"]
            return httpx.Response(204)
        return httpx.Response(404)


def config(password: str = ADMIN_PASSWORD, monkeypatch: pytest.MonkeyPatch | None = None) -> Settings:
    if monkeypatch is not None:
        monkeypatch.setenv("SECURESCAN_SONARQUBE_ADMIN_PASSWORD", password)
    return Settings(sonarqube_admin_password=password)  # type: ignore[call-arg]


def transport(server: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(server)


# --------------------------------------------------------------------------- the whole setup
async def test_a_fresh_server_is_set_up_completely(master_key: str) -> None:
    server, session, cfg = Server(), FakeSession(), config()
    assert await needs_initialisation(cfg, transport=transport(server)) is True
    changes = await initialise(session, cfg, transport=transport(server))  # type: ignore[arg-type]
    assert changes == [
        "changed the SonarQube admin password",
        "created the service user securescan-sonar",
        "created and stored the SonarQube service token",
        "switched SonarQube to Standard Experience mode",
    ]
    assert server.admin_password == ADMIN_PASSWORD and "securescan-sonar" in server.users
    assert server.permissions == [("securescan-sonar", "provisioning"), ("securescan-sonar", "scan")]
    assert server.settings["sonar.multi-quality-mode.enabled"] == "false"
    credential = session.added[0]
    assert credential.kind == CredentialKind.SONARQUBE_TOKEN and credential.extra == {"login": "securescan-sonar"}
    token = reveal_secret(credential)
    assert token in server.tokens and server.tokens[token] == "securescan-sonar"
    assert token not in credential.ciphertext, "stored encrypted"
    assert await needs_initialisation(cfg, transport=transport(server)) is False
    assert await stored_service_token(session) == token  # type: ignore[arg-type]


async def test_a_second_run_changes_nothing(master_key: str) -> None:
    server, session, cfg = Server(), FakeSession(), config()
    await initialise(session, cfg, transport=transport(server))  # type: ignore[arg-type]
    before = len(session.added)
    assert await initialise(session, cfg, transport=transport(server)) == []  # type: ignore[arg-type]
    assert len(session.added) == before, "no second credential"
    assert len(server.tokens) == 1


async def test_a_token_that_no_longer_works_is_replaced(master_key: str) -> None:
    server, session, cfg = Server(), FakeSession(), config()
    await initialise(session, cfg, transport=transport(server))  # type: ignore[arg-type]
    old = session.added[0]
    server.tokens.clear()  # for example after the SonarQube database was reset
    changes = await initialise(session, cfg, transport=transport(server))  # type: ignore[arg-type]
    assert changes == ["created and stored the SonarQube service token"]
    assert old.revoked_at is not None
    new = session.added[1]
    assert new is not old and reveal_secret(new) in server.tokens


async def test_the_admin_password_that_is_already_configured_is_not_touched() -> None:
    server = Server(admin_password=ADMIN_PASSWORD)
    assert await ensure_admin_password(config(), transport=transport(server)) == []
    assert ("POST", "/api/users/change_password") not in server.requests


async def test_an_unknown_admin_password_is_a_clear_error() -> None:
    server = Server(admin_password="somebody-elses-password")
    with pytest.raises(SonarInitError) as info:
        await ensure_admin_password(config(), transport=transport(server))
    assert "neither the configured one nor the initial one" in str(info.value)
    assert await needs_initialisation(config(), transport=transport(server)) is False


async def test_without_a_configured_password_nothing_can_be_set_up() -> None:
    with pytest.raises(SonarInitError) as info:
        await ensure_admin_password(config(""), transport=transport(Server()))
    assert "SECURESCAN_SONARQUBE_ADMIN_PASSWORD_FILE" in str(info.value)
    assert await needs_initialisation(config(""), transport=transport(Server())) is False


async def test_a_permission_that_is_already_granted_is_not_an_error(master_key: str) -> None:
    server, cfg = Server(admin_password=ADMIN_PASSWORD), config()
    server.users.add("securescan-sonar")
    server.permissions.append(("securescan-sonar", "scan"))
    async with SonarQubeClient(cfg.sonarqube_url, username="admin", password=ADMIN_PASSWORD, transport=transport(server)) as admin:
        assert await sonar_init.ensure_service_user(admin, "securescan-sonar") == []
    assert ("securescan-sonar", "provisioning") in server.permissions


async def test_a_mode_setting_the_server_refuses_is_reported_not_fatal() -> None:
    server = Server(admin_password=ADMIN_PASSWORD)
    server.refuse_mode_setting = True
    async with SonarQubeClient("http://sonarqube:9000", username="admin", password=ADMIN_PASSWORD, transport=transport(server)) as admin:
        changes = await ensure_standard_experience(admin)
    assert len(changes) == 1 and changes[0].startswith("could not switch SonarQube to Standard Experience mode")


async def test_standard_experience_already_on_is_left_alone() -> None:
    server = Server(admin_password=ADMIN_PASSWORD)
    server.settings["sonar.multi-quality-mode.enabled"] = "false"
    async with SonarQubeClient("http://sonarqube:9000", username="admin", password=ADMIN_PASSWORD, transport=transport(server)) as admin:
        assert await ensure_standard_experience(admin) == []
    assert ("POST", "/api/settings/set") not in server.requests


async def test_no_stored_token_means_none(master_key: str) -> None:
    assert await stored_service_token(FakeSession()) is None  # type: ignore[arg-type]

