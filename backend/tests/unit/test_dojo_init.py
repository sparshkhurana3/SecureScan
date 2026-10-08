"""dojo-init against a fake DefectDojo: first run, repeat run, token recovery, refusals."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest

from securescan.config import Settings
from securescan.db.models.audit import AuditEvent
from securescan.db.models.credentials import Credential
from securescan.db.models.enums import CredentialKind
from securescan.integrations.defectdojo import init
from securescan.integrations.defectdojo.client import DefectDojoClient
from securescan.security.secrets import decrypt_secret

BASE = "http://dd.test"
ADMIN_PASSWORD = "Admin-Password-1!"  # noqa: S105


class FakeDojo:
    """The slice of DefectDojo's API that dojo-init uses, with real token and privilege checks."""

    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {
            "admin": {
                "id": 1,
                "username": "admin",
                "password": ADMIN_PASSWORD,
                "is_staff": True,
                "is_superuser": True,
                "is_active": True,
                "last_login": None,
            }
        }
        self.token_of: dict[str, str] = {}
        self.user_of_token: dict[str, str] = {}
        self.counter = 0
        self.dedupe = False
        self.types: list[dict[str, Any]] = []
        self.up = True
        self.next_user_id = 10
        self.created_users: list[str] = []

    def revoke(self, username: str) -> None:
        token = self.token_of.pop(username)
        del self.user_of_token[token]

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def _user(self, request: httpx.Request) -> dict[str, Any] | None:
        header = request.headers.get("authorization", "")
        name = self.user_of_token.get(header.removeprefix("Token "))
        return self.users.get(name) if name else None

    def handle(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/v2/":
            return httpx.Response(200 if self.up else 502)
        if path == "/api/v2/api-token-auth/":
            body = json.loads(request.content)
            user = self.users.get(body["username"])
            if user is None or user["password"] != body["password"] or not user["is_active"]:
                return httpx.Response(400, json={"non_field_errors": ["Unable to log in"]})
            if body["username"] not in self.token_of:
                self.counter += 1
                token = f"{body['username']}-token-{self.counter}"
                self.token_of[body["username"]] = token
                self.user_of_token[token] = body["username"]
            return httpx.Response(200, json={"token": self.token_of[body["username"]]})
        caller = self._user(request)
        if caller is None:
            return httpx.Response(401, json={"detail": "Invalid token."})
        superuser = bool(caller["is_superuser"])
        if path == "/api/v2/user_profile/":
            return httpx.Response(200, json={"user": {k: v for k, v in caller.items() if k != "password"}})
        if path == "/api/v2/users/" and method == "GET":
            name = request.url.params.get("username")
            rows = [self._public(u) for u in self.users.values() if name in (None, u["username"])]
            return httpx.Response(200, json={"count": len(rows), "results": rows})
        if path == "/api/v2/users/" and method == "POST":
            if not superuser:
                return httpx.Response(403, json={"detail": "forbidden"})
            body = json.loads(request.content)
            self.next_user_id += 1
            user = {
                "id": self.next_user_id,
                "username": body["username"],
                "password": body["password"],
                "is_staff": body["is_staff"],
                "is_superuser": body["is_superuser"],
                "is_active": body["is_active"],
                "last_login": None,
            }
            self.users[body["username"]] = user
            self.created_users.append(body["username"])
            return httpx.Response(201, json=self._public(user))
        if path.startswith("/api/v2/users/") and method == "PATCH":
            if not superuser:
                return httpx.Response(403)
            user_id = int(path.strip("/").split("/")[-1])
            for user in self.users.values():
                if user["id"] == user_id:
                    user.update(json.loads(request.content))
                    return httpx.Response(200, json=self._public(user))
            return httpx.Response(404)
        if path == "/api/v2/system_settings/" and method == "GET":
            if not superuser:
                return httpx.Response(403)
            return httpx.Response(200, json={"results": [{"id": 1, "enable_deduplication": self.dedupe}]})
        if path == "/api/v2/system_settings/1/" and method == "PATCH":
            if not superuser:
                return httpx.Response(403)
            self.dedupe = bool(json.loads(request.content)["enable_deduplication"])
            return httpx.Response(200, json={"id": 1, "enable_deduplication": self.dedupe})
        if path == "/api/v2/product_types/" and method == "GET":
            name = request.url.params.get("name")
            return httpx.Response(200, json={"results": [t for t in self.types if name in (None, t["name"])]})
        if path == "/api/v2/product_types/" and method == "POST":
            created = {"id": len(self.types) + 1, "name": json.loads(request.content)["name"]}
            self.types.append(created)
            return httpx.Response(201, json=created)
        return httpx.Response(404)

    @staticmethod
    def _public(user: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in user.items() if k != "password"}


class InitDb:
    """Serves the two lookups dojo-init makes (credentials by kind, the admin baseline event)."""

    def __init__(self) -> None:
        self.added: list[Any] = []

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        return None

    async def scalar(self, stmt: Any) -> Any:
        sql = str(stmt)
        if "FROM credentials" in sql:
            kinds = [v for v in stmt.compile().params.values() if isinstance(v, CredentialKind)]
            for obj in reversed(self.added):
                if isinstance(obj, Credential) and obj.kind in kinds and obj.revoked_at is None:
                    return obj
            return None
        if "FROM audit_events" in sql:
            for obj in reversed(self.added):
                if isinstance(obj, AuditEvent) and obj.object_type == "defectdojo_admin":
                    return obj
        return None

    def credentials(self, kind: CredentialKind) -> list[Credential]:
        return [o for o in self.added if isinstance(o, Credential) and o.kind == kind]


class NoSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


@pytest.fixture
def settings() -> Settings:
    return Settings(defectdojo_url=BASE, defectdojo_admin_password=ADMIN_PASSWORD, defectdojo_init_wait_seconds=20)


@pytest.fixture
def setup(monkeypatch: pytest.MonkeyPatch, master_key: str) -> tuple[FakeDojo, InitDb]:
    dojo, db = FakeDojo(), InitDb()

    @asynccontextmanager
    async def fake_scope() -> Any:
        yield db

    monkeypatch.setattr(init, "session_scope", fake_scope)
    return dojo, db


async def run_init(dojo: FakeDojo, settings: Settings, sleeper: NoSleep | None = None) -> list[str]:
    return await init.initialise(settings, transport=dojo.transport(), sleep=sleeper or NoSleep())


# --- first run and repeat ------------------------------------------------------------------------------------------


async def test_first_run_sets_everything_up(setup: tuple[FakeDojo, InitDb], settings: Settings) -> None:
    dojo, db = setup
    changes = await run_init(dojo, settings)
    text = "\n".join(changes)
    assert "created DefectDojo user securescan-sync" in text
    assert "created DefectDojo user securescan-accounts" in text
    assert "enabled deduplication" in text
    assert "created product type Internal Applications" in text
    assert "created product type Vendor Applications" in text
    assert dojo.created_users == ["securescan-sync", "securescan-accounts"]
    # privileges: the importer is staff and not superuser; the accounts service is the superuser
    sync, accounts_user = dojo.users["securescan-sync"], dojo.users["securescan-accounts"]
    assert sync["is_staff"] is True and sync["is_superuser"] is False
    assert accounts_user["is_superuser"] is True
    assert dojo.dedupe is True
    assert [t["name"] for t in dojo.types] == ["Internal Applications", "Vendor Applications"]


async def test_tokens_are_stored_encrypted_and_the_admin_token_never(
    setup: tuple[FakeDojo, InitDb], settings: Settings
) -> None:
    dojo, db = setup
    await run_init(dojo, settings)
    sync = db.credentials(CredentialKind.DEFECTDOJO_TOKEN)
    superuser = db.credentials(CredentialKind.DEFECTDOJO_ADMIN_TOKEN)
    assert len(sync) == 1 and len(superuser) == 1
    assert decrypt_secret(sync[0].ciphertext, f"credential:{sync[0].id}") == dojo.token_of["securescan-sync"]
    assert decrypt_secret(superuser[0].ciphertext, f"credential:{superuser[0].id}") == dojo.token_of["securescan-accounts"]
    assert sync[0].ciphertext.startswith("ss1:")
    # the stored password lets a revoked token be replaced; it is encrypted too
    envelope = sync[0].extra["password_enc"]
    assert decrypt_secret(envelope, f"credential-password:{sync[0].id}") == dojo.users["securescan-sync"]["password"]
    assert dojo.users["securescan-sync"]["password"] not in json.dumps(sync[0].extra)
    # no credential, no audit detail, holds the admin's token
    admin_token = dojo.token_of["admin"]
    for obj in db.added:
        assert admin_token not in str(getattr(obj, "ciphertext", ""))
        assert admin_token not in json.dumps(getattr(obj, "detail", {}) or {}, default=str)
    assert sync[0].extra["username"] == "securescan-sync"


async def test_a_repeat_run_changes_nothing(setup: tuple[FakeDojo, InitDb], settings: Settings) -> None:
    dojo, db = setup
    await run_init(dojo, settings)
    stored = len(db.added)
    users = dict(dojo.users)
    again = await run_init(dojo, settings)
    assert again == []
    assert len(db.added) == stored
    assert dojo.users.keys() == users.keys()
    assert dojo.created_users == ["securescan-sync", "securescan-accounts"]
    assert len(dojo.types) == 2


async def test_the_baseline_of_the_admin_account_is_recorded_once(
    setup: tuple[FakeDojo, InitDb], settings: Settings
) -> None:
    dojo, db = setup
    dojo.users["admin"]["last_login"] = "2026-10-06T08:00:00Z"
    await run_init(dojo, settings)
    events = [o for o in db.added if isinstance(o, AuditEvent)]
    assert [e.action for e in events] == ["defectdojo.admin_baseline"]
    assert events[0].detail["last_login"] == "2026-10-06T08:00:00Z"


# --- recovery and drift ---------------------------------------------------------------------------------------------------


async def test_a_revoked_token_is_replaced_with_the_stored_password(
    setup: tuple[FakeDojo, InitDb], settings: Settings
) -> None:
    dojo, db = setup
    await run_init(dojo, settings)
    old = db.credentials(CredentialKind.DEFECTDOJO_TOKEN)[0]
    dojo.revoke("securescan-sync")
    changes = await run_init(dojo, settings)
    assert changes == ["stored a token for securescan-sync"]
    assert dojo.created_users == ["securescan-sync", "securescan-accounts"]  # not created again
    credentials = db.credentials(CredentialKind.DEFECTDOJO_TOKEN)
    assert len(credentials) == 2
    assert old.revoked_at is not None
    new = credentials[-1]
    assert decrypt_secret(new.ciphertext, f"credential:{new.id}") == dojo.token_of["securescan-sync"]


async def test_wrong_privileges_are_corrected(setup: tuple[FakeDojo, InitDb], settings: Settings) -> None:
    dojo, db = setup
    await run_init(dojo, settings)
    dojo.users["securescan-sync"]["is_superuser"] = True
    dojo.users["securescan-sync"]["is_active"] = True
    changes = await run_init(dojo, settings)
    assert changes == ["corrected securescan-sync: is_superuser"]
    assert dojo.users["securescan-sync"]["is_superuser"] is False


async def test_a_user_without_a_stored_credential_is_reported_not_deleted(
    setup: tuple[FakeDojo, InitDb], settings: Settings
) -> None:
    dojo, db = setup
    dojo.users["securescan-sync"] = {
        "id": 5,
        "username": "securescan-sync",
        "password": "unknown",
        "is_staff": True,
        "is_superuser": False,
        "is_active": True,
        "last_login": None,
    }
    with pytest.raises(init.InitError) as caught:
        await run_init(dojo, settings)
    assert "securescan-sync" in str(caught.value)
    assert "securescan-sync" in dojo.users  # nothing was deleted


# --- waiting and logging in ------------------------------------------------------------------------------------------------------------


async def test_it_waits_until_defectdojo_answers() -> None:
    state = {"pings": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["pings"] += 1
        return httpx.Response(502 if state["pings"] < 3 else 401)

    sleeper = NoSleep()
    assert await init.wait_for_defectdojo(BASE, 60, transport=httpx.MockTransport(handler), sleep=sleeper) is True
    assert sleeper.calls == [5.0, 5.0]


async def test_it_gives_up_when_defectdojo_never_answers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    sleeper = NoSleep()
    assert await init.wait_for_defectdojo(BASE, 10, transport=httpx.MockTransport(handler), sleep=sleeper) is False
    assert sleeper.calls == [5.0, 5.0]


async def test_a_wrong_admin_password_is_a_clear_error(settings: Settings) -> None:
    dojo = FakeDojo()
    wrong = Settings(defectdojo_url=BASE, defectdojo_admin_password="not-the-password")
    with pytest.raises(init.InitError) as caught:
        await init.admin_token(wrong, transport=dojo.transport(), sleep=NoSleep(), attempts=2)
    assert "dd_admin_password" in str(caught.value)
    assert "not-the-password" not in str(caught.value)


async def test_a_missing_admin_password_stops_early(setup: tuple[FakeDojo, InitDb]) -> None:
    dojo, _ = setup
    with pytest.raises(init.InitError):
        await init.initialise(Settings(defectdojo_url=BASE, defectdojo_admin_password=""), transport=dojo.transport())


async def test_dedup_and_product_types_are_idempotent() -> None:
    dojo = FakeDojo()
    token = await DefectDojoClient.obtain_token(BASE, "admin", ADMIN_PASSWORD, transport=dojo.transport())
    async with DefectDojoClient(BASE, token, transport=dojo.transport()) as client:
        assert await init.ensure_deduplication(client) == ["enabled deduplication in the system settings"]
        assert await init.ensure_deduplication(client) == []
        assert len(await init.ensure_product_types(client)) == 2
        assert await init.ensure_product_types(client) == []


def test_service_account_definitions(settings: Settings) -> None:
    sync, accounts_account = init.service_accounts(settings)
    assert (sync.username, sync.is_staff, sync.is_superuser) == ("securescan-sync", True, False)
    assert (accounts_account.username, accounts_account.is_superuser) == ("securescan-accounts", True)
    assert sync.kind == CredentialKind.DEFECTDOJO_TOKEN
    assert accounts_account.kind == CredentialKind.DEFECTDOJO_ADMIN_TOKEN


async def test_baseline_helper_does_nothing_when_one_exists(
    setup: tuple[FakeDojo, InitDb], settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    dojo, db = setup

    async def existing(session: Any) -> str | None:
        return ""

    monkeypatch.setattr(init, "_last_admin_login_seen", existing)
    token = await DefectDojoClient.obtain_token(BASE, "admin", ADMIN_PASSWORD, transport=dojo.transport())
    async with DefectDojoClient(BASE, token, transport=dojo.transport()) as admin:
        assert await init.ensure_admin_baseline(db, admin, settings) == []  # type: ignore[arg-type]
