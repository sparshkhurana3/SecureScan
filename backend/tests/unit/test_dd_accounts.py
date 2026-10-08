"""DefectDojo accounts: provisioning, one-time password, role sync, expiry, break-glass detection."""

from __future__ import annotations

import string
import types
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from securescan.db.models.enums import UserRole
from securescan.db.models.users import User
from securescan.domain import accounts
from securescan.domain.accounts import (
    PasswordResetUnavailable,
    desired_flags,
    ensure_account,
    expire_inactive_accounts,
    generate_password,
    is_expired,
    read_account,
    reset_password,
    split_name,
    unique_username,
    username_candidate,
)
from securescan.integrations.defectdojo.client import (
    DefectDojoError,
    DefectDojoNotFound,
    DefectDojoRejected,
)
from securescan.integrations.defectdojo.factory import DefectDojoNotConfigured
from securescan.security.secrets import decrypt_secret
from securescan.util import new_id

UTC = timezone.utc
NOW = datetime(2026, 10, 7, 4, 0, tzinfo=UTC)


class FakeDD:
    """The parts of DefectDojoClient the accounts code calls, recording what it was asked."""

    def __init__(self, users: dict[str, dict[str, Any]] | None = None) -> None:
        self.users: dict[str, dict[str, Any]] = users or {}
        self.created: list[dict[str, Any]] = []
        self.patched: list[tuple[int, dict[str, Any]]] = []
        self.forced: list[int] = []
        self.passwords: list[tuple[int, str]] = []
        self.fail_force = False
        self.refuse_password = False
        self.fail_patch_for: set[int] = set()
        self._next = 100

    async def find_user(self, username: str) -> dict[str, Any] | None:
        return self.users.get(username)

    async def get_user(self, user_id: int) -> dict[str, Any]:
        for user in self.users.values():
            if user["id"] == user_id:
                return user
        raise DefectDojoNotFound("no such user", status_code=404)

    async def create_user(self, **kwargs: Any) -> dict[str, Any]:
        self._next += 1
        self.created.append(kwargs)
        user = {
            "id": self._next,
            "username": kwargs["username"],
            "is_staff": kwargs["is_staff"],
            "is_superuser": kwargs["is_superuser"],
            "is_active": True,
        }
        self.users[kwargs["username"]] = user
        return user

    async def patch_user(self, user_id: int, fields: dict[str, Any]) -> dict[str, Any]:
        if user_id in self.fail_patch_for:
            raise DefectDojoError("DefectDojo is busy")
        self.patched.append((user_id, dict(fields)))
        for user in self.users.values():
            if user["id"] == user_id:
                user.update(fields)
        return {}

    async def set_force_password_reset(self, user_id: int) -> None:
        if self.fail_force:
            raise DefectDojoError("not allowed")
        self.forced.append(user_id)

    async def set_user_password(self, user_id: int, password: str) -> None:
        if self.refuse_password:
            raise DefectDojoRejected("Update of password though API is not allowed", status_code=400)
        self.passwords.append((user_id, password))


class Db:
    """A minimal AsyncSession stand-in: ``scalar`` answers come from a queue, ``scalars`` from rows."""

    def __init__(self, scalar_answers: list[Any] | None = None, rows: list[Any] | None = None) -> None:
        self.added: list[Any] = []
        self._answers = list(scalar_answers or [])
        self._rows = rows or []

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def scalar(self, stmt: Any) -> Any:
        return self._answers.pop(0) if self._answers else None

    async def scalars(self, stmt: Any) -> Any:
        return types.SimpleNamespace(all=lambda: list(self._rows))

    @property
    def actions(self) -> list[str]:
        return [getattr(o, "action", "") for o in self.added]


def make_user(role: UserRole = UserRole.ANALYST, **overrides: Any) -> User:
    values: dict[str, Any] = {
        "id": new_id(),
        "oid": "11111111-2222-3333-4444-555555555555",
        "name": "Jane Doe",
        "email": "jane.doe@sona.example",
        "upn": "jane.doe@sona.example",
        "role": role,
        "roles": [role.value],
        "dd_disabled": False,
        "created_at": NOW - timedelta(days=200),
        "updated_at": NOW - timedelta(days=1),
        "last_login": NOW - timedelta(days=1),
    }
    values.update(overrides)
    return User(**values)


# --- pure helpers --------------------------------------------------------------------------------------------------


def test_generated_passwords_meet_defectdojos_validators() -> None:
    seen = set()
    for _ in range(300):
        password = generate_password()
        assert len(password) == 20
        assert any(c in string.ascii_uppercase for c in password)
        assert any(c in string.ascii_lowercase for c in password)
        assert any(c in string.digits for c in password)
        assert any(c in accounts._SYMBOLS for c in password)
        seen.add(password)
    assert len(seen) == 300
    assert len(generate_password(32)) == 32
    with pytest.raises(ValueError):
        generate_password(8)


def test_username_is_the_local_part_of_the_upn() -> None:
    assert username_candidate(make_user()) == "jane.doe"
    guest = make_user(upn="Jane_Ext#EXT#@tenant.onmicrosoft.com", email=None)
    assert username_candidate(guest) == "jane_ext_ext"
    assert username_candidate(make_user(upn=None, email="Bob.Smith@x.example")) == "bob.smith"
    anonymous = make_user(upn=None, email=None, oid="ABCDEF12-0000-0000-0000-000000000000")
    assert username_candidate(anonymous) == "user-abcdef12"


def test_split_name_and_flags() -> None:
    assert split_name("Jane Q. Doe") == ("Jane", "Q. Doe")
    assert split_name("Prince") == ("Prince", "")
    assert split_name(None) == ("", "")
    assert desired_flags(UserRole.ADMIN) == {"is_superuser": True, "is_staff": True}
    assert desired_flags(UserRole.ANALYST) == {"is_superuser": False, "is_staff": True}


async def test_a_taken_or_reserved_name_gets_a_suffix() -> None:
    user = make_user()
    assert await unique_username(Db(), user) == "jane.doe"  # type: ignore[arg-type]
    taken = await unique_username(Db([uuid.uuid4()]), user)  # type: ignore[arg-type]
    assert taken == "jane.doe-111111"
    admin_like = make_user(upn="admin@sona.example")
    assert (await unique_username(Db(), admin_like)).startswith("admin-")  # type: ignore[arg-type]


# --- provisioning ----------------------------------------------------------------------------------------------------


async def test_first_sign_in_creates_a_staff_account_for_an_analyst(master_key: str) -> None:
    dd, db, user = FakeDD(), Db(), make_user()
    assert await ensure_account(db, dd, user) is True  # type: ignore[arg-type]
    created = dd.created[0]
    assert created["username"] == "jane.doe"
    assert created["email"] == "jane.doe@sona.example"
    assert (created["first_name"], created["last_name"]) == ("Jane", "Doe")
    assert created["is_staff"] is True and created["is_superuser"] is False
    assert len(created["password"]) == 20
    assert user.dd_user_id == 101
    assert user.dd_username == "jane.doe"
    assert user.dd_secret_shown_at is None
    # the initial password is stored encrypted, bound to this user, and equals what DefectDojo got
    assert user.dd_initial_secret and created["password"] not in user.dd_initial_secret
    assert decrypt_secret(user.dd_initial_secret, f"user-dd:{user.id}") == created["password"]
    assert dd.forced == [101]
    assert db.actions == ["defectdojo_account.create"]


async def test_an_admin_becomes_a_superuser(master_key: str) -> None:
    dd, user = FakeDD(), make_user(UserRole.ADMIN, upn="root.admin@sona.example")
    await ensure_account(Db(), dd, user)  # type: ignore[arg-type]
    assert dd.created[0]["is_superuser"] is True


async def test_a_failed_forced_reset_does_not_undo_the_account(master_key: str) -> None:
    dd, db, user = FakeDD(), Db(), make_user()
    dd.fail_force = True
    assert await ensure_account(db, dd, user) is True  # type: ignore[arg-type]
    assert user.dd_user_id is not None
    assert db.added[-1].detail["forced_change"] is False


async def test_a_second_sign_in_changes_nothing() -> None:
    user = make_user(dd_user_id=5, dd_username="jane.doe")
    dd = FakeDD({"jane.doe": {"id": 5, "username": "jane.doe", "is_staff": True, "is_superuser": False, "is_active": True}})
    db = Db()
    assert await ensure_account(db, dd, user) is False  # type: ignore[arg-type]
    assert dd.created == [] and dd.patched == []
    assert db.added == []


async def test_a_role_change_updates_the_flags() -> None:
    user = make_user(UserRole.ADMIN, dd_user_id=5, dd_username="jane.doe")
    dd = FakeDD({"jane.doe": {"id": 5, "username": "jane.doe", "is_staff": True, "is_superuser": False, "is_active": True}})
    db = Db()
    await ensure_account(db, dd, user)  # type: ignore[arg-type]
    assert dd.patched == [(5, {"is_superuser": True})]
    assert db.actions == ["defectdojo_account.update"]


async def test_an_account_deleted_in_defectdojo_is_created_again(master_key: str) -> None:
    user = make_user(dd_user_id=5, dd_username="jane.doe")
    dd = FakeDD()  # user 5 no longer exists
    assert await ensure_account(Db(), dd, user) is True  # type: ignore[arg-type]
    assert user.dd_user_id == 101
    assert user.dd_initial_secret


async def test_an_existing_defectdojo_user_is_adopted_not_touched() -> None:
    dd = FakeDD({"jane.doe": {"id": 42, "username": "jane.doe", "is_staff": False, "is_superuser": False}})
    user, db = make_user(), Db()
    assert await ensure_account(db, dd, user) is False  # type: ignore[arg-type]
    assert dd.created == []
    assert user.dd_user_id == 42
    assert user.dd_initial_secret is None  # we never knew its password
    assert dd.patched == [(42, {"is_staff": True})]
    assert db.actions == ["defectdojo_account.adopt"]


async def test_sign_in_after_automatic_expiry_re_enables_the_account(monkeypatch: pytest.MonkeyPatch) -> None:
    async def expired(session: Any, user_id: Any) -> str:
        return "expire"

    monkeypatch.setattr(accounts, "last_disable_reason", expired)
    user = make_user(dd_user_id=5, dd_username="jane.doe", dd_disabled=True, dd_disabled_at=NOW)
    dd = FakeDD({"jane.doe": {"id": 5, "username": "jane.doe", "is_staff": True, "is_superuser": False, "is_active": False}})
    db = Db()
    await ensure_account(db, dd, user)  # type: ignore[arg-type]
    assert dd.patched == [(5, {"is_active": True})]
    assert user.dd_disabled is False and user.dd_disabled_at is None
    assert "defectdojo_account.enable" in db.actions


async def test_an_admin_disabled_account_stays_disabled_at_sign_in(monkeypatch: pytest.MonkeyPatch) -> None:
    async def disabled_by_admin(session: Any, user_id: Any) -> str:
        return "disable"

    monkeypatch.setattr(accounts, "last_disable_reason", disabled_by_admin)
    user = make_user(dd_user_id=5, dd_username="jane.doe", dd_disabled=True)
    dd = FakeDD({"jane.doe": {"id": 5, "username": "jane.doe", "is_staff": True, "is_superuser": False, "is_active": False}})
    await ensure_account(Db(), dd, user)  # type: ignore[arg-type]
    assert dd.patched == []
    assert user.dd_disabled is True


# --- the account page -------------------------------------------------------------------------------------------------------


async def test_the_initial_password_is_shown_once(master_key: str) -> None:
    dd, db, user = FakeDD(), Db(), make_user()
    await ensure_account(db, dd, user)  # type: ignore[arg-type]
    password = dd.created[0]["password"]
    first = await read_account(db, user)  # type: ignore[arg-type]
    assert first.status == "ready"
    assert first.initial_password == password
    assert first.username == "jane.doe"
    assert first.must_change_password is True
    assert user.dd_initial_secret is None  # cleared as it was read
    assert user.dd_secret_shown_at is not None
    second = await read_account(db, user)  # type: ignore[arg-type]
    assert second.initial_password is None
    assert second.password_shown is True
    assert "defectdojo_account.password_shown" in db.actions


async def test_the_account_page_reports_unavailable_when_defectdojo_is_not_set_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def not_configured(session: Any, *, quick: bool = False) -> Any:
        raise DefectDojoNotConfigured("run dojo-init")

    monkeypatch.setattr(accounts, "accounts_client", not_configured)
    view = await read_account(Db(), make_user())  # type: ignore[arg-type]
    assert view.status == "unavailable"
    assert view.initial_password is None
    assert view.detail


# --- password reset ---------------------------------------------------------------------------------------------------------------


async def test_reset_returns_a_new_password_and_forces_a_change(master_key: str) -> None:
    dd, db = FakeDD(), Db()
    user = make_user(dd_user_id=5, dd_username="jane.doe", dd_initial_secret="x")
    password = await reset_password(db, dd, user)  # type: ignore[arg-type]
    assert dd.passwords == [(5, password)]
    assert dd.forced == [5]
    assert user.dd_initial_secret is None
    assert db.actions == ["defectdojo_account.reset"]


async def test_reset_explains_when_defectdojo_refuses() -> None:
    dd = FakeDD()
    dd.refuse_password = True
    user = make_user(dd_user_id=5)
    with pytest.raises(PasswordResetUnavailable) as caught:
        await reset_password(Db(), dd, user)  # type: ignore[arg-type]
    assert "Admin" in str(caught.value)
    with pytest.raises(PasswordResetUnavailable):
        await reset_password(Db(), FakeDD(), make_user())  # type: ignore[arg-type]


# --- expiry ---------------------------------------------------------------------------------------------------------------------------


def test_expiry_is_after_ninety_days_of_no_activity() -> None:
    quiet = make_user(
        dd_user_id=5, last_login=NOW - timedelta(days=91), updated_at=NOW - timedelta(days=91)
    )
    recent = make_user(dd_user_id=6, last_login=NOW - timedelta(days=89), updated_at=NOW - timedelta(days=89))
    assert is_expired(quiet, NOW, 90)
    assert not is_expired(recent, NOW, 90)
    assert not is_expired(make_user(dd_user_id=None, last_login=NOW - timedelta(days=500)), NOW, 90)
    already = make_user(dd_user_id=7, dd_disabled=True, last_login=NOW - timedelta(days=500))
    assert not is_expired(already, NOW, 90)


def test_an_admin_re_enabling_restarts_the_clock() -> None:
    user = make_user(dd_user_id=5, last_login=NOW - timedelta(days=200), updated_at=NOW - timedelta(days=2))
    assert not is_expired(user, NOW, 90)


def test_a_user_who_never_signed_in_expires_from_creation() -> None:
    user = make_user(dd_user_id=5, last_login=None, created_at=NOW - timedelta(days=100), updated_at=NOW - timedelta(days=100))
    assert is_expired(user, NOW, 90)


async def test_expiry_disables_only_the_inactive_accounts() -> None:
    old = make_user(dd_user_id=5, dd_username="old", last_login=NOW - timedelta(days=120), updated_at=NOW - timedelta(days=120))
    fresh = make_user(dd_user_id=6, dd_username="fresh", oid="2" * 36)
    no_account = make_user(dd_user_id=None, oid="3" * 36, last_login=NOW - timedelta(days=500))
    dd = FakeDD({"old": {"id": 5}, "fresh": {"id": 6}})
    db = Db(rows=[old, fresh, no_account])
    done = await expire_inactive_accounts(db, dd, now=NOW)  # type: ignore[arg-type]
    assert done == [old.id]
    assert dd.patched == [(5, {"is_active": False})]
    assert old.dd_disabled is True and old.dd_disabled_at is not None
    assert fresh.dd_disabled is False
    assert db.actions == ["defectdojo_account.expire"]


async def test_one_failure_does_not_stop_the_others() -> None:
    a = make_user(dd_user_id=5, dd_username="a", last_login=NOW - timedelta(days=120), updated_at=NOW - timedelta(days=120))
    b = make_user(dd_user_id=6, dd_username="b", oid="2" * 36, last_login=NOW - timedelta(days=120), updated_at=NOW - timedelta(days=120))
    dd = FakeDD({"a": {"id": 5}, "b": {"id": 6}})
    dd.fail_patch_for = {5}
    done = await expire_inactive_accounts(Db(rows=[a, b]), dd, now=NOW)  # type: ignore[arg-type]
    assert done == [b.id]
    assert a.dd_disabled is False


# --- break-glass --------------------------------------------------------------------------------------------------------------------------


class AdminDD:
    def __init__(self, last_login: str | None) -> None:
        self.last_login = last_login

    async def find_user(self, username: str) -> dict[str, Any] | None:
        return {"id": 1, "username": username, "last_login": self.last_login}


async def test_break_glass_detects_a_changed_last_login(monkeypatch: pytest.MonkeyPatch) -> None:
    async def seen(session: Any) -> str | None:
        return "2026-09-01T10:00:00Z"

    monkeypatch.setattr(accounts, "_last_admin_login_seen", seen)
    before = accounts.BREAK_GLASS_LOGINS.labels(tool="defectdojo")._value.get()  # noqa: SLF001
    db = Db()
    assert await accounts.check_break_glass(db, AdminDD("2026-10-06T22:15:00Z")) is True  # type: ignore[arg-type]
    assert db.actions == ["defectdojo.break_glass_login"]
    assert db.added[0].detail["last_login"] == "2026-10-06T22:15:00Z"
    assert accounts.BREAK_GLASS_LOGINS.labels(tool="defectdojo")._value.get() == before + 1  # noqa: SLF001


async def test_break_glass_ignores_an_unchanged_last_login(monkeypatch: pytest.MonkeyPatch) -> None:
    async def seen(session: Any) -> str | None:
        return "2026-09-01T10:00:00Z"

    monkeypatch.setattr(accounts, "_last_admin_login_seen", seen)
    db = Db()
    assert await accounts.check_break_glass(db, AdminDD("2026-09-01T10:00:00Z")) is False  # type: ignore[arg-type]
    assert db.added == []


async def test_break_glass_records_a_baseline_when_the_admin_never_logged_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def nothing(session: Any) -> str | None:
        return None

    monkeypatch.setattr(accounts, "_last_admin_login_seen", nothing)
    db = Db()
    assert await accounts.check_break_glass(db, AdminDD(None)) is False  # type: ignore[arg-type]
    assert db.actions == ["defectdojo.admin_baseline"]


async def test_break_glass_without_a_baseline_but_with_a_login_counts_as_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def nothing(session: Any) -> str | None:
        return None

    monkeypatch.setattr(accounts, "_last_admin_login_seen", nothing)
    assert await accounts.check_break_glass(Db(), AdminDD("2026-10-01T00:00:00Z")) is True  # type: ignore[arg-type]
