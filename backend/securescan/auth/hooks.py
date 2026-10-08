"""Post sign-in hooks.

Later milestones react to a successful sign-in without editing the auth code. M4 registers the
DefectDojo account provisioning like this (in ``securescan/domain/accounts.py``)::

    from securescan.auth.hooks import on_login

    @on_login
    async def provision_defectdojo_account(db: AsyncSession, user: User) -> None: ...

Hooks run after the user row is upserted and before the session is created, in the same
transaction. A hook that raises is logged and skipped: a DefectDojo outage must not block sign-in.
``load_hook_modules()`` imports the modules that may register hooks (missing ones are ignored).
"""

from __future__ import annotations

import importlib
from collections.abc import Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from securescan.db.models.users import User
from securescan.logging import get_logger

log = get_logger(__name__)

LoginHook = Callable[[AsyncSession, User], Awaitable[None]]

_HOOKS: list[LoginHook] = []

# Modules that register hooks when imported; absent until their milestone exists.
HOOK_MODULES = ("securescan.domain.accounts",)


def on_login(func: LoginHook) -> LoginHook:
    """Decorator: register ``func(db, user)`` to run after every successful sign-in."""
    if func not in _HOOKS:
        _HOOKS.append(func)
    return func


def load_hook_modules() -> None:
    for name in HOOK_MODULES:
        try:
            importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name != name:
                raise


async def run_login_hooks(db: AsyncSession, user: User) -> None:
    load_hook_modules()
    for hook in list(_HOOKS):
        try:
            async with db.begin_nested():
                await hook(db, user)
        except Exception as exc:  # noqa: BLE001 - provisioning must never block sign-in
            log.warning("login_hook_failed", hook=getattr(hook, "__name__", "?"), error=str(exc)[:300])
