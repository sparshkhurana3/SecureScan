"""The ``/api/v1`` router. Every module in ``securescan/api/`` that exposes a module-level
``router`` (``fastapi.APIRouter``) is included automatically, so a new endpoint module needs no
registration. Give each router its own ``tags=[...]`` and no ``/api/v1`` prefix.
"""

from __future__ import annotations

import importlib
import pkgutil

from fastapi import APIRouter

import securescan.api as api_package

API_PREFIX = "/api/v1"

# Modules that are helpers, not routers.
_SKIP = frozenset({"router", "problems", "pagination", "schemas", "middleware"})


def build_api_router() -> APIRouter:
    api_router = APIRouter(prefix=API_PREFIX)
    for module_info in sorted(pkgutil.iter_modules(api_package.__path__), key=lambda m: m.name):
        if module_info.name in _SKIP or module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{api_package.__name__}.{module_info.name}")
        router = getattr(module, "router", None)
        if isinstance(router, APIRouter):
            api_router.include_router(router)
    return api_router
