"""Tool builders, registered automatically.

Every module in this package (except ``base``) that exposes a module-level ``BUILDER`` (an object with a
``tool`` name and the ``ToolBuilder`` methods) is registered under ``BUILDER.tool``. To add a tool: write
``securescan/runner/tools/<tool>.py`` with ``BUILDER = MyBuilder()`` and add the catalogue entry; the
scan job needs no change.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any

from securescan.runner.tools.base import DefaultToolBuilder, ToolBuilder, ToolContext

__all__ = [
    "DefaultToolBuilder",
    "ToolBuilder",
    "ToolContext",
    "get_builder",
    "register_builder",
    "registered_tools",
]

_REGISTRY: dict[str, ToolBuilder] = {}
_LOADED = False
_REQUIRED = ("applicable", "prepare", "build_command", "container_spec", "post_run", "classify_exit")


def _load() -> None:
    global _LOADED
    if _LOADED:
        return
    package = importlib.import_module(__name__)
    for info in sorted(pkgutil.iter_modules(package.__path__), key=lambda m: m.name):
        if info.name == "base" or info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{info.name}")
        builder: Any = getattr(module, "BUILDER", None)
        if builder is None:
            continue
        name = getattr(builder, "tool", "")
        if not name:
            raise RuntimeError(f"{module.__name__}.BUILDER has no tool name")
        missing = [method for method in _REQUIRED if not callable(getattr(builder, method, None))]
        if missing:
            raise RuntimeError(f"{module.__name__}.BUILDER lacks {', '.join(missing)}")
        if name in _REGISTRY and _REGISTRY[name] is not builder:
            raise RuntimeError(f"tool {name} has two builders")
        _REGISTRY[name] = builder
    _LOADED = True


def registered_tools() -> list[str]:
    _load()
    return sorted(_REGISTRY)


def get_builder(tool: str) -> ToolBuilder:
    """The builder of ``tool``; ``KeyError`` when none is registered."""
    _load()
    return _REGISTRY[tool]


def register_builder(builder: ToolBuilder) -> None:
    """Register a builder programmatically (tests, or a module that cannot expose BUILDER)."""
    _load()
    _REGISTRY[builder.tool] = builder
