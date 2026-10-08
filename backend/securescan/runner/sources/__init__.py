"""Sources: how a job's ``src`` directory gets filled.

A handler is an ``async`` function ``(SourceRequest) -> SourceInfo`` registered for a target kind:

* ``zip``                          -> ``sources/zip.py`` (safe unpack of an uploaded archive)
* ``github_repo``, ``vendor_repo`` -> ``sources/github.py`` (full-history clone, remote removed)
* ``image``                        -> registered by M8 (``sources/image.py``: skopeo + rootfs extract)

Other milestones call ``register_source_handler(kind, handler)`` from their own module; ``acquire_source``
dispatches. Nothing here parses the scanned code.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from securescan.runner.sources.base import SourceError, SourceInfo, SourceRequest

SourceHandler = Callable[[SourceRequest], Awaitable[SourceInfo]]

_HANDLERS: dict[str, SourceHandler] = {}

__all__ = [
    "SourceError",
    "SourceHandler",
    "SourceInfo",
    "SourceRequest",
    "acquire_source",
    "register_source_handler",
    "supported_kinds",
]


def register_source_handler(kind: str, handler: SourceHandler) -> None:
    """Register (or replace) the handler for a target kind (``zip``, ``github_repo``, ``image`` ...)."""
    _HANDLERS[kind] = handler


def supported_kinds() -> list[str]:
    _ensure_defaults()
    return sorted(_HANDLERS)


_DEFAULTS_LOADED = False


def _ensure_defaults() -> None:
    """Register the built-in handlers once (a handler registered earlier for the same kind wins)."""
    global _DEFAULTS_LOADED
    if _DEFAULTS_LOADED:
        return
    from securescan.runner.sources.github import acquire_repository
    from securescan.runner.sources.zip import acquire_zip

    _HANDLERS.setdefault("zip", acquire_zip)
    _HANDLERS.setdefault("github_repo", acquire_repository)
    _HANDLERS.setdefault("vendor_repo", acquire_repository)
    _DEFAULTS_LOADED = True


async def acquire_source(request: SourceRequest) -> SourceInfo:
    """Fill ``request.workspace.src`` for the target's kind."""
    _ensure_defaults()
    kind = request.target.kind.value
    handler = _HANDLERS.get(kind)
    if handler is None:
        raise SourceError(
            f"Scanning a {kind} target is not available in this version.", code="source.unsupported_kind"
        )
    return await handler(request)
