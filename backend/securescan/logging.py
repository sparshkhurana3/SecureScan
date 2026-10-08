"""structlog configuration: JSON lines on stdout, secret scrubbing, job context.

Usage in any module::

    from securescan.logging import get_logger
    log = get_logger(__name__)
    log.info("scan_started", scan_id=str(scan.id), tool="semgrep")

``bind_job_context(scan_id=..., job_id=..., tool=...)`` adds those keys to every later line of the
current asyncio task. Request bodies, tokens and file contents are never logged.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog

# (pattern, replacement) - token shapes that must never reach a log line (plan section 1.2).
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "[redacted-github-token]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "[redacted-github-token]"),
    (re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{16,}"), r"\1[redacted]"),
    (re.compile(r"\b(Token\s+)[A-Za-z0-9._-]{16,}"), r"\1[redacted]"),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
        "[redacted-private-key]",
    ),
]

_SENSITIVE_KEY = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|ciphertext)")


def scrub(text: str) -> str:
    """Replace known secret shapes in ``text``."""
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def scrub_value(value: Any) -> Any:
    """Scrub strings inside nested lists, tuples and dicts; mask values of sensitive keys."""
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, dict):
        return {
            k: ("[redacted]" if isinstance(k, str) and _SENSITIVE_KEY.search(k) and v else scrub_value(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [scrub_value(v) for v in value]
    return value


def scrub_processor(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """structlog processor: scrub every value of the event dict."""
    for key, value in list(event_dict.items()):
        if key in ("event", "level", "timestamp", "logger"):
            if isinstance(value, str):
                event_dict[key] = scrub(value)
            continue
        if _SENSITIVE_KEY.search(key) and value:
            event_dict[key] = "[redacted]"
        else:
            event_dict[key] = scrub_value(value)
    return event_dict


def _json_dumps(obj: Any, **kwargs: Any) -> str:
    return json.dumps(obj, default=str, **kwargs)


def configure_logging(level: str = "INFO") -> None:
    """Configure structlog and route the standard library loggers (uvicorn, procrastinate) through it."""
    numeric = getattr(logging, level.upper(), logging.INFO)
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        scrub_processor,
    ]
    structlog.configure(
        processors=[*shared, structlog.processors.JSONRenderer(serializer=_json_dumps)],
        wrapper_class=structlog.make_filtering_bound_logger(numeric),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(serializer=_json_dumps),
            foreign_pre_chain=shared,
        )
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(numeric)
    for noisy in ("uvicorn.access",):
        logging.getLogger(noisy).setLevel(max(numeric, logging.WARNING))


def get_logger(name: str | None = None) -> Any:
    """A structlog logger (JSON, scrubbed). Works before ``configure_logging`` too."""
    return structlog.get_logger(name)


def bind_job_context(**values: Any) -> None:
    """Add ``scan_id`` / ``job_id`` / ``tool`` (or any key) to every later log line of this task."""
    structlog.contextvars.bind_contextvars(**{k: str(v) for k, v in values.items() if v is not None})


def clear_job_context() -> None:
    structlog.contextvars.clear_contextvars()
