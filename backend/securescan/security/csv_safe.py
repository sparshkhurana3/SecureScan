"""CSV output that spreadsheet programs cannot turn into formulas (plan section 1.2).

A cell that starts with ``=``, ``+``, ``-``, ``@``, a tab or a carriage return is prefixed with ``'``.
Use ``csv_safe_row`` for every row written to a CSV export (history, report finding lists).
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Iterator
from typing import Any

DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe_cell(value: Any) -> str:
    """The cell as text, with a leading ``'`` when it could be read as a formula. None is empty."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if text.startswith(DANGEROUS_PREFIXES):
        return "'" + text
    return text


def csv_safe_row(values: Iterable[Any]) -> list[str]:
    return [csv_safe_cell(v) for v in values]


def csv_line(values: Iterable[Any]) -> str:
    """One CSV line (RFC 4180 quoting, CRLF line end) for the safe version of ``values``."""
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\r\n").writerow(csv_safe_row(values))
    return buffer.getvalue()


def iter_csv(header: Iterable[str], rows: Iterable[Iterable[Any]]) -> Iterator[str]:
    """Yield the header line, then one line per row (header cells are fixed text, still escaped)."""
    yield csv_line(header)
    for row in rows:
        yield csv_line(row)
