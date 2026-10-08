"""Cron parsing, blackout windows and the "is this schedule due" decision (UTC, standard library only).

Used by the schedule evaluator (``securescan/jobs/schedules.py``) for weekly repository scans and
DAST schedules, and by the schedules API to validate input and compute the next run.

Cron syntax: five fields ``minute hour day-of-month month day-of-week``; each field is a comma list of
``*``, ``a``, ``a-b``, optionally with ``/step`` (``*/15``, ``10-50/10``, ``5/20``). Month and weekday
names (``jan``, ``mon``) are accepted; weekday 0 and 7 are both Sunday. When both day-of-month and
day-of-week are restricted, a day matches if either does (the traditional cron rule).

Blackout windows are the dictionaries of ``securescan.api.schemas.BlackoutWindow``: one-off
(``starts_at`` / ``ends_at``, ISO 8601 UTC) or weekly (``days`` 0 = Monday ... 6 = Sunday, ``start`` /
``end`` as ``HH:MM`` UTC; ``end`` earlier than ``start`` crosses midnight; equal means the whole day).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

UTC = timezone.utc

DEFAULT_WEEKLY_CRON = "0 2 * * 0"  # Sunday 02:00 UTC
MAX_BLACKOUT_DELAY = timedelta(hours=24)

_MONTH_NAMES = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}  # fmt: skip
_DAY_NAMES = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
_SEARCH_YEARS = 5


class CronError(ValueError):
    """The cron expression or a blackout window is not valid."""


@dataclass(frozen=True)
class CronSpec:
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]  # day of month
    months: frozenset[int]
    weekdays: frozenset[int]  # 0 = Sunday ... 6 = Saturday
    days_restricted: bool
    weekdays_restricted: bool

    def day_matches(self, moment: datetime) -> bool:
        dom_ok = moment.day in self.days
        dow_ok = ((moment.weekday() + 1) % 7) in self.weekdays  # Python: Monday = 0
        if self.days_restricted and self.weekdays_restricted:
            return dom_ok or dow_ok
        return dom_ok and dow_ok


def _parse_number(text: str, names: Mapping[str, int], low: int, high: int, field: str) -> int:
    token = text.lower()
    if token in names:
        return names[token]
    if not token.isdigit():
        raise CronError("%s: %r is not a number" % (field, text))
    value = int(token)
    if value < low or value > high:
        raise CronError("%s: %d is outside %d-%d" % (field, value, low, high))
    return value


def _parse_field(
    text: str, low: int, high: int, field: str, names: Mapping[str, int] | None = None
) -> frozenset[int]:
    names = names or {}
    values: set[int] = set()
    if not text:
        raise CronError("%s is empty" % field)
    for part in text.split(","):
        if not part:
            raise CronError("%s has an empty list item" % field)
        step = 1
        base = part
        if "/" in part:
            base, _, step_text = part.partition("/")
            if not step_text.isdigit() or int(step_text) < 1:
                raise CronError("%s: step %r must be a positive number" % (field, step_text))
            step = int(step_text)
        if base in ("*", "?"):
            start, end = low, high
        elif "-" in base:
            first, _, last = base.partition("-")
            start = _parse_number(first, names, low, high, field)
            end = _parse_number(last, names, low, high, field)
            if end < start:
                raise CronError("%s: range %r runs backwards" % (field, base))
        else:
            start = _parse_number(base, names, low, high, field)
            end = high if "/" in part else start
        values.update(range(start, end + 1, step))
    return frozenset(values)


def parse_cron(expression: str) -> CronSpec:
    """Parse a five-field cron expression; raises ``CronError`` with a plain-language reason."""
    fields = expression.split()
    if len(fields) != 5:
        raise CronError(
            "A cron expression has five fields: minute hour day-of-month month day-of-week"
        )
    minute, hour, dom, month, dow = fields
    minutes = _parse_field(minute, 0, 59, "minute")
    hours = _parse_field(hour, 0, 23, "hour")
    days = _parse_field(dom, 1, 31, "day of month")
    months = _parse_field(month, 1, 12, "month", _MONTH_NAMES)
    raw_weekdays = _parse_field(dow, 0, 7, "day of week", _DAY_NAMES)
    weekdays = frozenset(0 if d == 7 else d for d in raw_weekdays)
    return CronSpec(
        minutes=minutes,
        hours=hours,
        days=days,
        months=months,
        weekdays=weekdays,
        days_restricted=not dom.startswith(("*", "?")),
        weekdays_restricted=not dow.startswith(("*", "?")),
    )


def _as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _start_of_next_month(moment: datetime) -> datetime:
    if moment.month == 12:
        return moment.replace(year=moment.year + 1, month=1, day=1, hour=0, minute=0)
    return moment.replace(month=moment.month + 1, day=1, hour=0, minute=0)


def next_run(spec: CronSpec | str, after: datetime) -> datetime:
    """The first matching minute strictly after ``after`` (UTC). Raises ``CronError`` if none within 5 years."""
    if isinstance(spec, str):
        spec = parse_cron(spec)
    start = _as_utc(after).replace(second=0, microsecond=0)
    candidate = start + timedelta(minutes=1)
    limit = start + timedelta(days=366 * _SEARCH_YEARS)
    while candidate <= limit:
        if candidate.month not in spec.months:
            candidate = _start_of_next_month(candidate)
        elif not spec.day_matches(candidate):
            candidate = (candidate + timedelta(days=1)).replace(hour=0, minute=0)
        elif candidate.hour not in spec.hours:
            candidate = (candidate + timedelta(hours=1)).replace(minute=0)
        elif candidate.minute not in spec.minutes:
            candidate = candidate + timedelta(minutes=1)
        else:
            return candidate
    raise CronError("This cron expression never matches a real date")


def validate_cron_expression(expression: str) -> str:
    """Return the normalised expression (single spaces) or raise ``CronError``."""
    spec = parse_cron(expression)
    next_run(spec, datetime(2026, 1, 1, tzinfo=UTC))
    return " ".join(expression.split())


# ------------------------------------------------------------------------------ blackout windows


def _parse_time(value: Any, field: str) -> int:
    """``HH:MM`` as minutes since midnight."""
    try:
        hours_text, minutes_text = str(value).split(":")
        hours, minutes = int(hours_text), int(minutes_text)
    except ValueError as exc:
        raise CronError("Blackout window %s must look like 08:30" % field) from exc
    if not (0 <= hours <= 23 and 0 <= minutes <= 59):
        raise CronError("Blackout window %s must look like 08:30" % field)
    return hours * 60 + minutes


def _parse_moment(value: Any) -> datetime:
    if isinstance(value, datetime):
        return _as_utc(value)
    try:
        return _as_utc(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except ValueError as exc:
        raise CronError("Blackout window times must be ISO 8601 dates") from exc


def _window_active(window: Mapping[str, Any], when: datetime) -> bool:
    if window.get("starts_at") is not None:
        return _parse_moment(window["starts_at"]) <= when < _parse_moment(window["ends_at"])
    days = set(window.get("days") or [])
    start = _parse_time(window.get("start"), "start")
    end = _parse_time(window.get("end"), "end")
    minute_of_day = when.hour * 60 + when.minute
    today = when.weekday()
    yesterday = (today - 1) % 7
    if start == end:  # the whole day
        return today in days
    if start < end:
        return today in days and start <= minute_of_day < end
    return (today in days and minute_of_day >= start) or (yesterday in days and minute_of_day < end)


def _window_end(window: Mapping[str, Any], when: datetime) -> datetime:
    """When the active ``window`` stops being active, looking forward from ``when``."""
    if window.get("starts_at") is not None:
        return _parse_moment(window["ends_at"])
    end = _parse_time(window.get("end"), "end")
    candidate = when.replace(hour=end // 60, minute=end % 60, second=0, microsecond=0)
    if candidate <= when:
        candidate += timedelta(days=1)
    return candidate


def in_blackout(windows: Iterable[Mapping[str, Any]], when: datetime) -> bool:
    moment = _as_utc(when)
    return any(_window_active(w, moment) for w in windows)


def blackout_end(windows: Iterable[Mapping[str, Any]], when: datetime) -> datetime | None:
    """None when ``when`` is outside every window; otherwise the first moment no window is active.

    Back-to-back windows are chained. A set of windows that never ends gives ``when`` plus one year.
    """
    listed = list(windows)
    moment = _as_utc(when)
    if not any(_window_active(w, moment) for w in listed):
        return None
    current = moment
    for _ in range(2000):
        active = [w for w in listed if _window_active(w, current)]
        if not active:
            return current
        current = max(_window_end(w, current) for w in active)
    return moment + timedelta(days=366)


def validate_blackout_windows(windows: Iterable[Mapping[str, Any]]) -> None:
    """Raise ``CronError`` when a window cannot be evaluated."""
    probe = datetime(2026, 1, 1, tzinfo=UTC)
    for window in windows:
        _window_active(window, probe)


# ------------------------------------------------------------------------------ due decision


@dataclass(frozen=True)
class Decision:
    """What the evaluator must do with one schedule right now.

    ``action``: ``wait`` (not due), ``run`` (start it), ``delay`` (due but inside a blackout window),
    ``skip`` (due, but the blackout lasted too long: drop this occurrence).
    ``next_run_at`` is the value to store.
    """

    action: str
    next_run_at: datetime
    reason: str


def evaluate_schedule(
    *,
    cron: str,
    next_run_at: datetime | None,
    now: datetime,
    blackout_windows: Iterable[Mapping[str, Any]] = (),
    max_delay: timedelta = MAX_BLACKOUT_DELAY,
) -> Decision:
    """Decide what to do with a schedule at ``now``.

    A missed run (worker down) is collapsed into one run: after a run the next occurrence is the first
    one after ``now``. A run due inside a blackout window waits for the window to end, for at most
    ``max_delay``; after that the occurrence is skipped and the following one is scheduled.
    """
    spec = parse_cron(cron)
    current = _as_utc(now)
    if next_run_at is None:
        return Decision("wait", next_run(spec, current), "scheduled")
    due = _as_utc(next_run_at)
    if due > current:
        return Decision("wait", due, "not due yet")
    windows = list(blackout_windows)
    end = blackout_end(windows, current)
    if end is not None:
        if current - due > max_delay:
            return Decision(
                "skip",
                next_run(spec, current),
                "skipped: a blackout window lasted more than %d hours" % (max_delay.total_seconds() // 3600),
            )
        return Decision(
            "delay", due, "waiting for a blackout window to end at %s UTC" % end.strftime("%Y-%m-%d %H:%M")
        )
    return Decision("run", next_run(spec, current), "started")
