"""Cron parsing, blackout windows and the due decision for schedules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from securescan.integrations.github.scheduling import (
    DEFAULT_WEEKLY_CRON,
    CronError,
    blackout_end,
    evaluate_schedule,
    in_blackout,
    next_run,
    parse_cron,
    validate_blackout_windows,
    validate_cron_expression,
)

UTC = timezone.utc


def at(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


# --------------------------------------------------------------------------- cron
def test_default_weekly_schedule_is_sunday_0200() -> None:
    assert DEFAULT_WEEKLY_CRON == "0 2 * * 0"
    first = next_run(DEFAULT_WEEKLY_CRON, at(2026, 10, 7, 12, 0))  # a Wednesday
    assert first == at(2026, 10, 11, 2, 0)
    assert first.weekday() == 6


def test_next_run_is_strictly_after() -> None:
    assert next_run("0 2 * * 0", at(2026, 10, 11, 2, 0)) == at(2026, 10, 18, 2, 0)
    assert next_run("*/15 * * * *", at(2026, 10, 7, 12, 15)) == at(2026, 10, 7, 12, 30)
    assert next_run("*/15 * * * *", at(2026, 10, 7, 12, 7, 30)) == at(2026, 10, 7, 12, 15)


def test_next_run_rolls_over_month_and_year() -> None:
    assert next_run("30 4 1 * *", at(2026, 12, 31, 23, 59)) == at(2027, 1, 1, 4, 30)


def test_leap_day() -> None:
    assert next_run("0 0 29 2 *", at(2026, 1, 1)) == at(2028, 2, 29, 0, 0)


def test_day_of_month_and_weekday_are_ored_when_both_are_restricted() -> None:
    # the 15th or any Monday; 12 October 2026 is a Monday and comes first
    assert next_run("0 9 15 * mon", at(2026, 10, 7)) == at(2026, 10, 12, 9, 0)


def test_weekday_seven_is_sunday_and_names_work() -> None:
    assert next_run("0 9 * * 7", at(2026, 10, 7)) == at(2026, 10, 11, 9, 0)
    assert next_run("0 9 * * sun", at(2026, 10, 7)) == at(2026, 10, 11, 9, 0)
    assert parse_cron("0 0 1 jan,jul *").months == frozenset({1, 7})


def test_steps_and_ranges() -> None:
    spec = parse_cron("10-50/20 8-10 * * 1-5")
    assert spec.minutes == frozenset({10, 30, 50})
    assert spec.hours == frozenset({8, 9, 10})
    assert spec.weekdays == frozenset({1, 2, 3, 4, 5})


@pytest.mark.parametrize(
    "expression",
    ["* * * *", "61 * * * *", "a * * * *", "*/0 * * * *", "5-1 * * * *", "0 24 * * *", "0 0 0 * *"],
)
def test_invalid_cron_is_rejected_in_plain_words(expression: str) -> None:
    with pytest.raises(CronError):
        validate_cron_expression(expression)


def test_cron_that_never_matches_is_rejected() -> None:
    with pytest.raises(CronError):
        validate_cron_expression("0 0 31 2 *")


def test_validate_normalises_spaces() -> None:
    assert validate_cron_expression("  0   2 *  * 0 ") == "0 2 * * 0"


# --------------------------------------------------------------------------- blackout windows
SUNDAY_NIGHT = [{"days": [6], "start": "22:00", "end": "06:00"}]  # Sunday 22:00 to Monday 06:00


def test_weekly_window_crossing_midnight() -> None:
    assert in_blackout(SUNDAY_NIGHT, at(2026, 10, 11, 23, 0))
    assert in_blackout(SUNDAY_NIGHT, at(2026, 10, 12, 5, 59))
    assert not in_blackout(SUNDAY_NIGHT, at(2026, 10, 12, 6, 0))
    assert not in_blackout(SUNDAY_NIGHT, at(2026, 10, 11, 21, 59))
    assert not in_blackout(SUNDAY_NIGHT, at(2026, 10, 13, 1, 0))


def test_weekly_window_within_a_day() -> None:
    window = [{"days": [0, 1, 2, 3, 4], "start": "08:00", "end": "18:00"}]
    assert in_blackout(window, at(2026, 10, 7, 9, 0))  # Wednesday
    assert not in_blackout(window, at(2026, 10, 7, 18, 0))
    assert not in_blackout(window, at(2026, 10, 11, 9, 0))  # Sunday


def test_one_off_window_accepts_iso_strings() -> None:
    window = [{"starts_at": "2026-10-11T00:00:00Z", "ends_at": "2026-10-11T03:00:00+00:00"}]
    assert in_blackout(window, at(2026, 10, 11, 2, 59))
    assert not in_blackout(window, at(2026, 10, 11, 3, 0))


def test_blackout_end_is_none_outside_and_chains_windows() -> None:
    assert blackout_end(SUNDAY_NIGHT, at(2026, 10, 13, 1, 0)) is None
    assert blackout_end(SUNDAY_NIGHT, at(2026, 10, 11, 23, 0)) == at(2026, 10, 12, 6, 0)
    assert blackout_end(SUNDAY_NIGHT, at(2026, 10, 12, 1, 0)) == at(2026, 10, 12, 6, 0)
    back_to_back = [
        {"starts_at": "2026-10-11T00:00:00Z", "ends_at": "2026-10-11T03:00:00Z"},
        {"starts_at": "2026-10-11T03:00:00Z", "ends_at": "2026-10-11T04:00:00Z"},
    ]
    assert blackout_end(back_to_back, at(2026, 10, 11, 1, 0)) == at(2026, 10, 11, 4, 0)


def test_a_window_that_never_ends_is_bounded() -> None:
    always = [{"days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "00:00"}]
    start = at(2026, 10, 11, 1, 0)
    end = blackout_end(always, start)
    assert end is not None
    assert end >= start + timedelta(days=300)


def test_invalid_window_is_reported() -> None:
    with pytest.raises(CronError):
        validate_blackout_windows([{"days": [1], "start": "25:00", "end": "06:00"}])


# --------------------------------------------------------------------------- the due decision
def test_first_evaluation_only_anchors_the_next_run() -> None:
    now = at(2026, 10, 11, 2, 0)
    decision = evaluate_schedule(cron="0 2 * * 0", next_run_at=None, now=now)
    assert decision.action == "wait"
    assert decision.next_run_at == at(2026, 10, 18, 2, 0)


def test_not_due_yet_waits() -> None:
    decision = evaluate_schedule(
        cron="0 2 * * 0", next_run_at=at(2026, 10, 18, 2, 0), now=at(2026, 10, 17, 12, 0)
    )
    assert decision.action == "wait"
    assert decision.next_run_at == at(2026, 10, 18, 2, 0)


def test_due_runs_and_schedules_the_following_week() -> None:
    now = at(2026, 10, 11, 2, 0)
    decision = evaluate_schedule(cron="0 2 * * 0", next_run_at=now, now=now)
    assert decision.action == "run"
    assert decision.next_run_at == at(2026, 10, 18, 2, 0)


def test_missed_runs_collapse_into_one() -> None:
    decision = evaluate_schedule(
        cron="0 2 * * 0", next_run_at=at(2026, 9, 20, 2, 0), now=at(2026, 10, 11, 9, 0)
    )
    assert decision.action == "run"
    assert decision.next_run_at == at(2026, 10, 18, 2, 0)


def test_due_inside_a_blackout_window_is_delayed_until_it_ends() -> None:
    now = at(2026, 10, 11, 2, 0)
    window = [{"days": [6], "start": "00:00", "end": "06:00"}]
    decision = evaluate_schedule(
        cron="0 2 * * 0", next_run_at=now, now=now, blackout_windows=window
    )
    assert decision.action == "delay"
    assert decision.next_run_at == now  # stays due; it runs once the window is over
    assert "06:00" in decision.reason
    later = evaluate_schedule(
        cron="0 2 * * 0", next_run_at=now, now=at(2026, 10, 11, 6, 1), blackout_windows=window
    )
    assert later.action == "run"


def test_blackout_longer_than_a_day_skips_the_occurrence() -> None:
    due = at(2026, 10, 11, 2, 0)
    window = [{"starts_at": "2026-10-10T00:00:00Z", "ends_at": "2026-10-14T00:00:00Z"}]
    decision = evaluate_schedule(
        cron="0 2 * * 0",
        next_run_at=due,
        now=due + timedelta(hours=25),
        blackout_windows=window,
    )
    assert decision.action == "skip"
    assert decision.next_run_at == at(2026, 10, 18, 2, 0)


def test_naive_datetimes_are_treated_as_utc() -> None:
    decision = evaluate_schedule(
        cron="0 2 * * 0",
        next_run_at=datetime(2026, 10, 11, 2, 0),
        now=datetime(2026, 10, 11, 2, 0),
    )
    assert decision.action == "run"
