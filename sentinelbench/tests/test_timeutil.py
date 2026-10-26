"""Tests for timestamp helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelbench.timeutil import lag_sec, parse_utc, percentiles


def test_parse_utc_with_nanoseconds() -> None:
    value = parse_utc("2026-10-23T01:07:50.377020949Z")
    assert value == datetime(2026, 10, 23, 1, 7, 50, 377020, tzinfo=UTC)


def test_parse_utc_rejects_garbage() -> None:
    assert parse_utc("not-a-date") is None
    assert parse_utc(None) is None


def test_lag_and_percentiles() -> None:
    earlier = parse_utc("2026-10-23T01:00:00.000Z")
    later = parse_utc("2026-10-23T01:00:02.500Z")
    assert lag_sec(later, earlier) == 2.5
    stats = percentiles([1.0, 2.0, 3.0, 4.0, 100.0])
    assert stats["count"] == 5
    assert stats["p50"] == 3.0
    assert stats["max"] == 100.0
