"""Replay-drift classification for detection / window-score pairs."""

from __future__ import annotations

from sentinelbench.metrics.consistency import _REPLAY_DRIFT_SEC
from sentinelbench.timeutil import lag_sec, parse_utc


def test_replay_threshold_ignores_subsecond_emit_skew() -> None:
    left = parse_utc("2026-10-22T15:19:06.198Z")
    right = parse_utc("2026-10-22T15:19:06.200Z")
    gap = abs(lag_sec(left, right) or 0.0)
    assert gap < _REPLAY_DRIFT_SEC


def test_replay_threshold_flags_second_scale_skew() -> None:
    left = parse_utc("2026-10-22T15:19:06.000Z")
    right = parse_utc("2026-10-22T15:19:08.500Z")
    gap = abs(lag_sec(left, right) or 0.0)
    assert gap >= _REPLAY_DRIFT_SEC
