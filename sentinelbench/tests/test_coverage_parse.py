"""Notification message parsing used for alert coverage."""

from __future__ import annotations

import re

from sentinelbench.metrics.coverage import _MATCHING_RE, _WINDOW_ID_RE

WINDOW = "a" * 64


def test_window_id_and_matching_count() -> None:
    message = (
        "LogSentinel: reported ransomware detection windows\n"
        "Matching windows: 4\n"
        f"Window ID: {WINDOW}\n"
        f"Window ID: {'b' * 64}\n"
    )
    assert _MATCHING_RE.search(message).group(1) == "4"  # type: ignore[union-attr]
    assert _WINDOW_ID_RE.findall(message) == [WINDOW, "b" * 64]


def test_window_id_pattern_is_hex64() -> None:
    assert re.fullmatch(_WINDOW_ID_RE.pattern, f"Window ID: {WINDOW}", re.IGNORECASE)
    assert not _WINDOW_ID_RE.search("Window ID: short")
