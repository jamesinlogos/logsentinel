"""Shared pytest fixtures for inference tests.

All telemetry is real: ``fixtures/sessions`` and ``fixtures/single-events.json``
are copied from sentinelcap captures by ``fixtures/build_fixtures.py``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from inference.config import ServiceConfig, WindowConfig
from inference.features import compute
from inference.indicators import IndicatorResult, evaluate
from inference.logs import JsonFormatter, TextFormatter
from inference.pipeline import Pipeline
from inference.windowing import INDICATOR, Window
from training.sentinelcap_dataset import Session, iter_sessions, session_windows

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SESSIONS_DIR = FIXTURES_DIR / "sessions"


@pytest.fixture(scope="session")
def sessions() -> dict[str, Session]:
    """Real sentinelcap sessions keyed like ``conti/b14cde37``."""
    return {session.name: session for session in iter_sessions(SESSIONS_DIR)}


@pytest.fixture(scope="session")
def single_events() -> dict[str, dict[str, Any]]:
    """Single real events (raw documents) keyed by what they show."""
    return json.loads((FIXTURES_DIR / "single-events.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def gated_window(sessions: dict[str, Session]) -> tuple[Window, IndicatorResult, dict[str, float]]:
    """First window of the Conti fixture that passes the Phase 2 gate."""
    for window in session_windows(sessions["conti/b14cde37"], WindowConfig()):
        summary = window.summary
        result = evaluate(summary)
        if result.gated:
            return window, result, compute(summary, result)
    raise AssertionError("The Conti fixture has no gated window")


@pytest.fixture(scope="session")
def plain_window(sessions: dict[str, Session]) -> tuple[Window, IndicatorResult, dict[str, float]]:
    """First window of the goodware fixture: it does not pass the Phase 2 gate."""
    for window in session_windows(sessions["goodware/9923a8b2"], WindowConfig()):
        summary = window.summary
        result = evaluate(summary)
        if not result.gated:
            return window, result, compute(summary, result)
    raise AssertionError("The goodware fixture has no window outside the gate")


@pytest.fixture(scope="session")
def early_windows(
    sessions: dict[str, Session],
) -> dict[str, tuple[Window, IndicatorResult, dict[str, float]]]:
    """Real windows closed early: ``command`` at an Event 1 (it has a command line), ``file`` at an
    Event 11 (it has none)."""
    found: dict[str, tuple[Window, IndicatorResult, dict[str, float]]] = {}
    for session in sessions.values():
        pipeline = Pipeline(ServiceConfig(), None, 0.75)
        for event in session.events:
            for emission in pipeline.process(event, event.timestamp):
                window = emission.window
                trigger = window.trigger_event
                if window.trigger != INDICATOR or trigger is None:
                    continue
                kind = "command" if trigger.command_line else "file"
                if kind not in found:
                    result = evaluate(window.summary)
                    found[kind] = (window, result, compute(window.summary, result))
    assert found.keys() == {"command", "file"}, "the fixtures have no early window of a kind"
    return found


@pytest.fixture
def clean_logging() -> Iterator[None]:
    """Undo ``configure_logging``: remove its handler, restore the level and the warnings hook."""
    root = logging.getLogger()
    level = root.level
    yield
    root.handlers[:] = [
        h for h in root.handlers if not isinstance(h.formatter, JsonFormatter | TextFormatter)
    ]
    root.setLevel(level)
    logging.captureWarnings(False)
