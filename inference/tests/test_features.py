"""Window features shared by training and serving (inference/README.md section 8)."""

from __future__ import annotations

import math

from inference.config import WindowConfig
from inference.features import FEATURE_NAMES, compute
from inference.indicators import evaluate
from inference.summary import WindowSummary, summarize
from training.sentinelcap_dataset import Session, session_windows


def test_every_window_has_the_contract_features(sessions: dict[str, Session]) -> None:
    for session in sessions.values():
        for window in session_windows(session, WindowConfig()):
            summary = summarize(window.events)
            result = evaluate(summary)
            features = compute(summary, result)
            assert tuple(features) == FEATURE_NAMES
            assert all(math.isfinite(value) for value in features.values())
            flags = {name[4:] for name in FEATURE_NAMES if name.startswith("ind_")}
            assert {name for name in flags if features[f"ind_{name}"] == 1.0} == result.fired


def test_each_event_code_has_its_own_column() -> None:
    summary = WindowSummary()
    summary.codes.update({"11": 3, "26": 2})
    features = compute(summary, evaluate(summary))
    assert features["code_11"] == math.log1p(3)
    assert features["code_26"] == math.log1p(2)
    assert features["code_12"] == 0.0


def test_ratios_of_an_empty_window_are_zero() -> None:
    summary = WindowSummary()
    features = compute(summary, evaluate(summary))
    assert features["suspicious_path_ratio"] == 0.0
    assert features["file_name_entropy"] == 0.0
