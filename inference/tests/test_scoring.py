"""Verdict of one window (inference/README.md section 5.3)."""

from __future__ import annotations

import pytest

from inference.config import ScoringConfig
from inference.indicators import STRONG
from inference.scoring import LABEL_INDICATOR_MATCH, LABEL_SUSPICIOUS, confidence
from inference.summary import ACTIVITY_FIELDS
from tests.builders import WindowTriple, a_model, make_score


def test_confidence_uses_only_available_components() -> None:
    scoring = ScoringConfig()
    assert confidence(0.6, None, scoring) == pytest.approx(0.6)
    assert confidence(0.6, 1.0, scoring) == pytest.approx((0.5 * 0.6 + 0.3) / 0.8)


def test_a_gated_window_gets_a_confidence_and_a_label(gated_window: WindowTriple) -> None:
    score = make_score(gated_window, model_score=1.0)
    window, result, features = gated_window
    assert score.gated and score.confidence_score is not None
    assert score.indicators[0] in STRONG  # strong indicators come first
    assert set(score.indicators) == set(result.fired)
    assert score.indicator_score == pytest.approx(result.score, abs=1e-4)
    assert score.label == (
        LABEL_SUSPICIOUS if score.confidence_score >= score.threshold else LABEL_INDICATOR_MATCH
    )
    assert score.suspicious == (score.label == LABEL_SUSPICIOUS)
    assert score.activity.keys() == set(ACTIVITY_FIELDS)
    assert score.activity["events"] == len(window.events)
    assert score.features.keys() == features.keys()
    assert score.model_name is None and score.model_version is None  # no model given


def test_a_window_that_is_not_gated_has_no_verdict_but_keeps_the_model_score(
    plain_window: WindowTriple,
) -> None:
    score = make_score(plain_window, model_score=0.2)
    assert not score.gated
    assert score.confidence_score is None and score.label is None
    assert not score.suspicious
    assert score.model_score == 0.2  # recorded so that a human sees what the model thought


def test_the_model_name_and_version_come_from_the_model(gated_window: WindowTriple) -> None:
    score = make_score(gated_window, model=a_model())
    assert score.model_name == "adaptive_random_forest"
    assert score.model_version == "20261009T000000Z"


def test_label_follows_threshold(gated_window: WindowTriple) -> None:
    low = make_score(gated_window, threshold=1.0)
    high = make_score(gated_window, threshold=0.0)
    assert low.label == LABEL_INDICATOR_MATCH and not low.suspicious
    assert high.label == LABEL_SUSPICIOUS and high.suspicious
