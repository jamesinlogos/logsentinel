"""Builders shared by the tests of scoring, documents and the stack scripts (real windows)."""

from __future__ import annotations

import river

from inference.config import ScoringConfig
from inference.features import FEATURE_NAMES
from inference.indicators import IndicatorResult
from inference.model import GlobalModel, ModelMeta, new_classifier
from inference.scoring import WindowScore, score_window
from inference.windowing import Window

CREATED = 1_760_000_100.25
"""When the service built the document in these tests (epoch seconds)."""

WindowTriple = tuple[Window, IndicatorResult, dict[str, float]]
"""A real window with its indicator result and its features (``conftest.py`` fixtures)."""


def make_score(
    triple: WindowTriple,
    *,
    model_score: float | None = None,
    threshold: float = 0.75,
    model: GlobalModel | None = None,
) -> WindowScore:
    window, result, features = triple
    return score_window(
        window,
        result,
        features,
        model_score,
        scoring=ScoringConfig(),
        threshold=threshold,
        model=model,
    )


def a_model() -> GlobalModel:
    meta = ModelMeta(
        version="20261009T000000Z",
        feature_names=list(FEATURE_NAMES),
        river_version=river.__version__,
        python_version="3.14.0",
        window={"size_sec": 60, "slide_sec": 10},
    )
    return GlobalModel(new_classifier(1), meta)
