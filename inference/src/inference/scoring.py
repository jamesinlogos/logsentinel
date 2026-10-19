"""The verdict of one window (inference/README.md section 5.3).

``score_window`` turns the counts, indicators, features and scores of a window into a
:class:`WindowScore`: what the service concluded about one window of one host. Every window
has one. ``confidence_score`` is the weighted mean of the score components that exist: a
missing model is left out instead of counting as 0 (the service always has one; the tests of the
gate do without). It and ``label`` exist only for windows that passed the gate; ``label`` says
whether the confidence reached the threshold. ``documents.py`` turns a ``WindowScore`` into the
two documents the service writes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from inference.config import ScoringConfig
from inference.events import Event
from inference.indicators import IndicatorResult, ordered
from inference.model import MODEL_NAME, GlobalModel
from inference.windowing import Window, format_timestamp, window_id

LABEL_SUSPICIOUS = "suspicious_ransomware_behavior"
LABEL_INDICATOR_MATCH = "indicator_match"


@dataclass(frozen=True)
class WindowScore:
    """What the service concluded about one window of one host."""

    window_id: str
    host_id: str
    host_name: str | None
    start: float
    end: float
    trigger: str
    """Why the window closed: ``windowing.SLIDE`` (boundary, idle flush) or ``INDICATOR``."""
    process: dict[str, Any]
    """ECS ``process`` of the event an early window closed at (empty for a scheduled window)."""
    activity: dict[str, int]
    features: dict[str, float]
    indicators: list[str]
    """Every indicator that fired, strong ones first (``indicators.ordered``)."""
    indicator_score: float
    model_score: float | None
    """Scored for every window; it takes part in ``confidence_score`` only when gated."""
    gated: bool
    confidence_score: float | None
    label: str | None
    threshold: float
    model_name: str | None
    model_version: str | None

    @property
    def suspicious(self) -> bool:
        return self.label == LABEL_SUSPICIOUS


def confidence(
    indicator_score: float, global_model_score: float | None, scoring: ScoringConfig
) -> float:
    parts = [(scoring.weight_indicator, indicator_score)]
    if global_model_score is not None:
        parts.append((scoring.weight_global_model, global_model_score))
    weight = sum(w for w, _ in parts)
    return sum(w * value for w, value in parts) / weight


def score_window(
    window: Window,
    result: IndicatorResult,
    features: dict[str, float],
    model_score: float | None,
    *,
    scoring: ScoringConfig,
    threshold: float,
    model: GlobalModel | None,
) -> WindowScore:
    score = None
    label = None
    if result.gated:
        score = round(confidence(result.score, model_score, scoring), 4)
        label = LABEL_SUSPICIOUS if score >= threshold else LABEL_INDICATOR_MATCH
    return WindowScore(
        window_id=window_id(window.host_id, format_timestamp(window.end)),
        host_id=window.host_id,
        host_name=window.host_name,
        start=window.start,
        end=window.end,
        trigger=window.trigger,
        process=process_fields(window.trigger_event),
        activity=window.summary.activity(),
        features={name: round(value, 4) for name, value in features.items()},
        indicators=ordered(result.fired),
        indicator_score=round(result.score, 4),
        model_score=_round(model_score),
        gated=result.gated,
        confidence_score=score,
        label=label,
        threshold=threshold,
        model_name=MODEL_NAME if model is not None else None,
        model_version=model.version if model is not None else None,
    )


def process_fields(event: Event | None) -> dict[str, Any]:
    """The ECS ``process`` of ``event`` (the fields it has; none for no event).

    Paths and command lines are as ``events.py`` keeps them: case-folded, the command line cut at
    the Windows limit.
    """
    if event is None:
        return {}
    fields: dict[str, Any] = {}
    if event.entity_id:
        fields["entity_id"] = event.entity_id
    if event.executable:
        fields["executable"] = event.executable
        fields["name"] = event.executable.rsplit("\\", 1)[-1]
    if event.command_line:
        fields["command_line"] = event.command_line
    if event.parent_entity_id:
        fields["parent"] = {"entity_id": event.parent_entity_id}
    return fields


def _round(value: float | None) -> float | None:
    return round(value, 4) if value is not None else None
