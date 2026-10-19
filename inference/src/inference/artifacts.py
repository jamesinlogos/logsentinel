"""The trained artifacts as one consistent set (inference/README.md section 5).

``training.train`` writes the model and ``model-meta.json`` of one run; ``training.evaluate``
adds the threshold together with what it was chosen for (``threshold_basis``). The service
starts only with a complete set that fits its configuration: a model that is missing or
unusable, or a threshold chosen for other scoring settings, raises ``ArtifactError`` and the
service exits (code 2) instead of detecting with something else.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from inference.config import ScoringConfig, ServiceConfig, WindowConfig
from inference.model import ArtifactError, GlobalModel
from inference.model import load as load_model

CALIBRATED_SCORING_FIELDS = (
    "weight_indicator",
    "weight_global_model",
)
"""Scoring settings that change the confidence a threshold is compared with."""


@dataclass(frozen=True)
class Artifacts:
    model: GlobalModel


@dataclass(frozen=True)
class Threshold:
    value: float
    source: Literal["config", "calibrated"]


def load_artifacts(directory: Path, window: WindowConfig) -> Artifacts:
    """The model of one training run (``ArtifactError`` when it is missing or unusable)."""
    return Artifacts(load_model(directory, window))


def threshold_basis(config: ServiceConfig) -> dict[str, Any]:
    """What a threshold is chosen for; ``resolve_threshold`` compares it with the live config."""
    return {
        "scoring": {name: getattr(config.scoring, name) for name in CALIBRATED_SCORING_FIELDS},
        "window": {"size_sec": config.window.size_sec, "slide_sec": config.window.slide_sec},
    }


def resolve_threshold(scoring: ScoringConfig, model: GlobalModel) -> Threshold:
    """The configured threshold, else the one ``training.evaluate`` chose for these settings.

    ``ArtifactError`` when the model has none, or it was chosen for other scoring settings.
    """
    if scoring.threshold is not None:
        return Threshold(scoring.threshold, "config")
    if model.threshold is None:
        raise ArtifactError(
            "the model has no threshold; run `make evaluate` (or set scoring.threshold)"
        )
    problem = _basis_problem(model.threshold_basis, scoring)
    if problem is not None:
        raise ArtifactError(
            f"the model's threshold {model.threshold:.2f} cannot be used: {problem}"
        )
    return Threshold(model.threshold, "calibrated")


def _basis_problem(basis: dict[str, Any] | None, scoring: ScoringConfig) -> str | None:
    recorded = (basis or {}).get("scoring")
    if not isinstance(recorded, dict):
        return "it has no threshold_basis record; run `make evaluate`"
    for name in CALIBRATED_SCORING_FIELDS:
        value = recorded.get(name)
        current = getattr(scoring, name)
        if not isinstance(value, int | float) or not math.isclose(value, current):
            return f"it was chosen for scoring.{name}={value} but the service uses {current}"
    return None
