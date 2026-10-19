"""Phase 3 Global Model (inference/README.md section 5.1).

River Adaptive Random Forest, trained offline (``training.train``) on a
shuffled, stationary set of windows; the service only scores (no labels arrive
online). ARF's ADWIN drift and warning detectors are switched off: on this
offline data they only fired on session boundaries and replaced trees, which
lowered and destabilised out-of-fold AUC (inference/README.md section 5.1).

``load`` refuses, with ``ArtifactError``, a model that does not fit this code
or this configuration: other feature names, another River version, or another
window size or slide (the features count events per window). The service then does not
start (exit code 2) instead of scoring with a mismatched model.
"""

from __future__ import annotations

import json
import logging
import os
import pickle
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import river
from pydantic import BaseModel, ConfigDict, Field
from river import drift, forest

from inference.config import WindowConfig
from inference.features import FEATURE_NAMES

MODEL_FILE = "model.pkl"
META_FILE = "model-meta.json"
MODEL_NAME = "adaptive_random_forest"

logger = logging.getLogger(__name__)


class ArtifactError(ValueError):
    """A trained artifact is missing or cannot be used with this code or configuration."""


class ModelMeta(BaseModel):
    """What the service reads from ``model-meta.json``; training adds more fields."""

    model_config = ConfigDict(extra="allow")

    version: str
    feature_names: list[str]
    river_version: str
    python_version: str
    window: dict[str, float]
    threshold: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    threshold_basis: dict[str, Any] | None = None
    """What ``training.evaluate`` chose the threshold for (scoring weights, window)."""


class Classifier(Protocol):
    def learn_one(self, x: dict[str, float], y: int) -> Any: ...

    def predict_proba_one(self, x: dict[str, float]) -> dict[Any, float]: ...


def new_classifier(seed: int = 42) -> Classifier:
    model: Classifier = forest.ARFClassifier(
        n_models=10,
        seed=seed,
        drift_detector=drift.NoDrift(),
        warning_detector=drift.NoDrift(),
    )
    return model


@dataclass
class GlobalModel:
    classifier: Classifier
    meta: ModelMeta | None = None
    """None for a model that is being evaluated and was never saved."""

    def score(self, features: dict[str, float]) -> float:
        """Probability of the ransomware class."""
        return float(self.classifier.predict_proba_one(features).get(1, 0.0))

    @property
    def version(self) -> str | None:
        return self.meta.version if self.meta is not None else None

    @property
    def threshold(self) -> float | None:
        return self.meta.threshold if self.meta is not None else None

    @property
    def threshold_basis(self) -> dict[str, Any] | None:
        return self.meta.threshold_basis if self.meta is not None else None


def save(directory: Path, classifier: Classifier, meta: dict[str, Any]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    full_meta = {
        **meta,
        "model_name": MODEL_NAME,
        "feature_names": list(FEATURE_NAMES),
        "river_version": river.__version__,
        "python_version": platform.python_version(),
    }
    _write_atomic(directory / MODEL_FILE, pickle.dumps(classifier))
    write_meta(directory, full_meta)


def load(directory: Path, window: WindowConfig) -> GlobalModel:
    """The model in ``directory``; ``ArtifactError`` when it cannot be used."""
    meta_path = directory / META_FILE
    model_path = directory / MODEL_FILE
    if not (meta_path.is_file() and model_path.is_file()):
        raise ArtifactError(f"no trained model in {directory}")
    try:
        meta = ModelMeta.model_validate(read_meta(directory))
    except (OSError, ValueError) as exc:
        raise ArtifactError(f"{meta_path} is not usable: {exc}") from exc
    if meta.feature_names != list(FEATURE_NAMES):
        raise ArtifactError(f"the model in {directory} was trained on other features")
    if meta.river_version != river.__version__:
        raise ArtifactError(
            f"the model in {directory} needs river {meta.river_version} "
            f"(installed {river.__version__})"
        )
    if problem := _window_problem(meta, window):
        raise ArtifactError(f"the model in {directory} was {problem}")
    if meta.python_version != platform.python_version():
        logger.warning(
            "Model was trained with Python %s, running %s",
            meta.python_version,
            platform.python_version(),
        )
    try:
        # The artifacts directory is written only by training.train (trusted input).
        classifier = pickle.loads(model_path.read_bytes())
    except Exception as exc:  # noqa: BLE001 - a corrupt pickle can raise almost anything
        raise ArtifactError(f"{model_path} cannot be loaded: {type(exc).__name__}: {exc}") from exc
    return GlobalModel(classifier, meta)


def read_meta(directory: Path) -> dict[str, Any]:
    meta = json.loads((directory / META_FILE).read_text(encoding="utf-8"))
    if not isinstance(meta, dict):
        raise ValueError(f"{directory / META_FILE} is not a JSON object")
    return meta


def write_meta(directory: Path, meta: dict[str, Any]) -> None:
    _write_atomic(directory / META_FILE, json.dumps(meta, indent=2).encode("utf-8"))


def _window_problem(meta: ModelMeta, window: WindowConfig) -> str | None:
    for name in ("size_sec", "slide_sec"):
        trained, current = meta.window.get(name), getattr(window, name)
        if trained != current:
            shown = f"{trained:g}" if trained is not None else "nothing"
            return f"trained with window.{name}={shown} but the service uses {current}"
    return None


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
