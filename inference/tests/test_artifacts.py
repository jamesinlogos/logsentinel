"""The artifacts as one consistent set (inference/README.md section 5): complete and matching."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from inference.artifacts import (
    Threshold,
    load_artifacts,
    resolve_threshold,
    threshold_basis,
)
from inference.config import ScoringConfig, ServiceConfig, WindowConfig
from inference.model import (
    META_FILE,
    MODEL_FILE,
    ArtifactError,
    GlobalModel,
    ModelMeta,
    new_classifier,
    save,
)
from training.sentinelcap_dataset import Session
from training.train import SessionExamples, build_examples, fit_classifier, training_rows

CONFIG = ServiceConfig()
WINDOW = CONFIG.window
SHIPPED = Path(__file__).resolve().parents[1] / "artifacts"
"""The model and metadata that ``docker-compose.yml`` mounts into the service."""


@pytest.fixture(scope="module")
def examples(sessions: dict[str, Session]) -> list[SessionExamples]:
    return [build_examples(session, WINDOW) for session in sessions.values()]


def write_set(
    directory: Path,
    examples: list[SessionExamples],
    *,
    version: str = "v1",
    threshold: float | None = None,
    basis: dict[str, object] | None = None,
    window: dict[str, int] | None = None,
) -> None:
    classifier = fit_classifier(training_rows(examples, 30, seed=1), seed=1)
    meta: dict[str, object] = {
        "version": version,
        "window": window if window is not None else WINDOW.model_dump(),
        "threshold": threshold,
    }
    if basis is not None:
        meta["threshold_basis"] = basis
    save(directory, classifier, meta)


def rewrite(path: Path, change: Callable[[dict[str, Any]], object]) -> None:
    """Apply ``change`` to the parsed JSON file ``path`` and write it back."""
    data = json.loads(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_a_complete_set_loads(examples: list[SessionExamples], tmp_path: Path) -> None:
    write_set(tmp_path, examples)
    assert load_artifacts(tmp_path, WINDOW).model.version == "v1"


def test_missing_artifacts_are_an_error(tmp_path: Path) -> None:
    with pytest.raises(ArtifactError, match="no trained model"):
        load_artifacts(tmp_path, WINDOW)


def test_the_shipped_artifacts_are_one_usable_set() -> None:
    """What docker-compose.yml mounts really loads, with the threshold `make evaluate` chose."""
    model = load_artifacts(SHIPPED, WINDOW).model
    threshold = resolve_threshold(CONFIG.scoring, model)
    assert threshold.source == "calibrated"  # chosen by `make evaluate` for these scoring settings
    assert threshold.value == model.threshold
    assert 0.0 < threshold.value < 1.0


def test_a_model_trained_with_another_window_is_refused(
    examples: list[SessionExamples], tmp_path: Path
) -> None:
    write_set(tmp_path, examples)
    with pytest.raises(ArtifactError, match=r"window\.size_sec=60 but the service uses 120"):
        load_artifacts(tmp_path, WindowConfig(size_sec=120, slide_sec=20))


@pytest.mark.parametrize("missing", ["version", "window", "python_version"])
def test_a_model_meta_that_lacks_a_required_field_is_refused(
    examples: list[SessionExamples], tmp_path: Path, missing: str
) -> None:
    write_set(tmp_path, examples)
    rewrite(tmp_path / META_FILE, lambda meta: meta.pop(missing))
    with pytest.raises(ArtifactError, match=rf"(?s)is not usable.*{missing}"):
        load_artifacts(tmp_path, WINDOW)


def test_a_corrupt_model_file_is_an_error_not_a_crash(
    examples: list[SessionExamples], tmp_path: Path
) -> None:
    write_set(tmp_path, examples)
    (tmp_path / MODEL_FILE).write_bytes(b"this is not a pickle")
    with pytest.raises(ArtifactError, match="cannot be loaded"):
        load_artifacts(tmp_path, WINDOW)


@pytest.mark.parametrize("threshold", [1.5, -0.1, float("nan")])
def test_a_threshold_outside_0_1_makes_the_metadata_unusable(
    examples: list[SessionExamples], tmp_path: Path, threshold: float
) -> None:
    write_set(tmp_path, examples, threshold=threshold)
    with pytest.raises(ArtifactError, match="not usable"):
        load_artifacts(tmp_path, WINDOW)


def test_the_threshold_comes_from_the_config_first() -> None:
    model = GlobalModel(new_classifier(1))
    assert resolve_threshold(ScoringConfig(threshold=0.4), model) == Threshold(0.4, "config")


def test_a_calibrated_threshold_is_used_for_the_settings_it_was_chosen_for(
    examples: list[SessionExamples], tmp_path: Path
) -> None:
    write_set(tmp_path, examples, threshold=0.42, basis=threshold_basis(CONFIG))
    model = load_artifacts(tmp_path, WINDOW).model
    assert resolve_threshold(CONFIG.scoring, model) == Threshold(0.42, "calibrated")


def test_a_threshold_chosen_for_other_weights_is_refused(
    examples: list[SessionExamples], tmp_path: Path
) -> None:
    write_set(tmp_path, examples, threshold=0.42, basis=threshold_basis(CONFIG))
    model = load_artifacts(tmp_path, WINDOW).model
    with pytest.raises(ArtifactError, match=r"scoring\.weight_global_model"):
        resolve_threshold(ScoringConfig(weight_global_model=0.6), model)


def test_a_threshold_without_its_basis_is_refused(
    examples: list[SessionExamples], tmp_path: Path
) -> None:
    write_set(tmp_path, examples, threshold=0.42)
    model = load_artifacts(tmp_path, WINDOW).model
    with pytest.raises(ArtifactError, match="no threshold_basis record"):
        resolve_threshold(CONFIG.scoring, model)


def test_a_model_that_was_never_evaluated_has_no_threshold(
    examples: list[SessionExamples], tmp_path: Path
) -> None:
    write_set(tmp_path, examples)
    model = load_artifacts(tmp_path, WINDOW).model
    with pytest.raises(ArtifactError, match="make evaluate"):
        resolve_threshold(CONFIG.scoring, model)


def test_threshold_basis_lists_what_changes_the_confidence() -> None:
    basis = threshold_basis(CONFIG)
    assert set(basis["scoring"]) == {"weight_indicator", "weight_global_model"}
    assert basis["window"] == {"size_sec": 60, "slide_sec": 10}


def test_model_meta_accepts_the_fields_training_adds() -> None:
    meta = ModelMeta.model_validate(
        {
            "version": "v1",
            "feature_names": ["a"],
            "river_version": "0",
            "python_version": "3.14.0",
            "window": {"size_sec": 60, "slide_sec": 10},
            "sessions": {"ransomware": 1},
        }
    )
    assert meta.threshold is None
    assert meta.model_extra == {"sessions": {"ransomware": 1}}
