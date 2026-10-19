"""The parts of ``training/e2e_restart.py`` that need no broker: the reference it compares with."""

from __future__ import annotations

from pathlib import Path

from inference.artifacts import load_artifacts, resolve_threshold
from inference.config import ScoringConfig, ServiceConfig
from inference.pipeline import Pipeline
from tests.fakes import emissions_of, numbered, raw_lines
from training import e2e_restart
from training.sentinelcap_dataset import Session

SHIPPED = Path(__file__).resolve().parents[1] / "artifacts"


def test_the_reference_lists_every_window_and_the_reported_ones(
    sessions: dict[str, Session], tmp_path: Path
) -> None:
    config_path = tmp_path / "e2e.yaml"
    config_path.write_text("scoring:\n  reemit_after_sec: 0\n", encoding="utf-8")
    lines = raw_lines(sessions["blackbasta/11129aad"])
    detections, scores = e2e_restart.reference_ids(lines, config_path, SHIPPED)

    config = ServiceConfig(scoring=ScoringConfig(reemit_after_sec=0))
    artifacts = load_artifacts(SHIPPED, config.window)
    threshold = resolve_threshold(config.scoring, artifacts.model)
    pipeline = Pipeline(config, artifacts.model, threshold.value)
    emissions = emissions_of(pipeline, numbered(lines))
    assert scores == {e.score.window_id for e in emissions}
    assert detections == {e.score.window_id for e in emissions if e.reported}
    assert detections and detections < scores  # most windows are scored but not reported
