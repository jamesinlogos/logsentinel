"""Configuration loading and the healthcheck."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from inference.config import (
    CONFIG_ENV,
    ENV_PREFIX,
    KafkaConfig,
    ScoringConfig,
    ServiceConfig,
    WindowConfig,
    apply_env_overrides,
    load_config,
)
from inference.healthcheck import main as healthcheck
from inference.status import write_status

REPO_CONFIG = Path(__file__).resolve().parents[1] / "config.yaml"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in [n for n in os.environ if n.startswith(ENV_PREFIX)] + [CONFIG_ENV]:
        monkeypatch.delenv(name, raising=False)


def test_repository_config_matches_the_defaults() -> None:
    assert load_config(REPO_CONFIG) == ServiceConfig()


def test_a_missing_default_file_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(FileNotFoundError, match=r"config\.yaml"):
        load_config()


def test_explicit_missing_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "missing.yaml")


def test_environment_overrides_kafka(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INFERENCE__KAFKA__BOOTSTRAP_SERVERS", "kafka:29092")
    monkeypatch.setenv("INFERENCE__KAFKA__DETECTIONS_TOPIC", "detections.test")
    monkeypatch.setenv("INFERENCE__KAFKA__WINDOW_SCORES_TOPIC", "scores.test")
    config = load_config(REPO_CONFIG)
    assert config.kafka.bootstrap_servers == "kafka:29092"
    assert config.kafka.detections_topic == "detections.test"
    assert config.kafka.window_scores_topic == "scores.test"


def test_environment_overrides_any_section_and_beats_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("window:\n  size_sec: 30\n  slide_sec: 5\n", encoding="utf-8")
    monkeypatch.setenv("INFERENCE__WINDOW__SIZE_SEC", "120")
    monkeypatch.setenv("INFERENCE__SCORING__REEMIT_AFTER_SEC", "5")
    config = load_config(path)
    assert config.window.size_sec == 120  # the file said 30
    assert config.window.slide_sec == 5  # untouched keys of the file stay
    assert config.scoring.reemit_after_sec == 5


def test_config_path_comes_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "other.yaml"
    path.write_text("artifacts_dir: elsewhere\n", encoding="utf-8")
    monkeypatch.setenv("INFERENCE_CONFIG", str(path))
    assert load_config().artifacts_dir == "elsewhere"


def test_overrides_ignore_empty_values_and_the_log_section() -> None:
    data = {"kafka": {"group_id": "from-file"}}
    environ = {
        "INFERENCE__KAFKA__GROUP_ID": "",  # an empty variable means "not set"
        "INFERENCE__LOG__LEVEL": "DEBUG",  # read by logs.py, not a config key
        "INFERENCE_CONFIG": "x.yaml",  # one underscore: the path, not an override
        "KAFKA_BOOTSTRAP_SERVERS": "x:9092",  # no component prefix: not an override
    }
    assert apply_env_overrides(data, environ) == data
    assert data == {"kafka": {"group_id": "from-file"}}  # the input is not modified


def test_an_override_of_an_unknown_key_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INFERENCE__KAFKA__NO_SUCH_KEY", "detections.test")
    with pytest.raises(ValidationError):  # a typo must not pass silently
        load_config(REPO_CONFIG)


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("window:\n  size: 60\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(path)


@pytest.mark.parametrize("bad", [float("inf"), float("-inf"), float("nan")])
def test_non_finite_numbers_are_rejected(bad: float) -> None:
    for build in (
        lambda: ScoringConfig(weight_global_model=bad),
        lambda: ScoringConfig(threshold=bad),
        lambda: ScoringConfig(weight_indicator=bad),
        lambda: WindowConfig(idle_flush_sec=bad),
        lambda: KafkaConfig(produce_timeout_sec=bad),
    ):
        with pytest.raises(ValidationError):
            build()


def test_yaml_infinity_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("scoring:\n  weight_global_model: .inf\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(path)


def test_a_host_cannot_be_evicted_before_it_is_flushed() -> None:
    with pytest.raises(ValidationError, match="host_evict_sec"):
        WindowConfig(idle_flush_sec=100, host_evict_sec=10)
    with pytest.raises(ValidationError, match="slide_sec"):
        WindowConfig(size_sec=10, slide_sec=60)


@pytest.mark.parametrize(
    "build",
    [
        lambda: KafkaConfig(produce_timeout_sec=0),
        lambda: KafkaConfig(shutdown_timeout_sec=-1),
        lambda: WindowConfig(late_reset_events=0),
        lambda: ScoringConfig(weight_indicator=0),
    ],
)
def test_timeouts_and_counts_must_be_positive(build: object) -> None:
    with pytest.raises(ValidationError):
        build()  # type: ignore[operator]


def test_shutdown_fits_in_the_compose_grace_period() -> None:
    kafka = KafkaConfig()
    assert kafka.produce_timeout_sec + kafka.shutdown_timeout_sec < 30


def test_healthcheck_follows_the_status_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = tmp_path / "status.json"
    assert healthcheck([str(status)]) == 1  # no file: the loop never ran
    write_status(status, {"healthy": True, "degraded": ["kafka_unreachable"]})
    assert healthcheck([str(status)]) == 0  # the broker is away, not for long enough
    write_status(status, {"healthy": False, "degraded": ["kafka_unreachable"]})
    assert healthcheck([str(status)]) == 1
    assert "kafka_unreachable" in capsys.readouterr().out
    write_status(status, {"healthy": True})
    stale = time.time() - 120
    os.utime(status, (stale, stale))
    assert healthcheck([str(status)]) == 1  # the loop stopped rewriting it
    status.write_text("not json", encoding="utf-8")
    assert healthcheck([str(status)]) == 1
