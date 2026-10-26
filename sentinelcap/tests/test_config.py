"""Configuration: one strict schema; the template, the models and the environment agree."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from sentinelcap.config import (
    DEFAULT_CONFIG_TEMPLATE,
    BaselineConfig,
    CaptureConfig,
    KafkaConfig,
    SentinelcapConfig,
    VMwareConfig,
)

MODELS = {
    "vmware": VMwareConfig,
    "kafka": KafkaConfig,
    "capture": CaptureConfig,
    "baseline": BaselineConfig,
}


def write(tmp_path: Path, data: dict[str, Any]) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


@pytest.fixture
def template(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    # The template holds a placeholder host.id, which the schema refuses: the environment gives one.
    monkeypatch.setenv("SENTINELCAP__KAFKA__HOST_ID", "host-1")
    return copy.deepcopy(yaml.safe_load(DEFAULT_CONFIG_TEMPLATE))


def test_the_template_is_a_valid_configuration(tmp_path: Path, template: dict[str, Any]) -> None:
    cfg = SentinelcapConfig.load(write(tmp_path, template))
    assert cfg.kafka.host_id == "host-1"
    assert cfg.vmware.baseline_snapshot == "baseline"
    assert cfg.vmware.validate_snapshot == "validate"


def test_the_template_and_the_models_name_the_same_fields_and_defaults() -> None:
    template = yaml.safe_load(DEFAULT_CONFIG_TEMPLATE)
    assert set(template) == set(MODELS)
    for section, model in MODELS.items():
        assert set(template[section]) == set(model.model_fields), section
        for name, field in model.model_fields.items():
            if not field.is_required():
                assert template[section][name] == field.default, f"{section}.{name}"


@pytest.mark.parametrize(
    "extra",
    [{"typo": 1}, {"kafka": {"topc": "x"}}, {"capture": {"settle": 5}}, {"vmware": {"vmx": "x"}}],
)
def test_an_unknown_key_is_rejected(
    tmp_path: Path, template: dict[str, Any], extra: dict[str, Any]
) -> None:
    for key, value in extra.items():
        if isinstance(value, dict):
            template[key].update(value)
        else:
            template[key] = value
    with pytest.raises(ValidationError):
        SentinelcapConfig.load(write(tmp_path, template))


def test_the_environment_beats_the_file_and_an_empty_value_is_ignored(
    tmp_path: Path, template: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENTINELCAP__CAPTURE__SETTLE_SEC", "7")
    monkeypatch.setenv("SENTINELCAP__CAPTURE__QUIET_WINDOW_SEC", "")
    cfg = SentinelcapConfig.load(write(tmp_path, template))
    assert cfg.capture.settle_sec == 7
    assert cfg.capture.quiet_window_sec == CaptureConfig().quiet_window_sec


def test_a_missing_configuration_file_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(FileNotFoundError, match="config init"):
        SentinelcapConfig.load(None)
