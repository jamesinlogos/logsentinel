"""Service configuration.

Precedence (highest first):
1. Environment variables ``INFERENCE__<SECTION>__<KEY>`` (double underscore
   between segments, like sentinelcap's ``SENTINELCAP__...``), for example
   ``INFERENCE__KAFKA__BOOTSTRAP_SERVERS``. An empty value is ignored. The
   ``LOG`` section belongs to ``logs.py``, which reads it before this file is loaded.
2. The YAML file named by INFERENCE_CONFIG (default ``config.yaml``); it must
   exist.
3. Field defaults below.

Unknown keys are rejected so a typo cannot silently fall back to a default, and
so are ``inf`` and ``NaN`` (a weight of ``inf`` turns every confidence into NaN).
"""

from __future__ import annotations

import copy
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

CONFIG_ENV = "INFERENCE_CONFIG"
DEFAULT_CONFIG_PATH = "config.yaml"
ENV_PREFIX = "INFERENCE"
LOGGING_SECTION = "log"
STATUS_PATH = Path(tempfile.gettempdir()) / "inference.status.json"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _finite(default: float, *, minimum: float = 0.0, exclusive: bool = True) -> Any:
    """A finite float above ``minimum`` (or at it when not exclusive)."""
    if exclusive:
        return Field(default=default, gt=minimum, allow_inf_nan=False)
    return Field(default=default, ge=minimum, allow_inf_nan=False)


class KafkaConfig(_Strict):
    bootstrap_servers: str = "localhost:9092"
    input_topic: str = "telemetry.windows.normalized"
    detections_topic: str = "security.ransomware.detections"
    window_scores_topic: str = "security.ransomware.window-scores"
    group_id: str = "inference"
    auto_offset_reset: Literal["earliest", "latest"] = "latest"
    produce_timeout_sec: float = _finite(10)
    """How long an output record may wait for room in the producer queue before a stop."""
    delivery_timeout_sec: float = _finite(60)
    """How long Kafka may take to acknowledge an output record (``message.timeout.ms``)."""
    shutdown_timeout_sec: float = _finite(15)
    """Time to emit the pending windows and flush the producer after SIGTERM.

    ``produce_timeout_sec + shutdown_timeout_sec`` plus a few seconds must stay
    below ``stop_grace_period`` in docker-compose.yml (30 s), or Docker kills the
    service in the middle of the flush.
    """
    down_after_sec: float = _finite(60)
    """The healthcheck fails when no broker has been reachable for this long."""


class WindowConfig(_Strict):
    """Sliding window per host.id (inference/README.md section 4.0)."""

    size_sec: int = Field(default=60, gt=0)
    slide_sec: int = Field(default=10, gt=0)
    idle_flush_sec: float = _finite(3)
    """Close the pending window of a host that sent nothing for this long.

    Events arrive in clumps (Winlogbeat reads and ships in batches) and the loop polls once a
    second, so a lower value sends the same window again more often
    (inference/README.md section 9.2).
    """
    host_evict_sec: float = _finite(3600)
    max_events_per_host: int = Field(default=200_000, gt=0)
    late_reset_events: int = Field(default=20, ge=1)
    """Consecutive events older than the window after which a host's clock is followed."""

    @model_validator(mode="after")
    def check_relations(self) -> WindowConfig:
        if self.slide_sec > self.size_sec:
            raise ValueError("window.slide_sec must not exceed window.size_sec")
        if self.host_evict_sec < self.idle_flush_sec:
            raise ValueError("window.host_evict_sec must not be below window.idle_flush_sec")
        return self

    def training_fields(self) -> dict[str, Any]:
        """The settings that decide which events a window holds: what a model is trained with.

        ``idle_flush_sec`` and ``host_evict_sec`` only decide when the service closes or forgets
        the window of a silent host, so changing them does not change a model.
        """
        return self.model_dump(exclude={"idle_flush_sec", "host_evict_sec"})


class ScoringConfig(_Strict):
    """confidence_score = weighted mean of the available components.

    See inference/README.md section 5.3.
    """

    weight_indicator: float = _finite(0.5)
    weight_global_model: float = _finite(0.3, exclusive=False)
    threshold: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    reemit_after_sec: float = _finite(60, exclusive=False)


class ServiceConfig(_Strict):
    kafka: KafkaConfig = KafkaConfig()
    window: WindowConfig = WindowConfig()
    scoring: ScoringConfig = ScoringConfig()
    artifacts_dir: str = "artifacts"
    stats_interval_sec: float = _finite(60)


def load_config(path: str | Path | None = None) -> ServiceConfig:
    config_path = Path(
        path if path is not None else os.environ.get(CONFIG_ENV, DEFAULT_CONFIG_PATH)
    )
    if not config_path.is_file():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{config_path}: the top level must be a mapping")
    return ServiceConfig.model_validate(apply_env_overrides(loaded, os.environ))


def apply_env_overrides(data: dict[str, Any], environ: Mapping[str, str]) -> dict[str, Any]:
    """``data`` with the ``INFERENCE__SECTION__KEY=value`` variables applied."""
    merged = copy.deepcopy(data)
    for name, value in environ.items():
        if not name.startswith(ENV_PREFIX + "__") or not value:
            continue
        parts = name[len(ENV_PREFIX) + 2 :].lower().split("__")
        if parts[0] == LOGGING_SECTION:
            continue
        cursor = merged
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = value
    return merged
