"""Shared configuration for the sentinelcap CLI.

Precedence (highest to lowest):
1. CLI arguments (handled in cli.py)
2. Environment variables prefixed with SENTINELCAP__ (double underscore
   between segments, e.g. SENTINELCAP__VMWARE__GUEST_PASSWORD); they are
   applied on top of the YAML file, and an empty value is ignored
3. The YAML file passed via --config
4. Field defaults defined below

Unknown keys are rejected, so a typo or a misplaced key cannot silently fall back to
a default.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

ENV_PREFIX = "SENTINELCAP"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VMwareConfig(_Strict):
    """Connection details for the VMware Workstation victim VM."""

    vmrun_path: str = Field(
        default=r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
        description="Path to vmrun.exe on the host.",
    )
    vmx_path: str = Field(description="Path to the victim VM's .vmx file.")
    original_snapshot: str = Field(
        default="original",
        description="Clean Windows, decoy folders, no samples; `build baseline` starts here.",
    )
    baseline_snapshot: str = Field(
        default="baseline",
        description="Created by `build baseline`; every collection session reverts here.",
    )
    validate_snapshot: str = Field(
        default="validate",
        description=(
            "Created by `build validate`: every ransomware/goodware pair shares a "
            "guest folder for stack validation; does not replace baseline."
        ),
    )
    guest_user: str = Field(description="Guest OS username used for vmrun -gu/-gp operations.")
    guest_password: str = Field(
        description="Guest OS password. Prefer overriding this via environment variable."
    )
    explorer_path: str = Field(
        default=r"C:\Windows\explorer.exe",
        description="Path to Windows Explorer inside the guest.",
    )
    start_boot_wait_sec: int = Field(
        default=30, description="Extra settle time after VMware Tools reports ready."
    )
    tools_ready_timeout_sec: int = Field(
        default=120, description="Max seconds to wait for VMware Tools to be ready."
    )


class KafkaConfig(_Strict):
    """Normalized Kafka topic consumed by SentinelCap and the inference service."""

    bootstrap_servers: str = "localhost:9092"
    topic: str = "telemetry.windows.normalized"
    host_id: str = Field(description="ECS host.id of the dedicated victim VM.")
    consumer_group_prefix: str = "sentinelcap-capture"
    assignment_timeout_sec: int = 30
    post_capture_drain_sec: int = 45

    @field_validator("host_id")
    @classmethod
    def host_id_is_configured(cls, value: str) -> str:
        value = value.strip()
        if not value or value == "REPLACE_WITH_HOST_ID":
            raise ValueError("kafka.host_id must be the victim VM's ECS host.id")
        return value


class CaptureConfig(_Strict):
    """Timing parameters for manual sample collection and capture export."""

    out_dir: str = "captures"
    quiet_window_sec: int = 90
    settle_sec: int = 120
    max_wait_sec: int = 300
    exec_detect_timeout_sec: int = 120
    clock_offset_median_events: int = 5


class BaselineConfig(_Strict):
    """Inputs of `build baseline`: where samples come from and where they go in the guest."""

    samples_dir: str = "samples"
    """Host directory holding ``ransomware/<Family>/<sha256>.zip`` and ``goodware/<sha256>.exe``."""
    sample_target_roots: list[str] = [
        r"C:\Users\Administrator",
        r"C:\Users\Public",
        r"C:\Users\sysmaint",
        r"D:\Backup",
        r"D:\Shares",
    ]
    """Only existing sub-directories of these guest roots receive samples."""
    sample_zip_password: str = "infected"
    sevenzip_guest_path: str = r"C:\Program Files\7-Zip\7z.exe"
    seed: int | None = None


class SentinelcapConfig(_Strict):
    vmware: VMwareConfig
    kafka: KafkaConfig
    capture: CaptureConfig = CaptureConfig()
    baseline: BaselineConfig = BaselineConfig()

    @classmethod
    def load(cls, path: Path | None) -> SentinelcapConfig:
        """Load configuration from YAML and apply environment overrides on top of it.

        Falls back to './config.yaml' when no explicit path is given.
        """
        if path is None:
            default_path = Path("config.yaml")
            path = default_path if default_path.exists() else None

        if path is None:
            raise FileNotFoundError(
                "No configuration file found. Pass --config <path> or create "
                "'config.yaml' in the current directory (see 'sentinelcap config init')."
            )

        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        raw = _apply_env_overrides(raw, prefix=ENV_PREFIX)
        return cls.model_validate(raw)


def _apply_env_overrides(data: dict, prefix: str) -> dict:
    """Apply SENTINELCAP__SECTION__FIELD=value environment overrides in place."""
    for key, value in os.environ.items():
        if not key.startswith(prefix + "__") or not value:
            continue
        path = key[len(prefix) + 2 :].lower().split("__")
        cursor = data
        for part in path[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[path[-1]] = value
    return data


DEFAULT_CONFIG_TEMPLATE = """\
vmware:
  vmrun_path: 'C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe'
  vmx_path: 'D:\\VMs\\Victim\\Victim.vmx'
  # original: clean Windows + decoy folders, no samples. baseline: created by
  # `sentinelcap build baseline` (running, logged-in VM with samples placed).
  # validate: created by `sentinelcap build validate` (every ransomware/goodware
  # pair in a shared guest folder); does not replace baseline.
  original_snapshot: original
  baseline_snapshot: baseline
  validate_snapshot: validate
  guest_user: Administrator
  guest_password: 'CHANGE_ME'
  # SentinelCap opens this application at the sample directory. The operator
  # starts the sample manually from the interactive guest desktop.
  explorer_path: 'C:\\Windows\\explorer.exe'
  start_boot_wait_sec: 30
  tools_ready_timeout_sec: 120

kafka:
  # Must resolve to the address advertised by the Kafka broker to this host.
  bootstrap_servers: 'localhost:9092'
  topic: 'telemetry.windows.normalized'
  # Read host.id from one normalized event for the dedicated victim VM.
  host_id: 'REPLACE_WITH_HOST_ID'
  consumer_group_prefix: 'sentinelcap-capture'
  assignment_timeout_sec: 30
  post_capture_drain_sec: 45

capture:
  out_dir: captures
  quiet_window_sec: 90
  settle_sec: 120
  max_wait_sec: 300
  exec_detect_timeout_sec: 120
  clock_offset_median_events: 5

baseline:
  samples_dir: samples
  sample_target_roots:
    - 'C:\\Users\\Administrator'
    - 'C:\\Users\\Public'
    - 'C:\\Users\\sysmaint'
    - 'D:\\Backup'
    - 'D:\\Shares'
  sample_zip_password: infected
  sevenzip_guest_path: 'C:\\Program Files\\7-Zip\\7z.exe'
  seed: null
"""
