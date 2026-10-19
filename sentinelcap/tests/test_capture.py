"""The ``capture`` command: same session directory and metadata as ``run``."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from sentinelcap import cli, orchestrate
from sentinelcap.capture import SESSION_FORMAT, KafkaCapture
from sentinelcap.config import KafkaConfig, SentinelcapConfig, VMwareConfig
from sentinelcap.errors import SentinelcapError
from sentinelcap.manifest import Mode, parse_row
from sentinelcap.session import format_timestamp, parse_event


class FakeCapture(KafkaCapture):
    """Feeds events stamped with the current time instead of reading Kafka."""

    def start(self) -> None:
        pass

    def close(self) -> None:
        pass

    def poll_for(self, seconds: float) -> None:
        time.sleep(0.01)  # keep millisecond timestamps strictly inside the window
        now = datetime.now(timezone.utc)
        payload = json.dumps({"@timestamp": format_timestamp(now), "host": {"id": "h"}}).encode()
        self._events.append(parse_event(payload, time.monotonic(), now))
        time.sleep(0.01)


def make_cfg(tmp_path) -> SentinelcapConfig:
    cfg = SentinelcapConfig(
        vmware=VMwareConfig(vmx_path="x", guest_user="u", guest_password="p"),
        kafka=KafkaConfig(host_id="h", post_capture_drain_sec=0),
    )
    cfg.capture.out_dir = str(tmp_path)
    return cfg


def test_capture_writes_session_directory_with_capture_mode(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(orchestrate, "KafkaCapture", FakeCapture)
    entry = parse_row(
        {"family": "idle", "sample": "idle-01", "path": None, "label": "0"}, Mode.CAPTURE
    )
    d = orchestrate.run_capture(make_cfg(tmp_path), entry, duration=0)
    meta = json.loads((d / "metadata.json").read_text(encoding="utf-8"))
    # Same <out_dir>/<UTC timestamp>/<family>/<sample> layout as run/batch.
    assert d.parent.parent.parent == tmp_path and d.parts[-2:] == ("idle", "idle-01")
    assert re.fullmatch(r"\d{8}T\d{6}Z", d.parent.parent.name)
    assert meta["format"] == SESSION_FORMAT
    assert meta["mode"] == "capture"
    assert meta["label"] == {"target_class_name": "idle-idle-01", "target_class": 0}
    assert meta["environment"]["snapshot"] is None
    assert meta["event_count"] == 1  # the drain event falls after t_end
    assert "process_entity_id" not in meta
    assert "sample_entity_ids" not in meta


def test_capture_refuses_existing_directory(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(orchestrate, "KafkaCapture", FakeCapture)
    monkeypatch.setattr(orchestrate, "new_run_dir", lambda cfg: tmp_path / "run")
    (tmp_path / "run" / "idle" / "idle-01").mkdir(parents=True)
    entry = parse_row(
        {"family": "idle", "sample": "idle-01", "path": None, "label": "0"}, Mode.CAPTURE
    )
    with pytest.raises(SentinelcapError, match="already exists"):
        orchestrate.run_capture(make_cfg(tmp_path), entry, duration=0)


@pytest.mark.parametrize(
    "args",
    [
        [
            "--family",
            "idle",
            "--sample",
            "idle-01",
            "--label",
            "2",
            "--duration",
            "5",
        ],  # label not 0/1
        [
            "--family",
            "idle",
            "--sample",
            "../x",
            "--label",
            "0",
            "--duration",
            "5",
        ],  # unsafe session code
        [
            "--family",
            "idle",
            "--sample",
            "idle-01",
            "--label",
            "0",
            "--duration",
            "0",
        ],  # no duration
    ],
)
def test_capture_cli_rejects_invalid_input(args, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda p: make_cfg(tmp_path))
    monkeypatch.setattr(orchestrate, "KafkaCapture", FakeCapture)
    assert CliRunner().invoke(cli.app, ["capture", *args]).exit_code == 1
    assert not any(tmp_path.iterdir())
