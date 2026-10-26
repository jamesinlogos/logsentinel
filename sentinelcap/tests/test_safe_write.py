"""Crash-safe session writing, pipeline lag, clock offset and configuration precedence."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinelcap import capture as capture_mod
from sentinelcap.capture import KafkaCapture, pipeline_lag, prepare_session_dir
from sentinelcap.config import KafkaConfig, SentinelcapConfig
from sentinelcap.errors import SentinelcapError
from sentinelcap.session import format_timestamp, parse_event

SHA = "a" * 64
T0 = datetime(2026, 9, 24, tzinfo=timezone.utc)


def ev(sec: float, created_lag: float | None = None, received_lag: float = 0.0):
    ts = T0 + timedelta(seconds=sec)
    doc: dict = {"@timestamp": format_timestamp(ts), "host": {"id": "h"}}
    if created_lag is not None:
        doc["event"] = {"created": format_timestamp(ts + timedelta(seconds=created_lag))}
    return parse_event(json.dumps(doc).encode(), 0.0, ts + timedelta(seconds=received_lag))


def cap_with(*events, drain: int = 45) -> KafkaCapture:
    cap = KafkaCapture(KafkaConfig(host_id="h", post_capture_drain_sec=drain))
    cap._events.extend(events)
    return cap


def export(cap: KafkaCapture, out: Path, **kw) -> Path:
    args = {
        "mode": "execute",
        "family": "akira",
        "sample": SHA,
        "label": 1,
        "t_start": T0,
        "t_end": T0 + timedelta(seconds=60),
        "out_dir": out,
        "session_id": "s",
        "process_entity_id": "{R}",
    }
    args.update(kw)
    return cap.export_session(**args)


# ------------------------------------------------------------------ safe write
def test_failure_while_writing_metadata_leaves_no_session_dir(tmp_path, monkeypatch) -> None:
    cap = cap_with(ev(1))

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_text", boom)
    with pytest.raises(OSError):
        export(cap, tmp_path)
    monkeypatch.undo()
    assert not (tmp_path / "akira" / SHA).exists()
    assert (tmp_path / "akira" / f".{SHA}.partial").exists()
    # The next run is not blocked and cleans the leftover.
    d = export(cap, tmp_path)
    assert (d / "metadata.json").exists()
    assert not (tmp_path / "akira" / f".{SHA}.partial").exists()


def test_force_overwrites_existing_session(tmp_path) -> None:
    d = export(cap_with(ev(1)), tmp_path)
    export(cap_with(ev(1), ev(2)), tmp_path, force=True)
    assert json.loads((d / "metadata.json").read_text())["event_count"] == 2
    assert [p.name for p in (tmp_path / "akira").iterdir()] == [SHA]


def test_interrupted_force_swap_restores_previous_session(tmp_path, monkeypatch) -> None:
    d = export(cap_with(ev(1)), tmp_path)
    real_replace = capture_mod.os.replace
    calls = []

    def replace_then_die(src, dst):
        calls.append((src, dst))
        if len(calls) == 2:  # target -> .old done, .partial -> target dies
            raise OSError("killed")
        return real_replace(src, dst)

    monkeypatch.setattr(capture_mod.os, "replace", replace_then_die)
    with pytest.raises(OSError):
        export(cap_with(ev(1), ev(2)), tmp_path, force=True)
    monkeypatch.undo()
    assert not d.exists() and (tmp_path / "akira" / f".{SHA}.old").exists()
    # Next check restores the previous session instead of losing it.
    with pytest.raises(SentinelcapError, match="already exists"):
        prepare_session_dir(tmp_path, "akira", SHA, force=False)
    assert json.loads((d / "metadata.json").read_text())["event_count"] == 1


def test_partial_under_another_family_does_not_block_the_sample(tmp_path) -> None:
    (tmp_path / "lockbit" / f".{SHA}.partial").mkdir(parents=True)
    assert prepare_session_dir(tmp_path, "akira", SHA, force=False) == tmp_path / "akira" / SHA


# ------------------------------------------------------------------ pipeline lag
def test_parse_event_created_valid_missing_invalid() -> None:
    assert ev(0, created_lag=2).created == T0 + timedelta(seconds=2)
    assert ev(0).created is None
    bad = parse_event(b'{"@timestamp":"2026-09-24T00:00:00Z","event":{"created":"nope"}}', 0.0, T0)
    assert bad.created is None


def test_pipeline_lag_max_and_median_in_metadata(tmp_path) -> None:
    d = export(cap_with(ev(1, 1.0), ev(2, 3.0), ev(3, 10.0), ev(4)), tmp_path)
    meta = json.loads((d / "metadata.json").read_text())
    assert meta["pipeline_lag_max_sec"] == 10.0 and meta["pipeline_lag_p50_sec"] == 3.0
    assert pipeline_lag([ev(1)]) == (None, None)


def test_metadata_without_event_created(tmp_path) -> None:
    meta = json.loads((export(cap_with(ev(1)), tmp_path) / "metadata.json").read_text())
    assert meta["pipeline_lag_max_sec"] is None and meta["pipeline_lag_p50_sec"] is None


def test_warning_when_lag_reaches_drain(tmp_path, caplog) -> None:
    with caplog.at_level(logging.WARNING):
        export(cap_with(ev(1, 45.0), drain=45), tmp_path / "a")
    assert "may miss its last events" in caplog.text
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        export(cap_with(ev(1, 44.0), drain=45), tmp_path / "b")
    assert "may miss its last events" not in caplog.text


# ------------------------------------------------------------------ shared topic
class _Msg:
    def __init__(self, value) -> None:
        self._value = value

    def error(self):
        return None

    def value(self):
        return self._value


class _Consumer:
    def __init__(self, values) -> None:
        self._values = list(values)

    def poll(self, timeout):
        return _Msg(self._values.pop(0)) if self._values else None


def test_bad_messages_of_other_hosts_do_not_abort_the_session() -> None:
    cap = KafkaCapture(KafkaConfig(host_id="h"))
    cap._consumer = _Consumer(
        [
            b"not json",
            b"[1, 2]",
            b'{"host": {"id": "other"}, "@timestamp": "garbage"}',
            b'{"host": {"id": "h"}, "@timestamp": "2026-09-24T00:00:00Z"}',
        ]
    )
    for _ in range(4):
        cap.poll_event(0)
    assert (cap.skipped_invalid, cap.skipped_other_hosts, len(cap.events)) == (2, 1, 1)


def test_bad_timestamp_of_the_victim_still_fails() -> None:
    cap = KafkaCapture(KafkaConfig(host_id="h"))
    cap._consumer = _Consumer([b'{"host": {"id": "h"}, "@timestamp": "garbage"}'])
    with pytest.raises(SentinelcapError, match="@timestamp"):
        cap.poll_event(0)


# ------------------------------------------------------------------ clock offset
def test_clock_offset_is_median_of_first_events() -> None:
    cap = cap_with(
        ev(0, received_lag=12.0),
        ev(1, received_lag=1.0),
        ev(2, received_lag=2.0),
        ev(3, received_lag=3.0),
        ev(4, received_lag=30.0),
        ev(5, received_lag=100.0),
    )
    assert cap.clock_offset_sec(5) == 3.0
    assert cap.clock_offset_sec(1) == 12.0
    with pytest.raises(SentinelcapError):
        cap_with().clock_offset_sec(5)


# ------------------------------------------------------------------ config
def test_env_overrides_yaml(tmp_path, monkeypatch) -> None:
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "vmware: {vmx_path: x, guest_user: u, guest_password: from-yaml}\nkafka: {host_id: h}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SENTINELCAP__VMWARE__GUEST_PASSWORD", "from-env")
    cfg = SentinelcapConfig.load(cfg_file)
    assert cfg.vmware.guest_password == "from-env"
    assert cfg.kafka.post_capture_drain_sec == 45
    assert (cfg.vmware.original_snapshot, cfg.vmware.baseline_snapshot) == ("original", "baseline")
    assert cfg.vmware.validate_snapshot == "validate"
    assert cfg.baseline.sample_zip_password == "infected"


def test_shipped_yaml_and_template_load() -> None:
    import yaml

    from sentinelcap.config import DEFAULT_CONFIG_TEMPLATE

    # The operator tunes config.yaml (timeouts, waits): it must load, its values are theirs.
    SentinelcapConfig.model_validate(
        yaml.safe_load(
            Path(__file__).parents[1].joinpath("config.yaml").read_text(encoding="utf-8")
        )
    )
    template = yaml.safe_load(DEFAULT_CONFIG_TEMPLATE)
    template["kafka"]["host_id"] = "h"
    defaults = SentinelcapConfig.model_validate(template)
    assert defaults.kafka.post_capture_drain_sec == 45 and defaults.capture.settle_sec == 120
    assert defaults.baseline.sevenzip_guest_path.endswith("7z.exe")
