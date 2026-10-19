"""Directory export, lossless payloads, metadata, and batch behaviour."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinelcap import cli, orchestrate
from sentinelcap.capture import KafkaCapture
from sentinelcap.config import KafkaConfig, SentinelcapConfig, VMwareConfig
from sentinelcap.errors import SentinelcapError
from sentinelcap.manifest import ManifestEntry, Mode
from sentinelcap.session import parse_event

SHA = "a" * 64
NOW = datetime(2026, 9, 24, tzinfo=timezone.utc)


def dt(sec: int) -> datetime:
    return datetime(2026, 9, 24, 0, 0, sec, tzinfo=timezone.utc)


def loaded() -> tuple[KafkaCapture, list[bytes]]:
    cap = KafkaCapture(KafkaConfig(host_id="h"))
    payloads = [
        b'{"@timestamp":"2026-09-24T00:00:00.000Z","host":{"id":"h","os":{"build":"OLD"}}}',
        (
            b'{ "@timestamp": "2026-09-24T00:00:05.000Z",'
            b' "host":{"id":"h","os":{"build":"20348.587"}},'
            b' "agent":{"version":"9.5.4"}, "z": 1 }\n'
        ),
        b'{"@timestamp":"2026-09-24T00:00:20.000Z","host":{"id":"h"}}',
    ]
    cap._events.extend(parse_event(p, 0.0, NOW) for p in payloads)
    return cap, payloads


def export(cap: KafkaCapture, out: Path, **kw) -> Path:
    args = {
        "mode": "execute",
        "family": "akira",
        "sample": SHA,
        "label": 1,
        "t_start": dt(1),
        "t_end": dt(10),
        "out_dir": out,
        "session_id": "s1",
        "process_entity_id": "{R}",
    }
    args.update(kw)
    return cap.export_session(**args)


def test_export_window_bytes_and_metadata(tmp_path) -> None:
    cap, payloads = loaded()
    d = export(cap, tmp_path)
    assert d == tmp_path / "akira" / SHA
    assert (d / "session.jsonl").read_bytes() == payloads[
        1
    ]  # byte-for-byte, only the in-window event
    meta = json.loads((d / "metadata.json").read_text(encoding="utf-8"))
    assert meta["format"] == "logsentinel.normalized-sysmon.jsonl/v1" and meta["mode"] == "execute"
    assert meta["label"] == {"target_class_name": f"akira-{SHA}", "target_class": 1}
    assert meta["process_entity_id"] == "{R}" and "scenario" not in meta
    assert meta["event_count"] == 1 and meta["skipped_outside_session"] == 2
    assert "sample_entity_ids" not in meta


def test_environment_block_from_config_and_first_window_event(tmp_path) -> None:
    from sentinelcap import __version__

    cap, _ = loaded()
    d = export(cap, tmp_path, snapshot="baseline", sample_entity_ids=["{R}", "{R2}"])
    meta = json.loads((d / "metadata.json").read_text(encoding="utf-8"))
    # Read from the first event inside the window, not from the earlier "OLD" one.
    assert meta["environment"] == {
        "sentinelcap_version": __version__,
        "snapshot": "baseline",
        "windows_build": "20348.587",
        "winlogbeat_version": "9.5.4",
    }
    assert meta["sample_entity_ids"] == ["{R}", "{R2}"]


def test_environment_fields_missing_in_event_are_null(tmp_path) -> None:
    cap, _ = loaded()
    d = export(cap, tmp_path, t_start=dt(15), t_end=dt(25))
    env = json.loads((d / "metadata.json").read_text(encoding="utf-8"))["environment"]
    assert (
        env["windows_build"] is None
        and env["winlogbeat_version"] is None
        and env["snapshot"] is None
    )


def test_label_comes_from_the_label_not_family(tmp_path) -> None:
    cap, _ = loaded()
    d = export(cap, tmp_path, family="benign", label=1)
    assert json.loads((d / "metadata.json").read_text())["label"]["target_class"] == 1


def test_existing_directory_refused_unless_force(tmp_path) -> None:
    cap, _ = loaded()
    d = export(cap, tmp_path)
    data = d / "session.jsonl"
    before = data.read_bytes()
    with pytest.raises(SentinelcapError, match="already exists"):
        export(cap, tmp_path)
    assert data.read_bytes() == before
    export(cap, tmp_path, force=True, t_start=dt(0), t_end=dt(30))
    assert data.read_bytes() != before


def test_empty_window_writes_nothing(tmp_path) -> None:
    cap, _ = loaded()
    with pytest.raises(SentinelcapError):
        export(cap, tmp_path, t_start=dt(40), t_end=dt(50))
    assert not (tmp_path / "akira" / SHA).exists()


def test_same_sample_under_another_family_refused_even_with_force(tmp_path) -> None:
    cap, _ = loaded()
    export(cap, tmp_path, family="lockbit")
    with pytest.raises(SentinelcapError, match="different family"):
        export(cap, tmp_path, family="akira", force=True)
    assert not (tmp_path / "akira").exists()


def test_interactive_metadata(tmp_path) -> None:
    cap, _ = loaded()
    d = export(
        cap,
        tmp_path,
        mode="interactive",
        sample="backup-2",
        process_entity_id=None,
        scenario="backup-2",
        clock_offset_sec=1.5,
    )
    meta = json.loads((d / "metadata.json").read_text())
    assert (
        meta["scenario"] == "backup-2"
        and meta["clock_offset_sec"] == 1.5
        and "process_entity_id" not in meta
    )


def make_cfg() -> SentinelcapConfig:
    return SentinelcapConfig(
        vmware=VMwareConfig(vmx_path="x", guest_user="u", guest_password="p"),
        kafka=KafkaConfig(host_id="h"),
    )


def test_batch_continues_after_failure_and_exits_nonzero(tmp_path, monkeypatch) -> None:
    csv_path = tmp_path / "m.csv"
    h1, h2 = "1" * 64, "2" * 64
    csv_path.write_text(
        f"family,sample,path,label\nAkira,{h1},C:\\a.exe,1\nAkira,{h2},C:\\b.exe,1\n",
        encoding="utf-8",
    )
    calls: list[str] = []

    run_dirs: set = set()

    def fake_run(cfg, entry, mode, force=False, run_dir=None):
        calls.append(entry.sample)
        run_dirs.add(run_dir)
        if entry.sample == h1:
            raise SentinelcapError("boom")
        return tmp_path / entry.sample

    monkeypatch.setattr(orchestrate, "run_session", fake_run)
    monkeypatch.setattr(cli, "_load_config", lambda p: make_cfg())
    result = CliRunner().invoke(cli.app, ["batch", str(csv_path), "--execute"])
    assert calls == [h1, h2]
    assert len(run_dirs) == 1 and None not in run_dirs  # one run directory for the whole batch
    assert result.exit_code == 1
    assert "FAILED" in result.output and "boom" in result.output and "ok" in result.output


def test_mode_flag_required_exactly_one(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda p: make_cfg())
    runner = CliRunner()
    assert runner.invoke(cli.app, ["batch", "m.csv"]).exit_code == 1
    assert runner.invoke(cli.app, ["batch", "m.csv", "--execute", "--interactive"]).exit_code == 1


def test_run_rejects_existing_dir_before_touching_vm(tmp_path, monkeypatch) -> None:
    cfg = make_cfg()
    (tmp_path / "akira" / SHA).mkdir(parents=True)

    def boom(*a, **k):
        raise AssertionError("VM must not be touched")

    monkeypatch.setattr(orchestrate, "VMwareController", boom)
    entry = ManifestEntry(family="akira", sample=SHA, path="C:\\a.exe", label=1)
    with pytest.raises(SentinelcapError, match="already exists"):
        orchestrate.run_session(cfg, entry, Mode.EXECUTE, run_dir=tmp_path)


def test_detect_exec_times_out_without_event1() -> None:
    class Fake:
        events: list = []  # noqa: RUF012

        def poll_event(self, timeout=1.0):
            return None

    entry = ManifestEntry(family="Akira", sample=SHA, path="C:\\a.exe", label=1)
    with pytest.raises(SentinelcapError, match="No Sysmon Event 1"):
        orchestrate.detect_exec(Fake(), entry, 0.05)
