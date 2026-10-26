"""``batch --validate``: pair grouping, dual Event 1 detection, batch wiring."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinelcap import cli, orchestrate
from sentinelcap.config import KafkaConfig, SentinelcapConfig, VMwareConfig
from sentinelcap.errors import SentinelcapError
from sentinelcap.manifest import ManifestEntry, Mode, group_validate_pairs, parse_row
from sentinelcap.session import EventInfo, format_timestamp, parse_event

RW, GW = "1" * 64, "a" * 64
DIR = r"C:\Users\Public\Documents"
T0 = datetime(2026, 9, 24, 5, 0, 0, tzinfo=timezone.utc)


def make_cfg(out_dir: Path | None = None) -> SentinelcapConfig:
    cfg = SentinelcapConfig(
        vmware=VMwareConfig(vmx_path="x", guest_user="u", guest_password="p"),
        kafka=KafkaConfig(host_id="h"),
    )
    if out_dir is not None:
        cfg.capture.out_dir = str(out_dir)
    return cfg


def entry(sample: str, path: str, label: int, family: str = "akira") -> ManifestEntry:
    if label == 0:
        family = "goodware"
    return ManifestEntry(family=family, sample=sample, path=path, label=label)


def make_exec(path: str, sha: str, eid: str, at: float) -> EventInfo:
    ts = format_timestamp(T0)
    doc = {
        "@timestamp": ts,
        "host": {"id": "h"},
        "event": {"code": "1"},
        "process": {
            "executable": path,
            "entity_id": eid,
            "parent": {"entity_id": "{P}"},
            "hash": {"sha256": sha},
        },
    }
    return parse_event(json.dumps(doc).encode(), at, T0)


def test_parse_row_validate_matches_execute() -> None:
    row = {
        "family": "LockBit",
        "sample": RW.upper(),
        "path": rf"{DIR}\a.exe",
        "label": "1",
    }
    assert parse_row(row, Mode.VALIDATE) == parse_row(row, Mode.EXECUTE)


def test_group_validate_pairs_by_shared_directory() -> None:
    rw1 = entry(RW, rf"{DIR}\r1.exe", 1, "lockbit")
    gw1 = entry(GW, rf"{DIR}\g1.exe", 0)
    other = r"C:\Users\Public\Music"
    rw2 = entry("2" * 64, rf"{other}\r2.exe", 1, "akira")
    gw2 = entry("b" * 64, rf"{other}\g2.exe", 0)
    pairs = group_validate_pairs([rw1, gw1, rw2, gw2])
    assert pairs == [(rw1, gw1), (rw2, gw2)]
    pairs_reordered = group_validate_pairs([gw1, rw1, gw2, rw2])
    assert pairs_reordered == [(rw1, gw1), (rw2, gw2)]


def test_group_validate_pairs_rejects_bad_groups() -> None:
    with pytest.raises(ValueError, match="exactly 2"):
        group_validate_pairs(
            [
                entry(RW, rf"{DIR}\r.exe", 1),
                entry(GW, rf"{DIR}\g.exe", 0),
                entry("2" * 64, rf"{DIR}\extra.exe", 1, "akira"),
            ]
        )
    with pytest.raises(ValueError, match="ransomware"):
        group_validate_pairs(
            [
                entry(RW, rf"{DIR}\a.exe", 1),
                entry("2" * 64, rf"{DIR}\b.exe", 1, "akira"),
            ]
        )


def test_detect_exec_pair_finds_both() -> None:
    class Fake:
        def __init__(self) -> None:
            self.events: list[EventInfo] = []
            self._n = 0

        def poll_event(self, timeout: float = 1.0) -> EventInfo | None:
            self._n += 1
            if self._n == 1:
                self.events.append(make_exec(rf"{DIR}\r.exe", RW, "{rw}", 1.0))
            elif self._n == 2:
                self.events.append(make_exec(rf"{DIR}\g.exe", GW, "{gw}", 2.0))
            return self.events[-1] if self._n <= 2 else None

    found_rw, found_gw = orchestrate.detect_exec_pair(
        Fake(),
        entry(RW, rf"{DIR}\r.exe", 1),
        entry(GW, rf"{DIR}\g.exe", 0),
        2.0,
    )
    assert found_rw.entity_id == "{rw}" and found_gw.entity_id == "{gw}"


def test_detect_exec_pair_times_out() -> None:
    class Fake:
        events: list = []  # noqa: RUF012

        def poll_event(self, timeout: float = 1.0) -> None:
            return None

    with pytest.raises(SentinelcapError, match="No Sysmon Event 1"):
        orchestrate.detect_exec_pair(
            Fake(),
            entry(RW, rf"{DIR}\r.exe", 1),
            entry(GW, rf"{DIR}\g.exe", 0),
            0.05,
        )


def test_batch_validate_runs_pairs_and_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    csv_path = tmp_path / "manifest-validate.csv"
    h2, g2 = "2" * 64, "b" * 64
    other = r"C:\Users\Public\Music"
    csv_path.write_text(
        "family,sample,path,label\n"
        f"lockbit,{RW},{DIR}\\r1.exe,1\n"
        f"goodware,{GW},{DIR}\\g1.exe,0\n"
        f"akira,{h2},{other}\\r2.exe,1\n"
        f"goodware,{g2},{other}\\g2.exe,0\n",
        encoding="utf-8",
    )
    calls: list[tuple[str, str]] = []
    run_dirs: set[Path | None] = set()

    def fake_pair(cfg, ransomware, goodware, force=False, run_dir=None):
        calls.append((ransomware.sample, goodware.sample))
        run_dirs.add(run_dir)
        if ransomware.sample == RW:
            raise SentinelcapError("boom")
        return tmp_path / ransomware.sample, tmp_path / goodware.sample

    monkeypatch.setattr(orchestrate, "run_validate_pair", fake_pair)
    monkeypatch.setattr(cli, "_load_config", lambda p: make_cfg(tmp_path))
    result = CliRunner().invoke(cli.app, ["batch", str(csv_path), "--validate"])
    assert calls == [(RW, GW), (h2, g2)]
    assert len(run_dirs) == 1 and None not in run_dirs
    assert result.exit_code == 1
    assert "FAILED" in result.output and "boom" in result.output and "ok" in result.output


def test_batch_mode_flag_exactly_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda p: make_cfg())
    runner = CliRunner()
    assert runner.invoke(cli.app, ["batch", "m.csv"]).exit_code == 1
    assert runner.invoke(cli.app, ["batch", "m.csv", "--execute", "--validate"]).exit_code == 1
    assert (
        runner.invoke(
            cli.app, ["batch", "m.csv", "--execute", "--interactive", "--validate"]
        ).exit_code
        == 1
    )


def test_run_session_rejects_validate_mode(tmp_path: Path) -> None:
    cfg = make_cfg(tmp_path)
    with pytest.raises(SentinelcapError, match="batch --validate"):
        orchestrate.run_session(cfg, entry(RW, rf"{DIR}\a.exe", 1), Mode.VALIDATE, run_dir=tmp_path)
