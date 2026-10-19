"""Names the operator types or reads (AGENTS.md section 11): CLI flags and run directories."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from typer.testing import CliRunner

from sentinelcap import cli, orchestrate
from sentinelcap.config import KafkaConfig, SentinelcapConfig, VMwareConfig
from sentinelcap.session import RUN_STAMP_FORMAT, run_stamp

SHA = "a" * 64


def make_cfg(out_dir) -> SentinelcapConfig:
    cfg = SentinelcapConfig(
        vmware=VMwareConfig(vmx_path="x", guest_user="u", guest_password="p"),
        kafka=KafkaConfig(host_id="h"),
    )
    cfg.capture.out_dir = str(out_dir)
    return cfg


def test_run_stamp_is_utc_whatever_the_zone_of_the_moment() -> None:
    moment = datetime(2026, 10, 9, 10, 35, 57, tzinfo=timezone(timedelta(hours=7)))
    assert run_stamp(moment) == "20261009T033557Z"  # 10:35:57+07:00 is 03:35:57Z
    parsed = datetime.strptime(run_stamp(moment), RUN_STAMP_FORMAT).replace(tzinfo=timezone.utc)
    assert parsed == moment


def test_new_run_dir_is_named_by_the_utc_stamp(tmp_path) -> None:
    run_dir = orchestrate.new_run_dir(make_cfg(tmp_path))
    assert run_dir.parent == tmp_path
    assert re.fullmatch(r"\d{8}T\d{6}Z", run_dir.name)
    stamp = datetime.strptime(run_dir.name, RUN_STAMP_FORMAT).replace(tzinfo=timezone.utc)
    assert abs(datetime.now(timezone.utc) - stamp) < timedelta(seconds=5)


def test_help_shows_sample_and_label() -> None:
    for command in ("capture", "run"):
        output = CliRunner().invoke(cli.app, [command, "--help"]).output
        assert "--sample" in output and "--label" in output


def test_a_missing_sample_or_label_is_a_usage_error(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda p: make_cfg(tmp_path))
    runner = CliRunner()
    base = ["capture", "--family", "idle", "--duration", "5"]
    assert runner.invoke(cli.app, [*base, "--label", "0"]).exit_code == 2
    assert runner.invoke(cli.app, [*base, "--sample", "idle-01"]).exit_code == 2


def test_run_takes_sample_and_label(tmp_path, monkeypatch) -> None:
    seen = []

    def fake_run(cfg, entry, mode, force=False, run_dir=None):
        seen.append(entry)
        return tmp_path

    monkeypatch.setattr(cli, "_load_config", lambda p: make_cfg(tmp_path))
    monkeypatch.setattr(cli, "run_session", fake_run)
    path = r"C:\a.exe"
    args = [
        "run",
        "--family",
        "Akira",
        "--sample",
        SHA,
        "--label",
        "1",
        "--path",
        path,
        "--execute",
    ]
    assert CliRunner().invoke(cli.app, args).exit_code == 0
    assert (seen[0].family, seen[0].sample, seen[0].label) == ("akira", SHA, 1)
