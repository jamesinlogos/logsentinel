"""The repository scripts (``scripts/``): backup, migration, Logstash check, detection verification.

They are standard-library tools run by hand on data that cannot be recreated, so a test is the
only thing between a change and a lost archive.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import re
import tarfile
from pathlib import Path
from typing import Any

import backup_project
import check_logstash_config
import migrate_stack
import pytest
import verify_detections

from inference.documents import SCHEMA_VERSION, document
from inference.scoring import score_window

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------ backup_project
def a_project(base: Path) -> Path:
    """A small repository with data and caches that a backup must leave out."""
    files = {
        "README.md": "readme",
        "src/app.py": "print(1)",
        ".env": "LOGSENTINEL_X=1",
        ".venv/lib/x.py": "venv",
        "src/__pycache__/app.pyc": "cache",
        "pkg.egg-info/PKG-INFO": "info",
        "sentinelcap/captures/20261009T033557Z/akira/s/session.jsonl": "{}",
        "sentinelcap/samples/ransomware/Akira/abc.zip": "malware sample",
        "archives/old.txt": "old",
    }
    for name, content in files.items():
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return base


def backup(root: Path, out: Path, *extra: str) -> tuple[int, list[Path]]:
    code = backup_project.main(
        ["--root", str(root), "--out", str(out), "--min-free-gb", "0", *extra]
    )
    return code, sorted(out.iterdir()) if out.exists() else []


def test_a_backup_holds_the_sources_and_leaves_out_data_and_caches(tmp_path: Path) -> None:
    root = a_project(tmp_path / "repo")
    code, (directory,) = backup(root, tmp_path / "out", "--label", "unit-test")
    assert code == 0 and re.fullmatch(r"\d{8}T\d{6}Z-unit-test", directory.name)
    with tarfile.open(directory / "repo.tar.gz") as archive:
        assert sorted(archive.getnames()) == [".env", "README.md", "src/app.py"]
    assert backup_project.verify_backup(directory) == []
    assert (directory / "SHA256SUMS").read_text(encoding="utf-8").count("repo.tar.gz") == 1
    assert not (directory / "captures.tar.gz").exists()


def test_a_failed_backup_leaves_no_half_written_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file that cannot be read (antivirus blocks a malware sample, say) stops the backup, and
    what was written so far must not be mistaken for a backup."""

    def unreadable(*args: Any, **kwargs: Any) -> int:
        raise OSError(22, "Invalid argument")

    monkeypatch.setattr(backup_project, "write_archive", unreadable)
    root = a_project(tmp_path / "repo")
    with pytest.raises(OSError, match="Invalid argument"):
        backup(root, tmp_path / "out", "--label", "unit-test")
    assert list((tmp_path / "out").iterdir()) == []


def test_captures_are_backed_up_only_on_request(tmp_path: Path) -> None:
    root = a_project(tmp_path / "repo")
    code, (directory,) = backup(root, tmp_path / "out", "--label", "with-data", "--captures")
    assert code == 0
    with tarfile.open(directory / "captures.tar.gz") as archive:
        assert archive.getnames() == ["20261009T033557Z/akira/s/session.jsonl"]


def test_a_damaged_or_incomplete_backup_is_noticed(tmp_path: Path) -> None:
    root = a_project(tmp_path / "repo")
    _, (directory,) = backup(root, tmp_path / "out", "--label", "unit-test")
    archive = directory / "repo.tar.gz"
    data = bytearray(archive.read_bytes())
    data[len(data) // 2] ^= 0xFF
    archive.write_bytes(bytes(data))
    assert any("SHA-256 differs" in p for p in backup_project.verify_backup(directory))
    assert backup_project.main(["--verify", str(directory)]) == 1
    (directory / "MANIFEST.json").unlink()
    assert backup_project.verify_backup(directory)[0].startswith("MANIFEST.json unreadable")


def test_a_backup_needs_a_kebab_case_label_and_enough_space(tmp_path: Path) -> None:
    root = a_project(tmp_path / "repo")
    assert backup(root, tmp_path / "out", "--label", "Not Kebab")[0] == 2
    code = backup_project.main(
        [
            "--root",
            str(root),
            "--out",
            str(tmp_path / "out"),
            "--label",
            "x",
            "--min-free-gb",
            "1e9",
        ]
    )
    assert code == 2 and not list((tmp_path / "out").iterdir())  # nothing half written


# ------------------------------------------------------------------ migrate_stack
def test_the_project_archive_takes_the_sentinelcap_config_but_no_data_or_malware(
    tmp_path: Path,
) -> None:
    root = a_project(tmp_path / "repo")
    (root / "sentinelcap/config.yaml").write_text("vmware: {vmx: D:/vm.vmx}", encoding="utf-8")
    names = {p.relative_to(root).as_posix() for p in migrate_stack.project_files(root)}
    assert names == {".env", "README.md", "src/app.py", "sentinelcap/config.yaml"}


def an_export(directory: Path) -> Path:
    (directory / "volumes").mkdir(parents=True)
    for volume in migrate_stack.VOLUMES:
        with gzip.open(directory / "volumes" / f"{volume}.tar.gz", "wb") as stream:
            stream.write(volume.encode() * 1000)
    migrate_stack.write_manifest(directory, {"facts": {"indices": {}, "offsets": {}}})
    return directory


def an_export_command(root: Path, out: Path) -> argparse.Namespace:
    return argparse.Namespace(
        root=str(root), out=str(out), images=False, leave_stopped=False, force=False
    )


def test_an_export_inside_the_project_is_refused_before_anything_is_touched(
    tmp_path: Path,
) -> None:
    root = a_project(tmp_path / "repo")
    with pytest.raises(migrate_stack.MigrationError, match="inside the project"):
        migrate_stack.export_stack(an_export_command(root, root / "export"))
    assert not (root / "export").exists()


def test_a_previous_export_inside_the_project_is_refused(tmp_path: Path) -> None:
    """Its volumes would be archived again in project.tar.gz (as ``backup_project`` does)."""
    root = a_project(tmp_path / "repo")
    old = an_export(root / "old-export")
    assert migrate_stack.nested_exports(root) == [old]
    with pytest.raises(migrate_stack.MigrationError, match="old-export is an export inside"):
        migrate_stack.export_stack(an_export_command(root, tmp_path / "new-export"))
    (old / "MANIFEST.json").write_text("not json", encoding="utf-8")
    assert migrate_stack.nested_exports(root) == []  # a directory that is no export is left alone


def test_an_export_is_checked_against_its_manifest(tmp_path: Path) -> None:
    directory = an_export(tmp_path / "export")
    assert migrate_stack.verify_export(directory) == []
    assert migrate_stack.main(["verify", str(directory)]) == 0
    broken = directory / "volumes" / "kafka-data.tar.gz"
    broken.write_bytes(broken.read_bytes()[:-20])
    (problem,) = migrate_stack.verify_export(directory)
    assert problem.startswith("volumes/kafka-data.tar.gz: differs")
    (directory / "volumes" / "elasticsearch-data.tar.gz").unlink()
    assert any(
        "elasticsearch-data.tar.gz: missing" in p for p in migrate_stack.verify_export(directory)
    )
    assert migrate_stack.main(["verify", str(directory)]) == 1


def test_a_truncated_gzip_stream_is_not_taken_for_intact(tmp_path: Path) -> None:
    path = tmp_path / "volume.tar.gz"
    with gzip.open(path, "wb") as stream:
        stream.write(b"x" * 100_000)
    assert migrate_stack.gzip_is_intact(path)
    path.write_bytes(path.read_bytes()[:-8])
    assert not migrate_stack.gzip_is_intact(path)


def test_the_new_kafka_host_goes_into_the_env_file_with_its_line_endings(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    before = (
        b"# c\r\nLOGSENTINEL_KAFKA_ADVERTISED_HOST=192.168.110.1\r\nLOGSENTINEL_KAFKA_PORT=9092\r\n"
    )
    env.write_bytes(before)
    previous = migrate_stack.set_env_value(env, migrate_stack.KAFKA_HOST_VARIABLE, "10.0.0.5")
    assert previous == "192.168.110.1"
    assert env.read_bytes() == before.replace(b"192.168.110.1", b"10.0.0.5")
    assert migrate_stack.read_env(env)["LOGSENTINEL_KAFKA_PORT"] == "9092"
    with pytest.raises(migrate_stack.MigrationError, match="has no LOGSENTINEL_X"):
        migrate_stack.set_env_value(env, "LOGSENTINEL_X", "1")


def test_the_counts_and_offsets_of_the_source_are_compared_with_the_target() -> None:
    shown = "t.a:0:12\nt.a:1:0\nWARN noise\n"
    assert migrate_stack.parse_offsets(shown) == {"0": 12, "1": 0}
    source = {"indices": {"windows-telemetry-2026.10.12": 100}, "offsets": {"t.a": {"0": 12}}}
    assert migrate_stack.compare_facts(source, source) == []
    target = {"indices": {"windows-telemetry-2026.10.12": 99}, "offsets": {"t.a": {"0": 13}}}
    assert len(migrate_stack.compare_facts(source, target)) == 2


def test_an_archive_cannot_write_outside_the_target_directory(tmp_path: Path) -> None:
    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as archive:
        info = tarfile.TarInfo("../outside.txt")
        info.size = 2
        archive.addfile(info, io.BytesIO(b"hi"))
    with pytest.raises(tarfile.TarError):
        migrate_stack.extract(evil, tmp_path / "target")
    assert not (tmp_path / "outside.txt").exists()


# ------------------------------------------------------------------ check_logstash_config
def test_the_ingest_filter_is_cut_out_of_the_real_pipeline() -> None:
    conf = (ROOT / "config" / "logstash" / "ingest" / "ingest.conf").read_text(encoding="utf-8")
    block = check_logstash_config.filter_block(conf)
    assert block.startswith("filter {") and block.rstrip().endswith("}")
    assert 'remove_field => ["@version"]' in block and "[threat][framework]" in block
    assert "output {" not in block and "input {" not in block


def test_the_logstash_checks_expect_ecs_threat_fields() -> None:
    for _, threat, _ in check_logstash_config.RULES:
        if threat is not None:
            assert threat["framework"] == "MITRE ATT&CK" and "id" in threat["technique"]
    raw = check_logstash_config.raw_event("technique_id=T1490,technique_name=x")
    assert raw["winlog"]["event_data"]["RuleName"].startswith("technique_id=")


# ------------------------------------------------------------------ verify_detections
def service_documents(gated_window: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    from inference.config import ScoringConfig

    window, result, features = gated_window
    score = score_window(
        window, result, features, 0.9, scoring=ScoringConfig(), threshold=0.5, model=None
    )
    detection = document(score, "detection", reported=True, created=1_760_000_000.0)
    metric = document(score, "window_score", reported=True, created=1_760_000_000.0)
    for doc in (detection, metric):
        doc["event"]["ingested"] = "2026-10-09T10:00:00.000Z"  # what the ingest pipeline adds
    return detection, metric


def test_the_documents_the_service_writes_pass_the_verification(gated_window: Any) -> None:
    detection, metric = service_documents(gated_window)
    window_id = detection["logsentinel"]["window"]["id"]
    assert verify_detections.check_document(window_id, detection, kind="alert") == []
    assert verify_detections.check_document(window_id, metric, kind="metric") == []


def test_the_documents_of_an_early_window_pass_the_verification(
    early_windows: dict[str, Any],
) -> None:
    """They carry a top-level ``process`` and ``window.trigger`` that scheduled windows lack."""
    for triple in early_windows.values():
        detection, metric = service_documents(triple)
        window_id = detection["logsentinel"]["window"]["id"]
        assert detection["logsentinel"]["window"]["trigger"] == "indicator"
        assert "entity_id" in detection["process"]
        assert verify_detections.check_document(window_id, detection, kind="alert") == []
        assert verify_detections.check_document(window_id, metric, kind="metric") == []


def test_the_verification_names_what_is_wrong_with_a_document(gated_window: Any) -> None:
    detection, metric = service_documents(gated_window)
    window_id = detection["logsentinel"]["window"]["id"]
    check = verify_detections.check_document
    assert check("another-id", detection, kind="alert") == [
        "_id differs from logsentinel.window.id"
    ]
    assert "event.kind is 'metric', expected 'alert'" in check(window_id, metric, kind="alert")
    assert "a detection must not carry features" in check(window_id, metric, kind="alert")
    assert check(window_id, detection, kind="metric") == [
        "event.kind is 'alert', expected 'metric'",
        "a window score without features",
    ]
    stray = {**detection, "@version": "1"}
    stray["event"] = {**detection["event"], "original": "{}"}
    del stray["event"]["ingested"]
    problems = check(window_id, stray, kind="alert")
    assert {"has @version", "has event.original", "missing event.ingested"} <= set(problems)


def test_the_verification_expects_the_schema_version_of_the_service(
    gated_window: Any,
) -> None:
    assert verify_detections.SCHEMA_VERSION == SCHEMA_VERSION
    detection, _ = service_documents(gated_window)
    other = {**detection, "logsentinel": {**detection["logsentinel"], "schema_version": 99}}
    window_id = detection["logsentinel"]["window"]["id"]
    problems = verify_detections.check_document(window_id, other, kind="alert")
    assert problems == [f"logsentinel.schema_version is not {SCHEMA_VERSION}"]


def test_a_document_without_a_window_id_fails_the_verification() -> None:
    source = {"@timestamp": "2026-10-01T09:03:30.000Z"}
    problems = verify_detections.check_document("abc", source, kind="alert")
    assert "missing logsentinel.window.id" in problems


def test_a_consumer_group_row_is_recognised() -> None:
    row = (
        "logstash-detection-sink security.ransomware.detections 0 12 12 0 consumer-1 /172.18.0.5 c"
    )
    assert verify_detections.Report is not None
    assert verify_detections._is_row(row)
    assert not verify_detections._is_row("GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG")
    assert not verify_detections._is_row("g t 0 - 12 - consumer-1 /h c")  # no offset committed yet


def test_the_flow_check_compares_detections_with_reported_window_scores() -> None:
    class Searches:
        def __init__(self, detections: int, reported: int, have: list[str]) -> None:
            self.detections, self.reported, self.have = detections, reported, have

        def get(self, path: str, body: dict[str, Any] | None = None) -> Any:
            if path == "ransomware-detections-*/_count":
                return {"count": self.detections}
            if path == "ransomware-window-scores-*/_count":
                return {"count": self.reported}
            if path == "ransomware-detections-*/_search":
                return {"hits": {"hits": [{"_id": "a"}, {"_id": "b"}]}}
            return {"hits": {"hits": [{"_id": i} for i in self.have]}}

    good, report = Searches(2, 2, ["a", "b"]), verify_detections.Report()
    verify_detections.check_flow(good, report, "24h")  # type: ignore[arg-type]
    assert report.failed == 0
    bad, report = Searches(2, 1, ["a"]), verify_detections.Report()
    verify_detections.check_flow(bad, report, "24h")  # type: ignore[arg-type]
    assert report.failed == 2  # the counts differ and one detection has no window score


# ------------------------------------------------------------------ backup_project --stack
def fake_stack(monkeypatch: pytest.MonkeyPatch, *, documents: int = 2, fail: str = "") -> None:
    hits = [
        {"_index": "ransomware-detections-2026.10", "_id": f"id{i}", "_source": {"n": i}}
        for i in range(documents)
    ]

    def http(url: str, *, method: str = "GET", body: dict[str, Any] | None = None) -> bytes:
        if fail and fail in url:
            raise ValueError("boom")
        if url.endswith("/ransomware-*/_search"):
            return json.dumps({"hits": {"total": {"value": 5}, "hits": hits}}).encode()
        if "_cat/indices?format=json&h=index" in url:
            return json.dumps(
                [{"index": "windows-telemetry-2026.10.01"}, {"index": ".kibana"}]
            ).encode()
        return b"{}"

    monkeypatch.setattr(backup_project, "http", http)
    monkeypatch.setattr(backup_project, "run", lambda command: "docker output")


def test_the_stack_export_keeps_the_documents_of_the_ransomware_indices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_stack(monkeypatch, documents=5)
    errors = backup_project.export_stack(tmp_path / "stack", "http://es", "http://kibana")
    assert errors == {}
    lines = (tmp_path / "stack" / "es-ransomware-documents.ndjson").read_text("utf-8").splitlines()
    assert [json.loads(line)["_id"] for line in lines] == [f"id{i}" for i in range(5)]
    assert json.loads(lines[0]) == {
        "_index": "ransomware-detections-2026.10",
        "_id": "id0",
        "_source": {"n": 0},
    }
    names = {p.name for p in (tmp_path / "stack").iterdir()}
    assert {
        "es-index-templates.json",
        "kibana-saved-objects.ndjson",
        "docker-inspect.json",
    } <= names
    # system indices are not described, the lab's own are
    assert (tmp_path / "stack" / "es-index-mappings.json").is_file()


def test_a_failing_part_of_the_stack_export_is_reported_not_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_stack(
        monkeypatch, documents=3, fail="kibana"
    )  # more hits than the 3 returned: also refused
    errors = backup_project.export_stack(tmp_path / "stack", "http://es", "http://kibana")
    assert set(errors) == {"kibana-saved-objects.ndjson", "es-ransomware-documents.ndjson"}
    assert "boom" in errors["kibana-saved-objects.ndjson"]
    assert "more than" in errors["es-ransomware-documents.ndjson"]
    assert (tmp_path / "stack" / "es-index-templates.json").is_file()  # the rest is still written
