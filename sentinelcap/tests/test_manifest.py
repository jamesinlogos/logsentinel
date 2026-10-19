"""Manifest schema and per-mode validation."""

from __future__ import annotations

import pytest

from sentinelcap.manifest import MANIFEST_COLUMNS, Mode, load_manifest, parse_row

SHA = "a" * 64


def row(**kw):
    base = {"family": "Akira", "sample": SHA, "path": r"C:\Users\x\Downloads\a.exe", "label": "1"}
    base.update(kw)
    return base


def test_execute_row_ok_and_sample_lowercased() -> None:
    entry = parse_row(row(sample=SHA.upper()), Mode.EXECUTE)
    assert entry.sample == SHA
    assert entry.label == 1
    assert entry.session_name == f"akira-{SHA}"


@pytest.mark.parametrize("family", ["LockBit", "Lockbit", "lockbit"])
def test_family_lowercased_so_one_directory_per_family(family: str) -> None:
    assert parse_row(row(family=family), Mode.EXECUTE).family == "lockbit"


@pytest.mark.parametrize("bad", ["../akira", "a/b", "Black Basta", "a\\b"])
def test_family_must_be_path_safe(bad: str) -> None:
    with pytest.raises(ValueError, match="family"):
        parse_row(row(family=bad), Mode.EXECUTE)


@pytest.mark.parametrize("bad", ["2", "", "goodware", "-1"])
def test_label_must_be_0_or_1(bad: str) -> None:
    with pytest.raises(ValueError, match="label"):
        parse_row(row(label=bad), Mode.EXECUTE)


def test_execute_requires_path() -> None:
    with pytest.raises(ValueError, match="path"):
        parse_row(row(path=""), Mode.EXECUTE)


@pytest.mark.parametrize("bad", ["a" * 65, "a" * 63, "g" * 64, "backup"])
def test_execute_requires_a_hex64_sample(bad: str) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        parse_row(row(sample=bad), Mode.EXECUTE)


def test_interactive_rejects_path() -> None:
    with pytest.raises(ValueError, match="path"):
        parse_row(row(sample="backup"), Mode.INTERACTIVE)


@pytest.mark.parametrize(
    "name", ["backup", "backup-2", "compress-documents", "active-directory-setup"]
)
def test_interactive_scenario_name_is_kept_verbatim(name: str) -> None:
    entry = parse_row(row(family="goodware", sample=name, path="", label="0"), Mode.INTERACTIVE)
    assert entry.path is None
    assert entry.scenario == name
    assert entry.label == 0


@pytest.mark.parametrize("bad", ["..\\x", "a b", "a/b"])
def test_interactive_sample_must_be_path_safe(bad: str) -> None:
    with pytest.raises(ValueError, match="session name"):
        parse_row(row(sample=bad, path=""), Mode.INTERACTIVE)


@pytest.mark.parametrize("field", ["family", "sample"])
def test_empty_required_fields(field: str) -> None:
    with pytest.raises(ValueError):
        parse_row(row(**{field: " "}), Mode.EXECUTE)


def test_load_manifest_reports_row_and_missing_columns(tmp_path) -> None:
    good = tmp_path / "m.csv"
    good.write_text(
        f"family,sample,path,label\nAkira,{SHA},C:\\a.exe,1\nAkira,{SHA},,1\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="row 2"):
        load_manifest(good, Mode.EXECUTE)
    short = tmp_path / "short.csv"
    short.write_text("family,sample\nAkira,x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing column.*path, label"):
        load_manifest(short, Mode.EXECUTE)


def test_load_manifest_reads_every_row(tmp_path) -> None:
    manifest = tmp_path / "m.csv"
    manifest.write_text(f"family,sample,path,label\nAkira,{SHA},C:\\a.exe,1\n", encoding="utf-8")
    entries = load_manifest(manifest, Mode.EXECUTE)
    assert [(e.family, e.sample, e.label) for e in entries] == [("akira", SHA, 1)]


def test_the_columns_are_the_ones_the_shipped_manifests_use() -> None:
    from pathlib import Path

    shipped = Path(__file__).parents[1]
    for name in ("manifest.csv", "manifest-scenarios.csv"):
        header = (shipped / name).read_text(encoding="utf-8").splitlines()[0]
        assert tuple(header.split(",")) == MANIFEST_COLUMNS, name
