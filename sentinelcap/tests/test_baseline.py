"""`build baseline` with a fake VMware controller (no vmrun, no VM)."""

from __future__ import annotations

import csv
import random
import re
from pathlib import Path, PureWindowsPath

import pytest

from sentinelcap import baseline
from sentinelcap.config import KafkaConfig, SentinelcapConfig, VMwareConfig
from sentinelcap.guest_names import is_safe_name
from sentinelcap.manifest import Mode, load_manifest
from sentinelcap.vm import VMwareError

R1, R2, G1, G2 = "1" * 64, "2" * 64, "a" * 64, "b" * 64
DIRS = [
    r"C:\Users\Public\Documents",
    r"C:\Users\Public\Music",
    r"C:\Users\Public\Videos",
    r"C:\Users\Public\Pictures",
    r"C:\Users\sysmaint\Saved Games",
    r"D:\Backup\2024",
    r"D:\Shares\Finance",
    r"D:\Shares\Setup",
]


class FakeVM:
    def __init__(
        self, cfg=None, fail_on_extract: bool = False, missing_after_extract: bool = False
    ) -> None:
        self.calls: list[tuple] = []
        self.fail_on_extract = fail_on_extract
        self.missing_after_extract = missing_after_extract

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append((name, *args))
            if name == "list_dirs_in_guest":
                return DIRS
            if name == "file_exists_in_guest":
                return not self.missing_after_extract
            if name == "run_powershell" and "7z.exe" in args[0] and self.fail_on_extract:
                raise VMwareError("Guest program exited with non-zero exit code: 2")
            if name == "read_guest_text":
                return "ERROR: Wrong password"
            return None

        return record

    def names(self) -> list[str]:
        return [c[0] for c in self.calls]


def make_samples(root: Path) -> Path:
    (root / "ransomware" / "LockBit").mkdir(parents=True)
    (root / "ransomware" / "LockBit" / f"{R1}.zip").write_bytes(b"zip")
    (root / "ransomware" / "LockBit" / f"{R1}.zip_x").write_bytes(b"ignored")
    (root / "ransomware" / "Akira").mkdir()
    (root / "ransomware" / "Akira" / f"{R2}.zip").write_bytes(b"zip")
    (root / "goodware").mkdir()
    (root / "goodware" / f"{G1}.exe").write_bytes(b"exe")
    (root / "goodware" / "notes.txt").write_text("ignored")
    return root


def make_cfg() -> SentinelcapConfig:
    cfg = SentinelcapConfig(
        vmware=VMwareConfig(
            vmx_path="x", guest_user="u", guest_password="p", start_boot_wait_sec=0
        ),
        kafka=KafkaConfig(host_id="h"),
    )
    cfg.baseline.sample_target_roots = [
        r"C:\Users\Public",
        r"C:\Users\sysmaint",
        r"D:\Backup",
        r"D:\Shares",
    ]
    return cfg


def run(tmp_path, monkeypatch, vm: FakeVM, seed: int = 3):
    monkeypatch.setattr(baseline, "VMwareController", lambda cfg: vm)
    manifest = tmp_path / "manifest.csv"
    rows = baseline.build_baseline(
        make_cfg(),
        samples_dir=make_samples(tmp_path / "samples"),
        seed=seed,
        manifest_path=manifest,
    )
    return rows, manifest


def test_build_baseline_flow_and_manifest(tmp_path, monkeypatch) -> None:
    vm = FakeVM()
    rows, manifest = run(tmp_path, monkeypatch, vm)

    names = vm.names()
    assert names[:4] == ["revert_to", "start", "wait_tools_ready", "list_dirs_in_guest"]
    assert vm.calls[0] == ("revert_to", "original")
    # Snapshot while running, after the last guest command, then power off.
    assert names[-3:] == ["delete_snapshot", "create_snapshot", "stop_hard"]
    assert vm.calls[-2] == ("create_snapshot", "baseline")

    extracts = [c[1] for c in vm.calls if c[0] == "run_powershell"]
    assert len(extracts) == 2
    for script in extracts:
        assert script.startswith("& 'C:\\Program Files\\7-Zip\\7z.exe' 'x' 'C:\\Windows\\Temp\\")
        assert "'-pinfected'" in script and "'-o" in script and "'-y'" in script
        assert "tar" not in script.split("|")[0] and "Expand-Archive" not in script
    assert "run_in_guest" not in names  # no cmd / move, no arguments through vmrun's command line
    # Goodware is copied straight to its final path; no 7-Zip copied from the host.
    copies = [c for c in vm.calls if c[0] == "copy_to_guest"]
    assert len(copies) == 3 and not any("7z" in str(c[1]) for c in copies)

    assert sorted((r.family, r.sample, r.label) for r in rows) == sorted(
        [("lockbit", R1, 1), ("akira", R2, 1), ("goodware", G1, 0)]
    )
    entries = load_manifest(manifest, Mode.EXECUTE)
    assert len(entries) == 3
    for entry, row in zip(entries, rows):
        assert entry.path == row.path
        guest = PureWindowsPath(entry.path)
        assert str(guest.parent) in DIRS[:-1]  # never the "Setup" directory
        assert is_safe_name(guest.name) and entry.sample not in guest.name


def test_zip_is_extracted_then_moved_to_the_new_name(tmp_path, monkeypatch) -> None:
    vm = FakeVM()
    rows, _ = run(tmp_path, monkeypatch, vm)
    lockbit_path = next(r.path for r in rows if r.sample == R1)
    target_dir = str(PureWindowsPath(lockbit_path).parent)
    i = next(i for i, c in enumerate(vm.calls) if c[0] == "copy_to_guest" and R1 in str(c[1]))
    copy, extract, exists, rename, delete = vm.calls[i : i + 5]
    assert copy[2] == rf"C:\Windows\Temp\{R1}.zip"
    assert extract[0] == "run_powershell"
    assert f"'C:\\Windows\\Temp\\{R1}.zip'" in extract[1] and f"'-o{target_dir}'" in extract[1]
    assert exists == ("file_exists_in_guest", rf"{target_dir}\{R1}.exe")
    assert rename == ("rename_file_in_guest", rf"{target_dir}\{R1}.exe", lockbit_path)
    assert delete == ("delete_file_in_guest", rf"C:\Windows\Temp\{R1}.zip")


def test_same_seed_same_placement(tmp_path, monkeypatch) -> None:
    rows_a, _ = run(tmp_path / "a", monkeypatch, FakeVM(), seed=11)
    rows_b, _ = run(tmp_path / "b", monkeypatch, FakeVM(), seed=11)
    assert rows_a == rows_b


def test_extract_failure_stops_before_snapshot(tmp_path, monkeypatch) -> None:
    vm = FakeVM(fail_on_extract=True)
    with pytest.raises(
        baseline.SentinelcapError, match="Wrong password"
    ):  # 7-Zip output in the error
        run(tmp_path, monkeypatch, vm)
    assert "create_snapshot" not in vm.names() and "delete_snapshot" not in vm.names()
    assert vm.names()[-1] == "stop_hard"
    assert not (tmp_path / "manifest.csv").exists()


def test_missing_file_after_extract_stops_before_snapshot(tmp_path, monkeypatch) -> None:
    vm = FakeVM(missing_after_extract=True)
    with pytest.raises(baseline.SentinelcapError, match="does not exist"):
        run(tmp_path, monkeypatch, vm)
    assert "create_snapshot" not in vm.names()
    assert "rename_file_in_guest" not in vm.names()


def test_target_dir_with_space_stays_one_powershell_literal(monkeypatch) -> None:
    vm = FakeVM()
    sample = baseline.SampleFile(Path(f"{R1}.zip"), "lockbit", R1, 1)
    baseline.place_sample(make_cfg(), vm, sample, r"C:\Users\sysmaint\Saved Games\memo_0001.exe")
    script = next(c[1] for c in vm.calls if c[0] == "run_powershell")
    assert r"'-oC:\Users\sysmaint\Saved Games'" in script
    assert (
        "rename_file_in_guest",
        rf"C:\Users\sysmaint\Saved Games\{R1}.exe",
        r"C:\Users\sysmaint\Saved Games\memo_0001.exe",
    ) in vm.calls


def test_existing_manifest_is_kept_with_a_timestamp_every_time(tmp_path, monkeypatch) -> None:
    (tmp_path / "manifest.csv").write_text("family,sample,path,label\nold,x,,0\n", encoding="utf-8")
    run(tmp_path, monkeypatch, FakeVM())
    backups = list(tmp_path.glob("manifest-*.csv"))
    assert len(backups) == 1
    assert re.fullmatch(r"manifest-\d{8}T\d{6}Z\.csv", backups[0].name)
    assert "old" in backups[0].read_text(encoding="utf-8")
    with (tmp_path / "manifest.csv").open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == ["family", "sample", "path", "label"]
        assert len(list(reader)) == 3


def test_each_class_is_spread_evenly_over_roots(tmp_path, monkeypatch) -> None:
    # C:\Users\Public has 4 directories, the other roots 1: placement must not follow that.
    root = tmp_path / "samples"
    (root / "ransomware" / "Akira").mkdir(parents=True)
    (root / "goodware").mkdir()
    for i in range(8):
        (root / "ransomware" / "Akira" / f"{i:064x}.zip").write_bytes(b"zip")
        (root / "goodware" / f"{i + 100:064x}.exe").write_bytes(b"exe")
    monkeypatch.setattr(baseline, "VMwareController", lambda cfg: FakeVM())
    rows = baseline.build_baseline(
        make_cfg(), samples_dir=root, seed=5, manifest_path=tmp_path / "m.csv"
    )
    roots = make_cfg().baseline.sample_target_roots
    for cls in (0, 1):
        counts = [
            sum(1 for r in rows if r.label == cls and r.path.startswith(rt + "\\")) for rt in roots
        ]
        assert sum(counts) == 8
        assert max(counts) - min(counts) <= 1


def test_root_without_directory_stops_before_placing(tmp_path, monkeypatch) -> None:
    vm = FakeVM()
    cfg = make_cfg()
    cfg.baseline.sample_target_roots.append(r"E:\Empty")
    monkeypatch.setattr(baseline, "VMwareController", lambda c: vm)
    with pytest.raises(baseline.SentinelcapError, match="Empty"):
        baseline.build_baseline(
            cfg, samples_dir=make_samples(tmp_path / "s"), seed=1, manifest_path=tmp_path / "m.csv"
        )
    assert "copy_to_guest" not in vm.names()
    assert "create_snapshot" not in vm.names()


def test_no_samples_is_an_error(tmp_path) -> None:
    with pytest.raises(ValueError, match="No samples"):
        baseline.discover_samples(tmp_path)


G2 = "b" * 64


def make_validate_samples(root: Path) -> Path:
    """Equal ransomware and goodware counts for ``build validate``."""
    (root / "ransomware" / "LockBit").mkdir(parents=True)
    (root / "ransomware" / "LockBit" / f"{R1}.zip").write_bytes(b"zip")
    (root / "ransomware" / "Akira").mkdir()
    (root / "ransomware" / "Akira" / f"{R2}.zip").write_bytes(b"zip")
    (root / "goodware").mkdir()
    (root / "goodware" / f"{G1}.exe").write_bytes(b"exe")
    (root / "goodware" / f"{G2}.exe").write_bytes(b"exe")
    return root


def run_validate(
    tmp_path,
    monkeypatch,
    vm: FakeVM,
    seed: int = 3,
    samples: Path | None = None,
):
    monkeypatch.setattr(baseline, "VMwareController", lambda cfg: vm)
    manifest = tmp_path / "manifest-validate.csv"
    rows = baseline.build_validate(
        make_cfg(),
        samples_dir=samples or make_validate_samples(tmp_path / "samples"),
        seed=seed,
        manifest_path=manifest,
    )
    return rows, manifest


def test_build_validate_pairs_share_folders_and_validate_snapshot(tmp_path, monkeypatch) -> None:
    vm = FakeVM()
    rows, manifest = run_validate(tmp_path, monkeypatch, vm, seed=7)

    assert vm.calls[0] == ("revert_to", "original")
    assert vm.calls[-2] == ("create_snapshot", "validate")
    assert ("create_snapshot", "baseline") not in vm.calls
    assert len(rows) == 4
    assert [r.label for r in rows] == [1, 0, 1, 0]
    pair_dirs = [PureWindowsPath(rows[i].path).parent for i in range(0, len(rows), 2)]
    for i in range(0, len(rows), 2):
        assert PureWindowsPath(rows[i].path).parent == PureWindowsPath(rows[i + 1].path).parent
        assert rows[i].path != rows[i + 1].path
    assert len(set(pair_dirs)) == 2  # two pairs, two directories when enough exist
    for row in rows:
        assert is_safe_name(PureWindowsPath(row.path).name)
    entries = load_manifest(manifest, Mode.EXECUTE)
    assert [(e.sample, e.label) for e in entries] == [(r.sample, r.label) for r in rows]
    assert not (tmp_path / "manifest.csv").exists()


def test_build_validate_same_seed_same_placement(tmp_path, monkeypatch) -> None:
    rows_a, _ = run_validate(tmp_path / "a", monkeypatch, FakeVM(), seed=11)
    rows_b, _ = run_validate(tmp_path / "b", monkeypatch, FakeVM(), seed=11)
    assert rows_a == rows_b


def test_build_validate_extract_failure_stops_before_snapshot(tmp_path, monkeypatch) -> None:
    vm = FakeVM(fail_on_extract=True)
    with pytest.raises(baseline.SentinelcapError, match="Wrong password"):
        run_validate(tmp_path, monkeypatch, vm)
    assert "create_snapshot" not in vm.names()
    assert not (tmp_path / "manifest-validate.csv").exists()


def test_pair_validate_samples_requires_both_classes(tmp_path) -> None:
    root = tmp_path / "samples"
    (root / "goodware").mkdir(parents=True)
    (root / "goodware" / f"{G1}.exe").write_bytes(b"exe")
    samples = baseline.discover_samples(root)
    with pytest.raises(ValueError, match="ransomware"):
        baseline.pair_validate_samples(samples, random.Random(1))


def test_pair_validate_samples_requires_equal_counts(tmp_path) -> None:
    samples = baseline.discover_samples(make_samples(tmp_path / "samples"))
    with pytest.raises(ValueError, match="same number"):
        baseline.pair_validate_samples(samples, random.Random(1))


def test_pair_validate_samples_seeded_pairing() -> None:
    samples = [
        baseline.SampleFile(Path(f"{R1}.zip"), "lockbit", R1, 1),
        baseline.SampleFile(Path(f"{R2}.zip"), "akira", R2, 1),
        baseline.SampleFile(Path(f"{G1}.exe"), "goodware", G1, 0),
        baseline.SampleFile(Path(f"{G2}.exe"), "goodware", G2, 0),
    ]
    pairs_a = baseline.pair_validate_samples(samples, random.Random(11))
    pairs_b = baseline.pair_validate_samples(samples, random.Random(11))
    assert pairs_a == pairs_b
    assert len(pairs_a) == 2
    assert all(rw.label == 1 and gw.label == 0 for rw, gw in pairs_a)
