"""`build baseline` and `build validate`: place samples in the guest and save snapshots.

Samples are only copied, extracted (7-Zip inside the guest) and renamed; none is
executed. Ransomware stays AES-encrypted on the host.

``build validate`` pairs every ransomware with a goodware, places each pair in
the same guest folder, and saves the ``validate`` snapshot without touching
``baseline``.
"""

from __future__ import annotations

import csv
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from sentinelcap import guest_names
from sentinelcap.config import SentinelcapConfig
from sentinelcap.errors import SentinelcapError
from sentinelcap.logging_utils import get_logger
from sentinelcap.manifest import MANIFEST_COLUMNS, SAFE_NAME_RE, SHA256_RE, ManifestEntry
from sentinelcap.session import run_stamp
from sentinelcap.vm import GUEST_TMP_DIR, VMwareController, VMwareError, ps_literal

logger = get_logger(__name__)

SEVENZIP_LOG_PATH = GUEST_TMP_DIR + r"\sentinelcap-7z.log"


@dataclass(frozen=True)
class SampleFile:
    """One sample on the host: a ransomware ``<sha256>.zip`` or a goodware ``<sha256>.exe``."""

    host_path: Path
    family: str
    sha256: str
    label: int

    @property
    def zipped(self) -> bool:
        return self.host_path.suffix.lower() == ".zip"


def discover_samples(samples_dir: Path) -> list[SampleFile]:
    """``ransomware/<Family>/<sha256>.zip`` (class 1) and ``goodware/<sha256>.exe`` (class 0).

    Files whose stem is not a 64-hex SHA-256, or with another extension, are ignored.
    """
    samples: list[SampleFile] = []
    ransomware = samples_dir / "ransomware"
    if ransomware.is_dir():
        for family_dir in sorted(p for p in ransomware.iterdir() if p.is_dir()):
            if not SAFE_NAME_RE.fullmatch(family_dir.name):
                raise ValueError(f"family directory name is not path-safe: {family_dir}")
            for f in sorted(family_dir.glob("*.zip")):
                if SHA256_RE.fullmatch(f.stem):
                    samples.append(SampleFile(f, family_dir.name.lower(), f.stem.lower(), 1))
    goodware = samples_dir / "goodware"
    if goodware.is_dir():
        for f in sorted(goodware.glob("*.exe")):
            if SHA256_RE.fullmatch(f.stem):
                samples.append(SampleFile(f, "goodware", f.stem.lower(), 0))
    if not samples:
        raise ValueError(
            f"No samples found under {samples_dir} "
            "(ransomware/<Family>/<sha256>.zip, goodware/<sha256>.exe)"
        )
    return samples


def _sevenzip_output(vm: VMwareController) -> str:
    """7-Zip output of the last extraction, for error messages."""
    try:
        return "7-Zip output:\n" + vm.read_guest_text(SEVENZIP_LOG_PATH).strip()
    except Exception as e:  # noqa: BLE001 - diagnostics only, never mask the original error
        return f"(7-Zip output unavailable: {e})"


def place_sample(
    cfg: SentinelcapConfig, vm: VMwareController, sample: SampleFile, guest_path: str
) -> None:
    """Copy (goodware) or copy + extract + rename (ransomware) one sample to ``guest_path``."""
    target_dir = str(PureWindowsPath(guest_path).parent)
    if not sample.zipped:
        vm.copy_to_guest(sample.host_path, guest_path)
        return
    guest_zip = f"{GUEST_TMP_DIR}\\{sample.sha256}.zip"
    vm.copy_to_guest(sample.host_path, guest_zip)
    # 7-Zip runs inside an encoded PowerShell script: target directories such as
    # "Saved Games" never go through the command line vmrun builds, and the
    # 7-Zip output is kept in a guest log for the error message.
    args = ["x", guest_zip, f"-p{cfg.baseline.sample_zip_password}", f"-o{target_dir}", "-y"]
    script = (
        f"& {ps_literal(cfg.baseline.sevenzip_guest_path)} {' '.join(ps_literal(a) for a in args)}"
        f" 2>&1 | Out-File -Encoding UTF8 -LiteralPath {ps_literal(SEVENZIP_LOG_PATH)};"
        " exit $LASTEXITCODE"
    )
    try:
        vm.run_powershell(script)
    except VMwareError as e:
        raise SentinelcapError(
            f"7-Zip failed for {sample.sha256}: {e}\n{_sevenzip_output(vm)}"
        ) from e
    extracted = f"{target_dir}\\{sample.sha256}.exe"
    if not vm.file_exists_in_guest(extracted):
        raise SentinelcapError(
            f"7-Zip reported success but {extracted} does not exist in the guest\n"
            f"{_sevenzip_output(vm)}"
        )
    vm.rename_file_in_guest(extracted, guest_path)
    vm.delete_file_in_guest(guest_zip)


def write_manifest(rows: list[ManifestEntry], manifest_path: Path) -> None:
    """Write ``manifest_path``; an existing file is kept as ``<stem>-<YYYYMMDDTHHMMSSZ>.csv``."""
    if manifest_path.exists():
        stamp = run_stamp(datetime.now(timezone.utc))
        backup = manifest_path.with_name(f"{manifest_path.stem}-{stamp}{manifest_path.suffix}")
        manifest_path.replace(backup)
        logger.info("Previous manifest kept as %s", backup)
    with manifest_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(MANIFEST_COLUMNS)
        writer.writerows((row.family, row.sample, row.path, row.label) for row in rows)


def _assign_roots(
    samples: list[SampleFile], roots: list[str], rng: random.Random
) -> dict[SampleFile, str]:
    """Spread each class evenly over the roots (per class, counts differ by at most 1)."""
    assigned: dict[SampleFile, str] = {}
    for label in sorted({s.label for s in samples}):
        group = [s for s in samples if s.label == label]
        assigned.update(zip(group, guest_names.spread_over_roots(len(group), roots, rng)))
    return assigned


def _candidate_dirs(vm: VMwareController, roots: list[str]) -> dict[str, list[str]]:
    """Usable guest directories per root; every root must have at least one."""
    by_root = guest_names.group_by_root(
        guest_names.usable_target_dirs(vm.list_dirs_in_guest(roots), roots), roots
    )
    for root, root_dirs in by_root.items():
        logger.info("%-28s %d candidate directories", root, len(root_dirs))
    empty = [root for root, root_dirs in by_root.items() if not root_dirs]
    if empty:
        raise SentinelcapError(
            f"No usable sub-directory under {empty}; every root in "
            "baseline.sample_target_roots must have at least one (or remove the root)"
        )
    return by_root


def build_baseline(
    cfg: SentinelcapConfig,
    samples_dir: Path | None = None,
    seed: int | None = None,
    manifest_path: Path = Path("manifest.csv"),
) -> list[ManifestEntry]:
    """Place every sample in the guest from the original snapshot and save the baseline snapshot.

    The snapshot is taken while the VM is running with the guest user logged in.
    Any failure stops before the snapshot, so the previous baseline is only
    replaced after every sample was placed. Returns the manifest rows written.
    """
    samples = discover_samples(Path(samples_dir or cfg.baseline.samples_dir))
    rng = random.Random(seed if seed is not None else cfg.baseline.seed)
    vm = VMwareController(cfg.vmware)
    rows: list[ManifestEntry] = []
    vm_started = False
    try:
        vm.revert_to(cfg.vmware.original_snapshot)
        vm.start()
        vm_started = True
        vm.wait_tools_ready()
        time.sleep(cfg.vmware.start_boot_wait_sec)

        roots = cfg.baseline.sample_target_roots
        by_root = _candidate_dirs(vm, roots)
        sample_roots = _assign_roots(samples, roots, rng)
        logger.info("%d sample(s) over %d roots", len(samples), len(roots))

        # Fixed column widths so the per-sample log lines stay aligned: [01/94].
        count_width = len(str(len(samples)))
        name_width = max(len(s.family) for s in samples) + 1 + 12
        used: set[str] = set()
        for i, sample in enumerate(samples, start=1):
            target_dir = rng.choice(by_root[sample_roots[sample]])
            guest_path = f"{target_dir}\\{guest_names.random_name(rng)}"
            while guest_path.casefold() in used:
                guest_path = f"{target_dir}\\{guest_names.random_name(rng)}"
            used.add(guest_path.casefold())
            name = f"{sample.family}/{sample.sha256[:12]}"
            logger.info(
                "[%s/%d] %s -> %s",
                str(i).zfill(count_width),
                len(samples),
                name.ljust(name_width),
                guest_path,
            )
            place_sample(cfg, vm, sample, guest_path)
            rows.append(
                ManifestEntry(
                    family=sample.family,
                    sample=sample.sha256,
                    path=guest_path,
                    label=sample.label,
                )
            )

        vm.delete_snapshot(cfg.vmware.baseline_snapshot)
        vm.create_snapshot(cfg.vmware.baseline_snapshot)
    finally:
        if vm_started:
            vm.stop_hard()

    write_manifest(rows, manifest_path)
    logger.info("Wrote %d row(s) to %s", len(rows), manifest_path)
    return rows


def pair_validate_samples(
    samples: list[SampleFile], rng: random.Random
) -> list[tuple[SampleFile, SampleFile]]:
    """Pair every ransomware with a goodware (seeded shuffle, equal counts required).

    Returns ``(ransomware, goodware)`` tuples. Counts must match so no sample is
    left unpaired (fail-fast).
    """
    ransomware = [s for s in samples if s.label == 1]
    goodware = [s for s in samples if s.label == 0]
    if not ransomware:
        raise ValueError("validate needs at least one ransomware sample under samples_dir")
    if not goodware:
        raise ValueError("validate needs at least one goodware sample under samples_dir")
    if len(ransomware) != len(goodware):
        raise ValueError(
            "validate needs the same number of ransomware and goodware samples "
            f"(got {len(ransomware)} ransomware, {len(goodware)} goodware)"
        )
    rng.shuffle(ransomware)
    rng.shuffle(goodware)
    return list(zip(ransomware, goodware, strict=True))


def build_validate(
    cfg: SentinelcapConfig,
    samples_dir: Path | None = None,
    seed: int | None = None,
    manifest_path: Path = Path("manifest-validate.csv"),
) -> list[ManifestEntry]:
    """Place every ransomware/goodware pair in a shared guest folder; save ``validate``.

    Each pair shares one directory; different pairs get different directories when
    enough usable directories exist. Reverts to ``original``; does not modify
    ``baseline`` or ``manifest.csv``. Any failure stops before the snapshot.
    Returns manifest rows (ransomware then goodware for each pair, in pair order).
    """
    samples = discover_samples(Path(samples_dir or cfg.baseline.samples_dir))
    rng = random.Random(seed if seed is not None else cfg.baseline.seed)
    pairs = pair_validate_samples(samples, rng)
    pair_count = len(pairs)
    vm = VMwareController(cfg.vmware)
    rows: list[ManifestEntry] = []
    vm_started = False
    try:
        vm.revert_to(cfg.vmware.original_snapshot)
        vm.start()
        vm_started = True
        vm.wait_tools_ready()
        time.sleep(cfg.vmware.start_boot_wait_sec)

        by_root = _candidate_dirs(vm, cfg.baseline.sample_target_roots)
        candidates = [d for dirs in by_root.values() for d in dirs]
        free_dirs = list(candidates)
        rng.shuffle(free_dirs)
        used_paths: set[str] = set()
        count_width = len(str(pair_count))
        for i, (ransomware, goodware) in enumerate(pairs, start=1):
            if free_dirs:
                target_dir = free_dirs.pop()
            else:
                target_dir = rng.choice(candidates)
            logger.info(
                "[%s/%d] pair %s + goodware/%s -> %s",
                str(i).zfill(count_width),
                pair_count,
                f"{ransomware.family}/{ransomware.sha256[:12]}",
                goodware.sha256[:12],
                target_dir,
            )
            for sample in (ransomware, goodware):
                guest_path = f"{target_dir}\\{guest_names.random_name(rng)}"
                while guest_path.casefold() in used_paths:
                    guest_path = f"{target_dir}\\{guest_names.random_name(rng)}"
                used_paths.add(guest_path.casefold())
                place_sample(cfg, vm, sample, guest_path)
                rows.append(
                    ManifestEntry(
                        family=sample.family,
                        sample=sample.sha256,
                        path=guest_path,
                        label=sample.label,
                    )
                )

        vm.delete_snapshot(cfg.vmware.validate_snapshot)
        vm.create_snapshot(cfg.vmware.validate_snapshot)
    finally:
        if vm_started:
            vm.stop_hard()

    write_manifest(rows, manifest_path)
    logger.info("Wrote %d row(s) (%d pair(s)) to %s", len(rows), pair_count, manifest_path)
    return rows
