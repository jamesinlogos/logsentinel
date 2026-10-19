"""Load and validate the session manifest (CSV: family,sample,path,label).

The collection mode comes from the CLI flag, never from the manifest: every row
must match the mode it is loaded for. ``label`` is the only source of the label.
``family`` is lower-cased (one output directory per family) and, like ``sample``,
must be path-safe because both name the output directories.

* ``--execute``: ``sample`` is the SHA-256 of the sample and ``path`` is its
  location inside the victim VM.
* ``--interactive``: ``sample`` is a free-form scenario name such as ``backup`` or
  ``compress-documents`` (kept verbatim as the scenario) and ``path`` is empty.
* ``capture`` (CLI command, no manifest): ``sample`` is a session code such as
  ``idle-01`` and ``path`` is empty.
"""

from __future__ import annotations

import csv
import re
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

MANIFEST_COLUMNS = ("family", "sample", "path", "label")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
# family and sample name the output directories (<out_dir>/<family>/<sample>), so
# both must be path-safe.
SAFE_NAME_RE = re.compile(r"[A-Za-z0-9_-]+")


class Mode(str, Enum):
    EXECUTE = "execute"
    INTERACTIVE = "interactive"
    CAPTURE = "capture"


class ManifestEntry(BaseModel):
    """A single row from the manifest."""

    family: str
    sample: str
    """SHA-256 of the executable, scenario name or session code, by mode."""
    path: str | None = None
    """Path to the executable on the guest VM (not the host); empty when interactive."""
    label: int = Field(description="Label assigned by the operator: 1 = ransomware, 0 = benign.")

    @property
    def session_name(self) -> str:
        """``<family>-<sample>``: what logs and the batch table call this session."""
        return f"{self.family}-{self.sample}"

    @property
    def scenario(self) -> str:
        """Scenario name, verbatim (``backup-2`` stays ``backup-2``)."""
        return self.sample


def _clean(value: str | None) -> str:
    return (value or "").strip()


def parse_row(row: dict[str, str | None], mode: Mode) -> ManifestEntry:
    """Validate one manifest row (keys: ``MANIFEST_COLUMNS``) for ``mode``."""
    family = _clean(row.get("family"))
    sample = _clean(row.get("sample"))
    path = _clean(row.get("path"))
    raw_label = _clean(row.get("label"))

    if not family:
        raise ValueError("the 'family' column must not be empty")
    if not SAFE_NAME_RE.fullmatch(family):
        raise ValueError(f"'family' may only contain letters, digits, '-' and '_', got {family!r}")
    family = family.lower()  # one directory per family: "LockBit" and "Lockbit" are the same
    if not sample:
        raise ValueError("the 'sample' column must not be empty")
    if raw_label not in ("0", "1"):
        raise ValueError(f"the 'label' column must be 0 or 1, got {raw_label!r}")

    if mode is Mode.EXECUTE:
        if not SHA256_RE.fullmatch(sample):
            raise ValueError(
                f"--execute needs a 64-character hex SHA-256 in 'sample', got {sample!r}"
            )
        if not path:
            raise ValueError("--execute needs a guest 'path' for the sample")
        sample = sample.lower()
    else:
        if path:
            raise ValueError(f"{mode.value} sessions must leave 'path' empty")
        if not SAFE_NAME_RE.fullmatch(sample):
            raise ValueError(
                f"{mode.value} needs a session name such as backup or idle-01 in 'sample', "
                f"got {sample!r}"
            )

    return ManifestEntry(family=family, sample=sample, path=path or None, label=int(raw_label))


def load_manifest(path: str | Path, mode: Mode) -> list[ManifestEntry]:
    """Load and validate a manifest CSV for ``mode``, raising on the first invalid row."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")

    entries: list[ManifestEntry] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        missing = [column for column in MANIFEST_COLUMNS if column not in header]
        if missing:
            raise ValueError(f"Manifest is missing column(s): {', '.join(missing)}")
        for i, row in enumerate(reader, start=1):
            try:
                entries.append(parse_row(row, mode))
            except ValueError as e:
                raise ValueError(f"Invalid row {i} in manifest: {e}") from e

    if not entries:
        raise ValueError(f"Manifest '{path}' is empty.")
    return entries
