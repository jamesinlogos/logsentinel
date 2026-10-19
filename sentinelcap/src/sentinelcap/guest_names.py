"""Business-like sample names and guest target directories for `build baseline`.

Samples are renamed so that neither the file name nor the path carries the
SHA-256 (a shortcut feature), and so that no Sysmon exclude rule that matches
on ``Image`` drops their events. The forbidden tokens come from the deployed
Sysmon configuration (case-insensitive).
"""

from __future__ import annotations

import random
from pathlib import PureWindowsPath

BASE_NAMES = (
    "invoice",
    "report",
    "budget",
    "contract",
    "quotation",
    "statement",
    "memo",
    "proposal",
    "agenda",
    "timesheet",
    "payroll",
    "order",
    "receipt",
    "catalog",
    "brochure",
    "newsletter",
    "minutes",
    "roadmap",
    "forecast",
    "summary",
)
FORBIDDEN_SUBSTRINGS = ("setup",)
"""``Image contains setup`` (FileCreateTime exclude) matches anywhere in the path."""
FORBIDDEN_SUFFIXES = (
    "chrome.exe",
    "onedrive.exe",
    "slack.exe",
    "teams.exe",
    "outlook.exe",
    "dropbox.exe",
    "spotify.exe",
    "owncloud.exe",
    "winlogbeat.exe",
    "packetbeat.exe",
    "googleupdate.exe",
    "taskmgr.exe",
    "vmtoolsd.exe",
    "vboxservice.exe",
    "wmiprvse.exe",
    "svchost.exe",
    "powershell.exe",
)
"""Exclude rules that match a file name exactly or with ``end with``."""
_SUFFIX_ALPHABET = "0123456789abcdef"


def is_safe_name(name: str) -> bool:
    lowered = name.casefold()
    if any(token in lowered for token in FORBIDDEN_SUBSTRINGS):
        return False
    return not any(lowered.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES)


def assert_safe_name(name: str) -> str:
    if not is_safe_name(name):
        raise ValueError(f"sample name {name!r} matches a Sysmon exclude rule")
    return name


def is_safe_dir(path: str) -> bool:
    lowered = path.casefold()
    return not any(token in lowered for token in FORBIDDEN_SUBSTRINGS)


def random_name(rng: random.Random) -> str:
    """``<base>_<4 hex>.exe``, e.g. ``invoice_a7f3.exe``; regenerated until safe."""
    while True:
        suffix = "".join(rng.choice(_SUFFIX_ALPHABET) for _ in range(4))
        name = f"{rng.choice(BASE_NAMES)}_{suffix}.exe"
        if is_safe_name(name):
            return name


def _under(path: str, root: str) -> bool:
    p = PureWindowsPath(path)
    r = PureWindowsPath(root)
    return p != r and str(p).casefold().startswith(str(r).casefold().rstrip("\\") + "\\")


def group_by_root(dirs: list[str], roots: list[str]) -> dict[str, list[str]]:
    """``{root: [dirs under it]}`` in ``roots`` order; a root without directories maps to []."""
    return {root: [d for d in dirs if _under(d, root)] for root in roots}


def spread_over_roots(count: int, roots: list[str], rng: random.Random) -> list[str]:
    """One root per item, as even as possible (counts differ by at most 1), seeded order."""
    if not roots:
        raise ValueError("no root to spread samples over")
    order = list(roots)
    rng.shuffle(order)  # which roots get the extra item when count % len(roots) != 0
    assignment = [order[k % len(order)] for k in range(count)]
    rng.shuffle(assignment)
    return assignment


def usable_target_dirs(listing: list[str], roots: list[str]) -> list[str]:
    """Directories from a guest listing that lie under ``roots`` and pass ``is_safe_dir``.

    Sorted (case-insensitive, de-duplicated) so that a seeded choice is reproducible
    whatever order the guest returned them in.
    """
    seen: dict[str, str] = {}
    for raw in listing:
        path = raw.strip().rstrip("\\")
        if path and any(_under(path, root) for root in roots) and is_safe_dir(path):
            key = path.casefold()
            seen[key] = min(seen.get(key, path), path)
    return [seen[key] for key in sorted(seen)]
