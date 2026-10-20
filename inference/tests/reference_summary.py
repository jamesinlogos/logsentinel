"""The counting of the service before the ``Summarizer``, kept as an independent check.

``reference_summarize`` is the batch algorithm ``inference.summary.summarize`` had when windows
were counted from scratch: sets and counters built in one pass over a list of events. The
``Summarizer`` keeps the same counts incrementally (``add``, ``remove``), so any difference
between the two is a bug in its bookkeeping. Only the leaf definitions are shared with the
service (regexes, keywords, thresholds, entropy and path helpers); how they are aggregated is
not. Do not change this file to follow the service: a change of a count definition belongs in
both places on purpose.
"""

from __future__ import annotations

import dataclasses
from collections import Counter, defaultdict
from collections.abc import Iterable

import pytest

from inference.events import Event
from inference.summary import (
    _DISABLED_VALUES,
    _LOG_CLEAR,
    _POLICY,
    _RECOVERY,
    _RUN_KEY,
    _SERVICING,
    _SHADOW,
    _STOP,
    LOLBINS,
    NOTE_KEYWORDS,
    NOTE_MIN_BRANCHES,
    NOTE_MIN_DIRS,
    REPLACE_MIN_DIRS,
    REPLACE_MIN_FILES,
    WindowSummary,
    _branch,
    file_name_entropy,
    suspicious_path,
    system_executable,
)


def assert_same_counts(summary: WindowSummary, reference: WindowSummary) -> None:
    """Equal counts; the entropy sum only up to the order the reference added the names in."""
    assert dataclasses.replace(summary, name_entropy_sum=0.0) == dataclasses.replace(
        reference, name_entropy_sum=0.0
    )
    assert summary.name_entropy_sum == pytest.approx(
        reference.name_entropy_sum, rel=1e-12, abs=1e-12
    )


def reference_summarize(events: Iterable[Event]) -> WindowSummary:
    totals: Counter[str] = Counter()
    codes: Counter[str] = Counter()
    entropy_sum = 0.0
    name_dirs: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    extension_files: Counter[tuple[str, str]] = Counter()
    extensions: set[str] = set()
    deletes: Counter[str] = Counter()
    deleted_paths: defaultdict[str, set[str]] = defaultdict(set)
    appended: defaultdict[str, list[str]] = defaultdict(list)
    cmd_children: Counter[str] = Counter()
    ips: set[str] = set()
    for event in events:
        totals["events"] += 1
        codes[event.code] += 1
        process = event.entity_id or ""
        if event.code == "1":
            _process_start(totals, event, cmd_children)
        elif event.code == "11":
            totals["created_files"] += 1
            name = event.file_name or ""
            entropy_sum += file_name_entropy(name)
            if any(keyword in name for keyword in NOTE_KEYWORDS):
                totals["note_keyword_files"] += 1
            if (
                event.file_path is not None
                and "\\" in event.file_path
                and not _windows_metadata_note(event)
            ):
                name_dirs[(process, name)].add(event.file_path.rsplit("\\", 1)[0])
            if event.file_extension:
                extensions.add(event.file_extension)
                extension_files[(process, event.file_extension)] += 1
            if event.file_path is not None and name.count(".") >= 2:
                appended[process].append(event.file_path)
        elif event.code == "26":
            deletes[process] += 1
            if event.file_path is not None:
                deleted_paths[process].add(event.file_path)
        elif event.code == "13":
            _registry_write(totals, event)
        elif event.code == "3":
            totals["connections"] += 1
            if event.destination_ip:
                ips.add(event.destination_ip)
    max_dirs = max_branches = 0
    mass_note = False
    for dirs in name_dirs.values():
        branches = len({_branch(d) for d in dirs})
        max_dirs = max(max_dirs, len(dirs))
        max_branches = max(max_branches, branches)
        if len(dirs) >= NOTE_MIN_DIRS and branches >= NOTE_MIN_BRANCHES:
            mass_note = True
    max_replaced, mass_replace = _replaced_files(appended, deleted_paths)
    return WindowSummary(
        events=totals["events"],
        codes=codes,
        shadow_commands=totals["shadow_commands"],
        recovery_commands=totals["recovery_commands"],
        stop_commands=totals["stop_commands"],
        log_tamper=totals["log_tamper"],
        lolbin_runs=totals["lolbin_runs"],
        run_key_writes=totals["run_key_writes"],
        policy_writes=totals["policy_writes"],
        note_keyword_files=totals["note_keyword_files"],
        max_cmd_children=max(cmd_children.values(), default=0),
        max_name_dirs=max_dirs,
        max_name_branches=max_branches,
        mass_note=mass_note,
        max_replaced_files=max_replaced,
        mass_replace=mass_replace,
        created_files=totals["created_files"],
        distinct_extensions=len(extensions),
        max_same_extension=max(extension_files.values(), default=0),
        name_entropy_sum=entropy_sum,
        max_deletes=max(deletes.values(), default=0),
        process_starts=totals["process_starts"],
        suspicious_paths=totals["suspicious_paths"],
        non_system_executables=totals["non_system_executables"],
        command_line_chars=totals["command_line_chars"],
        connections=totals["connections"],
        destination_ips=len(ips),
    )


def _process_start(totals: Counter[str], event: Event, cmd_children: Counter[str]) -> None:
    totals["process_starts"] += 1
    command = event.command_line or ""
    totals["command_line_chars"] += len(command)
    if _SHADOW.search(command):
        totals["shadow_commands"] += 1
    if _RECOVERY.search(command):
        totals["recovery_commands"] += 1
    if _STOP.search(command):
        totals["stop_commands"] += 1
    if _LOG_CLEAR.search(command):
        totals["log_tamper"] += 1
    executable = event.executable or ""
    base = executable.rsplit("\\", 1)[-1]
    if base in LOLBINS:
        totals["lolbin_runs"] += 1
    if base == "cmd.exe":
        cmd_children[event.parent_entity_id or ""] += 1
    if suspicious_path(executable):
        totals["suspicious_paths"] += 1
    if not system_executable(executable):
        totals["non_system_executables"] += 1


def _registry_write(totals: Counter[str], event: Event) -> None:
    key = event.registry_path or ""
    if _RUN_KEY.search(key):
        totals["run_key_writes"] += 1
    if _POLICY.search(key):
        totals["policy_writes"] += 1
    if (
        "\\winevt\\channels\\" in key
        and key.endswith("\\enabled")
        and event.registry_value in _DISABLED_VALUES
        and not _SERVICING.match(event.executable or "")
        and not (
            event.executable == r"c:\windows\system32\drvinst.exe"
            and key.startswith(
                "hklm\\software\\microsoft\\windows\\currentversion\\winevt\\channels\\"
            )
        )
    ):
        totals["log_tamper"] += 1


def _windows_metadata_note(event: Event) -> bool:
    path = event.file_path or ""
    if (
        event.file_name == "desktop.ini"
        and event.executable == r"c:\windows\explorer.exe"
        and path.endswith(r"\desktop.ini")
        and path.startswith(("c:\\users\\", "c:\\$recycle.bin\\", "d:\\$recycle.bin\\"))
    ):
        return True
    return (
        event.file_name == "jsbytecodecache_64"
        and event.executable == r"c:\windows\system32\svchost.exe"
        and path.startswith("c:\\windows\\")
        and path.endswith(r"\microsoft.system.package.metadata\autogen\jsbytecodecache_64")
    )


def _replaced_files(
    appended: dict[str, list[str]], deleted_paths: dict[str, set[str]]
) -> tuple[int, bool]:
    """``(most files one process replaced by one extension, whether that is a mass replace)``."""
    most = 0
    mass = False
    for process, paths in appended.items():
        gone = deleted_paths.get(process)
        if not gone:
            continue
        directories: defaultdict[str, set[str]] = defaultdict(set)
        files: Counter[str] = Counter()
        for created in paths:
            original, extension = created.rsplit(".", 1)
            if original in gone:
                files[extension] += 1
                directories[extension].add(created.rsplit("\\", 1)[0])
        for extension, count in files.items():
            most = max(most, count)
            if count >= REPLACE_MIN_FILES and len(directories[extension]) >= REPLACE_MIN_DIRS:
                mass = True
    return most, mass
