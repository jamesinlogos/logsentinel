"""Counting (inference/README.md sections 4.0 and 8): the one definition of every count of a window.

The rules (``indicators.py``) and the features (``features.py``) read these counts and never
count anything themselves. A :class:`Summarizer` holds the counts of a set of events of one host
and follows the set as it changes: ``add`` and ``remove`` are one code path with a step of +1 or
-1, so they are exact inverses and a sliding window is never recounted from scratch.
``snapshot`` freezes the counts as a :class:`WindowSummary`; ``summarize`` is the same for a
list of events.

Every quantity is a count over a multiset of events, so it does not depend on the order in which
events were added or removed. A quantity that is a maximum or a number of distinct keys is
computed in ``snapshot`` from per-key counts; the few that a rule reads after every event
(``mass_note``, ``mass_replace``, ``max_cmd_children``) are kept up to date as events come and go.
"""

from __future__ import annotations

import functools
import itertools
import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from inference.events import Event

# Thresholds of inference/README.md section 4.1 that decide a count (the rules' own thresholds,
# which compare counts, are in indicators.py).
NOTE_MIN_DIRS = 10
NOTE_MIN_BRANCHES = 5
BRANCH_DEPTH = 4
# mass_file_replace: one process writes <file>.<ext> and deletes <file> (an encrypted
# copy replacing the original), for one appended extension, across many directories
# (the measurements behind both thresholds: inference/README.md section 4.1).
REPLACE_MIN_FILES = 50
REPLACE_MIN_DIRS = 10

# Event 1 command lines (already case-folded). Matched on every process, so a
# command run through cmd.exe or PowerShell counts on both processes.
# Two tokens of one command are at most 16 characters apart in the sentinelcap
# corpus; the gap between them is bounded because an unbounded ``.*`` takes
# quadratic time on a long command line made of repeated tokens (33 KB: 1 s).
_GAP = r".{0,256}"
_SHADOW = re.compile(
    r"delete\s+shadows|resize\s+shadowstorage|wbadmin(\.exe)?\"?\s+delete"
    rf"|win32_shadowcopy{_GAP}(remove-wmiobject|delete)"
    rf"|(remove-wmiobject|delete){_GAP}win32_shadowcopy"
    rf"|\bshadowcopy\b{_GAP}\bdelete\b"
)
_RECOVERY = re.compile(
    r"recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures|reagentc(\.exe)?\"?\s+/disable"
)
_STOP = re.compile(
    r"\bnet1?(\.exe)?\"?\s+stop\b|\bsc(\.exe)?\"?\s+stop\b"
    rf"|\bsc(\.exe)?\"?\s+config\b{_GAP}start=\s*disabled|stop-service|\btaskkill\b"
)
_LOG_CLEAR = re.compile(
    r"wevtutil(\.exe)?\"?\s+(cl|clear-log)\b"
    rf"|wevtutil(\.exe)?\"?\s+(sl|set-log)\b{_GAP}/e:false"
    r"|clear-eventlog"
)
# Event 13 registry keys (case-folded).
_RUN_KEY = re.compile(r"\\currentversion\\run(once)?\\")
_POLICY = re.compile(
    r"\\policies\\system\\(enablelua|consentpromptbehavioradmin|enablelinkedconnections)$"
    r"|\\policies\\microsoft\\windows defender"
)
_DISABLED_VALUES = frozenset({"dword (0x00000000)", "0"})
# The Windows servicing stack (TiWorker.exe, run from the component store) registers
# event log channels disabled while it installs updates and roles: in the captures it
# wrote every channel-disable value of the goodware sessions (Windows Update, AD DS
# install), while ransomware disabled channels from its own executable.
_SERVICING = re.compile(r"^c:\\windows\\winsxs\\[^\\]+\\tiworker\.exe$")

LOLBINS = frozenset(
    {
        "certutil.exe",
        "bitsadmin.exe",
        "mshta.exe",
        "regsvr32.exe",
        "rundll32.exe",
        "wscript.exe",
        "cscript.exe",
        "wmic.exe",
        "installutil.exe",
        "msbuild.exe",
    }
)
NOTE_KEYWORDS = ("readme", "read_me", "decrypt", "recover", "restore", "instruction", "how_to")

# Path heuristics (inference/README.md section 8), on case-folded paths.
SUSPICIOUS_PATH_KEYWORDS = (
    "temp",
    "appdata",
    "roaming",
    "startup",
    "downloads",
    "programdata",
    "users",
)
SYSTEM_PATH_PREFIXES = ("c:\\windows\\system32", "c:\\program files", "c:\\windows")

ACTIVITY_FIELDS: tuple[str, ...] = (
    "events",
    "process_starts",
    "created_files",
    "distinct_extensions",
    "max_same_extension",
    "max_deletes",
    "max_name_dirs",
    "max_name_branches",
    "max_replaced_files",
    "max_cmd_children",
    "shadow_commands",
    "recovery_commands",
    "stop_commands",
    "log_tamper",
    "lolbin_runs",
    "run_key_writes",
    "policy_writes",
    "note_keyword_files",
    "suspicious_paths",
    "non_system_executables",
    "command_line_chars",
    "connections",
    "destination_ips",
)
"""``WindowSummary`` counts published as ``logsentinel.window.activity.*`` (same names)."""


@dataclass(frozen=True)
class WindowSummary:
    """The counts of one window (all events of one host), frozen."""

    events: int = 0
    codes: Counter[str] = field(default_factory=Counter)
    shadow_commands: int = 0
    recovery_commands: int = 0
    stop_commands: int = 0
    log_tamper: int = 0
    lolbin_runs: int = 0
    run_key_writes: int = 0
    policy_writes: int = 0
    note_keyword_files: int = 0
    max_cmd_children: int = 0
    max_name_dirs: int = 0
    max_name_branches: int = 0
    mass_note: bool = False
    max_replaced_files: int = 0
    """Most files one process replaced by a copy with one appended extension."""
    mass_replace: bool = False
    created_files: int = 0
    distinct_extensions: int = 0
    max_same_extension: int = 0
    name_entropy_sum: float = 0.0
    max_deletes: int = 0
    process_starts: int = 0
    suspicious_paths: int = 0
    non_system_executables: int = 0
    command_line_chars: int = 0
    connections: int = 0
    destination_ips: int = 0

    def activity(self) -> dict[str, int]:
        """The raw counts a human reads next to the log1p ``features`` the model sees."""
        return {name: int(getattr(self, name)) for name in ACTIVITY_FIELDS}


class _NoteFiles:
    """The directories one process wrote one file name to (``mass_note_drop``)."""

    __slots__ = ("branches", "directories", "satisfied")

    def __init__(self) -> None:
        self.directories: dict[str, int] = {}
        """Directory -> files of that name written there."""
        self.branches: dict[str, int] = {}
        """Branch (first ``BRANCH_DEPTH`` path levels) -> directories in it."""
        self.satisfied = False


class _Replaced:
    """The files one process replaced by a copy with one appended extension."""

    __slots__ = ("directories", "files", "satisfied")

    def __init__(self) -> None:
        self.files = 0
        self.directories: dict[str, int] = {}
        self.satisfied = False


class Summarizer:
    """The counts of the events added so far and not removed since."""

    def __init__(self) -> None:
        self.events = 0
        self.codes: Counter[str] = Counter()
        self.shadow_commands = 0
        self.recovery_commands = 0
        self.stop_commands = 0
        self.log_tamper = 0
        self.lolbin_runs = 0
        self.run_key_writes = 0
        self.policy_writes = 0
        self.note_keyword_files = 0
        self.created_files = 0
        self.process_starts = 0
        self.suspicious_paths = 0
        self.non_system_executables = 0
        self.command_line_chars = 0
        self.connections = 0
        self._cmd_children: dict[str, int] = {}
        """Parent process -> ``cmd.exe`` started by it."""
        self._cmd_levels: dict[int, int] = {}
        """Number of ``cmd.exe`` children -> parents with that many (to keep the maximum)."""
        self._cmd_max = 0
        self._names: dict[str, int] = {}
        """Created file name -> files (for the mean entropy)."""
        self._notes: dict[tuple[str, str], _NoteFiles] = {}
        self._mass_note_keys = 0
        self._extensions: dict[str, int] = {}
        self._extension_files: dict[tuple[str, str], int] = {}
        self._deletes: dict[str, int] = {}
        self._deleted: dict[str, dict[str, int]] = {}
        """Process -> deleted path -> times."""
        self._copies: dict[str, dict[str, dict[tuple[str, str], int]]] = {}
        """Process -> original path -> (appended extension, directory) -> copies created."""
        self._replaced: dict[tuple[str, str], _Replaced] = {}
        self._mass_replace_keys = 0
        self._ips: dict[str, int] = {}

    # ---- the facts the rules read after every event

    @property
    def mass_note(self) -> bool:
        return self._mass_note_keys > 0

    @property
    def mass_replace(self) -> bool:
        return self._mass_replace_keys > 0

    @property
    def max_cmd_children(self) -> int:
        return self._cmd_max

    # ---- changing the set

    def add(self, event: Event) -> None:
        self._apply(event, 1)

    def remove(self, event: Event) -> None:
        """Take back an event that was added (``ValueError`` when a count would go below zero)."""
        self._apply(event, -1)

    def _apply(self, event: Event, step: int) -> None:
        code = event.code
        self.events += step
        _bump(self.codes, code, step)
        if code == "1":
            self._process_start(event, step)
        elif code == "11":
            self._file_created(event, event.entity_id or "", step)
        elif code == "26":
            self._file_deleted(event, event.entity_id or "", step)
        elif code == "13":
            self._registry_write(event, step)
        elif code == "3":
            self.connections += step
            if event.destination_ip:
                _bump(self._ips, event.destination_ip, step)

    def _process_start(self, event: Event, step: int) -> None:
        self.process_starts += step
        command = event.command_line or ""
        self.command_line_chars += step * len(command)
        if _SHADOW.search(command):
            self.shadow_commands += step
        if _RECOVERY.search(command):
            self.recovery_commands += step
        if _STOP.search(command):
            self.stop_commands += step
        if _LOG_CLEAR.search(command):
            self.log_tamper += step
        executable = event.executable or ""
        base = executable.rsplit("\\", 1)[-1]
        if base in LOLBINS:
            self.lolbin_runs += step
        if base == "cmd.exe":
            self._cmd_child(event.parent_entity_id or "", step)
        if suspicious_path(executable):
            self.suspicious_paths += step
        if not system_executable(executable):
            self.non_system_executables += step

    def _cmd_child(self, parent: str, step: int) -> None:
        before = self._cmd_children.get(parent, 0)
        after = _bump(self._cmd_children, parent, step)
        if before:
            _bump(self._cmd_levels, before, -1)
        if after:
            _bump(self._cmd_levels, after, 1)
        if after > self._cmd_max:
            self._cmd_max = after
        elif before == self._cmd_max and before not in self._cmd_levels:
            self._cmd_max = after  # the parent that held the maximum went down by one

    def _file_created(self, event: Event, process: str, step: int) -> None:
        self.created_files += step
        name = event.file_name or ""
        _bump(self._names, name, step)
        if any(keyword in name for keyword in NOTE_KEYWORDS):
            self.note_keyword_files += step
        path = event.file_path
        if path is not None and "\\" in path and not _windows_metadata_note(event):
            self._note_directory(process, name, path.rsplit("\\", 1)[0], step)
        if event.file_extension:
            _bump(self._extensions, event.file_extension, step)
            _bump(self._extension_files, (process, event.file_extension), step)
        if path is not None and name.count(".") >= 2:
            self._copy_created(process, path, step)

    def _file_deleted(self, event: Event, process: str, step: int) -> None:
        _bump(self._deletes, process, step)
        if event.file_path is not None:
            self._path_deleted(process, event.file_path, step)

    def _registry_write(self, event: Event, step: int) -> None:
        key = event.registry_path or ""
        if _RUN_KEY.search(key):
            self.run_key_writes += step
        if _POLICY.search(key):
            self.policy_writes += step
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
            self.log_tamper += step

    def _note_directory(self, process: str, name: str, directory: str, step: int) -> None:
        key = (process, name)
        entry = self._notes.get(key)
        if entry is None:
            entry = self._notes[key] = _NoteFiles()
        files_here = _bump(entry.directories, directory, step)
        if files_here == (1 if step > 0 else 0):  # the directory appeared or went away
            _bump(entry.branches, _branch(directory), step)
        satisfied = len(entry.directories) >= NOTE_MIN_DIRS and (
            len(entry.branches) >= NOTE_MIN_BRANCHES
        )
        self._mass_note_keys += satisfied - entry.satisfied
        entry.satisfied = satisfied
        if not entry.directories:
            del self._notes[key]

    def _copy_created(self, process: str, path: str, step: int) -> None:
        """``<file>.<ext>`` created: a replacement while the same process has deleted ``<file>``."""
        original, extension = path.rsplit(".", 1)
        directory = path.rsplit("\\", 1)[0]
        originals = self._copies.setdefault(process, {})
        copies = originals.setdefault(original, {})
        _bump(copies, (extension, directory), step)
        if not copies:
            del originals[original]
            if not originals:
                del self._copies[process]
        if self._deleted.get(process, {}).get(original):
            self._replace(process, extension, directory, step)

    def _path_deleted(self, process: str, path: str, step: int) -> None:
        paths = self._deleted.setdefault(process, {})
        times = _bump(paths, path, step)
        if not paths:
            del self._deleted[process]
        if times == (1 if step > 0 else 0):  # the path became deleted, or is no longer
            for (extension, directory), copies in (
                self._copies.get(process, {}).get(path, {}).items()
            ):
                self._replace(process, extension, directory, step * copies)

    def _replace(self, process: str, extension: str, directory: str, change: int) -> None:
        """``change`` more (or fewer) files that ``process`` replaced by ``<file>.<extension>``."""
        key = (process, extension)
        entry = self._replaced.get(key)
        if entry is None:
            entry = self._replaced[key] = _Replaced()
        entry.files += change
        _bump(entry.directories, directory, change)
        satisfied = entry.files >= REPLACE_MIN_FILES and len(entry.directories) >= REPLACE_MIN_DIRS
        self._mass_replace_keys += satisfied - entry.satisfied
        entry.satisfied = satisfied
        if not entry.files:
            del self._replaced[key]

    # ---- reading the counts

    def snapshot(self) -> WindowSummary:
        notes = self._notes.values()
        return WindowSummary(
            events=self.events,
            codes=Counter(self.codes),
            shadow_commands=self.shadow_commands,
            recovery_commands=self.recovery_commands,
            stop_commands=self.stop_commands,
            log_tamper=self.log_tamper,
            lolbin_runs=self.lolbin_runs,
            run_key_writes=self.run_key_writes,
            policy_writes=self.policy_writes,
            note_keyword_files=self.note_keyword_files,
            max_cmd_children=self._cmd_max,
            max_name_dirs=max((len(entry.directories) for entry in notes), default=0),
            max_name_branches=max((len(entry.branches) for entry in notes), default=0),
            mass_note=self.mass_note,
            max_replaced_files=max((entry.files for entry in self._replaced.values()), default=0),
            mass_replace=self.mass_replace,
            created_files=self.created_files,
            distinct_extensions=len(self._extensions),
            max_same_extension=max(self._extension_files.values(), default=0),
            name_entropy_sum=math.fsum(
                itertools.chain.from_iterable(
                    itertools.repeat(_entropy(name), files) for name, files in self._names.items()
                )
            ),
            max_deletes=max(self._deletes.values(), default=0),
            process_starts=self.process_starts,
            suspicious_paths=self.suspicious_paths,
            non_system_executables=self.non_system_executables,
            command_line_chars=self.command_line_chars,
            connections=self.connections,
            destination_ips=len(self._ips),
        )


def summarize(events: Iterable[Event]) -> WindowSummary:
    """The counts of ``events`` (one host's window)."""
    summarizer = Summarizer()
    for event in events:
        summarizer.add(event)
    return summarizer.snapshot()


def file_name_entropy(name: str) -> float:
    """Shannon entropy (bits) of the character distribution of a file name."""
    if not name:
        return 0.0
    counts = Counter(name)
    total = len(name)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


_entropy = functools.lru_cache(maxsize=65_536)(file_name_entropy)
"""``file_name_entropy`` remembered for the names a window repeats (a note in every directory)."""


def suspicious_path(path: str) -> bool:
    return any(keyword in path for keyword in SUSPICIOUS_PATH_KEYWORDS)


def system_executable(path: str) -> bool:
    return path.startswith(SYSTEM_PATH_PREFIXES)


def _windows_metadata_note(event: Event) -> bool:
    """Exclude the observed OS metadata writes from the bulk-note directory count."""
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


def _branch(directory: str) -> str:
    return "\\".join(directory.split("\\")[:BRANCH_DEPTH])


def _bump[K](counts: dict[K, int], key: K, step: int) -> int:
    """``counts[key] += step`` (a key at zero is dropped); the new count."""
    count = counts.get(key, 0) + step
    if count > 0:
        counts[key] = count
    elif count == 0:
        counts.pop(key, None)
    else:
        raise ValueError(f"{key!r} would be counted below zero: it was never added")
    return count
