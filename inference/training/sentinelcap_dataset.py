"""Loader for sentinelcap captures (inference/README.md section 9.1).

A session is ``<run>/<family>/<sample>/`` (``sample``: the SHA-256 of an executable or
the slug of a scenario) with ``metadata.json`` and ``session.jsonl`` (or
``session.jsonl.gz`` for test fixtures). Rules applied:

1. only ``logsentinel.normalized-sysmon.jsonl/v1`` sessions are loaded (another
   format is an error) and a directory whose name starts with ``.`` is an export
   that has not finished, which sentinelcap's contract says loaders skip;
2. every window of a goodware session is labelled 0; a window of a ransomware
   session is labelled 1 only when it holds an event of a tracked sample
   process (``sample_entity_ids``), otherwise it is left out of training;
   ``sample_entity_ids`` is used for labels only, never as a feature;
3. Sysmon queue drops (Event 255 ``ID=QUEUE``) are kept as reported and flag
   the session (``events_dropped``);
4. ``overlay`` builds a ransomware session with a goodware session running at
   the same time, for the evaluate.py robustness check only (training on such
   windows lowered the model's AUC, inference/README.md section 9.1).
"""

from __future__ import annotations

import dataclasses
import gzip
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from inference.config import WindowConfig
from inference.events import (
    Event,
    InvalidEventError,
    decode,
    parse_event,
    parse_timestamp,
    queue_drops,
)
from inference.windowing import Window, Windower

FORMAT = "logsentinel.normalized-sysmon.jsonl/v1"
SESSION_FILES = ("session.jsonl", "session.jsonl.gz")

logger = logging.getLogger(__name__)


@dataclass
class Session:
    directory: Path
    session_path: str
    """Path of the session below the captures directory (run, family, sample)."""
    family: str
    sample_id: str
    label: int
    events: list[Event]
    sample_ids: frozenset[str]
    queue_drops: list[tuple[str, int]]
    invalid_lines: int
    duration_sec: float
    """``t_end - t_start`` of the capture."""
    partner: str | None = None
    """Name of the goodware session overlaid on this one (``overlay``), if any."""

    @property
    def name(self) -> str:
        """Short label for reports; not unique when a sample was captured in several runs."""
        return f"{self.family}/{self.sample_id[:8]}"

    @property
    def key(self) -> str:
        """Unique within a run of train/evaluate, also for a session captured in several runs."""
        return f"{self.session_path}+{self.partner}" if self.partner else self.session_path

    @property
    def first_sample_ts(self) -> float | None:
        """Event time of the first event of a tracked sample process (ransomware sessions)."""
        if self.label != 1:
            return None
        return min(
            (e.timestamp for e in self.events if e.entity_id in self.sample_ids), default=None
        )

    @property
    def events_dropped(self) -> bool:
        return bool(self.queue_drops)


def iter_sessions(root: Path) -> Iterator[Session]:
    for meta_path in sorted(root.rglob("metadata.json")):
        if any(part.startswith(".") for part in meta_path.relative_to(root).parts):
            continue  # an export that did not finish (rule 1)
        yield load_session(meta_path.parent, root)


def load_session(directory: Path, root: Path | None = None) -> Session:
    meta = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    if meta.get("format") != FORMAT:
        raise ValueError(f"{directory}: format {meta.get('format')!r}, expected {FORMAT}")
    label = meta["label"]["target_class"]
    if label not in (0, 1):
        raise ValueError(f"{directory}: label.target_class must be 0 or 1, got {label!r}")
    events: list[Event] = []
    drops: list[tuple[str, int]] = []
    invalid = 0
    for line in _read_lines(directory):
        try:
            event = parse_event(decode(line))
        except InvalidEventError:
            invalid += 1
            continue
        events.append(event)
        drops.extend(queue_drops(event))
    if invalid:
        logger.warning("%s: %d unusable lines skipped", directory, invalid)
    family = directory.parent.name
    session_path = (
        directory.relative_to(root).as_posix() if root is not None else f"{family}/{directory.name}"
    )
    return Session(
        directory=directory,
        session_path=session_path,
        family=family,
        sample_id=directory.name,
        label=label,
        events=events,
        sample_ids=frozenset(meta.get("sample_entity_ids") or ()),
        queue_drops=drops,
        invalid_lines=invalid,
        duration_sec=parse_timestamp(meta["t_end"]) - parse_timestamp(meta["t_start"]),
    )


def overlay(ransomware: Session, goodware: Session) -> Session:
    """``ransomware`` with ``goodware`` running at the same time on the same host.

    The goodware events are shifted so that both sessions start together, then
    merged in time order. Labels still come from the ransomware session's
    sample processes. Events are real; only their co-occurrence is constructed
    (the two activities do not interact).
    """
    if ransomware.label != 1 or goodware.label != 0:
        raise ValueError("overlay needs a ransomware session and a goodware session")
    if not ransomware.events or not goodware.events:
        return dataclasses.replace(ransomware, partner=goodware.name)
    shift = ransomware.events[0].timestamp - goodware.events[0].timestamp
    moved = [dataclasses.replace(e, timestamp=e.timestamp + shift) for e in goodware.events]
    return dataclasses.replace(
        ransomware,
        events=sorted([*ransomware.events, *moved], key=lambda e: e.timestamp),
        partner=goodware.name,
    )


def session_windows(session: Session, config: WindowConfig) -> list[Window]:
    """The windows the service would close for this session, in order."""
    windower = Windower(
        config.size_sec, config.slide_sec, config.max_events_per_host, config.late_reset_events
    )
    windows: list[Window] = []
    for event in session.events:
        windows.extend(windower.add(event))
    for host_id in windower.hosts():
        last = windower.flush(host_id)
        if last is not None:
            windows.append(last)
    return windows


def window_label(session: Session, window: Window) -> int | None:
    """Training label of a window (rule 2 above); None = not used for training."""
    if session.label == 0:
        return 0
    if any(event.entity_id in session.sample_ids for event in window.events):
        return 1
    return None


def _read_lines(directory: Path) -> Iterator[str]:
    for name in SESSION_FILES:
        path = directory / name
        if path.is_file():
            opener = gzip.open if name.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8") as lines:
                yield from (line for line in lines if line.strip())
            return
    raise FileNotFoundError(f"{directory}: no session.jsonl")
