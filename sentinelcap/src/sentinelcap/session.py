"""Pure session logic: event field reading, ``t_exec`` detection, quiet-window rule.

Nothing here touches Kafka, VMware or the clock. Events are only *read* (never
modified) to find session bounds; only the fields listed in AGENTS.md are used.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinelcap.errors import SentinelcapError


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise SentinelcapError("Normalized event is missing a string @timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SentinelcapError(f"Normalized event has invalid @timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise SentinelcapError("Normalized event @timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


RUN_STAMP_FORMAT = "%Y%m%dT%H%M%SZ"


def run_stamp(moment: datetime) -> str:
    """``YYYYMMDDTHHMMSSZ`` of ``moment`` in UTC: the name of a run (AGENTS.md section 11.3)."""
    return moment.astimezone(timezone.utc).strftime(RUN_STAMP_FORMAT)


def _optional_timestamp(value: str | None) -> datetime | None:
    """Like ``parse_timestamp`` but returns None instead of raising."""
    if value is None:
        return None
    try:
        return parse_timestamp(value)
    except SentinelcapError:
        return None


def _get_str(event: dict[str, Any], *keys: str) -> str | None:
    cursor: Any = event
    for key in keys:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
    return cursor if isinstance(cursor, str) else None


@dataclass(frozen=True)
class EventInfo:
    """The read-only view of one normalized event, plus the original payload."""

    payload: bytes
    timestamp: datetime
    host_id: str | None
    code: str | None
    executable: str | None
    sha256: str | None
    entity_id: str | None
    parent_entity_id: str | None
    file_path: str | None
    created: datetime | None
    """``event.created`` (guest clock, Winlogbeat read time); None if absent or invalid."""
    os_build: str | None
    agent_version: str | None
    received_at: float
    """Host monotonic clock (seconds) when the message was received."""
    received_wall: datetime
    """Host wall clock (UTC) when the message was received."""


def decode_event(payload: bytes) -> dict[str, Any]:
    """The JSON object of one normalized Kafka message."""
    try:
        event = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SentinelcapError("Kafka normalized message is not valid JSON") from exc
    if not isinstance(event, dict):
        raise SentinelcapError("Kafka normalized message must be a JSON object")
    return event


def event_host_id(event: dict[str, Any]) -> str | None:
    return _get_str(event, "host", "id")


def parse_event(
    payload: bytes,
    received_at: float,
    received_wall: datetime,
    event: dict[str, Any] | None = None,
) -> EventInfo:
    """Read-only view of ``payload``; ``event`` is its already decoded JSON, if available."""
    if event is None:
        event = decode_event(payload)
    code = _get_str(event, "event", "code")
    return EventInfo(
        payload=payload,
        timestamp=parse_timestamp(event.get("@timestamp")),
        host_id=event_host_id(event),
        code=code,
        executable=_get_str(event, "process", "executable"),
        sha256=_get_str(event, "process", "hash", "sha256"),
        entity_id=_get_str(event, "process", "entity_id"),
        parent_entity_id=_get_str(event, "process", "parent", "entity_id"),
        file_path=_get_str(event, "file", "path"),
        created=_optional_timestamp(_get_str(event, "event", "created")),
        os_build=_get_str(event, "host", "os", "build"),
        agent_version=_get_str(event, "agent", "version"),
        received_at=received_at,
        received_wall=received_wall,
    )


_LONG_PATH_PREFIX = "\\\\?\\"
_FILE_WRITE_CODES = frozenset({"11", "29"})  # FileCreate, FileExecutableDetected


def _normalize_path(path: str) -> str:
    """Case-folded path without the ``\\\\?\\`` prefix Sysmon adds to some images."""
    return path.casefold().removeprefix(_LONG_PATH_PREFIX)


def matches_sample(event: EventInfo, path: str, sha256: str) -> bool:
    """True for a Sysmon Event 1 whose executable and SHA-256 are the sample's."""
    return (
        event.code == "1"
        and event.executable is not None
        and event.executable.casefold() == path.casefold()
        and event.sha256 is not None
        and event.sha256.casefold() == sha256.casefold()
        and event.entity_id is not None
    )


def find_exec_event(events: list[EventInfo], path: str, sha256: str) -> EventInfo | None:
    """First Event 1 (in arrival order) matching the sample, or ``None``."""
    for event in events:
        if matches_sample(event, path, sha256):
            return event
    return None


class ExecuteSession:
    """End-of-session rule for ``--execute``, driven by host monotonic time.

    Recording lasts at least ``settle`` seconds from ``t_exec``. It then stops
    once ``quiet`` seconds pass without an event from a sample process, counted
    from the later of the last such event and the end of settle (so the minimum
    is ``settle + quiet``), or once ``max_wait`` more seconds have elapsed.

    A sample process is the root, any process whose executable path contains
    the sample SHA-256 (relaunches such as UAC elevation through dllhost.exe,
    ``<hash>_online.paf.exe``), any process whose Event 1 carries the sample
    SHA-256 (renamed copies), any process whose Event 1 executable is a file a
    tracked process wrote earlier (Event 11/29 ``file.path``: dropped payloads,
    whoever launches them), and every descendant of those. Other processes
    spawned through WMI or services are not tracked.
    """

    def __init__(
        self,
        exec_event: EventInfo,
        *,
        settle: float,
        quiet: float,
        max_wait: float,
    ) -> None:
        if exec_event.entity_id is None or exec_event.sha256 is None:
            raise SentinelcapError("The sample's Event 1 has no process.entity_id or SHA-256")
        self.root_entity_id = exec_event.entity_id
        self._sha256 = exec_event.sha256.casefold()
        self.t_exec = exec_event.timestamp
        self._origin = exec_event.received_at
        self._last_activity = exec_event.received_at
        self._settle = settle
        self._quiet = quiet
        self._max_wait = max_wait
        self._entities: set[str] = {exec_event.entity_id}
        self._written: set[str] = set()

    def observe(self, event: EventInfo) -> None:
        """Feed one event; only events at or after ``t_exec`` count."""
        if event.timestamp < self.t_exec or event.entity_id is None:
            return
        if event.entity_id not in self._entities and self._is_sample_process(event):
            self._entities.add(event.entity_id)
        if event.entity_id in self._entities:
            self._last_activity = max(self._last_activity, event.received_at)
            if event.code in _FILE_WRITE_CODES and event.file_path is not None:
                self._written.add(_normalize_path(event.file_path))

    def _is_sample_process(self, event: EventInfo) -> bool:
        if event.executable is not None and self._sha256 in event.executable.casefold():
            return True
        if event.code != "1":
            return False
        if event.sha256 is not None and event.sha256.casefold() == self._sha256:
            return True
        if event.executable is not None and _normalize_path(event.executable) in self._written:
            return True
        return event.parent_entity_id in self._entities

    @property
    def entity_ids(self) -> list[str]:
        """Every tracked sample process (root first, then sorted)."""
        return [self.root_entity_id, *sorted(self._entities - {self.root_entity_id})]

    def elapsed(self, now: float) -> float:
        return now - self._origin

    def should_stop(self, now: float) -> bool:
        elapsed = self.elapsed(now)
        if elapsed >= self._settle + self._max_wait:
            return True
        # Silence only counts from the end of settle: quiet before it does not shorten the session.
        quiet_since = max(self._last_activity, self._origin + self._settle)
        return elapsed >= self._settle and now - quiet_since >= self._quiet

    def t_end(self, now: float) -> datetime:
        return self.t_exec + timedelta(seconds=self.elapsed(now))
