"""Input contract (inference/README.md section 3).

One message of ``telemetry.windows.normalized`` is reduced to the fields the
detector reads. ``@timestamp``, ``host.id`` and ``event.code`` are required;
every other field is optional because logstash-ingest leaves a field absent
when Sysmon has no value (it never forwards the ``"-"`` placeholder), and some
events carry no process at all (Event 255). Paths, command lines and registry
text are case-folded once here, so the rules match case-insensitively.

Everything a hostile or broken producer could send is rejected here, as
``InvalidEventError``, before it can reach pipeline state: oversized payloads,
integers over Python's digit limit, JSON nested deeper than the parser allows,
timestamps outside a sane range, and implausible Sysmon queue counts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

MAX_MESSAGE_BYTES = 256 * 1024
"""About 20 times the largest event in the sentinelcap corpus (12 KB)."""
MIN_EVENT_EPOCH = 946_684_800
"""2000-01-01T00:00:00Z."""
MAX_EVENT_EPOCH = 4_102_444_800
"""2100-01-01T00:00:00Z; keeps window ends inside what ``datetime`` can format."""
MAX_COUNT_DIGITS = 18
MAX_COMMAND_LINE_CHARS = 32_768
"""The Windows limit for a command line (the sentinelcap corpus maximum is 4,155)."""
MAX_DETAIL_CHARS = 2_048
"""Part of a Sysmon error description that is searched for queue counts."""

_LONG_PATH_PREFIX = "\\\\?\\"
# Bounded name length: an unbounded \w+ backtracks quadratically on a long run of
# word characters (40 KB took 16 s).
_QUEUE_DROP = re.compile(r"(\w{1,32}Event):(\d+)")


class InvalidEventError(ValueError):
    """The message cannot be used: not a JSON object, or a required field is missing."""


@dataclass(frozen=True, slots=True)
class Event:
    timestamp: float
    """``@timestamp`` in seconds since the epoch (UTC)."""
    host_id: str
    host_name: str | None
    code: str
    entity_id: str | None
    executable: str | None
    command_line: str | None
    parent_entity_id: str | None
    file_path: str | None
    file_name: str | None
    file_extension: str | None
    registry_path: str | None
    registry_value: str | None
    destination_ip: str | None
    sysmon_error: str | None
    """Event 255: ``winlog.event_data.ID`` (for example ``QUEUE``)."""
    sysmon_error_detail: str | None
    """Event 255: ``winlog.event_data.Description``, original case."""
    drops: tuple[tuple[str, int], ...] = ()
    """Event 255 ``QUEUE``: ``(event type, count)`` pairs, as reported.

    Sysmon does not say whether the counts are cumulative (inference/README.md section 9.1,
    rule 8), so they are kept as reported and never added up.
    """
    partition: int | None = None
    """Kafka partition the message came from (None outside the service)."""
    offset: int | None = None
    """Kafka offset of the message in ``partition``."""


def decode(payload: bytes | str) -> dict[str, Any]:
    """The JSON object of one Kafka message."""
    if len(payload) > MAX_MESSAGE_BYTES:
        raise InvalidEventError(
            f"message is {len(payload)} bytes, over the {MAX_MESSAGE_BYTES} limit"
        )
    try:
        doc = json.loads(payload)
    except (ValueError, RecursionError) as exc:
        # ValueError: invalid JSON or UTF-8, and integers over Python's digit
        # limit; RecursionError: nesting deeper than the parser allows.
        raise InvalidEventError("message is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise InvalidEventError("message is not a JSON object")
    return doc


def parse_timestamp(value: Any) -> float:
    if not isinstance(value, str):
        raise InvalidEventError("@timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise InvalidEventError(f"@timestamp is not ISO 8601: {value!r}") from exc
    if parsed.tzinfo is None:
        raise InvalidEventError(f"@timestamp has no timezone: {value!r}")
    epoch = parsed.timestamp()
    if not MIN_EVENT_EPOCH <= epoch < MAX_EVENT_EPOCH:
        raise InvalidEventError(f"@timestamp is outside 2000-2100: {value!r}")
    return epoch


def parse_event(
    doc: dict[str, Any], partition: int | None = None, offset: int | None = None
) -> Event:
    host_id = _get_str(doc, "host", "id")
    if not host_id:
        raise InvalidEventError("host.id is missing")
    code = _get_str(doc, "event", "code")
    if not code:
        raise InvalidEventError("event.code is missing")
    file_path = _path(_get_str(doc, "file", "path"))
    sysmon_error = _get_str(doc, "winlog", "event_data", "ID") if code == "255" else None
    detail = _get_str(doc, "winlog", "event_data", "Description") if code == "255" else None
    return Event(
        timestamp=parse_timestamp(doc.get("@timestamp")),
        host_id=host_id,
        host_name=_get_str(doc, "host", "name"),
        code=code,
        entity_id=_get_str(doc, "process", "entity_id"),
        executable=_path(_get_str(doc, "process", "executable")),
        command_line=_fold(_get_str(doc, "process", "command_line"), MAX_COMMAND_LINE_CHARS),
        parent_entity_id=_get_str(doc, "process", "parent", "entity_id"),
        file_path=file_path,
        file_name=_fold(_get_str(doc, "file", "name")),
        file_extension=_fold(_get_str(doc, "file", "extension")),
        registry_path=_fold(_get_str(doc, "registry", "path")),
        registry_value=_fold(_get_str(doc, "registry", "data", "strings")),
        destination_ip=_get_str(doc, "destination", "ip"),
        sysmon_error=sysmon_error,
        sysmon_error_detail=detail,
        drops=_parse_drops(detail) if sysmon_error == "QUEUE" and detail else (),
        partition=partition,
        offset=offset,
    )


def queue_drops(event: Event) -> list[tuple[str, int]]:
    """``(event type, count)`` pairs of a Sysmon "events dropped from driver queue" report."""
    return list(event.drops)


def _parse_drops(detail: str) -> tuple[tuple[str, int], ...]:
    pairs = []
    for kind, count in _QUEUE_DROP.findall(detail[:MAX_DETAIL_CHARS]):
        if len(count) > MAX_COUNT_DIGITS:
            raise InvalidEventError("Sysmon queue report has an implausible event count")
        pairs.append((kind, int(count)))
    return tuple(pairs)


def _get_str(doc: dict[str, Any], *keys: str) -> str | None:
    cursor: Any = doc
    for key in keys:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
    return cursor if isinstance(cursor, str) else None


def _fold(value: str | None, limit: int | None = None) -> str | None:
    if value is None:
        return None
    return (value if limit is None else value[:limit]).casefold()


def _path(value: str | None) -> str | None:
    folded = _fold(value)
    return folded.removeprefix(_LONG_PATH_PREFIX) if folded is not None else None
