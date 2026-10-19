"""Input contract (inference/README.md section 3) on real sentinelcap events."""

from __future__ import annotations

import copy
import json
import time
from typing import Any

import pytest

from inference.events import (
    MAX_COMMAND_LINE_CHARS,
    MAX_MESSAGE_BYTES,
    InvalidEventError,
    decode,
    parse_event,
    queue_drops,
)
from training.sentinelcap_dataset import Session


def test_every_fixture_line_parses(sessions: dict[str, Session]) -> None:
    for session in sessions.values():
        assert session.events
        assert session.invalid_lines == 0


def test_process_create_is_case_folded(sessions: dict[str, Session]) -> None:
    event = next(
        e
        for e in sessions["conti/b14cde37"].events
        if e.code == "1" and e.executable and e.executable.endswith("\\vssadmin.exe")
    )
    assert event.executable == "c:\\windows\\system32\\vssadmin.exe"
    assert event.command_line is not None
    assert "delete shadows" in event.command_line
    assert event.entity_id and event.parent_entity_id


def test_registry_value_set(single_events: dict[str, Any]) -> None:
    event = parse_event(single_events["sysmon_channel_disabled"])
    assert event.code == "13"
    assert event.registry_path is not None
    assert event.registry_path.endswith("\\microsoft-windows-sysmon/operational\\enabled")
    assert event.registry_value == "dword (0x00000000)"


def test_sysmon_queue_drop_has_no_process(single_events: dict[str, Any]) -> None:
    event = parse_event(single_events["sysmon_queue_drop"])
    assert event.code == "255"
    assert event.entity_id is None and event.executable is None
    assert queue_drops(event) == [("RegistryEvent", 63)]


def test_other_sysmon_errors_are_not_queue_drops(single_events: dict[str, Any]) -> None:
    event = parse_event(single_events["sysmon_image_load_error"])
    assert event.sysmon_error == "IMAGE_LOAD"
    assert queue_drops(event) == []


def test_unresolved_parent_is_absent(single_events: dict[str, Any]) -> None:
    doc = single_events["parent_unresolved"]
    assert "executable" not in doc["process"]["parent"]
    event = parse_event(doc)
    assert event.code == "1" and event.executable is not None


def test_network_connection_destination(single_events: dict[str, Any]) -> None:
    event = parse_event(single_events["network_connection"])
    assert event.code == "3"
    assert event.destination_ip


@pytest.mark.parametrize("payload", [b"not json", b"[1, 2]", b""])
def test_decode_rejects_non_objects(payload: bytes) -> None:
    with pytest.raises(InvalidEventError):
        decode(payload)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("host", "id"), None),
        (("event", "code"), None),
        (("@timestamp",), "2026-10-01T01:20:32.847"),
        (("@timestamp",), "Oct 14, 2024 @ 22:15:47.330"),
    ],
)
def test_required_fields(
    single_events: dict[str, Any], path: tuple[str, ...], value: str | None
) -> None:
    doc = copy.deepcopy(single_events["network_connection"])
    parent = doc
    for key in path[:-1]:
        parent = parent[key]
    if value is None:
        del parent[path[-1]]
    else:
        parent[path[-1]] = value
    with pytest.raises(InvalidEventError):
        parse_event(doc)


def test_event_carries_its_kafka_position(single_events: dict[str, Any]) -> None:
    event = parse_event(single_events["network_connection"], partition=2, offset=17)
    assert (event.partition, event.offset) == (2, 17)
    assert parse_event(single_events["network_connection"]).partition is None


def test_oversized_message_is_rejected() -> None:
    with pytest.raises(InvalidEventError, match="limit"):
        decode(b'{"a":"' + b"x" * MAX_MESSAGE_BYTES + b'"}')


def test_integer_over_the_digit_limit_is_invalid_not_a_crash(single_events: dict[str, Any]) -> None:
    payload = json.dumps(single_events["network_connection"])
    huge = (payload[:-1] + ', "big": ' + "9" * 4301 + "}").encode()
    with pytest.raises(InvalidEventError):
        decode(huge)


@pytest.mark.parametrize("depth", [2_000, 5_000])
def test_moderate_nesting_is_accepted(depth: int) -> None:
    body = '{"host":{"id":"h"},"x":' + "[" * depth + "]" * depth + "}"
    assert decode(body.encode())["host"] == {"id": "h"}


def test_nesting_beyond_the_parser_limit_is_invalid_not_a_crash() -> None:
    body = '{"host":{"id":"h"},"x":' + "[" * 20_000 + "]" * 20_000 + "}"
    with pytest.raises(InvalidEventError):
        decode(body.encode())


@pytest.mark.parametrize("timestamp", ["1999-12-31T23:59:59Z", "2100-01-01T00:00:00Z"])
def test_timestamp_outside_2000_2100_is_rejected(
    single_events: dict[str, Any], timestamp: str
) -> None:
    doc = copy.deepcopy(single_events["network_connection"])
    doc["@timestamp"] = timestamp
    with pytest.raises(InvalidEventError, match="2000-2100"):
        parse_event(doc)


def test_queue_count_with_too_many_digits_is_rejected(single_events: dict[str, Any]) -> None:
    doc = copy.deepcopy(single_events["sysmon_queue_drop"])
    detail = doc["winlog"]["event_data"]["Description"]
    doc["winlog"]["event_data"]["Description"] = detail.replace(
        "RegistryEvent:63", "RegistryEvent:" + "9" * 19
    )
    with pytest.raises(InvalidEventError, match="implausible"):
        parse_event(doc)
    doc["winlog"]["event_data"]["Description"] = detail.replace(
        "RegistryEvent:63", "RegistryEvent:" + "9" * 18
    )
    assert parse_event(doc).drops == (("RegistryEvent", int("9" * 18)),)


def test_a_long_queue_description_is_cheap(single_events: dict[str, Any]) -> None:
    """The count pattern once backtracked quadratically: 40 KB of letters took 16 s."""
    doc = copy.deepcopy(single_events["sysmon_queue_drop"])
    doc["winlog"]["event_data"]["Description"] = "a" * 100_000
    started = time.perf_counter()
    event = parse_event(doc)
    assert time.perf_counter() - started < 1.0
    assert event.drops == ()


def test_a_very_long_command_line_is_cut(single_events: dict[str, Any]) -> None:
    doc = copy.deepcopy(single_events["wevtutil_clear_log"])
    doc["process"]["command_line"] = "wevtutil cl " + "x" * 100_000
    event = parse_event(doc)
    assert event.command_line is not None
    assert len(event.command_line) == MAX_COMMAND_LINE_CHARS
    assert event.command_line.startswith("wevtutil cl ")
