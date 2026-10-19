"""Input contract of telemetry.windows.normalized as produced by logstash-ingest.

The fixture holds real events captured by sentinelcap (Akira sample, VM lab) and
run through the current logstash-ingest filter (config/logstash/ingest).
"""

import json
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "sentinelcap-normalized-events.json"
PE_FIELDS = ("original_file_name", "file_version", "description", "product", "company")


@pytest.fixture
def normalized_events() -> list[dict]:
    with open(FIXTURE, encoding="utf-8") as f:
        return json.load(f)


def _dash_paths(node: dict, prefix: str = "") -> list[str]:
    found = []
    for key, value in node.items():
        if isinstance(value, dict):
            found += _dash_paths(value, f"{prefix}{key}.")
        elif value == "-":
            found.append(f"{prefix}{key}")
    return found


def test_payload_has_no_duplicated_raw_fields(normalized_events):
    for event in normalized_events:
        assert "message" not in event
        assert "type" not in event
        assert "@metadata" not in event
        assert "original" not in event["event"]


def test_no_dash_placeholder_outside_raw_event_data(normalized_events):
    for event in normalized_events:
        dashes = [p for p in _dash_paths(event) if not p.startswith("winlog.event_data.")]
        assert dashes == []


def test_missing_pe_metadata_is_absent_not_dash(normalized_events):
    process_events = [e for e in normalized_events if e["event"]["code"] == "1"]

    def has_pe_strings(event: dict) -> bool:
        return any(name in event["process"].get("pe", {}) for name in PE_FIELDS)

    without_pe = [e for e in process_events if not has_pe_strings(e)]
    with_pe = [e for e in process_events if has_pe_strings(e)]
    assert without_pe and with_pe
    for event in without_pe:
        # Sysmon had no version resource; the raw "-" stays only in winlog.event_data.
        assert event["winlog"]["event_data"]["Company"] == "-"
    for event in with_pe:
        assert all(event["process"]["pe"].get(name) for name in PE_FIELDS)
