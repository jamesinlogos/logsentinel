"""Document shape helpers."""

from __future__ import annotations

from sentinelbench.config import DETECTION_REQUIRED, SCHEMA_VERSION
from sentinelbench.paths import missing_paths


def test_detection_required_fields() -> None:
    source = {
        "@timestamp": "2026-10-23T01:07:44.085Z",
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "alert",
            "module": "logsentinel",
            "dataset": "logsentinel.detection",
            "end": "2026-10-23T01:07:44.085Z",
            "created": "2026-10-23T01:07:50.067Z",
            "ingested": "2026-10-23T01:07:50.377Z",
        },
        "logsentinel": {
            "schema_version": SCHEMA_VERSION,
            "window": {"id": "abc"},
            "verdict": {"reported": True, "gated": True},
        },
    }
    assert missing_paths(source, DETECTION_REQUIRED) == []


def test_missing_paths_reports_dotted_names() -> None:
    assert missing_paths({}, DETECTION_REQUIRED[:2]) == ["@timestamp", "ecs.version"]
