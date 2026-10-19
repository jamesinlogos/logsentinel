"""Output contract (inference/README.md section 7) and the index templates it must fit."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from inference import ECS_VERSION, SERVICE_NAME
from inference.documents import (
    DATASET_DETECTION,
    DATASET_WINDOW_SCORE,
    SCHEMA_VERSION,
    Kind,
    document,
    encode,
    summary_line,
    threat_fields,
)
from inference.events import Event
from inference.indicators import STRONG
from inference.scoring import LABEL_SUSPICIOUS, process_fields
from inference.windowing import INDICATOR, SLIDE, format_timestamp, window_id
from tests.builders import CREATED, WindowTriple, a_model, make_score
from tests.mappings import document_leaves, effective_mappings, mapped_leaves, unmapped_fields

SET_BY_ELASTICSEARCH = {"event.ingested"}
"""Mapped fields the service never writes: the ingest pipeline stamps them."""


def test_the_window_id_is_the_one_the_document_carries(gated_window: WindowTriple) -> None:
    window = gated_window[0]
    score = make_score(gated_window)
    assert score.window_id == window_id(window.host_id, format_timestamp(window.end))
    doc = document(score, "window_score", reported=False, created=CREATED)
    assert doc["logsentinel"]["window"]["id"] == score.window_id


def test_detection_document(gated_window: WindowTriple) -> None:
    score = make_score(gated_window, model_score=1.0, model=a_model())
    doc = json.loads(encode(document(score, "detection", reported=True, created=CREATED)))
    event, verdict = doc["event"], doc["logsentinel"]["verdict"]
    assert doc["@timestamp"] == event["end"] == format_timestamp(score.end)
    assert doc["ecs"] == {"version": ECS_VERSION}
    assert doc["service"]["name"] == SERVICE_NAME
    assert doc["host"]["id"] == score.host_id
    assert (event["kind"], event["module"], event["dataset"]) == (
        "alert",
        "logsentinel",
        DATASET_DETECTION,
    )
    assert event["category"] == ["malware"] and event["type"] == ["info"]
    assert event["start"] == format_timestamp(score.start)
    assert event["duration"] == round((score.end - score.start) * 1_000_000_000)
    assert event["created"] == format_timestamp(CREATED)
    assert event["risk_score"] == verdict["confidence_score"] == score.confidence_score
    assert event["risk_score_norm"] == round(score.confidence_score * 100, 2)  # type: ignore[operator]
    assert doc["logsentinel"]["schema_version"] == SCHEMA_VERSION
    assert doc["logsentinel"]["model"] == {
        "name": "adaptive_random_forest",
        "version": "20261009T000000Z",
    }
    assert (verdict["gated"], verdict["reported"]) == (True, True)
    assert verdict["scores"] == {
        "indicator": score.indicator_score,
        "model": 1.0,
    }
    assert verdict["indicators"][0] in STRONG
    assert "features" not in doc["logsentinel"]["window"]  # the detail lives in the window score
    assert doc["logsentinel"]["window"]["activity"] == score.activity
    assert "T1490" in doc["threat"]["technique"]["id"]
    assert doc["threat"]["framework"] == "MITRE ATT&CK"
    assert doc["message"] == summary_line(score)


def test_window_score_document_of_a_gated_window(gated_window: WindowTriple) -> None:
    score = make_score(gated_window, model_score=0.9)
    doc = document(score, "window_score", reported=False, created=CREATED)
    event, window, verdict = (
        doc["event"],
        doc["logsentinel"]["window"],
        doc["logsentinel"]["verdict"],
    )
    assert (event["kind"], event["dataset"]) == ("metric", DATASET_WINDOW_SCORE)
    assert "category" not in event and "type" not in event  # only an alert is categorised
    assert window["features"] == score.features  # the model input, next to the raw activity
    assert (verdict["gated"], verdict["reported"]) == (True, False)
    assert verdict["scores"] == {"indicator": score.indicator_score, "model": 0.9}


def test_window_score_document_of_a_window_that_is_not_gated(plain_window: WindowTriple) -> None:
    score = make_score(plain_window, model_score=0.2)
    doc = document(score, "window_score", reported=False, created=CREATED)
    verdict = doc["logsentinel"]["verdict"]
    assert verdict["gated"] is False and verdict["suspicious"] is False
    assert verdict["reported"] is False
    assert "label" not in verdict and "confidence_score" not in verdict
    assert "risk_score" not in doc["event"] and "risk_score_norm" not in doc["event"]
    assert verdict["scores"]["model"] == 0.2
    assert "model" not in doc["logsentinel"]  # no model object when none was used
    assert ("threat" in doc) == bool(threat_fields(score.indicators))


def test_a_detection_never_claims_to_be_unreported(gated_window: WindowTriple) -> None:
    doc = document(make_score(gated_window), "detection", reported=False, created=CREATED)
    assert doc["logsentinel"]["verdict"]["reported"] is True


def test_the_two_documents_of_a_window_cannot_drift_apart(gated_window: WindowTriple) -> None:
    score = make_score(gated_window, model_score=0.8, model=a_model())
    detection = document(score, "detection", reported=True, created=CREATED)
    window_score = document(score, "window_score", reported=True, created=CREATED)
    del window_score["logsentinel"]["window"]["features"]  # the one part only the score carries
    for doc in (detection, window_score):
        for name in ("kind", "dataset", "category", "type"):  # what says which stream it is
            doc["event"].pop(name, None)
    assert detection == window_score


def test_absent_values_are_left_out_not_null(gated_window: WindowTriple) -> None:
    doc = document(make_score(gated_window), "window_score", reported=False, created=CREATED)
    assert doc["logsentinel"]["verdict"]["scores"].keys() == {"indicator"}

    def nulls(value: Any, path: str = "") -> list[str]:
        if isinstance(value, dict):
            return [p for k, v in value.items() for p in nulls(v, f"{path}{k}.")]
        return [path] if value is None else []

    assert nulls(doc) == []


def test_encode_is_compact_json(gated_window: WindowTriple) -> None:
    doc = document(make_score(gated_window), "detection", reported=True, created=CREATED)
    encoded = encode(doc)
    assert json.loads(encoded) == doc
    assert len(encoded) < len(json.dumps(doc))  # no spaces after the separators


def test_summary_line_tells_the_story_in_one_line(
    gated_window: WindowTriple, plain_window: WindowTriple
) -> None:
    gated = make_score(gated_window, threshold=0.0)
    line = summary_line(gated)
    assert "\n" not in line
    assert LABEL_SUSPICIOUS in line and gated.indicators[0] in line
    assert f"{gated.confidence_score:.4f}" in line
    plain = summary_line(make_score(plain_window))
    assert "not gated" in plain and "confidence" not in plain


def test_threat_fields_split_technique_from_subtechnique() -> None:
    assert threat_fields([]) is None
    assert threat_fields(["event_log_tamper"]) == {
        "framework": "MITRE ATT&CK",
        "technique": {
            "id": ["T1070", "T1562"],
            "subtechnique": {"id": ["T1070.001", "T1562.002"]},
        },
        "tactic": {"name": ["Defense Evasion"]},
    }
    both = threat_fields(["shadow_copy_deletion", "mass_note_drop"])
    assert both is not None
    assert both["technique"] == {"id": ["T1486", "T1490"]}  # no sub-technique key when none
    assert both["tactic"] == {"name": ["Impact"]}


def test_a_scheduled_window_says_why_it_closed_and_has_no_process(
    gated_window: WindowTriple,
) -> None:
    doc = document(make_score(gated_window), "window_score", reported=False, created=CREATED)
    assert doc["logsentinel"]["window"]["trigger"] == SLIDE
    assert "process" not in doc


def test_an_early_window_names_the_process_of_the_event_it_closed_at(
    early_windows: dict[str, WindowTriple],
) -> None:
    for kind, triple in early_windows.items():
        window = triple[0]
        trigger = window.trigger_event
        assert trigger is not None
        doc = document(make_score(triple), "detection", reported=True, created=CREATED)
        assert doc["logsentinel"]["window"]["trigger"] == INDICATOR
        process = doc["process"]
        assert process["entity_id"] == trigger.entity_id
        assert process["executable"] == trigger.executable
        assert process["name"] == (trigger.executable or "").rsplit("\\", 1)[-1]
        assert process.get("parent", {}).get("entity_id") == trigger.parent_entity_id
        assert ("command_line" in process) == (kind == "command")
        if kind == "command":
            assert process["command_line"] == trigger.command_line


def test_the_process_of_an_early_window_has_only_the_fields_the_event_has() -> None:
    event = Event(
        timestamp=1_760_000_000.0,
        host_id="h",
        host_name=None,
        code="11",
        entity_id="{abc}",
        executable=None,
        command_line=None,
        parent_entity_id=None,
        file_path=None,
        file_name=None,
        file_extension=None,
        registry_path=None,
        registry_value=None,
        destination_ip=None,
        sysmon_error=None,
        sysmon_error_detail=None,
    )
    assert process_fields(event) == {"entity_id": "{abc}"}
    assert process_fields(None) == {}


# The service writes into indices whose templates say ``dynamic: false``: a field the templates do
# not describe is kept in ``_source`` but silently not indexed. These tests tie the documents to
# the templates in config/elasticsearch, using what Elasticsearch builds from them.


def all_documents(
    gated: WindowTriple, plain: WindowTriple, early: dict[str, WindowTriple]
) -> dict[Kind, list[dict[str, Any]]]:
    """Every shape the service writes, with every optional part present once."""
    full = make_score(gated, model_score=0.8, model=a_model())
    with_subtechnique = dataclasses.replace(full, indicators=[*full.indicators, "event_log_tamper"])
    by_command = make_score(early["command"], model_score=0.8, model=a_model())
    by_file = make_score(early["file"], model_score=0.8, model=a_model())
    return {
        "detection": [
            document(full, "detection", reported=True, created=CREATED),
            document(with_subtechnique, "detection", reported=True, created=CREATED),
            document(by_command, "detection", reported=True, created=CREATED),
            document(by_file, "detection", reported=True, created=CREATED),
        ],
        "window_score": [
            document(full, "window_score", reported=True, created=CREATED),
            document(
                make_score(plain, model_score=0.1), "window_score", reported=False, created=CREATED
            ),
            document(by_command, "window_score", reported=True, created=CREATED),
            document(by_file, "window_score", reported=False, created=CREATED),
        ],
    }


@pytest.mark.parametrize(
    ("kind", "index_template"),
    [
        ("detection", "ransomware-detections"),
        ("window_score", "ransomware-window-scores"),
    ],
)
def test_every_field_is_mapped_in_the_index_template(
    kind: Kind,
    index_template: str,
    gated_window: WindowTriple,
    plain_window: WindowTriple,
    early_windows: dict[str, WindowTriple],
) -> None:
    mappings = effective_mappings(index_template)
    assert mappings["dynamic"] is False  # an unmapped field would be dropped from the index
    for doc in all_documents(gated_window, plain_window, early_windows)[kind]:
        assert unmapped_fields(doc, mappings, mappings.get("dynamic_templates", [])) == []


def test_the_window_score_features_are_mapped_as_floats() -> None:
    mappings = effective_mappings("ransomware-window-scores")
    (entry,) = mappings["dynamic_templates"]
    (template,) = entry.values()
    assert template["path_match"] == "logsentinel.window.features.*"
    assert template["mapping"] == {"type": "float"}
    # The detections index has no features object: a stray feature would be reported above.
    assert "features" not in effective_mappings("ransomware-detections")["properties"][
        "logsentinel"
    ]["properties"]["window"].get("properties", {})


def test_the_templates_describe_nothing_the_service_does_not_write(
    gated_window: WindowTriple, plain_window: WindowTriple, early_windows: dict[str, WindowTriple]
) -> None:
    # The two indices share one component template, so a shared field (``event.category`` is only
    # written for detections) has to be written by one of the two streams, not by both.
    written: set[str] = set()
    for documents in all_documents(gated_window, plain_window, early_windows).values():
        for doc in documents:
            written |= document_leaves(doc)
    for index_template in ("ransomware-detections", "ransomware-window-scores"):
        # A name that changes in the code but not in the template shows up here.
        unused = mapped_leaves(effective_mappings(index_template)) - written - SET_BY_ELASTICSEARCH
        assert unused == set(), f"{index_template}: mapped but never written: {sorted(unused)}"
