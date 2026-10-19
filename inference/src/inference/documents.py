"""Output contract (inference/README.md section 7).

Every window the service scores gives a *window score*; a window that passed the Phase 2 gate
and survives the suppression of ``EmissionPolicy`` is also a *detection*. Both documents are
built from one :class:`WindowScore`, so they cannot drift apart: the detection is the window
score without ``features``, flagged as an alert. Field names follow AGENTS.md section 11: an
ECS field where ECS has one, everything else under ``logsentinel.*``.

``logsentinel.window.id`` depends only on the host and the window end, so a document sent again
overwrites itself in Elasticsearch (the sink uses it as ``document_id``).
"""

from __future__ import annotations

import json
from typing import Any, Literal

from inference import ECS_VERSION, PRODUCT, SERVICE_NAME, __version__
from inference.indicators import MITRE
from inference.scoring import WindowScore
from inference.windowing import format_timestamp

SCHEMA_VERSION = 2
FRAMEWORK = "MITRE ATT&CK"
DATASET_DETECTION = f"{PRODUCT}.detection"
DATASET_WINDOW_SCORE = f"{PRODUCT}.window_score"
NANOSECONDS = 1_000_000_000

Kind = Literal["detection", "window_score"]


def document(score: WindowScore, kind: Kind, *, reported: bool, created: float) -> dict[str, Any]:
    """The JSON document of ``score``; ``created``: when the service built it (epoch seconds)."""
    detection = kind == "detection"
    end = format_timestamp(score.end)
    event: dict[str, Any] = {
        "kind": "alert" if detection else "metric",
        "module": PRODUCT,
        "dataset": DATASET_DETECTION if detection else DATASET_WINDOW_SCORE,
        "start": format_timestamp(score.start),
        "end": end,
        "duration": round((score.end - score.start) * NANOSECONDS),
        "created": format_timestamp(created),
    }
    if detection:
        event["category"] = ["malware"]
        event["type"] = ["info"]
    if score.confidence_score is not None:
        event["risk_score"] = score.confidence_score
        event["risk_score_norm"] = round(score.confidence_score * 100, 2)
    window: dict[str, Any] = {
        "id": score.window_id,
        "trigger": score.trigger,
        "activity": score.activity,
    }
    if not detection:
        window["features"] = score.features
    verdict: dict[str, Any] = {
        "gated": score.gated,
        "suspicious": score.suspicious,
        "reported": reported or detection,
        "threshold": score.threshold,
        "indicators": score.indicators,
        "scores": _present(indicator=score.indicator_score, model=score.model_score),
    }
    verdict.update(_present(label=score.label, confidence_score=score.confidence_score))
    vendor: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "window": window,
        "verdict": verdict,
    }
    if score.model_name is not None:
        vendor["model"] = {"name": score.model_name, "version": score.model_version}
    doc: dict[str, Any] = {
        "@timestamp": end,
        "ecs": {"version": ECS_VERSION},
        "message": summary_line(score),
        "event": event,
        "host": _present(id=score.host_id, name=score.host_name),
        "service": {"name": SERVICE_NAME, "version": __version__},
        PRODUCT: vendor,
    }
    if score.process:
        doc["process"] = score.process
    threat = threat_fields(score.indicators)
    if threat is not None:
        doc["threat"] = threat
    return doc


def encode(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, separators=(",", ":")).encode("utf-8")


def summary_line(score: WindowScore) -> str:
    """The ``message`` of a document: what a person scanning a list of documents needs."""
    host = score.host_name or score.host_id
    span = f"{format_timestamp(score.start)} to {format_timestamp(score.end)}"
    if not score.gated:
        return f"Window {span} of host {host}: not gated, {score.activity['events']} events"
    return (
        f"Window {span} of host {host}: {score.label}, confidence {score.confidence_score:.4f} "
        f"(threshold {score.threshold:.2f}), indicators: {', '.join(score.indicators)}"
    )


def threat_fields(indicators: list[str]) -> dict[str, Any] | None:
    """ECS ``threat`` of the indicators that fired: parent techniques apart from sub-techniques."""
    techniques = {t for name in indicators for t in MITRE[name][0]}
    tactics = {t for name in indicators for t in MITRE[name][1]}
    if not techniques:
        return None
    technique: dict[str, Any] = {"id": sorted({t.split(".")[0] for t in techniques})}
    subtechniques = sorted(t for t in techniques if "." in t)
    if subtechniques:
        technique["subtechnique"] = {"id": subtechniques}
    return {"framework": FRAMEWORK, "technique": technique, "tactic": {"name": sorted(tactics)}}


def _present(**values: Any) -> dict[str, Any]:
    """The values that exist: an absent score is left out, never written as ``null``."""
    return {name: value for name, value in values.items() if value is not None}
