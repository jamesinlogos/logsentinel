"""Quality checks against an in-memory Elasticsearch stub."""

from __future__ import annotations

from typing import Any

from sentinelbench.config import SCHEMA_VERSION, StackEndpoints
from sentinelbench.metrics.completeness import evaluate_completeness
from sentinelbench.metrics.consistency import evaluate_consistency
from sentinelbench.metrics.detection import evaluate_detection


class FakeES:
    def __init__(self, counts: dict[str, int], searches: dict[str, list[dict[str, Any]]]) -> None:
        self.counts = counts
        self.searches = searches

    def period_query(self, since: str, *, field: str = "@timestamp") -> dict[str, Any]:
        return {"range": {field: {"gte": f"now-{since}"}}}

    def count(self, index: str, query: dict[str, Any] | None = None) -> int:
        if query and "exists" in str(query):
            return 0
        if query and "reported" in str(query):
            return self.counts.get(f"{index}:reported", self.counts.get(index, 0))
        if query and "gated" in str(query):
            return self.counts.get(f"{index}:gated", 0)
        if query and "suspicious" in str(query):
            return self.counts.get(f"{index}:suspicious", 0)
        if query and "indicator" in str(query):
            return self.counts.get(f"{index}:indicator", 0)
        if query and "slide" in str(query):
            return self.counts.get(f"{index}:slide", 0)
        return self.counts.get(index, 0)

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        if body.get("size") == 0:
            return {
                "hits": {"hits": []},
                "aggregations": {
                    "indicators": {"buckets": [{"key": "lolbins_execution", "doc_count": 2}]}
                },
            }
        if "ids" in str(body.get("query")):
            wanted = set(((body.get("query") or {}).get("ids") or {}).get("values") or [])
            hits = [hit for hit in self.searches.get(index, []) if hit["_id"] in wanted]
            return {"hits": {"hits": hits}}
        return {"hits": {"hits": self.searches.get(index, [])}}


def _detection_doc(doc_id: str) -> dict[str, Any]:
    return {
        "_id": doc_id,
        "_source": {
            "@timestamp": "2026-10-23T01:07:44.085Z",
            "ecs": {"version": "8.11"},
            "event": {
                "kind": "alert",
                "module": "logsentinel",
                "dataset": "logsentinel.detection",
                "end": "2026-10-23T01:07:44.085Z",
                "created": "2026-10-23T01:07:50.067Z",
                "ingested": "2026-10-23T01:07:50.377Z",
            },
            "host": {"id": "h1"},
            "logsentinel": {
                "schema_version": SCHEMA_VERSION,
                "window": {"id": doc_id},
                "verdict": {
                    "gated": True,
                    "suspicious": True,
                    "reported": True,
                    "label": "suspicious_ransomware_behavior",
                    "confidence_score": 0.9,
                    "threshold": 0.6,
                },
            },
        },
    }


def _score_doc(doc_id: str, *, reported: bool = True) -> dict[str, Any]:
    doc = _detection_doc(doc_id)
    doc["_source"]["event"]["kind"] = "metric"
    doc["_source"]["event"]["dataset"] = "logsentinel.window_score"
    doc["_source"]["logsentinel"]["window"]["features"] = {"x": 1.0}
    doc["_source"]["logsentinel"]["verdict"]["reported"] = reported
    return doc


def test_completeness_and_consistency_agree_on_matching_pair() -> None:
    doc_id = "a" * 64
    es = FakeES(
        counts={
            "ransomware-detections-*": 1,
            "ransomware-window-scores-*": 1,
            "ransomware-window-scores-*:reported": 1,
            "ransomware-window-scores-*:gated": 1,
            "ransomware-window-scores-*:suspicious": 1,
            "ransomware-notifications-*": 0,
            "ransomware-notification-deliveries-*": 0,
            "windows-telemetry-*": 0,
        },
        searches={
            "ransomware-detections-*": [_detection_doc(doc_id)],
            "ransomware-window-scores-*": [_score_doc(doc_id)],
            "ransomware-notifications-*": [],
            "ransomware-notification-deliveries-*": [],
            "windows-telemetry-*": [],
        },
    )
    endpoints = StackEndpoints(since="24h", sample_size=10, skip_docker=True)
    completeness = evaluate_completeness(es, endpoints)  # type: ignore[arg-type]
    consistency = evaluate_consistency(es, endpoints)  # type: ignore[arg-type]
    detection = evaluate_detection(es, endpoints)  # type: ignore[arg-type]
    assert completeness["ok"] is True
    assert consistency["ok"] is True
    assert detection["ok"] is True
    assert detection["funnel"]["detections"] == 1
