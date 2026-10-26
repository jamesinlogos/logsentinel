"""Detection funnel and score distribution (no ground-truth labels from captures)."""

from __future__ import annotations

from typing import Any

from sentinelbench.clients.elasticsearch import ElasticsearchClient
from sentinelbench.config import INDEX_DETECTIONS, INDEX_WINDOW_SCORES, StackEndpoints
from sentinelbench.paths import get_path


def evaluate_detection(es: ElasticsearchClient, endpoints: StackEndpoints) -> dict[str, Any]:
    period = es.period_query(endpoints.since)
    total = es.count(INDEX_WINDOW_SCORES, period)
    gated = es.count(
        INDEX_WINDOW_SCORES,
        {"bool": {"filter": [period, {"term": {"logsentinel.verdict.gated": True}}]}},
    )
    suspicious = es.count(
        INDEX_WINDOW_SCORES,
        {"bool": {"filter": [period, {"term": {"logsentinel.verdict.suspicious": True}}]}},
    )
    reported = es.count(
        INDEX_WINDOW_SCORES,
        {"bool": {"filter": [period, {"term": {"logsentinel.verdict.reported": True}}]}},
    )
    detections = es.count(INDEX_DETECTIONS, period)
    early = es.count(
        INDEX_WINDOW_SCORES,
        {"bool": {"filter": [period, {"term": {"logsentinel.window.trigger": "indicator"}}]}},
    )
    scheduled = es.count(
        INDEX_WINDOW_SCORES,
        {"bool": {"filter": [period, {"term": {"logsentinel.window.trigger": "slide"}}]}},
    )
    indicators = _indicator_terms(es, period)
    confidence = _confidence_stats(es, period, endpoints.sample_size)
    funnel = {
        "window_scores": total,
        "gated": gated,
        "suspicious": suspicious,
        "reported_window_scores": reported,
        "detections": detections,
    }
    rates = {
        "gate_rate": _rate(gated, total),
        "suspicious_given_gated": _rate(suspicious, gated),
        "report_rate_given_suspicious": _rate(reported, suspicious),
        "detection_to_reported_ratio": _rate(detections, reported) if reported else None,
    }
    ok = detections == reported
    return {
        "ok": ok,
        "since": endpoints.since,
        "funnel": funnel,
        "rates": rates,
        "triggers": {"slide": scheduled, "indicator": early},
        "indicators": indicators,
        "reported_confidence": confidence,
        "note": (
            "Rates describe the live stack only; they are not precision/recall against "
            "sentinelcap labels"
        ),
    }


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 6)


def _indicator_terms(es: ElasticsearchClient, period: dict[str, Any]) -> list[dict[str, Any]]:
    result = es.search(
        INDEX_WINDOW_SCORES,
        {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        period,
                        {"term": {"logsentinel.verdict.reported": True}},
                    ]
                }
            },
            "aggs": {
                "indicators": {
                    "terms": {
                        "field": "logsentinel.verdict.indicators",
                        "size": 50,
                    }
                }
            },
        },
    )
    buckets = ((result.get("aggregations") or {}).get("indicators") or {}).get("buckets") or []
    return [{"indicator": bucket["key"], "count": bucket["doc_count"]} for bucket in buckets]


def _confidence_stats(
    es: ElasticsearchClient, period: dict[str, Any], sample_size: int
) -> dict[str, Any]:
    hits = es.search(
        INDEX_DETECTIONS,
        {
            "size": sample_size,
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": [
                "logsentinel.verdict.confidence_score",
                "logsentinel.verdict.threshold",
                "logsentinel.verdict.scores",
            ],
        },
    )["hits"]["hits"]
    scores: list[float] = []
    below_threshold = 0
    for hit in hits:
        source = hit.get("_source") or {}
        confidence = get_path(source, ("logsentinel", "verdict", "confidence_score"))
        threshold = get_path(source, ("logsentinel", "verdict", "threshold"))
        if isinstance(confidence, (int, float)):
            scores.append(float(confidence))
            if isinstance(threshold, (int, float)) and confidence < threshold:
                below_threshold += 1
    if not scores:
        return {"sampled": 0}
    scores.sort()
    n = len(scores)
    return {
        "sampled": n,
        "min": scores[0],
        "max": scores[-1],
        "mean": round(sum(scores) / n, 6),
        "p50": scores[n // 2],
        "below_threshold": below_threshold,
    }
