"""Live operational metrics beyond the core five quality dimensions."""

from __future__ import annotations

from typing import Any

from sentinelbench.clients.elasticsearch import ElasticsearchClient
from sentinelbench.config import (
    INDEX_DETECTIONS,
    INDEX_NOTIFICATIONS,
    INDEX_TELEMETRY,
    INDEX_WINDOW_SCORES,
    StackEndpoints,
)
from sentinelbench.paths import get_path
from sentinelbench.timeutil import lag_sec, parse_utc, percentiles


def evaluate_operations(es: ElasticsearchClient, endpoints: StackEndpoints) -> dict[str, Any]:
    period = es.period_query(endpoints.since)
    return {
        "ok": True,
        "since": endpoints.since,
        "score_distribution": _score_distribution(es, period, endpoints.sample_size),
        "end_to_end_latency": _end_to_end(es, period, endpoints.sample_size),
        "telemetry_throughput": _telemetry_throughput(es, endpoints.since),
        "timestamp_order": _timestamp_order(es, period, endpoints.sample_size),
        "index_inventory": _index_inventory(es),
        "notification_gaps": _notification_gaps(es, period, endpoints.sample_size),
        "early_window_share": _early_share(es, period),
    }


def _score_distribution(
    es: ElasticsearchClient, period: dict[str, Any], sample_size: int
) -> dict[str, Any]:
    hits = es.search(
        INDEX_WINDOW_SCORES,
        {
            "size": sample_size,
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [period, {"term": {"logsentinel.verdict.gated": True}}],
                }
            },
            "_source": [
                "logsentinel.verdict.scores.indicator",
                "logsentinel.verdict.scores.model",
                "logsentinel.verdict.confidence_score",
                "logsentinel.verdict.threshold",
                "logsentinel.verdict.reported",
            ],
        },
    )["hits"]["hits"]
    indicator: list[float] = []
    model: list[float] = []
    confidence: list[float] = []
    margin: list[float] = []
    for hit in hits:
        source = hit.get("_source") or {}
        scores = get_path(source, ("logsentinel", "verdict", "scores")) or {}
        if isinstance(scores.get("indicator"), (int, float)):
            indicator.append(float(scores["indicator"]))
        if isinstance(scores.get("model"), (int, float)):
            model.append(float(scores["model"]))
        conf = get_path(source, ("logsentinel", "verdict", "confidence_score"))
        thr = get_path(source, ("logsentinel", "verdict", "threshold"))
        if isinstance(conf, (int, float)):
            confidence.append(float(conf))
            if isinstance(thr, (int, float)):
                margin.append(float(conf) - float(thr))
    return {
        "sampled_gated_windows": len(hits),
        "indicator_score": percentiles(indicator) or None,
        "model_score": percentiles(model) or None,
        "confidence_score": percentiles(confidence) or None,
        "confidence_minus_threshold": percentiles(margin) or None,
    }


def _end_to_end(
    es: ElasticsearchClient, period: dict[str, Any], sample_size: int
) -> dict[str, Any]:
    """Window end → notification sent_at for windows cited in recent envelopes."""
    notifications = es.search(
        INDEX_NOTIFICATIONS,
        {
            "size": min(sample_size, 100),
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": ["event.id", "event.created", "message"],
        },
    )["hits"]["hits"]
    import re

    window_re = re.compile(r"Window ID:\s*([0-9a-f]{64})", re.IGNORECASE)
    window_ids: set[str] = set()
    for hit in notifications:
        window_ids.update(window_re.findall((hit.get("_source") or {}).get("message") or ""))
    if not window_ids:
        return {"measured": 0, "stats": None}
    detections = es.search(
        INDEX_DETECTIONS,
        {
            "size": len(window_ids),
            "query": {"ids": {"values": list(window_ids)}},
            "_source": ["event.end", "event.ingested", "logsentinel.window.id"],
        },
    )["hits"]["hits"]
    end_by_id = {
        hit["_id"]: parse_utc(get_path(hit.get("_source") or {}, ("event", "end")))
        for hit in detections
    }
    # Use envelope created vs detection end (lower-bound path to the notice).
    values_end_to_created: list[float] = []
    for hit in notifications:
        source = hit.get("_source") or {}
        created = parse_utc(get_path(source, ("event", "created")))
        for wid in window_re.findall(source.get("message") or ""):
            lag = lag_sec(created, end_by_id.get(wid))
            if lag is not None and lag >= 0:
                values_end_to_created.append(lag)
    return {
        "description": "window event.end -> notification event.created (cited examples)",
        "windows_cited": len(window_ids),
        "measured": len(values_end_to_created),
        "stats": percentiles(values_end_to_created) or None,
        "unit": "seconds",
    }


def _telemetry_throughput(es: ElasticsearchClient, since: str) -> dict[str, Any]:
    """Approximate events/s from a date_histogram over the lookback window."""
    result = es.search(
        INDEX_TELEMETRY,
        {
            "size": 0,
            "query": es.period_query(since),
            "aggs": {
                "per_minute": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1m",
                        "min_doc_count": 1,
                    }
                }
            },
        },
    )
    buckets = ((result.get("aggregations") or {}).get("per_minute") or {}).get("buckets") or []
    rates = [bucket["doc_count"] / 60.0 for bucket in buckets if bucket.get("doc_count")]
    total = sum(bucket.get("doc_count", 0) for bucket in buckets)
    return {
        "minutes_with_data": len(buckets),
        "events_in_period": total,
        "events_per_sec": percentiles(rates) or None,
        "note": "per-minute histogram of windows-telemetry-* @timestamp",
    }


def _timestamp_order(
    es: ElasticsearchClient, period: dict[str, Any], sample_size: int
) -> dict[str, Any]:
    """Count adjacent @timestamp inversions in a recent telemetry sample (per host)."""
    hits = es.search(
        INDEX_TELEMETRY,
        {
            "size": sample_size,
            "sort": [{"@timestamp": "asc"}],
            "query": period,
            "_source": ["@timestamp", "host.name"],
        },
    )["hits"]["hits"]
    last_by_host: dict[str, Any] = {}
    inversions = 0
    compared = 0
    for hit in hits:
        source = hit.get("_source") or {}
        host = get_path(source, ("host", "name")) or "_"
        ts = parse_utc(source.get("@timestamp"))
        if ts is None:
            continue
        previous = last_by_host.get(host)
        if previous is not None:
            compared += 1
            if ts < previous:
                inversions += 1
        last_by_host[host] = ts
    return {
        "sampled": len(hits),
        "adjacent_pairs": compared,
        "inversions": inversions,
        "inversion_rate": round(inversions / compared, 6) if compared else None,
    }


def _index_inventory(es: ElasticsearchClient) -> dict[str, Any]:
    try:
        text = es.cat_indices("windows-telemetry-*,ransomware-*")
    except Exception as exc:  # noqa: BLE001 — surface as metric note
        return {"error": str(exc)}
    lines = [line for line in text.splitlines() if line.strip() and not line.startswith("index")]
    return {"rows": len(lines), "cat": text}


def _notification_gaps(
    es: ElasticsearchClient, period: dict[str, Any], sample_size: int
) -> dict[str, Any]:
    hits = es.search(
        INDEX_NOTIFICATIONS,
        {
            "size": sample_size,
            "sort": [{"@timestamp": "asc"}],
            "query": period,
            "_source": ["event.created"],
        },
    )["hits"]["hits"]
    created = [parse_utc(get_path(hit.get("_source") or {}, ("event", "created"))) for hit in hits]
    created = [value for value in created if value is not None]
    gaps: list[float] = []
    for left, right in zip(created, created[1:], strict=False):
        gap = (right - left).total_seconds()
        if gap >= 0:
            gaps.append(gap)
    return {
        "envelopes": len(created),
        "gap_sec": percentiles(gaps) or None,
        "note": "gaps between successive notification event.created stamps",
    }


def _early_share(es: ElasticsearchClient, period: dict[str, Any]) -> dict[str, Any]:
    total = es.count(INDEX_DETECTIONS, period)
    early = es.count(
        INDEX_DETECTIONS,
        {"bool": {"filter": [period, {"term": {"logsentinel.window.trigger": "indicator"}}]}},
    )
    return {
        "detections": total,
        "early_trigger": early,
        "early_rate": round(early / total, 6) if total else None,
    }
