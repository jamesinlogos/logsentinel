"""Alert coverage: how detections appear in Kibana notification envelopes."""

from __future__ import annotations

import re
from typing import Any

from sentinelbench.clients.elasticsearch import ElasticsearchClient
from sentinelbench.config import (
    INDEX_DETECTIONS,
    INDEX_NOTIFICATIONS,
    StackEndpoints,
)
from sentinelbench.paths import get_path

_WINDOW_ID_RE = re.compile(r"Window ID:\s*([0-9a-f]{64})", re.IGNORECASE)
_MATCHING_RE = re.compile(r"Matching windows:\s*(\d+)", re.IGNORECASE)


def evaluate_coverage(es: ElasticsearchClient, endpoints: StackEndpoints) -> dict[str, Any]:
    period = es.period_query(endpoints.since)
    detection_ids = _all_detection_ids(es, period, endpoints.sample_size)
    notifications = es.search(
        INDEX_NOTIFICATIONS,
        {
            "size": min(endpoints.sample_size, 500),
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": ["event.id", "event.created", "message", "logsentinel.notification.count"],
        },
    )["hits"]["hits"]
    cited: set[str] = set()
    matching_declared = 0
    matching_parsed_ok = 0
    example_slots = 0
    for hit in notifications:
        source = hit.get("_source") or {}
        message = source.get("message") or ""
        ids = _WINDOW_ID_RE.findall(message)
        cited.update(ids)
        example_slots += len(ids)
        match = _MATCHING_RE.search(message)
        if match:
            matching_parsed_ok += 1
            matching_declared += int(match.group(1))
        count_field = get_path(source, ("logsentinel", "notification", "count"))
        if count_field is not None and match is None:
            try:
                matching_declared += int(count_field)
                matching_parsed_ok += 1
            except (TypeError, ValueError):
                pass

    covered = sorted(detection_ids & cited)
    uncovered = sorted(detection_ids - cited)
    detection_total = es.count(INDEX_DETECTIONS, period)
    notification_total = es.count(INDEX_NOTIFICATIONS, period)
    # Kibana only embeds up to 10 example windows per envelope; coverage of IDs is a lower bound.
    sample_coverage = round(len(covered) / len(detection_ids), 6) if detection_ids else None
    return {
        "ok": True,
        "since": endpoints.since,
        "detections_in_period": detection_total,
        "notifications_in_period": notification_total,
        "detection_sample_size": len(detection_ids),
        "windows_cited_in_notification_examples": len(cited),
        "sampled_detections_cited": len(covered),
        "sampled_detections_not_in_examples": len(uncovered),
        "sample_example_coverage_rate": sample_coverage,
        "matching_windows_declared_sum": matching_declared,
        "notification_messages_parsed": matching_parsed_ok,
        "example_window_slots": example_slots,
        "uncovered_examples": uncovered[:10],
        "note": (
            "Kibana notice examples list at most 10 windows; a detection can be covered by "
            "the rule count without appearing in the message examples"
        ),
    }


def _all_detection_ids(
    es: ElasticsearchClient, period: dict[str, Any], sample_size: int
) -> set[str]:
    hits = es.search(
        INDEX_DETECTIONS,
        {
            "size": sample_size,
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": False,
        },
    )["hits"]["hits"]
    return {hit["_id"] for hit in hits}
