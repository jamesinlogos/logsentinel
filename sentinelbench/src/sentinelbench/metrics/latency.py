"""Per-stage latency from document timestamps along the monitoring path."""

from __future__ import annotations

import re
from typing import Any

from sentinelbench.clients.elasticsearch import ElasticsearchClient
from sentinelbench.config import (
    INDEX_DELIVERIES,
    INDEX_DETECTIONS,
    INDEX_NOTIFICATIONS,
    INDEX_TELEMETRY,
    INDEX_WINDOW_SCORES,
    StackEndpoints,
)
from sentinelbench.paths import get_path
from sentinelbench.timeutil import lag_sec, parse_utc, percentiles

_WINDOW_ID_RE = re.compile(r"Window ID:\s*([0-9a-f]{64})", re.IGNORECASE)


def evaluate_latency(es: ElasticsearchClient, endpoints: StackEndpoints) -> dict[str, Any]:
    period = es.period_query(endpoints.since)
    size = endpoints.sample_size
    stages: dict[str, Any] = {
        "telemetry_ship": _stage_telemetry(es, period, size),
        "window_score_build": _stage_from_docs(
            es,
            INDEX_WINDOW_SCORES,
            period,
            size,
            earlier=("event", "end"),
            later=("event", "created"),
            description="window end -> inference event.created",
        ),
        "window_score_index": _stage_from_docs(
            es,
            INDEX_WINDOW_SCORES,
            period,
            size,
            earlier=("event", "created"),
            later=("event", "ingested"),
            description="inference created -> ES ingested (Kafka + detection-sink)",
        ),
        "detection_index": _stage_from_docs(
            es,
            INDEX_DETECTIONS,
            period,
            size,
            earlier=("event", "created"),
            later=("event", "ingested"),
            description="detection created -> ES ingested",
        ),
        "notification_deliver": _stage_notification_deliver(es, period, size),
        "detection_to_notification": _stage_detection_to_notification(es, period, size),
    }
    measured = [name for name, body in stages.items() if body.get("stats")]
    return {
        "ok": True,
        "since": endpoints.since,
        "stages": stages,
        "measured_stages": measured,
        "unit": "seconds",
    }


def _stage_from_docs(
    es: ElasticsearchClient,
    index: str,
    period: dict[str, Any],
    size: int,
    *,
    earlier: tuple[str, ...],
    later: tuple[str, ...],
    description: str,
) -> dict[str, Any]:
    hits = es.search(
        index,
        {
            "size": size,
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": ["event.end", "event.created", "event.ingested", "@timestamp"],
        },
    )["hits"]["hits"]
    values: list[float] = []
    negative = 0
    for hit in hits:
        source = hit.get("_source") or {}
        lag = lag_sec(parse_utc(get_path(source, later)), parse_utc(get_path(source, earlier)))
        if lag is None:
            continue
        if lag < 0:
            negative += 1
            continue
        values.append(lag)
    return {
        "description": description,
        "sampled_docs": len(hits),
        "measured": len(values),
        "negative_skipped": negative,
        "stats": percentiles(values) or None,
    }


def _stage_telemetry(es: ElasticsearchClient, period: dict[str, Any], size: int) -> dict[str, Any]:
    hits = es.search(
        INDEX_TELEMETRY,
        {
            "size": size,
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": ["@timestamp", "event.created"],
        },
    )["hits"]["hits"]
    values: list[float] = []
    missing_created = 0
    for hit in hits:
        source = hit.get("_source") or {}
        created = parse_utc(get_path(source, ("event", "created")))
        stamped = parse_utc(source.get("@timestamp"))
        if created is None:
            missing_created += 1
            continue
        lag = lag_sec(created, stamped)
        if lag is None or lag < 0:
            continue
        values.append(lag)
    return {
        "description": "Sysmon @timestamp -> Winlogbeat event.created (ship lag)",
        "sampled_docs": len(hits),
        "measured": len(values),
        "missing_event_created": missing_created,
        "stats": percentiles(values) or None,
    }


def _stage_notification_deliver(
    es: ElasticsearchClient, period: dict[str, Any], size: int
) -> dict[str, Any]:
    hits = es.search(
        INDEX_DELIVERIES,
        {
            "size": size,
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [
                        period,
                        {"term": {"logsentinel.notification.sent": True}},
                    ]
                }
            },
            "_source": [
                "logsentinel.notification.id",
                "logsentinel.notification.sent_at",
                "logsentinel.notification.channel",
                "event.ingested",
            ],
        },
    )["hits"]["hits"]
    notif_ids = sorted(
        {
            get_path(hit.get("_source") or {}, ("logsentinel", "notification", "id"))
            for hit in hits
            if get_path(hit.get("_source") or {}, ("logsentinel", "notification", "id"))
        }
    )
    created_by_id: dict[str, Any] = {}
    if notif_ids:
        # Fetch envelopes in chunks by ids query.
        for offset in range(0, len(notif_ids), 100):
            chunk = notif_ids[offset : offset + 100]
            found = es.search(
                INDEX_NOTIFICATIONS,
                {
                    "size": len(chunk),
                    "query": {"terms": {"event.id": chunk}},
                    "_source": ["event.id", "event.created"],
                },
            )["hits"]["hits"]
            for hit in found:
                source = hit.get("_source") or {}
                eid = get_path(source, ("event", "id"))
                if eid:
                    created_by_id[eid] = parse_utc(get_path(source, ("event", "created")))
    values: list[float] = []
    by_channel: dict[str, list[float]] = {}
    for hit in hits:
        source = hit.get("_source") or {}
        nid = get_path(source, ("logsentinel", "notification", "id"))
        channel = get_path(source, ("logsentinel", "notification", "channel")) or "unknown"
        sent_at = parse_utc(get_path(source, ("logsentinel", "notification", "sent_at")))
        created = created_by_id.get(nid) if nid else None
        lag = lag_sec(sent_at, created)
        if lag is None or lag < 0:
            continue
        values.append(lag)
        by_channel.setdefault(channel, []).append(lag)
    return {
        "description": "notification event.created -> delivery sent_at",
        "sampled_docs": len(hits),
        "measured": len(values),
        "stats": percentiles(values) or None,
        "by_channel": {name: percentiles(vals) for name, vals in sorted(by_channel.items())},
    }


def _stage_detection_to_notification(
    es: ElasticsearchClient, period: dict[str, Any], size: int
) -> dict[str, Any]:
    """Approximate Kibana rule lag: detection ingested -> first envelope that cites the window."""
    detections = es.search(
        INDEX_DETECTIONS,
        {
            "size": size,
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": ["logsentinel.window.id", "event.ingested", "event.end"],
        },
    )["hits"]["hits"]
    det_ingested = {
        get_path(hit.get("_source") or {}, ("logsentinel", "window", "id")): parse_utc(
            get_path(hit.get("_source") or {}, ("event", "ingested"))
        )
        for hit in detections
        if get_path(hit.get("_source") or {}, ("logsentinel", "window", "id"))
    }
    notifications = es.search(
        INDEX_NOTIFICATIONS,
        {
            "size": min(size, 100),
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": ["event.created", "message"],
        },
    )["hits"]["hits"]
    first_notif: dict[str, Any] = {}
    for hit in notifications:
        source = hit.get("_source") or {}
        created = parse_utc(get_path(source, ("event", "created")))
        message = source.get("message") or ""
        for window_id in _WINDOW_ID_RE.findall(message):
            previous = first_notif.get(window_id)
            if previous is None or (created is not None and created < previous):
                first_notif[window_id] = created
    values: list[float] = []
    matched = 0
    for window_id, ingested in det_ingested.items():
        created = first_notif.get(window_id)
        lag = lag_sec(created, ingested)
        if lag is None:
            continue
        matched += 1
        if lag >= 0:
            values.append(lag)
    return {
        "description": "detection event.ingested -> first notification citing Window ID",
        "detection_sample": len(det_ingested),
        "windows_matched_in_notifications": matched,
        "measured": len(values),
        "stats": percentiles(values) or None,
        "note": (
            "Kibana batches windows into one envelope; only windows listed in the "
            "message examples (up to 10) can be matched"
        ),
    }
