"""Cross-index consistency: detections ↔ window scores, envelopes ↔ deliveries."""

from __future__ import annotations

from typing import Any

from sentinelbench.clients.elasticsearch import ElasticsearchClient
from sentinelbench.config import (
    CHANNELS,
    INDEX_DELIVERIES,
    INDEX_DETECTIONS,
    INDEX_NOTIFICATIONS,
    INDEX_WINDOW_SCORES,
    StackEndpoints,
)
from sentinelbench.paths import get_path
from sentinelbench.timeutil import lag_sec, parse_utc

# Same-millisecond created stamps are normal for one WindowScore emit;
# a larger gap suggests one index family was overwritten later (replay).
_REPLAY_DRIFT_SEC = 1.0


def evaluate_consistency(es: ElasticsearchClient, endpoints: StackEndpoints) -> dict[str, Any]:
    period = es.period_query(endpoints.since)
    detection_count = es.count(INDEX_DETECTIONS, period)
    reported_count = es.count(
        INDEX_WINDOW_SCORES,
        {"bool": {"filter": [period, {"term": {"logsentinel.verdict.reported": True}}]}},
    )
    pair = _detection_window_pairs(es, period, endpoints.sample_size)
    notify = _notification_delivery_pairs(es, period, endpoints.sample_size)
    counts_match = detection_count == reported_count
    ok = counts_match and pair["ok"] and notify["ok"]
    return {
        "ok": ok,
        "since": endpoints.since,
        "detection_vs_reported_scores": {
            "detections": detection_count,
            "reported_window_scores": reported_count,
            "match": counts_match,
        },
        "detection_window_pairs": pair,
        "notification_deliveries": notify,
    }


def _detection_window_pairs(
    es: ElasticsearchClient, period: dict[str, Any], sample_size: int
) -> dict[str, Any]:
    detections = es.search(
        INDEX_DETECTIONS,
        {
            "size": sample_size,
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": [
                "logsentinel.window.id",
                "logsentinel.verdict",
                "event.end",
                "event.created",
                "host.id",
            ],
        },
    )["hits"]["hits"]
    ids = [hit["_id"] for hit in detections]
    if not ids:
        return {"ok": True, "sampled": 0, "missing_window_scores": 0, "verdict_mismatches": 0}
    scores = es.search(
        INDEX_WINDOW_SCORES,
        {
            "size": len(ids),
            "query": {"ids": {"values": ids}},
            "_source": [
                "logsentinel.window.id",
                "logsentinel.verdict",
                "event.end",
                "event.created",
                "host.id",
            ],
        },
    )["hits"]["hits"]
    by_id = {hit["_id"]: hit.get("_source") or {} for hit in scores}
    missing = [doc_id for doc_id in ids if doc_id not in by_id]
    mismatches: list[dict[str, Any]] = []
    compare_fields = ("gated", "suspicious", "reported", "label", "confidence_score", "threshold")
    replay_drift = 0
    for hit in detections:
        source = hit.get("_source") or {}
        other = by_id.get(hit["_id"])
        if other is None:
            continue
        left = get_path(source, ("logsentinel", "verdict")) or {}
        right = get_path(other, ("logsentinel", "verdict")) or {}
        diffs = {
            field: {"detection": left.get(field), "window_score": right.get(field)}
            for field in compare_fields
            if left.get(field) != right.get(field)
        }
        left_indicators = left.get("indicators") or []
        right_indicators = right.get("indicators") or []
        if left_indicators != right_indicators:
            diffs["indicators"] = {
                "detection": left_indicators,
                "window_score": right_indicators,
            }
        if right.get("reported") is not True:
            diffs["reported"] = {"detection": True, "window_score": right.get("reported")}
        if get_path(source, ("event", "end")) != get_path(other, ("event", "end")):
            diffs["event.end"] = {
                "detection": get_path(source, ("event", "end")),
                "window_score": get_path(other, ("event", "end")),
            }
        if not diffs:
            continue
        det_created = get_path(source, ("event", "created"))
        score_created = get_path(other, ("event", "created"))
        created_gap = lag_sec(parse_utc(det_created), parse_utc(score_created))
        if created_gap is not None:
            created_gap = abs(created_gap)
        likely_replay = created_gap is not None and created_gap >= _REPLAY_DRIFT_SEC
        if likely_replay:
            replay_drift += 1
        mismatches.append(
            {
                "id": hit["_id"],
                "diffs": diffs,
                "event.created": {"detection": det_created, "window_score": score_created},
                "created_gap_sec": created_gap,
                "likely_replay_drift": likely_replay,
            }
        )
    return {
        "ok": not missing and not mismatches,
        "sampled": len(ids),
        "missing_window_scores": len(missing),
        "missing_examples": missing[:5],
        "verdict_mismatches": len(mismatches),
        "likely_replay_drift": replay_drift,
        "mismatch_examples": mismatches[:5],
        "note": (
            "Shared _id with differing verdicts is a pipeline defect; "
            f"created_gap ≥ {_REPLAY_DRIFT_SEC:g}s is tagged likely_replay_drift"
            if mismatches
            else None
        ),
    }


def _notification_delivery_pairs(
    es: ElasticsearchClient, period: dict[str, Any], sample_size: int
) -> dict[str, Any]:
    envelopes = es.search(
        INDEX_NOTIFICATIONS,
        {
            "size": sample_size,
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": ["event.id"],
        },
    )["hits"]["hits"]
    event_ids = [
        get_path(hit.get("_source") or {}, ("event", "id"))
        for hit in envelopes
        if get_path(hit.get("_source") or {}, ("event", "id"))
    ]
    if not event_ids:
        return {
            "ok": True,
            "sampled_envelopes": 0,
            "complete_both_channels": 0,
            "missing_any_channel": 0,
            "unsent_channels": 0,
        }
    deliveries = es.search(
        INDEX_DELIVERIES,
        {
            "size": min(10000, len(event_ids) * len(CHANNELS)),
            "query": {
                "bool": {
                    "filter": [
                        {"terms": {"logsentinel.notification.id": event_ids}},
                    ]
                }
            },
            "_source": [
                "logsentinel.notification.id",
                "logsentinel.notification.channel",
                "logsentinel.notification.sent",
            ],
        },
    )["hits"]["hits"]
    by_id: dict[str, dict[str, bool | None]] = {eid: {} for eid in event_ids}
    for hit in deliveries:
        source = hit.get("_source") or {}
        nid = get_path(source, ("logsentinel", "notification", "id"))
        channel = get_path(source, ("logsentinel", "notification", "channel"))
        sent = get_path(source, ("logsentinel", "notification", "sent"))
        if nid in by_id and channel:
            by_id[nid][channel] = bool(sent) if sent is not None else None
    complete = 0
    missing_any = 0
    unsent = 0
    examples: list[dict[str, Any]] = []
    for eid, channels in by_id.items():
        have = {channel: channels.get(channel) for channel in CHANNELS}
        if all(value is True for value in have.values()):
            complete += 1
            continue
        if any(value is None for value in have.values()):
            missing_any += 1
        if any(value is False for value in have.values()):
            unsent += 1
        if len(examples) < 5:
            examples.append({"event.id": eid, "channels": have})
    ok = missing_any == 0 and unsent == 0
    return {
        "ok": ok,
        "sampled_envelopes": len(event_ids),
        "complete_both_channels": complete,
        "missing_any_channel": missing_any,
        "unsent_channels": unsent,
        "examples": examples,
        "expected_channels": list(CHANNELS),
    }
