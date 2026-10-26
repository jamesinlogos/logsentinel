"""Data completeness and document correctness across index families."""

from __future__ import annotations

from typing import Any

from sentinelbench.clients.elasticsearch import ElasticsearchClient
from sentinelbench.config import (
    DELIVERY_REQUIRED,
    DETECTION_REQUIRED,
    INDEX_DELIVERIES,
    INDEX_DETECTIONS,
    INDEX_NOTIFICATIONS,
    INDEX_TELEMETRY,
    INDEX_WINDOW_SCORES,
    NOTIFICATION_REQUIRED,
    SCHEMA_VERSION,
    WINDOW_SCORE_REQUIRED,
    StackEndpoints,
)
from sentinelbench.paths import get_path, missing_paths


def evaluate_completeness(es: ElasticsearchClient, endpoints: StackEndpoints) -> dict[str, Any]:
    period = es.period_query(endpoints.since)
    families = [
        _check_family(
            es,
            INDEX_DETECTIONS,
            kind="alert",
            dataset="logsentinel.detection",
            required=DETECTION_REQUIRED,
            period=period,
            sample_size=endpoints.sample_size,
            features_forbidden=True,
        ),
        _check_family(
            es,
            INDEX_WINDOW_SCORES,
            kind="metric",
            dataset="logsentinel.window_score",
            required=WINDOW_SCORE_REQUIRED,
            period=period,
            sample_size=endpoints.sample_size,
            features_forbidden=False,
        ),
        _check_family(
            es,
            INDEX_NOTIFICATIONS,
            kind="alert",
            dataset="logsentinel.notification",
            required=NOTIFICATION_REQUIRED,
            period=period,
            sample_size=endpoints.sample_size,
            features_forbidden=None,
            id_field=("event", "id"),
        ),
        _check_family(
            es,
            INDEX_DELIVERIES,
            kind="state",
            dataset="logsentinel.notification_delivery",
            required=DELIVERY_REQUIRED,
            period=period,
            sample_size=endpoints.sample_size,
            features_forbidden=None,
            id_field=("event", "id"),
        ),
        _check_telemetry(es, period, endpoints.sample_size),
    ]
    ok = all(item.get("ok") for item in families)
    return {
        "ok": ok,
        "since": endpoints.since,
        "families": families,
    }


def _check_family(
    es: ElasticsearchClient,
    index: str,
    *,
    kind: str,
    dataset: str,
    required: tuple[tuple[str, ...], ...],
    period: dict[str, Any],
    sample_size: int,
    features_forbidden: bool | None,
    id_field: tuple[str, ...] | None = ("logsentinel", "window", "id"),
) -> dict[str, Any]:
    total = es.count(index, period)
    ignored = es.count(
        index,
        {"bool": {"filter": [period, {"exists": {"field": "_ignored"}}]}},
    )
    hits = es.search(
        index,
        {
            "size": sample_size,
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": True,
        },
    )["hits"]["hits"]
    problems: list[dict[str, Any]] = []
    for hit in hits:
        source = hit.get("_source") or {}
        doc_problems = missing_paths(source, required)
        if get_path(source, ("event", "kind")) not in (None, kind):
            doc_problems.append(f"event.kind={get_path(source, ('event', 'kind'))!r}")
        if get_path(source, ("event", "dataset")) not in (None, dataset):
            doc_problems.append(f"event.dataset={get_path(source, ('event', 'dataset'))!r}")
        if get_path(source, ("logsentinel", "schema_version")) not in (None, SCHEMA_VERSION):
            doc_problems.append("schema_version mismatch")
        if "@version" in source:
            doc_problems.append("has @version")
        if id_field == ("logsentinel", "window", "id"):
            window_id = get_path(source, id_field)
            if window_id not in (None, hit.get("_id")):
                doc_problems.append("_id != logsentinel.window.id")
        if (
            features_forbidden is True
            and get_path(source, ("logsentinel", "window", "features")) is not None
        ):
            doc_problems.append("detection must not carry features")
        if (
            features_forbidden is False
            and get_path(source, ("logsentinel", "window", "features")) is None
        ):
            doc_problems.append("window score missing features")
        if doc_problems:
            problems.append({"id": hit.get("_id"), "problems": doc_problems})
    sampled = len(hits)
    bad = len(problems)
    ok = total == 0 or (ignored == 0 and bad == 0)
    return {
        "index": index,
        "documents_in_period": total,
        "ignored": ignored,
        "sampled": sampled,
        "incorrect_sampled": bad,
        "example_problems": problems[:5],
        "ok": ok,
        "note": "no documents in period" if total == 0 else None,
    }


def _check_telemetry(
    es: ElasticsearchClient, period: dict[str, Any], sample_size: int
) -> dict[str, Any]:
    total = es.count(INDEX_TELEMETRY, period)
    hits = es.search(
        INDEX_TELEMETRY,
        {
            "size": sample_size,
            "sort": [{"@timestamp": "desc"}],
            "query": period,
            "_source": [
                "@timestamp",
                "event.code",
                "event.created",
                "host.name",
                "winlog.event_id",
            ],
        },
    )["hits"]["hits"]
    missing_ts = 0
    missing_code = 0
    for hit in hits:
        source = hit.get("_source") or {}
        if not source.get("@timestamp"):
            missing_ts += 1
        code = get_path(source, ("event", "code"))
        if code is None and get_path(source, ("winlog", "event_id")) is None:
            missing_code += 1
    ok = total == 0 or (missing_ts == 0 and missing_code == 0)
    return {
        "index": INDEX_TELEMETRY,
        "documents_in_period": total,
        "sampled": len(hits),
        "missing_timestamp": missing_ts,
        "missing_event_code": missing_code,
        "ok": ok,
        "note": "no documents in period" if total == 0 else None,
    }
