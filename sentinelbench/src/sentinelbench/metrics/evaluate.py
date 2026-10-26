"""Compose component probes and quality dimensions into one stack evaluation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sentinelbench import __version__
from sentinelbench.clients.elasticsearch import ElasticsearchClient
from sentinelbench.config import StackEndpoints
from sentinelbench.metrics.completeness import evaluate_completeness
from sentinelbench.metrics.consistency import evaluate_consistency
from sentinelbench.metrics.coverage import evaluate_coverage
from sentinelbench.metrics.detection import evaluate_detection
from sentinelbench.metrics.latency import evaluate_latency
from sentinelbench.metrics.operations import evaluate_operations
from sentinelbench.query_components import (
    query_elasticsearch,
    query_inference,
    query_kafka,
    query_kibana,
    query_logstash,
    query_notifications,
)


def evaluate_stack(endpoints: StackEndpoints) -> dict[str, Any]:
    es = ElasticsearchClient(endpoints.elasticsearch, timeout_sec=endpoints.timeout_sec)
    components = {
        "elasticsearch": query_elasticsearch(endpoints),
        "kafka": query_kafka(endpoints),
        "logstash": query_logstash(endpoints),
        "kibana": query_kibana(endpoints),
        "inference": query_inference(endpoints),
        "notifications": query_notifications(endpoints),
    }
    quality = {
        "completeness": evaluate_completeness(es, endpoints),
        "latency": evaluate_latency(es, endpoints),
        "detection": evaluate_detection(es, endpoints),
        "consistency": evaluate_consistency(es, endpoints),
        "coverage": evaluate_coverage(es, endpoints),
        "operations": evaluate_operations(es, endpoints),
    }
    verdicts = {name: bool(body.get("ok")) for name, body in quality.items() if "ok" in body}
    component_ok = _components_ok(components)
    failed = [name for name, ok in {**component_ok, **verdicts}.items() if not ok]
    return {
        "tool": "sentinelbench",
        "version": __version__,
        "evaluated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "since": endpoints.since,
        "sample_size": endpoints.sample_size,
        "endpoints": {
            "elasticsearch": endpoints.elasticsearch,
            "kibana": endpoints.kibana,
            "skip_docker": endpoints.skip_docker,
        },
        "components": components,
        "quality": quality,
        "summary": {
            "ok": not failed,
            "failed": failed,
            "component_ok": component_ok,
            "quality_ok": verdicts,
        },
    }


def _components_ok(components: dict[str, Any]) -> dict[str, bool]:
    result: dict[str, bool] = {}
    es = components.get("elasticsearch") or {}
    result["elasticsearch"] = bool(es.get("reachable")) and es.get("status") != "red"
    kafka = components.get("kafka") or {}
    result["kafka"] = bool(kafka.get("reachable")) and not kafka.get("missing_topics")
    if kafka.get("reachable"):
        lags = [
            group.get("lag_total")
            for group in kafka.get("consumer_groups") or []
            if group.get("lag_total") is not None
        ]
        if any(isinstance(lag, int) and lag > 0 for lag in lags):
            # Lag is a soft failure for the component probe; quality still runs.
            result["kafka"] = True
    logstash = components.get("logstash") or {}
    services = logstash.get("services") or {}
    result["logstash"] = bool(services) and all(
        svc.get("reachable") and svc.get("status") in (None, "green", "yellow")
        for svc in services.values()
    )
    kibana = components.get("kibana") or {}
    result["kibana"] = bool(kibana.get("reachable")) and kibana.get("overall_level") in (
        "available",
        "degraded",
        None,
    )
    inference = components.get("inference") or {}
    result["inference"] = bool(inference.get("reachable")) and bool(
        (inference.get("status") or {}).get("healthy", inference.get("healthcheck_ok"))
    )
    notifications = components.get("notifications") or {}
    health = (notifications.get("health") or {}).get("status")
    result["notifications"] = bool(notifications.get("reachable")) and health in (
        "healthy",
        "degraded",
        None,
    )
    if notifications.get("reachable") and health is None and notifications.get("healthcheck_ok"):
        result["notifications"] = True
    return result
