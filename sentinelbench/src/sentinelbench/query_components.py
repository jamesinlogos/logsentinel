"""Per-component status probes used by ``sentinelbench query``."""

from __future__ import annotations

from typing import Any

from sentinelbench.clients.docker_exec import DockerExec
from sentinelbench.clients.elasticsearch import ElasticsearchClient
from sentinelbench.clients.http import HttpClient, HttpError
from sentinelbench.config import (
    CONSUMER_GROUPS,
    INDEX_DELIVERIES,
    INDEX_DETECTIONS,
    INDEX_NOTIFICATIONS,
    INDEX_TELEMETRY,
    INDEX_WINDOW_SCORES,
    INFERENCE_CONTAINER,
    KAFKA_BIN,
    LOGSTASH_CONTAINERS,
    NOTIFICATIONS_CONTAINER,
    TOPICS,
    StackEndpoints,
)


def query_elasticsearch(endpoints: StackEndpoints) -> dict[str, Any]:
    es = ElasticsearchClient(endpoints.elasticsearch, timeout_sec=endpoints.timeout_sec)
    try:
        health = es.cluster_health()
        info = es.ping()
    except HttpError as exc:
        return {"reachable": False, "error": str(exc)}
    counts = {
        "windows_telemetry": es.count(INDEX_TELEMETRY),
        "window_scores": es.count(INDEX_WINDOW_SCORES),
        "detections": es.count(INDEX_DETECTIONS),
        "notifications": es.count(INDEX_NOTIFICATIONS),
        "notification_deliveries": es.count(INDEX_DELIVERIES),
    }
    return {
        "reachable": True,
        "cluster_name": health.get("cluster_name"),
        "status": health.get("status"),
        "number_of_nodes": health.get("number_of_nodes"),
        "version": (info or {}).get("version", {}).get("number"),
        "document_counts": counts,
        "indices": es.cat_indices("windows-telemetry-*,ransomware-*"),
    }


def query_kibana(endpoints: StackEndpoints) -> dict[str, Any]:
    http = HttpClient(endpoints.kibana, timeout_sec=endpoints.timeout_sec)
    try:
        status = http.request("GET", "/api/status")
    except HttpError as exc:
        return {"reachable": False, "error": str(exc)}
    overall = (status or {}).get("status", {}).get("overall", {})
    level = overall.get("level") or overall.get("state")
    rule = _kibana_rule(http)
    return {
        "reachable": True,
        "overall_level": level,
        "alerting_rule": rule,
    }


def _kibana_rule(http: HttpClient) -> dict[str, Any]:
    """Locate the stack rule by saved-object id (``ransomware-detections``)."""
    rule_id = "ransomware-detections"
    try:
        rule = http.request(
            "GET",
            f"/api/alerting/rule/{rule_id}",
            headers={"kbn-xsrf": "true"},
        )
    except HttpError as exc:
        if exc.status == 404:
            return {"found": False, "id": rule_id}
        return {"error": str(exc), "id": rule_id}
    if not rule:
        return {"found": False, "id": rule_id}
    return {
        "found": True,
        "id": rule.get("id") or rule_id,
        "name": rule.get("name"),
        "enabled": rule.get("enabled"),
        "running": rule.get("execution_status", {}).get("status"),
        "last_execution": rule.get("execution_status", {}).get("last_execution_date"),
    }


def query_kafka(endpoints: StackEndpoints) -> dict[str, Any]:
    docker = DockerExec(enabled=not endpoints.skip_docker)
    container = endpoints.kafka_container
    bootstrap = endpoints.kafka_bootstrap
    topics_text = docker.exec(
        container,
        f"{KAFKA_BIN}/kafka-topics.sh",
        "--list",
        "--bootstrap-server",
        bootstrap,
    )
    if topics_text is None:
        return {"reachable": False, "error": "docker exec failed or kafka container down"}
    present = set(topics_text.split())
    groups = []
    for group in CONSUMER_GROUPS:
        text = docker.exec(
            container,
            f"{KAFKA_BIN}/kafka-consumer-groups.sh",
            "--bootstrap-server",
            bootstrap,
            "--describe",
            "--group",
            group,
        )
        groups.append({"group": group, **_parse_group_lag(text)})
    return {
        "reachable": True,
        "topics": {topic: topic in present for topic in TOPICS},
        "missing_topics": [topic for topic in TOPICS if topic not in present],
        "consumer_groups": groups,
    }


def _parse_group_lag(text: str | None) -> dict[str, Any]:
    if not text:
        return {"lag_total": None, "partitions": 0, "no_offset": 0, "rows": []}
    lag_total = 0
    partitions = 0
    no_offset = 0
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[2].isdigit():
            continue
        partitions += 1
        topic, partition = parts[1], int(parts[2])
        current, end = parts[3], parts[4]
        lag_raw = parts[5]
        if lag_raw.isdigit():
            lag = int(lag_raw)
            lag_total += lag
        else:
            lag = None
            no_offset += 1
        rows.append(
            {
                "topic": topic,
                "partition": partition,
                "current_offset": None
                if current == "-"
                else int(current)
                if current.isdigit()
                else current,
                "log_end_offset": None if end == "-" else int(end) if end.isdigit() else end,
                "lag": lag,
            }
        )
    return {"lag_total": lag_total, "partitions": partitions, "no_offset": no_offset, "rows": rows}


def query_logstash(endpoints: StackEndpoints) -> dict[str, Any]:
    docker = DockerExec(enabled=not endpoints.skip_docker)
    services: dict[str, Any] = {}
    for container in LOGSTASH_CONTAINERS:
        node = docker.exec_json(container, "curl", "-sf", "http://localhost:9600/")
        pipelines = docker.exec_json(
            container, "curl", "-sf", "http://localhost:9600/_node/stats/pipelines"
        )
        name = container.removeprefix("logsentinel-")
        if node is None:
            services[name] = {"reachable": False}
            continue
        pipe_summary = {}
        for pipe_name, stats in ((pipelines or {}).get("pipelines") or {}).items():
            events = stats.get("events") or {}
            queue = stats.get("queue") or {}
            pipe_summary[pipe_name] = {
                "events_in": events.get("in"),
                "events_out": events.get("out"),
                "events_filtered": events.get("filtered"),
                "queue_events": queue.get("events_count"),
                "queue_type": queue.get("type"),
            }
        services[name] = {
            "reachable": True,
            "status": node.get("status"),
            "version": node.get("version"),
            "pipelines": pipe_summary,
        }
    return {"services": services}


def query_inference(endpoints: StackEndpoints) -> dict[str, Any]:
    docker = DockerExec(enabled=not endpoints.skip_docker)
    healthy = docker.exec(INFERENCE_CONTAINER, "python", "-m", "inference.healthcheck")
    status = docker.exec_json(
        INFERENCE_CONTAINER, "python", "-m", "json.tool", "/tmp/inference.status.json"
    )
    return {
        "reachable": status is not None,
        "healthcheck_ok": healthy is not None,
        "status": status,
    }


def query_notifications(endpoints: StackEndpoints) -> dict[str, Any]:
    docker = DockerExec(enabled=not endpoints.skip_docker)
    healthy = docker.exec(NOTIFICATIONS_CONTAINER, "python", "-m", "notifications", "--healthcheck")
    health = docker.exec_json(
        NOTIFICATIONS_CONTAINER,
        "python",
        "-m",
        "json.tool",
        "/tmp/notifications-health.json",
    )
    return {
        "reachable": health is not None,
        "healthcheck_ok": healthy is not None,
        "health": health,
    }


COMPONENT_QUERIES = {
    "elasticsearch": query_elasticsearch,
    "kibana": query_kibana,
    "kafka": query_kafka,
    "logstash": query_logstash,
    "inference": query_inference,
    "notifications": query_notifications,
}
