"""Defaults and stack endpoint settings for SentinelBench."""

from __future__ import annotations

from dataclasses import dataclass, field

SCHEMA_VERSION = 2
ECS_MODULE = "logsentinel"

INDEX_TELEMETRY = "windows-telemetry-*"
INDEX_DETECTIONS = "ransomware-detections-*"
INDEX_WINDOW_SCORES = "ransomware-window-scores-*"
INDEX_NOTIFICATIONS = "ransomware-notifications-*"
INDEX_DELIVERIES = "ransomware-notification-deliveries-*"

TOPICS = (
    "telemetry.windows.sysmon.raw",
    "telemetry.windows.normalized",
    "security.ransomware.detections",
    "security.ransomware.window-scores",
)

CONSUMER_GROUPS = (
    "logstash-ingest",
    "inference",
    "logstash-detection-sink",
    "logstash-detection-sink-window-scores",
)

KAFKA_CONTAINER = "logsentinel-kafka"
KAFKA_BIN = "/opt/kafka/bin"
KAFKA_INTERNAL_BOOTSTRAP = "localhost:29092"

LOGSTASH_CONTAINERS = (
    "logsentinel-logstash-ingest",
    "logsentinel-logstash-detection-sink",
)
INFERENCE_CONTAINER = "logsentinel-inference"
NOTIFICATIONS_CONTAINER = "logsentinel-notifications"

DETECTION_REQUIRED = (
    ("@timestamp",),
    ("ecs", "version"),
    ("event", "kind"),
    ("event", "module"),
    ("event", "dataset"),
    ("event", "end"),
    ("event", "created"),
    ("event", "ingested"),
    ("logsentinel", "schema_version"),
    ("logsentinel", "window", "id"),
    ("logsentinel", "verdict", "reported"),
    ("logsentinel", "verdict", "gated"),
)

WINDOW_SCORE_REQUIRED = DETECTION_REQUIRED + (("logsentinel", "window", "features"),)

NOTIFICATION_REQUIRED = (
    ("@timestamp",),
    ("event", "id"),
    ("event", "created"),
    ("event", "dataset"),
    ("message",),
    ("logsentinel", "schema_version"),
)

DELIVERY_REQUIRED = (
    ("@timestamp",),
    ("event", "id"),
    ("logsentinel", "schema_version"),
    ("logsentinel", "notification", "id"),
    ("logsentinel", "notification", "channel"),
    ("logsentinel", "notification", "sent"),
)

CHANNELS = ("telegram", "gmail")


@dataclass(frozen=True)
class StackEndpoints:
    """HTTP and Docker targets used to query the running lab stack."""

    elasticsearch: str = "http://localhost:9200"
    kibana: str = "http://localhost:5601"
    kafka_container: str = KAFKA_CONTAINER
    kafka_bootstrap: str = KAFKA_INTERNAL_BOOTSTRAP
    since: str = "24h"
    sample_size: int = 200
    timeout_sec: float = 60.0
    skip_docker: bool = False
    extra: dict[str, str] = field(default_factory=dict)
