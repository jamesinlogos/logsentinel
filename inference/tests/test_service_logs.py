"""What the service logs: statistics, detections, anomalies and the contract of the JSON stream."""

from __future__ import annotations

import io
import json
import logging
import os
import signal
import threading
from pathlib import Path
from typing import Any

import pytest
from confluent_kafka import KafkaError

from inference import service
from inference.config import CONFIG_ENV, ENV_PREFIX, ServiceConfig
from inference.logs import (
    ECS_ATTR,
    FORMAT_ENV,
    LEVEL_ENV,
    LogSettings,
    configure_logging,
)
from inference.model import read_meta
from inference.pipeline import Pipeline
from inference.service import DeliveryError, KafkaMonitor, run_loop
from tests.fakes import Clock, FakeConsumer, FakeMessage, FakeProducer, messages, raw_lines
from training.sentinelcap_dataset import Session

CONFIG = ServiceConfig()
SHIPPED = Path(__file__).resolve().parents[1] / "artifacts"
"""The complete artifact set that docker-compose.yml mounts: ``main()`` starts with it."""
BROKER_UP = json.dumps({"brokers": {"kafka:9092/1": {"nodeid": 1, "state": "UP"}}})
BROKER_DOWN = json.dumps({"brokers": {"kafka:9092/1": {"nodeid": 1, "state": "DOWN"}}})
STATUS_ONLY = {
    "updated_at",
    "healthy",
    "degraded",
    "kafka_down_for_sec",
    "model_version",
    "threshold",
}
REQUIRED = {
    "@timestamp",
    "log.level",
    "log.logger",
    "message",
    "service.name",
    "service.version",
    "event.module",
    "event.dataset",
    "ecs.version",
}
ROOTS = {"@timestamp", "log", "message", "service", "event", "ecs", "error", "logsentinel"}
"""ECS fields and the vendor namespace only: no other top-level name (AGENTS.md section 11.9)."""


def fields_of(record: logging.LogRecord) -> dict[str, Any]:
    return getattr(record, ECS_ATTR, {})


def with_action(caplog: pytest.LogCaptureFixture, action: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if fields_of(r).get("event.action") == action]


def run_session(
    session: Session, tmp_path: Path, producer: FakeProducer | None = None
) -> tuple[FakeProducer, Pipeline]:
    producer = producer or FakeProducer()
    stop = threading.Event()
    consumer = FakeConsumer([messages(raw_lines(session))], stop)
    pipeline = Pipeline(CONFIG, None, 0.75)
    run_loop(consumer, producer, pipeline, CONFIG, stop, status_path=tmp_path / "status")
    return producer, pipeline


def test_the_statistics_record_uses_the_vocabulary_of_the_status_file(
    sessions: dict[str, Session], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    _, pipeline = run_session(sessions["conti/b14cde37"], tmp_path)
    records = with_action(caplog, "stats")
    assert len(records) == 1  # the one at shutdown: stats_interval_sec never passed
    fields = fields_of(records[0])
    counters = {
        k.removeprefix("logsentinel.stats."): v
        for k, v in fields.items()
        if k.startswith("logsentinel.stats.")
    }
    assert counters.pop("uptime_sec") >= 0 and fields["logsentinel.kafka.down_sec"] == 0
    status = json.loads((tmp_path / "status").read_text(encoding="utf-8"))
    assert set(counters) == set(status) - STATUS_ONLY
    assert counters["consumed"] == pipeline.stats.consumed == status["consumed"]
    assert counters["acked"] == pipeline.stats.acked > 0
    assert records[0].getMessage() == " ".join(f"{k}={v}" for k, v in counters.items())


def test_statistics_are_logged_every_interval_and_at_shutdown(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    stop = threading.Event()
    consumer = FakeConsumer([[], [], []], stop)
    run_loop(
        consumer,
        FakeProducer(),
        Pipeline(CONFIG, None, 0.75),
        CONFIG,
        stop,
        status_path=tmp_path / "status",
        clock=Clock(step=61.0),
    )
    stats = with_action(caplog, "stats")
    uptimes = [fields_of(r)["logsentinel.stats.uptime_sec"] for r in stats]
    assert len(uptimes) >= 2 and uptimes == sorted(uptimes) and uptimes[0] > 0


def test_each_delivered_detection_is_logged_with_the_fields_of_its_document(
    sessions: dict[str, Session], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    producer, _ = run_session(sessions["blackbasta/11129aad"], tmp_path)
    topic = CONFIG.kafka.detections_topic
    docs = [json.loads(value) for name, _, value in producer.produced if name == topic]
    records = with_action(caplog, "detection")
    assert docs and len(records) == len(docs)  # a window score is not logged when delivered
    assert not with_action(caplog, "window_score")
    by_id = {fields_of(r)["logsentinel.window.id"]: r for r in records}
    for doc in docs:
        vendor = doc["logsentinel"]
        record = by_id[vendor["window"]["id"]]
        fields = fields_of(record)
        assert record.levelno == logging.INFO and fields["event.outcome"] == "success"
        for name in ("label", "confidence_score", "threshold", "indicators"):
            assert fields[f"logsentinel.verdict.{name}"] == vendor["verdict"][name]
        assert fields["logsentinel.model.version"] == vendor.get("model", {}).get("version")
        assert (fields["event.start"], fields["event.end"]) == (
            doc["event"]["start"],
            doc["event"]["end"],
        )
        assert fields["logsentinel.monitored_host.id"] == doc["host"]["id"]
        assert vendor["verdict"]["indicators"][0] in record.getMessage()


def test_a_failed_delivery_is_an_error_record_with_the_window_id(
    sessions: dict[str, Session], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    lines = raw_lines(sessions["conti/b14cde37"])
    producer = FakeProducer("manual", error=KafkaError(KafkaError._MSG_TIMED_OUT))
    stop = threading.Event()
    consumer = FakeConsumer(
        [messages(lines), []],
        stop,
        on_consume=lambda call: producer.release() if call == 2 else None,
    )
    with pytest.raises(DeliveryError):
        run_loop(
            consumer,
            producer,
            Pipeline(CONFIG, None, 0.75),
            CONFIG,
            stop,
            status_path=tmp_path / "status",
        )
    for topic, action in (
        (CONFIG.kafka.detections_topic, "detection"),
        (CONFIG.kafka.window_scores_topic, "window_score"),
    ):
        sent = {
            json.loads(value)["logsentinel"]["window"]["id"]
            for name, _, value in producer.produced
            if name == topic
        }
        records = with_action(caplog, action)
        assert sent and {fields_of(r)["logsentinel.window.id"] for r in records} == sent
        for record in records:
            assert record.levelno == logging.ERROR
            assert fields_of(record)["event.outcome"] == "failure"
            assert "error.message" in fields_of(record)


def test_debug_traces_every_scored_window(
    sessions: dict[str, Session], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    pipeline = Pipeline(CONFIG, None, 0.75)
    for offset, event in enumerate(sessions["blackbasta/11129aad"].events):
        pipeline.process(event, float(offset))
    pipeline.drain()
    traced = [fields_of(r) for r in caplog.records if "logsentinel.window.id" in fields_of(r)]
    assert len(traced) == pipeline.stats.windows > 0
    assert sum(f["logsentinel.verdict.gated"] for f in traced) == pipeline.stats.gated
    assert sum(f["logsentinel.verdict.reported"] for f in traced) == pipeline.stats.detections
    assert all(f["logsentinel.window.activity.events"] > 0 for f in traced)
    suppressed = [r for r in caplog.records if "suppressed" in r.getMessage()]
    assert len(suppressed) == pipeline.stats.suppressed > 0


def test_nothing_is_traced_at_info(
    sessions: dict[str, Session], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    pipeline = Pipeline(CONFIG, None, 0.75)
    for offset, event in enumerate(sessions["blackbasta/11129aad"].events):
        pipeline.process(event, float(offset))
    pipeline.drain()
    assert pipeline.stats.windows > 0 and not caplog.records


def test_a_broker_leaving_and_coming_back_is_logged_once_each(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    clock = Clock()
    monitor = KafkaMonitor(clock)
    monitor.on_stats(BROKER_UP)
    monitor.on_stats(BROKER_UP)
    assert not caplog.records
    clock.now += 5
    monitor.on_stats(BROKER_DOWN)
    monitor.on_stats(BROKER_DOWN)
    clock.now += 25
    monitor.on_stats(BROKER_UP)
    monitor.on_stats(BROKER_UP)
    records = with_action(caplog, "kafka_connection")
    assert [r.levelno for r in records] == [logging.WARNING, logging.INFO]
    assert fields_of(records[0])["logsentinel.kafka.up"] is False
    assert fields_of(records[1])["logsentinel.kafka.up"] is True
    assert fields_of(records[1])["logsentinel.kafka.down_sec"] == 30.0
    assert "30 s" in records[1].getMessage()


def test_a_hostile_timestamp_is_not_echoed_whole(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    hostile = {"@timestamp": "x" * 100_000, "host": {"id": "h"}, "event": {"code": "1"}}
    stop = threading.Event()
    consumer = FakeConsumer([[FakeMessage(json.dumps(hostile).encode())]], stop)
    run_loop(
        consumer,
        FakeProducer(),
        Pipeline(CONFIG, None, 0.75),
        CONFIG,
        stop,
        status_path=tmp_path / "status",
    )
    warning = next(r for r in caplog.records if "unusable" in r.getMessage())
    assert "@timestamp is not ISO 8601" in warning.getMessage()
    assert len(warning.getMessage()) < 300


def test_every_line_of_a_run_is_a_valid_ecs_record(
    sessions: dict[str, Session], tmp_path: Path, clean_logging: None
) -> None:
    stream = io.StringIO()
    configure_logging(LogSettings(logging.DEBUG, "json"), stream)
    run_session(sessions["blackbasta/11129aad"], tmp_path)
    docs = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert docs and all(REQUIRED <= doc.keys() for doc in docs)
    assert {"stats", "detection"} <= {doc.get("event.action") for doc in docs}
    assert {key.split(".")[0] for doc in docs for key in doc} <= ROOTS
    assert {doc["event.module"] for doc in docs} == {"logsentinel"}
    assert {doc["event.dataset"] for doc in docs} == {"logsentinel.inference"}


@pytest.fixture
def isolated_main(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, clean_logging: None) -> None:
    """The environment of ``service.main()``: its own config file, JSON logs, no signal handlers."""
    config = tmp_path / "config.yaml"
    config.write_text(f"artifacts_dir: {json.dumps(str(SHIPPED))}\n", encoding="utf-8")
    for name in [n for n in os.environ if n.startswith(ENV_PREFIX)]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(CONFIG_ENV, str(config))
    monkeypatch.setenv(FORMAT_ENV, "json")
    monkeypatch.setattr(signal, "signal", lambda *args: None)

    def no_loop(*args: Any, **kwargs: Any) -> None:
        # A setting that the test failed to isolate would start the real service; fail instead.
        raise AssertionError("main() reached the service loop")

    monkeypatch.setattr(service, "run_loop", no_loop)


def test_a_bad_log_setting_stops_the_service_with_exit_code_2(
    isolated_main: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(LEVEL_ENV, "LOUD")
    assert service.main() == 2
    out = capsys.readouterr().out
    assert "Invalid logging configuration" in out and LEVEL_ENV in out


def test_an_unexpected_error_is_one_critical_record_and_exit_code_1(
    isolated_main: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(service, "Consumer", broken)
    assert service.main() == 1
    docs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert all(REQUIRED <= doc.keys() for doc in docs)  # nothing but ECS records on stdout
    startup = next(d for d in docs if d.get("event.action") == "startup")
    assert startup["logsentinel.model.version"] == read_meta(SHIPPED)["version"]
    assert startup["logsentinel.threshold_source"] == "calibrated"
    assert "logsentinel.degraded" not in startup
    assert startup["logsentinel.kafka.input_topic"] == CONFIG.kafka.input_topic
    assert startup["logsentinel.kafka.detections_topic"] == CONFIG.kafka.detections_topic
    assert startup["logsentinel.kafka.window_scores_topic"] == CONFIG.kafka.window_scores_topic
    last = docs[-1]
    assert last["log.level"] == "critical" and last["error.type"] == "RuntimeError"
    assert "boom" in last["error.stack_trace"] and "\n" not in json.dumps(last)


def test_a_service_without_a_complete_model_stops_with_exit_code_2(
    isolated_main: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}__ARTIFACTS_DIR", str(tmp_path / "no-artifacts"))
    assert service.main() == 2
    docs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert docs[-1]["log.level"] == "error" and "Cannot start" in docs[-1]["message"]
    assert "no trained model" in docs[-1]["message"]
    assert not [d for d in docs if d.get("event.action") == "startup"]


def test_a_threshold_chosen_for_other_settings_stops_the_service_with_exit_code_2(
    isolated_main: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}__SCORING__WEIGHT_GLOBAL_MODEL", "0.6")
    assert service.main() == 2
    last = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert "scoring.weight_global_model" in last["message"]


def test_librdkafka_logs_are_forwarded_to_the_service_logger(
    isolated_main: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    created: list[dict[str, Any]] = []

    class FakeClient:
        def __init__(self, conf: dict[str, Any], **kwargs: Any) -> None:
            created.append(kwargs)

        def subscribe(self, topics: list[str]) -> None:
            pass

    monkeypatch.setattr(service, "Consumer", FakeClient)
    monkeypatch.setattr(service, "Producer", FakeClient)
    monkeypatch.setattr(service, "run_loop", lambda *args, **kwargs: None)
    assert service.main() == 0
    assert created == [{"logger": service.kafka_logger}] * 2
    assert service.kafka_logger.name == "inference.librdkafka"
    last = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert (last["event.action"], last["event.outcome"]) == ("shutdown", "success")
