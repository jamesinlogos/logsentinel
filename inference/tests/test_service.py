"""The Kafka loop around the pipeline, with real events and fake Kafka clients."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from confluent_kafka import KafkaError, KafkaException

from inference.config import ScoringConfig, ServiceConfig
from inference.events import MAX_MESSAGE_BYTES
from inference.healthcheck import main as healthcheck
from inference.pipeline import Emission, Pipeline
from inference.service import DeliveryError, KafkaMonitor, run_loop
from inference.windowing import format_timestamp
from tests.fakes import (
    Clock,
    FakeConsumer,
    FakeMessage,
    FakeProducer,
    as_host,
    emissions_of,
    fail_second_evaluation,
    messages,
    numbered,
    raw_lines,
    shifted,
)
from training.sentinelcap_dataset import Session

CONFIG = ServiceConfig()
CREATED_AT = 1_760_000_100.25
"""The wall clock of the tests that look at ``event.created``."""
EVERY_WINDOW = ServiceConfig(scoring=ScoringConfig(reemit_after_sec=0))
"""No suppression: every gated window is emitted, so tests compare windows, not policy."""


# Statistics as librdkafka 2.15 reports them (captured from a live and an unreachable broker).
STATS_BROKER_UP = {
    "brokers": {
        "192.168.110.1:9092/1": {"nodeid": 1, "state": "UP"},
        "GroupCoordinator": {"nodeid": -1, "state": "UP"},
    }
}
STATS_BROKER_DOWN = {
    "brokers": {
        "192.168.110.1:9092/1": {"nodeid": 1, "state": "DOWN"},
        "GroupCoordinator": {
            "nodeid": -1,
            "state": "UP",
        },  # internal: says nothing about the cluster
    }
}
STATS_UNREACHABLE_AT_STARTUP = {
    "brokers": {
        "127.0.0.1:1/bootstrap": {"nodeid": -1, "state": "CONNECT"},
        "GroupCoordinator": {"nodeid": -1, "state": "INIT"},
    }
}


def window_ids(payloads: Sequence[bytes]) -> set[str]:
    return {json.loads(payload)["logsentinel"]["window"]["id"] for payload in payloads}


def records(producer: FakeProducer, topic: str) -> list[dict[str, Any]]:
    """The documents the producer was given for ``topic``."""
    return [json.loads(value) for name, _, value in producer.produced if name == topic]


def run(
    stream: list[FakeMessage],
    producer: FakeProducer,
    tmp_path: Path,
    config: ServiceConfig = CONFIG,
    **loop: Any,
) -> tuple[FakeConsumer, Pipeline]:
    stop = threading.Event()
    consumer = FakeConsumer([stream], stop)
    pipeline = Pipeline(config, None, 0.75)
    run_loop(consumer, producer, pipeline, config, stop, status_path=tmp_path / "status", **loop)
    return consumer, pipeline


def test_run_loop_end_to_end(sessions: dict[str, Session], tmp_path: Path) -> None:
    session = sessions["conti/b14cde37"]
    lines = raw_lines(session)
    count = len(lines)
    stream = messages(lines) + [
        FakeMessage(b"not json", offset=count),
        FakeMessage(None, offset=count + 1),
        FakeMessage(error=KafkaError(KafkaError.UNKNOWN_TOPIC_OR_PART)),
        FakeMessage(error=KafkaError(KafkaError._PARTITION_EOF)),
    ]
    producer = FakeProducer()
    consumer, pipeline = run(stream, producer, tmp_path, wall_clock=lambda: CREATED_AT)

    stats = pipeline.stats
    assert (stats.consumed, stats.invalid, stats.consumer_errors) == (count + 2, 2, 1)
    assert stats.acked == stats.produced == len(producer.produced) > 0
    host_id = session.events[0].host_id
    kafka = CONFIG.kafka
    assert {topic for topic, _, _ in producer.produced} == {
        kafka.detections_topic,
        kafka.window_scores_topic,
    }
    assert all(key == host_id.encode() for _, key, _ in producer.produced)
    detections = records(producer, kafka.detections_topic)
    scores = records(producer, kafka.window_scores_topic)
    # Every scored window gives a window score; the reported ones also give a detection.
    assert len(scores) == stats.windows and len(detections) == stats.detections > 0
    assert stats.produced == len(scores) + len(detections)
    assert all(d["event"]["kind"] == "alert" for d in detections)
    assert all(s["event"]["kind"] == "metric" for s in scores)
    assert all(d["logsentinel"]["verdict"]["indicators"] for d in detections)
    assert all("features" in s["logsentinel"]["window"] for s in scores)
    assert all(d["event"]["created"] == format_timestamp(CREATED_AT) for d in detections + scores)
    by_id = {s["logsentinel"]["window"]["id"]: s for s in scores}
    assert len(by_id) == len(scores)
    for detection in detections:  # the same window, told twice
        score = by_id[detection["logsentinel"]["window"]["id"]]
        assert detection["logsentinel"]["verdict"] == score["logsentinel"]["verdict"]
        assert detection["host"] == score["host"] and detection["@timestamp"] == score["@timestamp"]
    assert sum(s["logsentinel"]["verdict"]["reported"] for s in scores) == len(detections)
    # Everything is acknowledged: the commit stops at the oldest event a window still holds.
    assert consumer.stored[0] == pipeline.windower.oldest_offsets()[0]
    assert producer.flushed and consumer.closed
    status = json.loads((tmp_path / "status").read_text(encoding="utf-8"))
    assert status["healthy"] is True and status["degraded"] == []
    # The status file is written once per loop step: the records of the final drain come after it.
    assert status["pending_outputs"] == 0 and status["acked"] <= stats.acked
    assert status["consumed"] == stats.consumed


def test_the_records_of_a_window_sent_twice_agree(
    sessions: dict[str, Session], tmp_path: Path
) -> None:
    """A quiet moment after every batch makes the idle flush close windows early, so some windows
    are sent again, completed. Elasticsearch keeps the last record of each id: the detection and
    the window score it ends up with must tell the same story."""
    lines = raw_lines(sessions["conti/b14cde37"])
    batches: list[list[FakeMessage]] = []
    for start in range(0, len(lines), 3):
        batches.append(messages(lines[start : start + 3], start=start))
        batches.append([])
    stop = threading.Event()
    producer = FakeProducer()
    consumer = FakeConsumer(batches, stop)
    pipeline = Pipeline(CONFIG, None, 0.75)
    run_loop(
        consumer,
        producer,
        pipeline,
        CONFIG,
        stop,
        status_path=tmp_path / "status",
        clock=Clock(step=11.0),
    )

    scores = records(producer, CONFIG.kafka.window_scores_topic)
    detections = records(producer, CONFIG.kafka.detections_topic)
    final_score = {s["logsentinel"]["window"]["id"]: s["logsentinel"] for s in scores}
    final_detection = {d["logsentinel"]["window"]["id"]: d["logsentinel"] for d in detections}
    assert len(final_score) < len(scores)  # some windows were sent more than once
    assert final_detection
    for window_id, detection in final_detection.items():
        score = final_score[window_id]
        assert score["verdict"]["reported"] is True
        assert detection["verdict"] == score["verdict"]
        assert detection["window"]["activity"] == score["window"]["activity"]
    reported = [s for s in final_score.values() if s["verdict"]["reported"]]
    assert len(reported) == len(final_detection)


def test_offsets_wait_for_acknowledgement(sessions: dict[str, Session], tmp_path: Path) -> None:
    lines = raw_lines(sessions["conti/b14cde37"])
    # A real event ten minutes later closes and evicts every window before it.
    stream = [*lines, shifted(lines[-1], 600)]
    needed = [e.offsets[0] for e in emissions_of(Pipeline(CONFIG, None, 0.75), numbered(stream))]
    assert needed and min(needed) < len(lines)

    seen: dict[str, dict[int, int]] = {}
    producer = FakeProducer("manual")
    stop = threading.Event()

    def at_call(call: int) -> None:
        if call == 2:  # the broker acknowledges between two loop iterations
            seen["before"] = dict(consumer.stored)
            producer.release()
        if call == 3:
            seen["after"] = dict(consumer.stored)

    consumer = FakeConsumer([messages(stream), []], stop, on_consume=at_call)
    pipeline = Pipeline(CONFIG, None, 0.75)
    run_loop(consumer, producer, pipeline, CONFIG, stop, status_path=tmp_path / "status")

    # Unacknowledged detections hold the commit back to the input they need ...
    assert seen["before"] == {0: min(needed)}
    # ... and once acknowledged only the event still buffered holds it.
    assert seen["after"] == {0: len(lines)}


def test_terminal_delivery_failure_stops_the_service(
    sessions: dict[str, Session], tmp_path: Path
) -> None:
    lines = raw_lines(sessions["conti/b14cde37"])
    needed = [e.offsets[0] for e in emissions_of(Pipeline(CONFIG, None, 0.75), numbered(lines))]
    producer = FakeProducer("manual", error=KafkaError(KafkaError._MSG_TIMED_OUT))
    stop = threading.Event()
    consumer = FakeConsumer(
        [messages(lines), []],
        stop,
        on_consume=lambda call: producer.release() if call == 2 else None,
    )
    pipeline = Pipeline(CONFIG, None, 0.75)
    with pytest.raises(DeliveryError, match="could not be delivered"):
        run_loop(consumer, producer, pipeline, CONFIG, stop, status_path=tmp_path / "status")
    assert consumer.closed and producer.flushed
    assert pipeline.stats.delivery_errors == len(producer.produced) > 0
    assert consumer.stored[0] <= min(needed)  # replayed after the restart


def test_shutdown_with_undelivered_records_fails(
    sessions: dict[str, Session], tmp_path: Path
) -> None:
    lines = raw_lines(sessions["conti/b14cde37"])
    needed = [e.offsets[0] for e in emissions_of(Pipeline(CONFIG, None, 0.75), numbered(lines))]
    producer = FakeProducer("never")
    stop = threading.Event()
    consumer = FakeConsumer([messages(lines)], stop)
    pipeline = Pipeline(CONFIG, None, 0.75)
    with pytest.raises(DeliveryError, match="not delivered before shutdown"):
        run_loop(consumer, producer, pipeline, CONFIG, stop, status_path=tmp_path / "status")
    assert consumer.closed and producer.flushed
    assert consumer.stored[0] <= min(needed)


def test_full_producer_queue_gives_up_at_the_deadline(
    sessions: dict[str, Session], tmp_path: Path
) -> None:
    lines = raw_lines(sessions["conti/b14cde37"])
    producer = FakeProducer(buffer_full=-1)
    stop = threading.Event()
    consumer = FakeConsumer([messages(lines)], stop)
    pipeline = Pipeline(CONFIG, None, 0.75)
    with pytest.raises(DeliveryError, match="queue stayed full"):
        run_loop(
            consumer,
            producer,
            pipeline,
            CONFIG,
            stop,
            status_path=tmp_path / "status",
            clock=Clock(step=3.0),
        )
    assert producer.polls > 0  # delivery reports were served while waiting
    assert consumer.closed


def test_unusable_messages_are_skipped(
    sessions: dict[str, Session], single_events: dict[str, Any], tmp_path: Path
) -> None:
    lines = raw_lines(sessions["conti/b14cde37"])
    event = json.dumps(single_events["network_connection"])
    queue = json.loads(json.dumps(single_events["sysmon_queue_drop"]))
    queue["winlog"]["event_data"]["Description"] = "RegistryEvent:" + "9" * 4301
    bad = [
        b"not json",
        (event[:-1] + ', "big": ' + "9" * 4301 + "}").encode(),  # integer over Python's limit
        ('{"host":{"id":"h"},"x":' + "[" * 20_000 + "]" * 20_000 + "}").encode(),  # nesting
        json.dumps(queue).encode(),  # implausible Sysmon queue count
        b'{"a":"' + b"x" * (MAX_MESSAGE_BYTES + 1) + b'"}',  # oversized
    ]
    stream = messages([lines[0], *bad, *lines[1:]])
    consumer, pipeline = run(stream, FakeProducer(), tmp_path)
    assert pipeline.stats.invalid == len(bad)
    assert pipeline.stats.consumed == len(stream)
    # Every message was processed, so the loop never stalled on a bad one.
    assert consumer.stored[0] == pipeline.windower.oldest_offsets()[0]


@pytest.mark.parametrize("eighths", range(1, 8))
@pytest.mark.parametrize("ack_mode", ["immediate", "never"])
@pytest.mark.parametrize("failure", ["crash", "stop"])
def test_replay_after_a_restart_loses_no_record(
    sessions: dict[str, Session], tmp_path: Path, failure: str, ack_mode: str, eighths: int
) -> None:
    """Restart from the committed offset: records of the first run that were never delivered,
    and the windows that were open, come back on both topics (same window ids). Scheduled and
    early windows alike, whichever part of the session the crash falls in."""
    kafka = EVERY_WINDOW.kafka
    stream = messages(raw_lines(sessions["blackbasta/11129aad"]))
    reference_producer = FakeProducer()
    run(list(stream), reference_producer, tmp_path, EVERY_WINDOW)
    reference = {
        topic: window_ids(reference_producer.delivered_on(topic))
        for topic in (kafka.detections_topic, kafka.window_scores_topic)
    }
    assert all(reference.values())
    assert reference[kafka.detections_topic] <= reference[kafka.window_scores_topic]

    cut = len(stream) * eighths // 8
    stop = threading.Event()
    first = FakeConsumer(
        [stream[: cut // 2], stream[cut // 2 : cut]],
        stop,
        crash_after=2 if failure == "crash" else None,
    )
    first_producer = FakeProducer(ack_mode)
    try:
        run_loop(
            first,
            first_producer,
            Pipeline(EVERY_WINDOW, None, 0.75),
            EVERY_WINDOW,
            stop,
            status_path=tmp_path / "status",
        )
    except (RuntimeError, DeliveryError):
        pass  # the crash, or a stop whose detections were never acknowledged
    committed = first.stored.get(0, 0)
    assert committed <= cut

    second_producer = FakeProducer()
    run([m for m in stream if m.offset() >= committed], second_producer, tmp_path, EVERY_WINDOW)
    for topic, expected in reference.items():
        delivered = window_ids(first_producer.delivered_on(topic)) | window_ids(
            second_producer.delivered_on(topic)
        )
        assert expected <= delivered, topic


def three_hosts(sessions: dict[str, Session]) -> list[FakeMessage]:
    """Three hosts, each on its own partition (the sink keys by host), interleaved in chunks."""
    names = ("conti/b14cde37", "akira/c974d8c6", "blackbasta/11129aad")
    per_partition = [
        messages(
            [as_host(line, f"host-{partition}") for line in raw_lines(sessions[name])],
            partition=partition,
        )
        for partition, name in enumerate(names)
    ]
    chunk = 40
    stream: list[FakeMessage] = []
    for start in range(0, max(len(batch) for batch in per_partition), chunk):
        for batch in per_partition:
            stream.extend(batch[start : start + chunk])
    return stream


def test_each_partition_keeps_its_own_commit(sessions: dict[str, Session], tmp_path: Path) -> None:
    producer = FakeProducer()
    consumer, pipeline = run(three_hosts(sessions), producer, tmp_path)
    scores = records(producer, CONFIG.kafka.window_scores_topic)
    assert {score["host"]["id"] for score in scores} == {"host-0", "host-1", "host-2"}
    assert pipeline.stats.acked == pipeline.stats.produced > 0
    # Everything is acknowledged: each partition commits up to its oldest event still in a window.
    assert set(consumer.stored) == {0, 1, 2}
    assert consumer.stored == pipeline.windower.oldest_offsets()


@pytest.mark.parametrize("ack_mode", ["immediate", "never"])
def test_replay_after_a_restart_loses_no_record_on_three_partitions(
    sessions: dict[str, Session], tmp_path: Path, ack_mode: str
) -> None:
    """The restart reads every partition from its own committed offset."""
    kafka = EVERY_WINDOW.kafka
    stream = three_hosts(sessions)
    reference_producer = FakeProducer()
    run(list(stream), reference_producer, tmp_path, EVERY_WINDOW)
    reference = {
        topic: window_ids(reference_producer.delivered_on(topic))
        for topic in (kafka.detections_topic, kafka.window_scores_topic)
    }
    assert all(reference.values())

    cut = len(stream) * 3 // 4
    stop = threading.Event()
    first = FakeConsumer(
        [stream[: cut // 2], stream[cut // 2 : cut]],
        stop,
        crash_after=2,
    )
    first_producer = FakeProducer(ack_mode)
    try:
        run_loop(
            first,
            first_producer,
            Pipeline(EVERY_WINDOW, None, 0.75),
            EVERY_WINDOW,
            stop,
            status_path=tmp_path / "status",
        )
    except (RuntimeError, DeliveryError):
        pass  # the crash
    committed = {partition: first.stored.get(partition, 0) for partition in (0, 1, 2)}
    if ack_mode == "immediate":
        assert any(committed.values())  # the commit moved, so the restart really skips input

    second_producer = FakeProducer()
    rest = [message for message in stream if message.offset() >= committed[message.partition()]]
    run(rest, second_producer, tmp_path, EVERY_WINDOW)
    for topic, expected in reference.items():
        delivered = window_ids(first_producer.delivered_on(topic)) | window_ids(
            second_producer.delivered_on(topic)
        )
        assert expected <= delivered, topic


class StoreFailsConsumer(FakeConsumer):
    """A partition was revoked meanwhile: storing the offsets raises."""

    def store_offsets(self, message: Any = None, offsets: Sequence[Any] | None = None) -> None:
        raise KafkaException(KafkaError(KafkaError._STATE))


def test_a_failed_offset_store_does_not_stop_the_loop(
    sessions: dict[str, Session], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    stop = threading.Event()
    consumer = StoreFailsConsumer([messages(raw_lines(sessions["conti/b14cde37"]))], stop)
    producer = FakeProducer()
    pipeline = Pipeline(CONFIG, None, 0.75)
    with caplog.at_level(logging.WARNING, logger="inference.service"):
        run_loop(consumer, producer, pipeline, CONFIG, stop, status_path=tmp_path / "status")
    assert pipeline.stats.acked == pipeline.stats.produced > 0
    assert consumer.closed and producer.flushed
    assert consumer.stored == {}  # nothing was stored, so the next start replays from the commit
    stores = [r for r in caplog.records if "Could not store offsets" in r.getMessage()]
    assert len(stores) == 1  # logged once, not on every loop step


def test_status_follows_the_broker_and_the_healthcheck(
    sessions: dict[str, Session], tmp_path: Path
) -> None:
    status_path = tmp_path / "status"
    clock = Clock()
    down = KafkaMonitor(clock)
    down.on_stats(json.dumps(STATS_BROKER_DOWN))
    stop = threading.Event()
    consumer = FakeConsumer(
        [[]], stop, on_consume=lambda call: setattr(clock, "now", clock.now + 100.0)
    )
    run_loop(
        consumer,
        FakeProducer(),
        Pipeline(CONFIG, None, 0.75),
        CONFIG,
        stop,
        status_path=status_path,
        clock=clock,
        monitor=down,
    )
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status["healthy"] is False
    assert status["degraded"] == ["kafka_unreachable"]
    assert status["kafka_down_for_sec"] >= CONFIG.kafka.down_after_sec
    assert healthcheck([str(status_path)]) == 1

    up = KafkaMonitor(clock)
    up.on_stats(json.dumps(STATS_BROKER_UP))
    stop = threading.Event()
    run_loop(
        FakeConsumer([[]], stop),
        FakeProducer(),
        Pipeline(CONFIG, None, 0.75),
        CONFIG,
        stop,
        status_path=status_path,
        monitor=up,
    )
    assert json.loads(status_path.read_text(encoding="utf-8"))["healthy"] is True
    assert healthcheck([str(status_path)]) == 0


def test_fatal_kafka_error_stops_after_flushing(tmp_path: Path) -> None:
    stop = threading.Event()
    fatal = FakeMessage(error=KafkaError(KafkaError._FATAL, fatal=True))
    consumer = FakeConsumer([[fatal]], stop)
    producer = FakeProducer()
    with pytest.raises(KafkaException):
        run_loop(
            consumer,
            producer,
            Pipeline(CONFIG, None, 0.75),
            CONFIG,
            stop,
            status_path=tmp_path / "status",
        )
    assert producer.flushed and consumer.closed


def test_the_loop_keeps_going_when_a_window_cannot_be_scored(
    sessions: dict[str, Session], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lines = raw_lines(sessions["conti/b14cde37"])
    fail_second_evaluation(monkeypatch)
    producer = FakeProducer()
    consumer, pipeline = run(messages(lines), producer, tmp_path)
    stats = pipeline.stats
    assert stats.internal_errors == 1
    assert stats.acked == stats.produced > 0
    assert producer.flushed and consumer.closed
    # The commit never stalled on the window that failed.
    assert consumer.stored[0] == pipeline.windower.oldest_offsets()[0]
    status = json.loads((tmp_path / "status").read_text(encoding="utf-8"))
    assert status["internal_errors"] == 1


def test_shutdown_still_closes_everything_when_the_final_windows_cannot_be_emitted(
    sessions: dict[str, Session], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: Pipeline) -> list[Emission]:
        raise RuntimeError("drain failed")

    monkeypatch.setattr(Pipeline, "drain", broken)
    producer = FakeProducer()
    stop = threading.Event()
    consumer = FakeConsumer([messages(raw_lines(sessions["conti/b14cde37"]))], stop)
    pipeline = Pipeline(CONFIG, None, 0.75)
    with pytest.raises(DeliveryError, match="RuntimeError: drain failed"):
        run_loop(consumer, producer, pipeline, CONFIG, stop, status_path=tmp_path / "status")
    assert producer.flushed and consumer.closed


def test_kafka_monitor_reads_the_real_statistics_shapes() -> None:
    clock = Clock()
    monitor = KafkaMonitor(clock)
    monitor.on_stats(json.dumps(STATS_BROKER_UP))
    assert monitor.down_for(clock.now) == 0.0
    clock.now += 30
    monitor.on_stats(json.dumps(STATS_BROKER_DOWN))
    assert monitor.down_for(clock.now) == 0.0 + 30  # down since the last time a broker was UP
    clock.now += 10
    assert monitor.down_for(clock.now) == 40
    monitor.on_stats(json.dumps(STATS_BROKER_UP))
    assert monitor.down_for(clock.now) == 0.0
    monitor.on_stats("not json")  # ignored
    monitor.on_stats(json.dumps({"brokers": {}}))
    assert monitor.down_for(clock.now) == 0.0


def test_a_broker_that_was_never_reachable_is_down() -> None:
    clock = Clock()
    monitor = KafkaMonitor(clock)
    monitor.on_stats(json.dumps(STATS_UNREACHABLE_AT_STARTUP))
    clock.now += 90
    assert monitor.down_for(clock.now) == 90
