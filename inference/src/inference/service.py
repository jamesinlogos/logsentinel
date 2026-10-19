"""Kafka service loop (inference/README.md sections 2 and 9.2).

``run_loop`` moves messages between Kafka and the pipeline (``pipeline.py``), at least once
(``offsets.py`` explains the commit rule):

* every scored window gives a window score record and, when it was reported, a
  detection record too; an input offset is committed only when no window buffer
  needs it and every record built from its window was acknowledged, so a restart
  re-reads the open windows and unacknowledged records are produced again with the
  same ``logsentinel.window.id``;
* a record that cannot be delivered (``delivery_timeout_sec`` passed, or the
  producer queue stayed full for ``produce_timeout_sec``) stops the service with
  ``DeliveryError``; Docker restarts it and the replay produces the record;
* on SIGTERM the pending windows are emitted and the producer flushed within
  ``shutdown_timeout_sec``; whatever is still not acknowledged makes the exit fail.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
from collections.abc import Callable, Sequence
from functools import partial
from pathlib import Path
from types import FrameType
from typing import Any, Protocol

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer, TopicPartition

from inference import __version__
from inference.artifacts import load_artifacts, resolve_threshold
from inference.config import STATUS_PATH, ServiceConfig, load_config
from inference.documents import Kind, document, encode
from inference.events import InvalidEventError, decode, parse_event
from inference.logs import Action, LogSettings, Throttle, configure_logging, ecs
from inference.model import ArtifactError
from inference.offsets import OffsetTracker
from inference.pipeline import Emission, Pipeline
from inference.scoring import WindowScore
from inference.status import write_status
from inference.windowing import format_timestamp

logger = logging.getLogger(__name__)
kafka_logger = logging.getLogger("inference.librdkafka")
"""Where confluent-kafka forwards the log lines of librdkafka (served on poll)."""

POLL_TIMEOUT_SEC = 1.0
PRODUCE_RETRY_WAIT_SEC = 0.5
STATS_CALLBACK_INTERVAL_MS = 5000


class DeliveryError(RuntimeError):
    """An output record could not be handed to Kafka; the service stops and replays on restart."""


class ConsumerLike(Protocol):
    def consume(self, num_messages: int, timeout: float) -> Sequence[Any]: ...

    def store_offsets(
        self, message: Any = None, offsets: list[TopicPartition] | None = None
    ) -> None: ...

    def close(self) -> None: ...


class ProducerLike(Protocol):
    def produce(
        self,
        topic: str,
        *,
        value: bytes,
        key: bytes,
        on_delivery: Callable[[Any, Any], None],
    ) -> None: ...

    def poll(self, timeout: float) -> int: ...

    def flush(self, timeout: float) -> int: ...


class KafkaMonitor:
    """Whether any broker is reachable, from librdkafka's statistics callback."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._last_up = clock()
        self.up = True

    def on_stats(self, raw: str) -> None:
        """Up when a broker connection (the bootstrap one, until the cluster is known) is UP.

        librdkafka lists, next to the brokers, the internal ``GroupCoordinator``
        entry, which says nothing about the cluster and is ignored.
        """
        try:
            brokers = json.loads(raw).get("brokers", {})
        except (ValueError, AttributeError):
            return
        states = [
            b.get("state")
            for name, b in brokers.items()
            if isinstance(b, dict) and "Coordinator" not in name
        ]
        if not states:
            return
        was_up = self.up
        self.up = "UP" in states
        now = self._clock()
        if self.up:
            if not was_up:
                down_for = now - self._last_up
                logger.info(
                    "Kafka is reachable again after %.0f s",
                    down_for,
                    extra=ecs(
                        {
                            "event.action": Action.KAFKA_CONNECTION,
                            "logsentinel.kafka.up": True,
                            "logsentinel.kafka.down_sec": round(down_for, 1),
                        }
                    ),
                )
            self._last_up = now
        elif was_up:
            logger.warning(
                "No Kafka broker is reachable",
                extra=ecs({"event.action": Action.KAFKA_CONNECTION, "logsentinel.kafka.up": False}),
            )

    def down_for(self, now: float) -> float:
        return 0.0 if self.up else now - self._last_up


class ServiceLoop:
    def __init__(
        self,
        consumer: ConsumerLike,
        producer: ProducerLike,
        pipeline: Pipeline,
        config: ServiceConfig,
        stop: threading.Event,
        *,
        status_path: Path,
        clock: Callable[[], float],
        wall_clock: Callable[[], float],
        batch_size: int,
        monitor: KafkaMonitor,
    ) -> None:
        self.consumer = consumer
        self.producer = producer
        self.pipeline = pipeline
        self.config = config
        self.stop = stop
        self.status_path = status_path
        self.clock = clock
        self.wall_clock = wall_clock
        self.batch_size = batch_size
        self.monitor = monitor
        self.stats = pipeline.stats
        self.tracker = OffsetTracker()
        self._failures: list[str] = []
        self._throttle = Throttle(config.stats_interval_sec)
        self._started = clock()
        self._next_stats = self._started + config.stats_interval_sec

    def run(self) -> None:
        try:
            while not self.stop.is_set():
                self._step()
        except BaseException:
            self._shutdown(drain=False)
            raise
        self._shutdown(drain=True)

    def _step(self) -> None:
        messages = self.consumer.consume(num_messages=self.batch_size, timeout=POLL_TIMEOUT_SEC)
        now = self.clock()
        for message in messages:
            error = message.error()
            if error is not None:
                self._handle_error(error, now)
            else:
                self._handle_message(message, now)
        self._send(self.pipeline.tick(now))
        self.producer.poll(0)
        self._raise_if_failed()
        self._store_offsets(now)
        self._write_status(now)
        if now >= self._next_stats:
            self._log_stats(now)
            self._next_stats = now + self.config.stats_interval_sec

    def _handle_message(self, message: Any, now: float) -> None:
        self.stats.consumed += 1
        partition, offset = message.partition(), message.offset()
        try:
            event = parse_event(decode(message.value() or b""), partition, offset)
        except InvalidEventError as exc:
            self.stats.invalid += 1
            if self._throttle.ready("invalid", now):
                logger.warning(
                    "Skipped unusable messages (%d so far): %.200s", self.stats.invalid, exc
                )
        else:
            self._send(self.pipeline.process(event, now))
        self.tracker.processed(partition, offset)

    def _handle_error(self, error: Any, now: float) -> None:
        if error.code() == KafkaError._PARTITION_EOF:
            return
        self.stats.consumer_errors += 1
        if error.fatal():
            raise KafkaException(error)
        if self._throttle.ready(f"kafka:{error.code()}", now):
            logger.warning("Kafka consumer: %s", error, extra=ecs({"error.code": error.name()}))

    def _send(self, emissions: Sequence[Emission], deadline: float | None = None) -> None:
        topics = self.config.kafka
        for emission in emissions:
            created = self.wall_clock()
            self._send_one(emission, "window_score", topics.window_scores_topic, created, deadline)
            if emission.reported:
                self._send_one(emission, "detection", topics.detections_topic, created, deadline)

    def _send_one(
        self,
        emission: Emission,
        kind: Kind,
        topic: str,
        created: float,
        deadline: float | None,
    ) -> None:
        score = emission.score
        payload = encode(document(score, kind, reported=emission.reported, created=created))
        sequence = self.tracker.output_enqueued(emission.offsets)
        limit = deadline
        if limit is None:
            limit = self.clock() + self.config.kafka.produce_timeout_sec
        _produce(
            self.producer,
            topic,
            payload,
            score.host_id.encode("utf-8"),
            partial(self._delivered, sequence, kind, score),
            clock=self.clock,
            deadline=limit,
        )
        self.stats.produced += 1

    def _delivered(
        self, sequence: int, kind: Kind, score: WindowScore, error: Any, _message: Any
    ) -> None:
        fields: dict[str, Any] = {
            "event.action": Action.DETECTION if kind == "detection" else Action.WINDOW_SCORE,
            "event.start": format_timestamp(score.start),
            "event.end": format_timestamp(score.end),
            "logsentinel.window.id": score.window_id,
            "logsentinel.window.trigger": score.trigger,
            "logsentinel.monitored_host.id": score.host_id,
            "logsentinel.monitored_host.name": score.host_name,
            "logsentinel.verdict.label": score.label,
            "logsentinel.verdict.confidence_score": score.confidence_score,
            "logsentinel.verdict.threshold": score.threshold,
            "logsentinel.verdict.indicators": score.indicators,
            "logsentinel.model.version": score.model_version,
        }
        if error is None:
            self.tracker.output_acked(sequence)
            self.stats.acked += 1
            if kind == "detection":
                logger.info(
                    "Detection %.12s delivered: %s for host %s, window ending %s, "
                    "confidence %.4f (threshold %.2f), indicators: %s",
                    score.window_id,
                    score.label,
                    score.host_name or score.host_id,
                    format_timestamp(score.end),
                    score.confidence_score or 0.0,
                    score.threshold,
                    ", ".join(score.indicators),
                    extra=ecs({**fields, "event.outcome": "success"}),
                )
            return
        # The record stays registered: its input offsets are never committed.
        self.stats.delivery_errors += 1
        self._failures.append(str(error))
        logger.error(
            "%s %.12s delivery failed: %s",
            "Detection" if kind == "detection" else "Window score",
            score.window_id,
            error,
            extra=ecs({**fields, "event.outcome": "failure", "error.message": str(error)}),
        )

    def _raise_if_failed(self) -> None:
        if self._failures:
            raise DeliveryError(
                f"{len(self._failures)} output records could not be delivered "
                f"(first error: {self._failures[0]})"
            )

    def _store_offsets(self, now: float) -> None:
        advanced = self.tracker.advance(self.pipeline.windower.oldest_offsets())
        if not advanced:
            return
        topic = self.config.kafka.input_topic
        offsets = [TopicPartition(topic, p, offset) for p, offset in advanced.items()]
        try:
            self.consumer.store_offsets(offsets=offsets)
        except KafkaException as exc:
            # A partition was revoked meanwhile; its new owner re-reads from the commit.
            if self._throttle.ready("store_offsets", now):
                logger.warning("Could not store offsets: %s", exc)

    def _shutdown(self, *, drain: bool) -> None:
        """Flush within the budget and close the consumer (which commits what was acknowledged).

        With ``drain`` (a requested stop) the pending windows are emitted first and
        anything still undelivered raises ``DeliveryError``. Without it (another
        error is already propagating) nothing is emitted: the replay will.
        """
        deadline = self.clock() + self.config.kafka.shutdown_timeout_sec
        problem: str | None = None
        try:
            if drain:
                self._send(self.pipeline.drain(), deadline=deadline)
        except DeliveryError as exc:
            problem = str(exc)
        except Exception as exc:  # noqa: BLE001 - the producer is flushed and the consumer closed below
            logger.exception("Cannot emit the pending windows at shutdown")
            problem = f"{type(exc).__name__}: {exc}"
        try:
            pending = self.producer.flush(max(0.0, deadline - self.clock()))
            if pending and problem is None:
                problem = f"{pending} output records were not delivered before shutdown"
            if self._failures and problem is None:
                problem = f"{len(self._failures)} output records could not be delivered"
            self._store_offsets(self.clock())
        finally:
            self.consumer.close()
            self._log_stats(self.clock())
        if problem is not None:
            logger.error(
                "Shutdown: %s",
                problem,
                extra=ecs({"event.action": Action.SHUTDOWN, "event.outcome": "failure"}),
            )
            if drain:
                raise DeliveryError(problem)

    def _counters(self) -> dict[str, int]:
        """The counters of the status file and of the statistics record (one vocabulary)."""
        s = self.stats
        w = self.pipeline.windower
        return {
            "consumed": s.consumed,
            "invalid": s.invalid,
            "consumer_errors": s.consumer_errors,
            "late_events": w.late_events,
            "clock_resets": w.clock_resets,
            "overflow_events": w.overflow_events,
            "windows": s.windows,
            "early_windows": s.early_windows,
            "gated": s.gated,
            "suppressed": s.suppressed,
            "detections": s.detections,
            "produced": s.produced,
            "acked": s.acked,
            "pending_outputs": self.tracker.pending_outputs,
            "delivery_errors": s.delivery_errors,
            "internal_errors": s.internal_errors,
            "sysmon_dropped": s.sysmon_dropped,
            "hosts": len(w.hosts()),
        }

    def _write_status(self, now: float) -> None:
        down = self.monitor.down_for(now)
        degraded = ["kafka_unreachable"] if down > 0 else []
        status = {
            "updated_at": round(time.time(), 3),
            "healthy": down < self.config.kafka.down_after_sec,
            "degraded": degraded,
            "kafka_down_for_sec": round(down, 1),
            "model_version": self.pipeline.model.version if self.pipeline.model else None,
            "threshold": self.pipeline.threshold,
            **self._counters(),
        }
        try:
            write_status(self.status_path, status)
        except OSError as exc:
            if self._throttle.ready("status", now):
                logger.error("Cannot write status file %s: %s", self.status_path, exc)

    def _log_stats(self, now: float) -> None:
        """INFO: cumulative counters since start, as text and as ``logsentinel.stats.*`` fields."""
        counters = self._counters()
        fields: dict[str, Any] = {
            "event.action": Action.STATS,
            "logsentinel.stats.uptime_sec": round(now - self._started, 1),
            "logsentinel.kafka.down_sec": round(self.monitor.down_for(now), 1),
            **{f"logsentinel.stats.{name}": value for name, value in counters.items()},
        }
        logger.info(
            "%s",
            " ".join(f"{name}={value}" for name, value in counters.items()),
            extra=ecs(fields),
        )


def run_loop(
    consumer: ConsumerLike,
    producer: ProducerLike,
    pipeline: Pipeline,
    config: ServiceConfig,
    stop: threading.Event,
    *,
    status_path: Path = STATUS_PATH,
    clock: Callable[[], float] = time.monotonic,
    wall_clock: Callable[[], float] = time.time,
    batch_size: int = 500,
    monitor: KafkaMonitor | None = None,
) -> None:
    ServiceLoop(
        consumer,
        producer,
        pipeline,
        config,
        stop,
        status_path=status_path,
        clock=clock,
        wall_clock=wall_clock,
        batch_size=batch_size,
        monitor=monitor or KafkaMonitor(clock),
    ).run()


def main() -> int:
    try:
        settings = LogSettings.from_env(os.environ)
    except ValueError as exc:
        configure_logging()
        logger.error("Invalid logging configuration: %s", exc)
        return 2
    configure_logging(settings)
    try:
        return _run()
    except Exception:  # noqa: BLE001 - the traceback goes to the log as one record
        logger.critical("Stopping on an unexpected error", exc_info=True)
        return 1


def _run() -> int:
    try:
        config = load_config()
    except (OSError, ValueError) as exc:
        logger.error("Invalid configuration: %s", exc)
        return 2
    try:
        artifacts = load_artifacts(Path(config.artifacts_dir), config.window)
        threshold = resolve_threshold(config.scoring, artifacts.model)
    except ArtifactError as exc:
        logger.error("Cannot start without a complete model that fits this configuration: %s", exc)
        return 2
    logger.info(
        "inference %s: %s -> %s + %s, model %s, threshold %.2f (%s)",
        __version__,
        config.kafka.input_topic,
        config.kafka.detections_topic,
        config.kafka.window_scores_topic,
        artifacts.model.version,
        threshold.value,
        threshold.source,
        extra=ecs(
            {
                "event.action": Action.STARTUP,
                "logsentinel.model.version": artifacts.model.version,
                "logsentinel.verdict.threshold": threshold.value,
                "logsentinel.threshold_source": threshold.source,
                "logsentinel.kafka.input_topic": config.kafka.input_topic,
                "logsentinel.kafka.detections_topic": config.kafka.detections_topic,
                "logsentinel.kafka.window_scores_topic": config.kafka.window_scores_topic,
                "logsentinel.kafka.group_id": config.kafka.group_id,
            }
        ),
    )
    monitor = KafkaMonitor(time.monotonic)
    consumer = Consumer(
        {
            "bootstrap.servers": config.kafka.bootstrap_servers,
            "group.id": config.kafka.group_id,
            "auto.offset.reset": config.kafka.auto_offset_reset,
            "enable.auto.commit": True,
            "enable.auto.offset.store": False,
            "enable.partition.eof": False,
            "statistics.interval.ms": STATS_CALLBACK_INTERVAL_MS,
            "stats_cb": monitor.on_stats,
        },
        logger=kafka_logger,
    )
    consumer.subscribe([config.kafka.input_topic])
    producer = Producer(
        {
            "bootstrap.servers": config.kafka.bootstrap_servers,
            "acks": "all",
            "enable.idempotence": True,
            "linger.ms": 50,
            "message.timeout.ms": int(config.kafka.delivery_timeout_sec * 1000),
        },
        logger=kafka_logger,
    )
    stop = threading.Event()

    def request_stop(signum: int, _frame: FrameType | None) -> None:
        logger.info(
            "Signal %d received: shutting down",
            signum,
            extra=ecs({"event.action": Action.SHUTDOWN}),
        )
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    pipeline = Pipeline(config, artifacts.model, threshold.value)
    try:
        run_loop(consumer, producer, pipeline, config, stop, monitor=monitor)
    except (DeliveryError, KafkaException) as exc:
        logger.error(
            "Stopping: %s",
            exc,
            extra=ecs({"event.action": Action.SHUTDOWN, "event.outcome": "failure"}),
        )
        return 1
    logger.info("Stopped", extra=ecs({"event.action": Action.SHUTDOWN, "event.outcome": "success"}))
    return 0


def _produce(
    producer: ProducerLike,
    topic: str,
    payload: bytes,
    key: bytes,
    on_delivery: Callable[[Any, Any], None],
    *,
    clock: Callable[[], float],
    deadline: float,
) -> None:
    while True:
        try:
            producer.produce(topic, value=payload, key=key, on_delivery=on_delivery)
            return
        except BufferError:
            # Local queue full: serve delivery reports, then retry until the deadline.
            if clock() >= deadline:
                raise DeliveryError("the producer queue stayed full until the deadline") from None
            producer.poll(PRODUCE_RETRY_WAIT_SEC)
