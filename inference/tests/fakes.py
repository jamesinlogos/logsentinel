"""Fake Kafka clients and helpers for the service tests (real telemetry, fake broker)."""

from __future__ import annotations

import gzip
import json
import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

import pytest
from confluent_kafka import KafkaError

from inference.events import Event, decode, parse_event
from inference.indicators import IndicatorResult, RuleFacts, evaluate
from inference.pipeline import Emission, Pipeline
from training.sentinelcap_dataset import Session

MAX_CONSUME_CALLS = 200
"""A loop that never stops would hang the test run; this makes it fail instead."""


class FakeMessage:
    def __init__(
        self,
        value: bytes | None = None,
        error: KafkaError | None = None,
        *,
        partition: int = 0,
        offset: int = 0,
    ) -> None:
        self._value = value
        self._error = error
        self._partition = partition
        self._offset = offset

    def value(self) -> bytes | None:
        return self._value

    def error(self) -> KafkaError | None:
        return self._error

    def partition(self) -> int:
        return self._partition

    def offset(self) -> int:
        return self._offset


class FakeConsumer:
    """Hands out the given batches, then asks the loop to stop.

    ``on_consume`` runs at the start of every ``consume`` call (1-based count), so
    a test can look at the stored offsets or let acknowledgements arrive between
    two loop iterations. ``crash_after`` makes the call after that many raise.
    """

    def __init__(
        self,
        batches: list[list[FakeMessage]],
        stop: threading.Event,
        *,
        crash_after: int | None = None,
        on_consume: Callable[[int], None] | None = None,
    ) -> None:
        self.batches = list(batches)
        self.stop = stop
        self.crash_after = crash_after
        self.on_consume = on_consume
        self.consume_calls = 0
        self.stored: dict[int, int] = {}
        self.closed = False

    def consume(self, num_messages: int, timeout: float) -> list[FakeMessage]:
        self.consume_calls += 1
        if self.consume_calls > MAX_CONSUME_CALLS:
            raise AssertionError("the loop under test did not stop")
        if self.on_consume is not None:
            self.on_consume(self.consume_calls)
        if self.crash_after is not None and self.consume_calls > self.crash_after:
            raise RuntimeError("consumer crashed")
        if not self.batches:
            self.stop.set()
            return []
        return self.batches.pop(0)

    def store_offsets(self, message: Any = None, offsets: Sequence[Any] | None = None) -> None:
        for tp in offsets or ():
            self.stored[tp.partition] = max(self.stored.get(tp.partition, -1), tp.offset)

    def close(self) -> None:
        self.closed = True


class FakeProducer:
    """``ack_mode``: "immediate" acknowledges inside produce(); "manual" holds the
    delivery reports until ``release()`` (or flush); "never" loses them, so flush
    reports them pending."""

    def __init__(
        self,
        ack_mode: str = "immediate",
        *,
        error: KafkaError | None = None,
        buffer_full: int = 0,
    ) -> None:
        self.ack_mode = ack_mode
        self.error = error
        self.buffer_full = buffer_full
        """BufferError raised by this many produce() calls (-1: for ever)."""
        self.produced: list[tuple[str, bytes, bytes]] = []
        self.delivered: list[tuple[str, bytes]] = []
        """``(topic, value)`` of every record the broker acknowledged."""
        self.flushed = False
        self.polls = 0
        self._reports: list[tuple[Callable[[Any, Any], None], str, bytes]] = []

    def produce(
        self, topic: str, *, value: bytes, key: bytes, on_delivery: Callable[[Any, Any], None]
    ) -> None:
        if self.buffer_full != 0:
            if self.buffer_full > 0:
                self.buffer_full -= 1
            raise BufferError("queue full")
        self.produced.append((topic, key, value))
        if self.ack_mode == "immediate":
            self._report(on_delivery, topic, value)
        else:
            self._reports.append((on_delivery, topic, value))

    def poll(self, timeout: float) -> int:
        self.polls += 1
        return 0

    def release(self) -> None:
        reports, self._reports = self._reports, []
        for callback, topic, value in reports:
            self._report(callback, topic, value)

    def flush(self, timeout: float) -> int:
        self.flushed = True
        if self.ack_mode == "never":
            return len(self._reports)
        self.release()
        return 0

    def delivered_on(self, topic: str) -> list[bytes]:
        return [value for name, value in self.delivered if name == topic]

    def _report(self, callback: Callable[[Any, Any], None], topic: str, value: bytes) -> None:
        if self.error is None:
            self.delivered.append((topic, value))
        callback(self.error, None)


class Clock:
    """A monotonic clock the tests drive; ``step`` is added after every reading."""

    def __init__(self, step: float = 0.0) -> None:
        self.now = 1000.0
        self.step = step

    def __call__(self) -> float:
        value = self.now
        self.now += self.step
        return value


def emissions_of(pipeline: Pipeline, events: Sequence[Event]) -> list[Emission]:
    """One emission per scored window, whether it is reported as a detection or not."""
    found: list[Emission] = []
    for index, event in enumerate(events):
        found.extend(pipeline.process(event, float(index)))
    found.extend(pipeline.drain())
    return found


def numbered(lines: Sequence[bytes]) -> list[Event]:
    """Events with the Kafka position they would have had: partition 0, offset = line number."""
    return [parse_event(decode(line), 0, offset) for offset, line in enumerate(lines)]


def fail_second_evaluation(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Make the scoring of the second window raise, as a bug on an odd event would."""
    calls: list[int] = []

    def flaky(facts: RuleFacts) -> IndicatorResult:
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("an event the rules have never met")
        return evaluate(facts)

    monkeypatch.setattr("inference.pipeline.evaluate", flaky)
    return calls


def raw_lines(session: Session) -> list[bytes]:
    with gzip.open(session.directory / "session.jsonl.gz", "rb") as lines:
        return [line.rstrip(b"\n") for line in lines if line.strip()]


def messages(lines: Sequence[bytes], *, partition: int = 0, start: int = 0) -> list[FakeMessage]:
    return [FakeMessage(v, partition=partition, offset=start + i) for i, v in enumerate(lines)]


def as_host(line: bytes, host: str) -> bytes:
    """The same real event, reported by another host (another window state)."""
    doc = json.loads(line)
    doc["host"] = {**doc.get("host", {}), "id": host, "name": host}
    return json.dumps(doc).encode()


def shifted(line: bytes, seconds: float) -> bytes:
    """The same real event with its ``@timestamp`` moved by ``seconds``."""
    doc = json.loads(line)
    moved = datetime.fromisoformat(doc["@timestamp"]).timestamp() + seconds
    doc["@timestamp"] = datetime.fromtimestamp(moved, UTC).isoformat(timespec="milliseconds")
    return json.dumps(doc).encode()
