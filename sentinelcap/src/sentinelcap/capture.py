"""Capture lossless Logstash-normalized Sysmon events directly from Kafka.

SentinelCap consumes the same ``telemetry.windows.normalized`` topic as the
inference service. It only reads a few fields to apply session bounds and never
modifies an event: ``session.jsonl`` holds the original Kafka message payloads.
Labels, session timing and the collection environment are stored in
``metadata.json`` next to it.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from confluent_kafka import Consumer, KafkaError

from sentinelcap import __version__
from sentinelcap.config import KafkaConfig
from sentinelcap.errors import SentinelcapError
from sentinelcap.logging_utils import get_logger
from sentinelcap.session import (
    EventInfo,
    decode_event,
    event_host_id,
    format_timestamp,
    parse_event,
)

logger = get_logger(__name__)

SESSION_FORMAT = "logsentinel.normalized-sysmon.jsonl/v1"


def session_dir(out_dir: str | Path, family: str, sample: str) -> Path:
    """``<out_dir>/<family>/<sample>``; family is already normalized by the manifest.

    ``out_dir`` is one collection run directory (``<capture.out_dir>/<UTC timestamp>``).
    """
    return Path(out_dir) / family / sample


def _partial_dir(target: Path) -> Path:
    return target.parent / f".{target.name}.partial"


def _old_dir(target: Path) -> Path:
    return target.parent / f".{target.name}.old"


def _recover_leftovers(target: Path) -> None:
    """Clean up after an export that died midway.

    ``.<sample>.partial`` is an unfinished new session and is removed. ``.<sample>.old``
    is the previous session moved aside by ``--force``: it is restored when the
    new one never replaced it, otherwise removed.
    """
    partial, old = _partial_dir(target), _old_dir(target)
    if partial.exists():
        shutil.rmtree(partial)
    if old.exists():
        if target.exists():
            shutil.rmtree(old)
        else:
            os.replace(old, target)
            logger.warning("Restored %s from an interrupted --force export", target)


def prepare_session_dir(out_dir: str | Path, family: str, sample: str, force: bool) -> Path:
    """Return the session directory, refusing a sample already collected.

    A sample present under another family is always refused (``--force`` cannot
    move it); the same family/sample is refused unless ``force`` is set. Leftovers
    of an interrupted export of this family/sample are cleaned up first.
    """
    target = session_dir(out_dir, family, sample)
    _recover_leftovers(target)
    elsewhere = [p for p in Path(out_dir).glob(f"*/{sample}") if p.is_dir() and p != target]
    if elsewhere:
        raise SentinelcapError(
            f"{sample} was already collected in {elsewhere[0]} (different family)"
        )
    if target.exists() and not force:
        raise SentinelcapError(
            f"Session directory already exists: {target} (use --force to overwrite)"
        )
    return target


@dataclass
class KafkaCapture:
    """Collect one victim host's normalized Kafka messages into a lossless buffer."""

    cfg: KafkaConfig
    _consumer: Consumer | None = field(default=None, init=False, repr=False)
    _events: list[EventInfo] = field(default_factory=list, init=False, repr=False)
    skipped_other_hosts: int = field(default=0, init=False)
    skipped_invalid: int = field(default=0, init=False)
    """Messages that are not a JSON object (host unknown)."""

    def start(self) -> None:
        """Join a fresh consumer group at the topic tail before recording starts."""
        if self._consumer is not None:
            raise SentinelcapError("Kafka capture is already running")

        group_id = f"{self.cfg.consumer_group_prefix}-{uuid.uuid4()}"
        self._consumer = Consumer(
            {
                "bootstrap.servers": self.cfg.bootstrap_servers,
                "group.id": group_id,
                "auto.offset.reset": "latest",
                "enable.auto.commit": False,
                "enable.partition.eof": False,
            }
        )
        self._consumer.subscribe([self.cfg.topic])

        deadline = time.monotonic() + self.cfg.assignment_timeout_sec
        while time.monotonic() < deadline:
            message = self._consumer.poll(0.25)
            self._raise_if_error(message)
            if self._consumer.assignment():
                logger.info("Kafka capture is ready on topic '%s'.", self.cfg.topic)
                return

        self.close()
        raise SentinelcapError(
            f"Timed out waiting for Kafka topic assignment: {self.cfg.topic}. "
            "Check kafka.bootstrap_servers, topic, and broker health."
        )

    @property
    def events(self) -> list[EventInfo]:
        """Every buffered event of the victim host, in arrival order."""
        return self._events

    def poll_event(self, timeout: float = 1.0) -> EventInfo | None:
        """Poll one message and buffer it when it belongs to the victim host.

        Session bounds are applied later by ``export_session``, because ``t_exec``
        is only known after the sample's Event 1 has been seen.
        """
        if self._consumer is None:
            raise SentinelcapError("Kafka capture has not been started")
        message = self._consumer.poll(timeout)
        self._raise_if_error(message)
        if message is None:
            return None
        received_at = time.monotonic()
        received_wall = datetime.now(timezone.utc)
        payload = message.value()
        # The topic is shared by every host: a message that is not a JSON object
        # cannot be attributed to the victim and must not abort its session.
        try:
            if not isinstance(payload, bytes):
                raise SentinelcapError("Kafka normalized message payload is not bytes")
            doc = decode_event(payload)
        except SentinelcapError as e:
            self.skipped_invalid += 1
            logger.warning("Skipped an unreadable Kafka message: %s", e)
            return None
        if event_host_id(doc) != self.cfg.host_id:
            self.skipped_other_hosts += 1
            return None
        # Victim events are read strictly: a bad @timestamp here fails the session.
        event = parse_event(payload, received_at, received_wall, doc)
        self._events.append(event)
        return event

    def poll_for(self, seconds: float) -> None:
        """Buffer host events for ``seconds`` of host monotonic time."""
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            self.poll_event(timeout=min(1.0, remaining))

    def clock_offset_sec(self, median_events: int = 5) -> float:
        """Median of host wall clock minus ``@timestamp`` over the first ``median_events`` events.

        The value still includes the pipeline delay (Sysmon -> host); the median
        only removes the effect of a single late event.
        """
        if not self._events:
            raise SentinelcapError(
                "No event received from the victim host; cannot measure the clock offset"
            )
        first = self._events[: max(1, median_events)]
        return statistics.median((e.received_wall - e.timestamp).total_seconds() for e in first)

    def export_session(
        self,
        *,
        mode: str,
        family: str,
        sample: str,
        label: int,
        t_start: datetime,
        t_end: datetime,
        out_dir: str | Path,
        session_id: str,
        process_entity_id: str | None = None,
        sample_entity_ids: list[str] | None = None,
        scenario: str | None = None,
        clock_offset_sec: float = 0.0,
        snapshot: str | None = None,
        force: bool = False,
    ) -> Path:
        """Write ``<out_dir>/<family>/<sample>/session.jsonl`` and ``metadata.json``.

        Keeps buffered events with ``t_start <= @timestamp <= t_end``. Payloads are
        written byte for byte; the label lives only in the metadata. The
        ``environment`` block records the collection environment; Windows build
        and Winlogbeat version are read from the first event in the window.

        Both files are written to ``.<sample>.partial`` and the directory is renamed
        to ``<sample>`` only once complete; with ``force`` an existing session is
        moved to ``.<sample>.old`` first and removed after the swap.
        """
        target = prepare_session_dir(out_dir, family, sample, force)

        selected = [e for e in self._events if t_start <= e.timestamp <= t_end]
        if not selected:
            raise SentinelcapError("No normalized Kafka documents found inside the session window")

        lag_max, lag_p50 = pipeline_lag(selected)
        if lag_max is not None and lag_max >= self.cfg.post_capture_drain_sec:
            logger.warning(
                "Pipeline lag (event.created - @timestamp) reached %.1fs (median %.1fs), "
                "at or above post_capture_drain_sec (%ss): the session may miss its last "
                "events.",
                lag_max,
                lag_p50,
                self.cfg.post_capture_drain_sec,
            )

        partial = _partial_dir(target)
        partial.mkdir(parents=True)
        with (partial / "session.jsonl").open("wb") as output:
            for event in selected:
                output.write(event.payload)
                if not event.payload.endswith(b"\n"):
                    output.write(b"\n")

        metadata: dict[str, Any] = {
            "format": SESSION_FORMAT,
            "session_id": session_id,
            "source": {
                "kafka_topic": self.cfg.topic,
                "host_id": self.cfg.host_id,
                "processing": "none; original normalized Kafka payloads",
            },
            "label": {
                "target_class_name": f"{family}-{sample}",
                "target_class": label,
            },
            "mode": mode,
            "t_start": format_timestamp(t_start),
            "t_end": format_timestamp(t_end),
            "clock_offset_sec": clock_offset_sec,
            "event_count": len(selected),
            "pipeline_lag_max_sec": lag_max,
            "pipeline_lag_p50_sec": lag_p50,
            "skipped_other_hosts": self.skipped_other_hosts,
            "skipped_invalid": self.skipped_invalid,
            "skipped_outside_session": len(self._events) - len(selected),
            "environment": {
                "sentinelcap_version": __version__,
                "snapshot": snapshot,
                "windows_build": selected[0].os_build,
                "winlogbeat_version": selected[0].agent_version,
            },
        }
        if process_entity_id is not None:
            metadata["process_entity_id"] = process_entity_id
        if sample_entity_ids is not None:
            metadata["sample_entity_ids"] = sample_entity_ids
        if scenario is not None:
            metadata["scenario"] = scenario
        (partial / "metadata.json").write_text(
            json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
        )
        _swap_in(partial, target)
        logger.info("Wrote %d lossless normalized event(s) to %s", len(selected), target)
        return target

    def close(self) -> None:
        """Leave the ephemeral consumer group without committing offsets."""
        if self._consumer is not None:
            self._consumer.close()
            self._consumer = None

    @staticmethod
    def _raise_if_error(message: Any) -> None:
        if message is not None and message.error() is not None:
            error = message.error()
            if error.code() != KafkaError._PARTITION_EOF:
                raise SentinelcapError(f"Kafka consumer error: {error}")


def pipeline_lag(events: list[EventInfo]) -> tuple[float | None, float | None]:
    """(max, median) of ``event.created - @timestamp`` in seconds.

    (None, None) when no event carries ``event.created``.

    Both stamps come from the guest clock, so this measures Sysmon -> Winlogbeat
    only; the Kafka/Logstash part of the delay is not visible in the payload.
    """
    lags = [(e.created - e.timestamp).total_seconds() for e in events if e.created is not None]
    if not lags:
        return None, None
    return round(max(lags), 3), round(statistics.median(lags), 3)


def _swap_in(partial: Path, target: Path) -> None:
    """Rename the finished ``partial`` directory to ``target``.

    ``os.replace`` cannot overwrite an existing directory on Windows, so an
    existing session (``--force``) is moved aside to ``.<sample>.old`` first.
    """
    old = _old_dir(target)
    if target.exists():
        os.replace(target, old)
    os.replace(partial, target)
    if old.exists():
        shutil.rmtree(old)
