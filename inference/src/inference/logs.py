"""Logging of the service: one configuration point, two formats, one event vocabulary.

Every module logs through ``logging.getLogger(__name__)``. ``configure_logging``
runs once, first thing in ``service.main``, and is driven by the environment only
(a configuration error must already be logged in the final format):

* ``INFERENCE__LOG__LEVEL``: DEBUG, INFO (default), WARNING, ERROR or
  CRITICAL;
* ``INFERENCE__LOG__FORMAT``: ``text`` (default, for a terminal) or ``json``
  (the container: docker-compose.yml sets it).

Both formats print one record per line on stdout, in UTC with milliseconds, and
carry the same message, so a line means the same thing in a terminal and in
Kibana. ``json`` follows ECS (the field names Elasticsearch uses for its own log
lines in this stack, dotted keys at the top level); a log call adds fields with
``extra=ecs({...})`` and keeps a human-readable message.

Levels: ERROR is a failure the service cannot work around (it is usually about to
stop) or a detection it could not deliver; WARNING is an anomaly it works around
(unusable input, a moved host clock, a broker that is away); INFO is the life
cycle, one statistics record per ``stats_interval_sec`` and one record per
delivered detection; DEBUG is one record per scored window.
"""

from __future__ import annotations

import json
import logging
import math
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, TextIO

from inference import ECS_VERSION, PRODUCT, SERVICE_NAME, __version__

DATASET = f"{PRODUCT}.{SERVICE_NAME.replace('-', '_')}"
"""``logsentinel.inference``."""
LEVEL_ENV = "INFERENCE__LOG__LEVEL"
FORMAT_ENV = "INFERENCE__LOG__FORMAT"
ECS_ATTR = "ecs_fields"
"""``LogRecord`` attribute that carries the structured fields of a record."""
MAX_MESSAGE_CHARS = 4096
"""A longer message (a hostile input echoed in an error) is cut, in both formats."""

LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}
FORMATS = ("text", "json")


class Action(StrEnum):
    """``event.action`` of the records that machines are expected to look for."""

    STARTUP = "startup"
    STATS = "stats"
    DETECTION = "detection"
    WINDOW_SCORE = "window_score"
    KAFKA_CONNECTION = "kafka_connection"
    SCORING_ERROR = "scoring_error"
    SHUTDOWN = "shutdown"


def ecs(fields: Mapping[str, Any]) -> dict[str, Any]:
    """The ``extra=`` argument of a log call that carries structured fields."""
    return {ECS_ATTR: dict(fields)}


class Throttle:
    """Lets a repeated log line through at most once per interval."""

    def __init__(self, interval: float) -> None:
        self.interval = interval
        self._last: dict[str, float] = {}

    def ready(self, key: str, now: float) -> bool:
        last = self._last.get(key)
        if last is not None and now - last < self.interval:
            return False
        self._last[key] = now
        return True


@dataclass(frozen=True)
class LogSettings:
    level: int = logging.INFO
    format: str = "text"

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> LogSettings:
        level_name = environ.get(LEVEL_ENV, "").strip().upper() or "INFO"
        if level_name not in LEVELS:
            raise ValueError(
                f"{LEVEL_ENV} must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL, "
                f"not {level_name!r}"
            )
        log_format = environ.get(FORMAT_ENV, "").strip().lower() or "text"
        if log_format not in FORMATS:
            raise ValueError(f"{FORMAT_ENV} must be one of text, json, not {log_format!r}")
        return cls(LEVELS[level_name], log_format)


def configure_logging(settings: LogSettings | None = None, stream: TextIO | None = None) -> None:
    """Replace the root handlers with one stdout handler in the chosen format."""
    settings = settings or LogSettings()
    handler = logging.StreamHandler(stream if stream is not None else sys.stdout)
    handler.setFormatter(JsonFormatter() if settings.format == "json" else TextFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(settings.level)
    # Warnings of libraries go through the same handler instead of raw stderr text.
    logging.captureWarnings(True)


class TextFormatter(logging.Formatter):
    """``2026-10-03T08:00:00.123Z INFO inference.service: message``."""

    def format(self, record: logging.LogRecord) -> str:
        line = f"{_timestamp(record.created)} {record.levelname} {record.name}: {_message(record)}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        if record.stack_info:
            line += "\n" + self.formatStack(record.stack_info)
        return line


class JsonFormatter(logging.Formatter):
    """One ECS JSON object per record, on one line (a traceback is a field, not extra lines)."""

    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {
            "@timestamp": _timestamp(record.created),
            "log.level": record.levelname.lower(),
            "log.logger": record.name,
            "message": _message(record),
            "service.name": SERVICE_NAME,
            "service.version": __version__,
            "event.module": PRODUCT,
            "event.dataset": DATASET,
            "ecs.version": ECS_VERSION,
        }
        for key, value in getattr(record, ECS_ATTR, {}).items():
            doc.setdefault(key, _plain(value))  # a field never replaces a core key
        if record.exc_info and record.exc_info[0] is not None:
            error_type, error, _ = record.exc_info
            doc["error.type"] = error_type.__name__
            doc["error.message"] = _truncate(str(error))
            doc["error.stack_trace"] = self.formatException(record.exc_info)
        # ensure_ascii: the line is valid ASCII whatever the encoding of the output.
        return json.dumps(doc, separators=(",", ":"), default=str)


def _timestamp(epoch: float) -> str:
    moment = datetime.fromtimestamp(epoch, UTC)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _truncate(text: str) -> str:
    if len(text) <= MAX_MESSAGE_CHARS:
        return text
    return f"{text[:MAX_MESSAGE_CHARS]}... [{len(text) - MAX_MESSAGE_CHARS} more characters]"


def _message(record: logging.LogRecord) -> str:
    return _truncate(record.getMessage())


def _plain(value: Any) -> Any:
    """JSON has no NaN or infinity: a field that is not finite becomes null."""
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]
    return value
