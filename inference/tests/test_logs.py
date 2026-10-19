"""Log formats, settings from the environment and the root configuration (logs.py)."""

from __future__ import annotations

import io
import json
import logging
import sys
import warnings
from pathlib import Path
from typing import Any

import pytest

from inference import ECS_VERSION, __version__
from inference.logs import (
    FORMAT_ENV,
    LEVEL_ENV,
    MAX_MESSAGE_CHARS,
    JsonFormatter,
    LogSettings,
    TextFormatter,
    configure_logging,
    ecs,
)


def record(
    message: str = "hello",
    *args: Any,
    level: int = logging.INFO,
    created: float = 0.0,
    exc_info: Any = None,
    fields: dict[str, Any] | None = None,
) -> logging.LogRecord:
    made = logging.makeLogRecord(
        {
            "name": "inference.test",
            "levelno": level,
            "levelname": logging.getLevelName(level),
            "msg": message,
            "args": args,
            "created": created,
            "exc_info": exc_info,
        }
    )
    if fields is not None:
        made.__dict__.update(ecs(fields))
    return made


def test_settings_default_to_info_and_text() -> None:
    assert LogSettings.from_env({}) == LogSettings(logging.INFO, "text")
    assert LogSettings.from_env({LEVEL_ENV: "", FORMAT_ENV: ""}) == LogSettings()


def test_settings_ignore_case_and_space() -> None:
    settings = LogSettings.from_env({LEVEL_ENV: " debug ", FORMAT_ENV: "JSON"})
    assert settings == LogSettings(logging.DEBUG, "json")
    assert LogSettings.from_env({LEVEL_ENV: "warning"}).level == logging.WARNING


@pytest.mark.parametrize(
    ("environ", "name"),
    [
        ({LEVEL_ENV: "LOUD"}, LEVEL_ENV),
        ({LEVEL_ENV: "WARN"}, LEVEL_ENV),  # one spelling per level
        ({FORMAT_ENV: "xml"}, FORMAT_ENV),
    ],
)
def test_settings_reject_unknown_values(environ: dict[str, str], name: str) -> None:
    with pytest.raises(ValueError, match=name):
        LogSettings.from_env(environ)


def test_json_record_has_the_ecs_core_fields() -> None:
    line = JsonFormatter().format(record("Detection %s", "abc"))
    assert json.loads(line) == {
        "@timestamp": "1970-01-01T00:00:00.000Z",
        "log.level": "info",
        "log.logger": "inference.test",
        "message": "Detection abc",
        "service.name": "inference",
        "service.version": __version__,
        "event.module": "logsentinel",
        "event.dataset": "logsentinel.inference",
        "ecs.version": ECS_VERSION,
    }


def test_both_formats_print_utc_with_milliseconds() -> None:
    made = record("hello %s", "there", level=logging.WARNING, created=1_000_000_000.123)
    assert json.loads(JsonFormatter().format(made))["@timestamp"] == "2001-09-09T01:46:40.123Z"
    assert TextFormatter().format(made) == (
        "2001-09-09T01:46:40.123Z WARNING inference.test: hello there"
    )


def test_fields_are_added_but_never_replace_a_core_key() -> None:
    fields = {
        "event.action": "stats",
        "logsentinel.stats.consumed": 3,
        "message": "x",
        "log.level": "y",
    }
    doc = json.loads(JsonFormatter().format(record(fields=fields)))
    assert doc["event.action"] == "stats" and doc["logsentinel.stats.consumed"] == 3
    assert doc["message"] == "hello" and doc["log.level"] == "info"


def test_numbers_json_cannot_hold_become_null() -> None:
    fields = {"a": float("nan"), "b": [1.0, float("inf")], "c": 1.5}
    doc = json.loads(JsonFormatter().format(record(fields=fields)))
    assert doc["a"] is None and doc["b"] == [1.0, None] and doc["c"] == 1.5


def test_an_exception_is_a_field_and_the_record_stays_on_one_line() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        made = record("Stopping", level=logging.CRITICAL, exc_info=sys.exc_info())
    line = JsonFormatter().format(made)
    assert "\n" not in line
    doc = json.loads(line)
    assert doc["log.level"] == "critical"
    assert doc["error.type"] == "ValueError" and doc["error.message"] == "boom"
    assert 'raise ValueError("boom")' in doc["error.stack_trace"]


def test_the_json_line_is_ascii_and_survives_odd_values() -> None:
    made = record("Host name: %s", "Zürich", fields={"path": Path("C:/x"), "n": 1})
    line = JsonFormatter().format(made)
    line.encode("ascii")
    doc = json.loads(line)
    assert doc["message"] == "Host name: Zürich" and doc["path"] == str(Path("C:/x"))


def test_a_long_message_is_cut_in_both_formats() -> None:
    made = record("%s", "x" * (MAX_MESSAGE_CHARS + 500))
    for formatter in (JsonFormatter(), TextFormatter()):
        line = formatter.format(made)
        assert "500 more characters" in line
        assert len(line) < MAX_MESSAGE_CHARS + 400


def test_the_text_record_ends_with_the_traceback_and_hides_the_fields() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        made = record("Stopping", level=logging.CRITICAL, exc_info=sys.exc_info(), fields={"x": 1})
    lines = TextFormatter().format(made).splitlines()
    assert lines[0] == "1970-01-01T00:00:00.000Z CRITICAL inference.test: Stopping"
    assert lines[1] == "Traceback (most recent call last):" and lines[-1] == "ValueError: boom"


def test_configure_logging_installs_one_handler_in_the_chosen_format(clean_logging: None) -> None:
    first, second = io.StringIO(), io.StringIO()
    configure_logging(LogSettings(logging.INFO, "text"), first)
    configure_logging(LogSettings(logging.DEBUG, "json"), second)  # replaces, never stacks
    root = logging.getLogger()
    ours = [h for h in root.handlers if isinstance(h.formatter, JsonFormatter | TextFormatter)]
    assert len(ours) == 1 and root.level == logging.DEBUG
    logging.getLogger("inference.test").debug("traced", extra=ecs({"k": 1}))
    assert first.getvalue() == ""
    doc = json.loads(second.getvalue())
    assert doc["message"] == "traced" and doc["k"] == 1 and doc["log.level"] == "debug"


def test_configure_logging_defaults_to_text_on_stdout(
    clean_logging: None, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging()
    logging.getLogger("inference.test").info("hello")
    logging.getLogger("inference.test").debug("not shown at INFO")
    assert capsys.readouterr().out.endswith("INFO inference.test: hello\n")


def test_warnings_of_libraries_go_through_the_same_handler(clean_logging: None) -> None:
    stream = io.StringIO()
    configure_logging(LogSettings(logging.INFO, "json"), stream)
    with warnings.catch_warnings():
        warnings.simplefilter("always")
        warnings.warn("careful", UserWarning, stacklevel=1)
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    doc = json.loads(lines[0])
    assert doc["log.logger"] == "py.warnings" and "careful" in doc["message"]
