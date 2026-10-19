"""Run the worker, one actual delivery poll, or its local health check."""

from __future__ import annotations

import argparse
import json
import os
import signal
import threading
from pathlib import Path

from notifications.service import (
    ConfigurationError,
    NotificationService,
    StoreError,
    emit,
    load_settings,
    parse_timestamp,
    safe_error,
    timestamp,
    utc_now,
)

HEALTH_PATH = Path("/tmp/notifications-health.json")


def write_health(report: dict, poll_sec: float = 30, timeout_sec: float = 15) -> None:
    report = {
        **report,
        "checked_at": timestamp(utc_now()),
        "max_age_sec": max(120, poll_sec * 3 + timeout_sec * 4),
    }
    temporary = HEALTH_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(report), encoding="utf-8")
    os.replace(temporary, HEALTH_PATH)


def healthcheck() -> int:
    try:
        report = json.loads(HEALTH_PATH.read_text(encoding="utf-8"))
        age_sec = (utc_now() - parse_timestamp(report["checked_at"])).total_seconds()
        return int(report.get("status") != "healthy" or not 0 <= age_sec <= report["max_age_sec"])
    except (OSError, ValueError, TypeError, KeyError, StoreError):
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--healthcheck", action="store_true")
    parser.add_argument(
        "--once", action="store_true", help="perform one poll, including real sends"
    )
    args = parser.parse_args()
    if args.healthcheck:
        return healthcheck()
    try:
        settings = load_settings()
    except ConfigurationError:
        write_health({"status": "unhealthy", "error": "configuration is incomplete or invalid"})
        emit("notification_startup", "failure", error={"type": "ConfigurationError"})
        return 2
    stopped = threading.Event()
    for event in (signal.SIGINT, signal.SIGTERM):
        signal.signal(event, lambda *_: stopped.set())
    service = NotificationService(settings)
    while not stopped.is_set():
        try:
            report = service.poll()
        except Exception as exc:
            report = {"status": "unhealthy", "error": safe_error(exc)}
        write_health(report, settings.poll_sec, settings.timeout_sec)
        emit(
            "notification_poll",
            "success" if report["status"] == "healthy" else "failure",
            logsentinel={"notifications": report},
        )
        if args.once:
            return int(report["status"] != "healthy")
        stopped.wait(settings.poll_sec)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
