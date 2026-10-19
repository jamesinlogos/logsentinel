"""Read the latest synthetic notification receipts, or explicitly enqueue one test notice.

Default mode reads only the last local test report and its two Elasticsearch delivery receipts.
``--enqueue`` first requires the canonical Basic notification setup to be installed, then calls
the existing Kibana Index connector once. It queues a clearly labelled synthetic TEST notice
without detection or monitored-host information. The worker sends that notice to its configured
Telegram and Gmail destinations. No source index, rule, Docker or VM changes are performed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from alerting_setup import AlertHttp
from dashboard_setup import DashboardError, endpoint, space_identifier, write_json
from notification_setup import CONNECTOR_ID, setup

ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = Path("archives/kibana-notification-test.json")
CHANNELS = ("telegram", "gmail")
TEST_ID = re.compile(r"notification-test:[0-9a-f]{32}")


def created_time(value: Any) -> datetime:
    """Accept only timezone-aware UTC timestamps; never interpolate report text into URLs."""
    if not isinstance(value, str):
        raise ValueError("invalid test timestamp")
    created = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if created.tzinfo is None or created.utcoffset() != timedelta(0):
        raise ValueError("test timestamp must be UTC")
    return created.astimezone(UTC)


def saved_identity(root: Path, space: str) -> dict[str, Any] | None:
    """Read only the whitelisted identity needed to find receipts for the latest test."""
    path = root / REPORT_PATH
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("invalid local test report")
    if value.get("status") == "no_test_yet" and "test_id" not in value:
        return None
    identifier = value.get("test_id")
    if (
        not isinstance(identifier, str)
        or not TEST_ID.fullmatch(identifier)
        or value.get("space") != space
    ):
        raise ValueError("invalid test identity or Kibana space")
    created_time(value.get("event_created"))
    return {
        "test_id": identifier,
        "event_created": value["event_created"],
        "enqueued": value.get("enqueued") is True,
    }


def receipt_status(
    es: AlertHttp, identifier: str, created: datetime, channel: str
) -> dict[str, Any]:
    """Report a provider acknowledgement without including messages or provider responses."""
    digest = hashlib.sha256(f"{identifier}\0{channel}".encode()).hexdigest()
    index = f"ransomware-notification-deliveries-{created:%Y.%m}"
    response = es.request("GET", f"/{index}/_doc/{digest}", allow_missing=True)
    if response is None:
        return {"status": "pending", "sent": False}
    if not isinstance(response, dict) or response.get("found") is not True:
        raise ValueError("invalid receipt response")
    source = response.get("_source")
    sentinel = source.get("logsentinel") if isinstance(source, dict) else None
    receipt = sentinel.get("notification") if isinstance(sentinel, dict) else None
    if (
        not isinstance(receipt, dict)
        or receipt.get("id") != identifier
        or receipt.get("channel") != channel
        or type(receipt.get("sent")) is not bool
        or type(receipt.get("attempts")) is not int
        or receipt["attempts"] < 1
    ):
        raise ValueError("invalid receipt identity or state")
    return {
        "status": "sent" if receipt["sent"] else "retrying",
        "sent": receipt["sent"],
        "attempts": receipt["attempts"],
    }


def run_test(
    root: Path, es: AlertHttp, kibana: AlertHttp, *, space: str = "default", enqueue: bool = False
) -> dict[str, Any]:
    """Queue at most one explicit synthetic test and inspect independent channel receipts."""
    report: dict[str, Any] = {
        "created_utc": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        "space": space,
        "enqueue": enqueue,
        "status": "failed",
        "enqueued": False,
    }
    if enqueue:
        try:
            preflight = setup(root, es, kibana, space=space)
        except (DashboardError, OSError, TypeError, ValueError):
            preflight = {}
        if not isinstance(preflight, dict) or preflight.get("status") != "unchanged":
            report["errors"] = ["notification setup must already be installed and unchanged"]
            return report
        created = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        identifier = f"notification-test:{uuid4().hex}"
        report.update(test_id=identifier, event_created=created)
        document = {
            "@timestamp": created,
            "ecs": {"version": "8.0.0"},
            "event": {
                "kind": "alert",
                "module": "logsentinel",
                "dataset": "logsentinel.notification",
                "id": identifier,
                "created": created,
            },
            "logsentinel": {"schema_version": 2, "notification": {"count": 0}},
            "message": "TEST: LogSentinel notification delivery check.\n"
            "Synthetic test; no ransomware detection or monitored host data.\n"
            f"Test ID: {identifier}",
        }
        prefix = "" if space == "default" else f"/s/{space}"
        try:
            result = kibana.request(
                "POST",
                f"{prefix}/api/actions/connector/{CONNECTOR_ID}/_execute",
                {"params": {"documents": [document]}},
            )
            if not isinstance(result, dict) or result.get("status") != "ok":
                raise ValueError("connector did not acknowledge execution")
        except (DashboardError, OSError, TypeError, ValueError):
            report["errors"] = ["connector execution failed; response details omitted"]
            return report
        report["enqueued"] = True
    else:
        try:
            identity = saved_identity(root, space)
        except (OSError, TypeError, ValueError):
            report["errors"] = ["cannot read a valid local test identity for this Kibana space"]
            return report
        if identity is None:
            report["status"] = "no_test_yet"
            return report
        report.update(identity)
    try:
        created_at = created_time(report["event_created"])
        report["channels"] = {
            channel: receipt_status(es, report["test_id"], created_at, channel)
            for channel in CHANNELS
        }
        report["status"] = (
            "accepted" if all(item["sent"] for item in report["channels"].values()) else "queued"
        )
    except (DashboardError, OSError, KeyError, TypeError, ValueError):
        report["errors"] = ["notification delivery status is invalid or unavailable"]
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--es", type=endpoint, default="http://localhost:9200")
    parser.add_argument("--kibana", type=endpoint, default="http://localhost:5601")
    parser.add_argument("--space", type=space_identifier, default="default")
    parser.add_argument("--enqueue", action="store_true")
    args = parser.parse_args()
    report = run_test(
        ROOT, AlertHttp(args.es), AlertHttp(args.kibana), space=args.space, enqueue=args.enqueue
    )
    try:
        destination = ROOT / REPORT_PATH
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_json(destination, report)
    except OSError:
        report.update(status="failed", errors=["cannot write local notification test report"])
    print(json.dumps(report, indent=2))
    return int(report["status"] == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
