"""Check explicit synthetic enqueue and receipt verification against fake local APIs."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import notification_test as notices  # noqa: E402

IDENTIFIER = "notification-test:" + "a" * 32
CREATED = "2026-10-31T23:59:59.000000Z"


class MemoryHttp(notices.AlertHttp):
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, Any]] = []

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        allow_missing: bool = False,
    ) -> Any:
        self.calls.append((method, path, copy.deepcopy(body)))
        assert self.responses, f"unexpected {method} {path}"
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        if result is None:
            assert allow_missing
        return copy.deepcopy(result)


def save_identity(root: Path, **extra: Any) -> None:
    path = root / notices.REPORT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "test_id": IDENTIFIER,
                "event_created": CREATED,
                "space": "default",
                "enqueued": True,
                **extra,
            }
        ),
        encoding="utf-8",
    )


def receipt(channel: str, *, sent: bool = True, identifier: str = IDENTIFIER) -> dict[str, Any]:
    return {
        "found": True,
        "_source": {
            "logsentinel": {
                "notification": {
                    "id": identifier,
                    "channel": channel,
                    "sent": sent,
                    "attempts": 1,
                }
            },
            "private": "response-secret-must-not-appear",
        },
    }


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def preflight(root: Path, es: Any, kibana: Any, **kwargs: Any) -> dict[str, Any]:
        assert es.calls == [] and kibana.calls == []
        calls.append({"root": root, **kwargs})
        return {"status": "unchanged"}

    monkeypatch.setattr(notices, "setup", preflight)
    return calls


def test_no_saved_test_reads_no_apis(tmp_path: Path) -> None:
    es, kibana = MemoryHttp([]), MemoryHttp([])
    report = notices.run_test(tmp_path, es, kibana)
    assert report["status"] == "no_test_yet"
    assert es.calls == kibana.calls == []


def test_default_checks_both_receipts_without_kibana_or_mutations(tmp_path: Path) -> None:
    save_identity(tmp_path, private="local-secret-must-not-appear")
    es = MemoryHttp([receipt("telegram"), receipt("gmail")])
    kibana = MemoryHttp([])
    report = notices.run_test(tmp_path, es, kibana)
    assert report["status"] == "accepted"
    assert all(value["sent"] for value in report["channels"].values())
    assert kibana.calls == []
    for channel, (method, path, body) in zip(notices.CHANNELS, es.calls, strict=True):
        digest = hashlib.sha256(f"{IDENTIFIER}\0{channel}".encode()).hexdigest()
        assert method == "GET" and body is None
        assert path == f"/ransomware-notification-deliveries-2026.10/_doc/{digest}"
    assert "secret" not in str(report)


def test_missing_or_failed_channel_remains_queued(tmp_path: Path) -> None:
    save_identity(tmp_path)
    report = notices.run_test(
        tmp_path, MemoryHttp([None, receipt("gmail", sent=False)]), MemoryHttp([])
    )
    assert report["status"] == "queued"
    assert report["channels"]["telegram"] == {"status": "pending", "sent": False}
    assert report["channels"]["gmail"] == {"status": "retrying", "sent": False, "attempts": 1}


@pytest.mark.parametrize("change", ["id", "channel", "sent", "attempts", "found"])
def test_invalid_receipt_never_claims_success_or_exposes_response(
    tmp_path: Path, change: str
) -> None:
    save_identity(tmp_path)
    value = receipt("telegram")
    fields = value["_source"]["logsentinel"]["notification"]
    if change == "found":
        value["found"] = False
    else:
        fields[change] = {"id": "foreign", "channel": "gmail", "sent": 1, "attempts": 0}[change]
    report = notices.run_test(tmp_path, MemoryHttp([value]), MemoryHttp([]))
    assert report["status"] == "failed" and "secret" not in str(report)


@pytest.mark.parametrize(
    "identity",
    [
        {"test_id": "../../private"},
        {"event_created": "2026-10-31T23:59:59"},
        {"event_created": "invalid-secret"},
        {"space": "other-space"},
    ],
)
def test_bad_saved_identity_stops_before_network(tmp_path: Path, identity: dict[str, Any]) -> None:
    save_identity(tmp_path, **identity)
    es, kibana = MemoryHttp([]), MemoryHttp([])
    report = notices.run_test(tmp_path, es, kibana)
    assert report["status"] == "failed" and es.calls == kibana.calls == []
    assert "secret" not in str(report)


def test_explicit_enqueue_calls_connector_once_after_readonly_preflight(
    tmp_path: Path,
    installed: list[dict[str, Any]],
) -> None:
    es, kibana = MemoryHttp([None, None]), MemoryHttp([{"status": "ok", "private": "secret"}])
    report = notices.run_test(tmp_path, es, kibana, space="lab", enqueue=True)
    assert report["status"] == "queued" and report["enqueued"] is True
    assert installed == [{"root": tmp_path, "space": "lab"}]
    assert len(kibana.calls) == 1
    method, path, body = kibana.calls[0]
    assert method == "POST" and path == (
        "/s/lab/api/actions/connector/ransomware-notifications/_execute"
    )
    assert len(body["params"]["documents"]) == 1
    document = body["params"]["documents"][0]
    assert document["event"]["id"] == report["test_id"]
    assert notices.TEST_ID.fullmatch(report["test_id"])
    assert document["event"]["created"] == report["event_created"]
    assert notices.created_time(report["event_created"]).tzinfo is not None
    assert document["message"].startswith("TEST:")
    assert not {"host", "process", "threat"} & document.keys()
    assert "message" not in report and "secret" not in str(report)
    assert all(method == "GET" for method, _, _ in es.calls)


def test_each_explicit_enqueue_has_a_new_test_identity(
    tmp_path: Path,
    installed: list[dict[str, Any]],
) -> None:
    first = notices.run_test(
        tmp_path, MemoryHttp([None, None]), MemoryHttp([{"status": "ok"}]), enqueue=True
    )
    second = notices.run_test(
        tmp_path, MemoryHttp([None, None]), MemoryHttp([{"status": "ok"}]), enqueue=True
    )
    assert first["test_id"] != second["test_id"]
    assert len(installed) == 2


@pytest.mark.parametrize("status", ["ready", "failed", "applied"])
def test_enqueue_refuses_incomplete_or_changed_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    monkeypatch.setattr(
        notices,
        "setup",
        lambda *_args, **_kwargs: {
            "status": status,
            "errors": ["secret-must-not-appear"],
        },
    )
    es, kibana = MemoryHttp([]), MemoryHttp([])
    report = notices.run_test(tmp_path, es, kibana, enqueue=True)
    assert report["status"] == "failed" and report["enqueued"] is False
    assert es.calls == kibana.calls == [] and "secret" not in str(report)


@pytest.mark.parametrize(
    "response",
    [
        {"status": "error", "message": "secret-response"},
        {"unexpected": "secret-response"},
        notices.DashboardError("secret-response"),
    ],
)
def test_execute_failure_keeps_identity_without_leaking_provider_data(
    tmp_path: Path,
    installed: list[dict[str, Any]],
    response: Any,
) -> None:
    es, kibana = MemoryHttp([]), MemoryHttp([response])
    report = notices.run_test(tmp_path, es, kibana, enqueue=True)
    assert report["status"] == "failed" and report["enqueued"] is False
    assert notices.TEST_ID.fullmatch(report["test_id"])
    assert len(kibana.calls) == 1 and es.calls == [] and "secret" not in str(report)


def test_receipt_transport_failure_does_not_expose_credentials(tmp_path: Path) -> None:
    save_identity(tmp_path)
    report = notices.run_test(
        tmp_path, MemoryHttp([notices.DashboardError("password=secret")]), MemoryHttp([])
    )
    assert report["status"] == "failed" and "secret" not in str(report)


def test_main_default_persists_only_local_no_test_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(notices, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["notification_test.py"])
    assert notices.main() == 0
    saved = json.loads((tmp_path / notices.REPORT_PATH).read_text(encoding="utf-8"))
    assert saved["status"] == "no_test_yet"
    assert json.loads(capsys.readouterr().out) == saved
    assert notices.main() == 0
