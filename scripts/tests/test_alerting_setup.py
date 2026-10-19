"""Safety checks for Kibana rule creation against mocked complete and partial searches."""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import alerting_setup as alerting  # noqa: E402


class MemoryHttp(alerting.AlertHttp):
    """Route known requests and retain only mocked request bodies for assertions."""

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

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
        response = self.responses.pop(0)
        if response is None:
            assert allow_missing
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response)


@pytest.fixture
def definition() -> dict[str, Any]:
    return alerting.load_rule(Path(__file__).resolve().parents[2])


def search(count: int = 7) -> dict[str, Any]:
    return {
        "timed_out": False,
        "_shards": {"total": 2, "successful": 2, "failed": 0},
        "hits": {
            "total": {"value": count, "relation": "eq"},
            "hits": [{"_source": {"private": "must never appear in reports"}}],
        },
        "aggregations": {
            "first": {"value": 1_700_000_000_000 if count else None},
            "last": {"value": 1_700_000_001_000 if count else None},
        },
    }


def client(existing: Any, *later: Any, key: bool = True, secure: bool = True) -> MemoryHttp:
    return MemoryHttp(
        [
            {"has_permanent_encryption_key": key, "is_sufficiently_secure": secure},
            [{"id": ".es-query", "enabled_in_license": True}],
            existing,
            *later,
        ]
    )


def test_missing_key_still_reports_counts_but_never_creates(definition: dict[str, Any]) -> None:
    es = MemoryHttp([search(), search(0)])
    kibana = client(None, key=False)

    report = alerting.setup(es, kibana, definition, apply=True)

    assert report["status"] == "blocked"
    assert "encryptionKey" in report["errors"][0]
    assert report["query"]["historical"]["count"] == 7
    assert report["query"]["current"]["count"] == 0
    assert all(method == "GET" for method, _, _ in kibana.calls)
    assert "private" not in str(report)


def test_insecure_health_never_creates(definition: dict[str, Any]) -> None:
    kibana = client(None, secure=False)
    report = alerting.setup(MemoryHttp([search(), search()]), kibana, definition, apply=True)
    assert report["status"] == "blocked"
    assert all(method == "GET" for method, _, _ in kibana.calls)


def test_existing_different_rule_is_refused(definition: dict[str, Any]) -> None:
    different = copy.deepcopy(definition)
    different["schedule"]["interval"] = "10m"
    kibana = client(different)

    report = alerting.setup(MemoryHttp([search(), search()]), kibana, definition, apply=True)

    assert report["status"] == "blocked"
    assert "existing rule differs" in report["errors"][0]
    assert all(method == "GET" for method, _, _ in kibana.calls)


def test_identical_rule_with_server_defaults_is_a_noop(definition: dict[str, Any]) -> None:
    existing = copy.deepcopy(definition)
    existing.update(
        id=alerting.RULE_ID,
        created_by=None,
        api_key_owner=None,
        mute_all=False,
        alert_delay={"active": 1},
        execution_status={"status": "ok"},
    )
    existing["params"]["sourceFields"] = []
    existing["tags"].reverse()
    kibana = client(existing)

    report = alerting.setup(MemoryHttp([search(), search()]), kibana, definition, apply=True)

    assert report["status"] == "unchanged"
    assert all(method == "GET" for method, _, _ in kibana.calls)


@pytest.mark.parametrize("failure", ["timed-out", "partial", "inexact", "failed", "missing-date"])
def test_incomplete_search_prevents_creation(definition: dict[str, Any], failure: str) -> None:
    result = search()
    if failure == "timed-out":
        result["timed_out"] = True
    elif failure == "partial":
        result["_shards"]["successful"] = 1
    elif failure == "failed":
        result["_shards"]["failed"] = 1
    elif failure == "inexact":
        result["hits"]["total"]["relation"] = "gte"
    else:
        result["aggregations"]["first"]["value"] = None
    kibana = client(None)

    report = alerting.setup(MemoryHttp([search(), result]), kibana, definition, apply=True)

    assert report["status"] == "failed"
    assert all(method == "GET" for method, _, _ in kibana.calls)


def test_transport_failure_prevents_creation(definition: dict[str, Any]) -> None:
    kibana = client(None)
    es = MemoryHttp([alerting.DashboardError("GET detection query: HTTP 503")])
    report = alerting.setup(es, kibana, definition, apply=True)
    assert report["status"] == "failed"
    assert all(method == "GET" for method, _, _ in kibana.calls)


def test_read_back_mismatch_is_reported_without_automatic_cleanup(
    definition: dict[str, Any],
) -> None:
    different = copy.deepcopy(definition)
    different["enabled"] = False
    kibana = client(None, definition, different)

    report = alerting.setup(MemoryHttp([search(), search()]), kibana, definition, apply=True)

    assert report["status"] == "failed"
    assert report["created"] is True
    assert "read-back differs" in report["errors"][0]
    assert [method for method, _, _ in kibana.calls] == ["GET", "GET", "GET", "POST", "GET"]


def test_successful_creation_is_verified_and_counts_never_request_documents(
    definition: dict[str, Any],
) -> None:
    before = copy.deepcopy(definition)
    es = MemoryHttp([search(), search(0)])
    kibana = client(None, definition, definition)

    report = alerting.setup(es, kibana, definition, apply=True, space="lab")

    assert report["status"] == "created"
    assert definition == before
    assert all("/s/lab/api/alerting/" in path for _, path, _ in kibana.calls)
    historical, current = [body for _, _, body in es.calls]
    assert historical is not None and current is not None
    for body in (historical, current):
        assert body["size"] == 0 and body["track_total_hits"] is True
        assert "_source" not in body and "fields" not in body
    assert "now-5m" not in str(historical)
    assert "now-5m" in str(current)
    assert report["query"]["historical"]["count"] == 7
    assert "private" not in str(report)


def test_default_mode_preflights_without_creating(definition: dict[str, Any]) -> None:
    kibana = client(None)
    report = alerting.setup(MemoryHttp([search(0), search(0)]), kibana, definition)
    assert report["status"] == "ready"
    assert all(method == "GET" for method, _, _ in kibana.calls)


def test_extra_meaningful_parameter_is_not_ignored(definition: dict[str, Any]) -> None:
    existing = copy.deepcopy(definition)
    existing["params"]["excludeHitsFromPreviousRun"] = False
    assert not alerting.rule_matches(definition, existing)


def test_installed_managed_notification_action_preserves_base_setup(
    definition: dict[str, Any],
) -> None:
    import json

    path = alerting.ROOT / "config/kibana/actions/ransomware-notifications.json"
    installed = copy.deepcopy(definition)
    installed["actions"] = [json.loads(path.read_text(encoding="utf-8"))]
    kibana = client(installed)
    report = alerting.setup(MemoryHttp([search(), search(0)]), kibana, definition, apply=True)
    assert report["status"] == "unchanged"
    assert all(method == "GET" for method, _, _ in kibana.calls)
    assert not alerting.rule_matches(definition, installed)


def test_changed_notification_action_is_not_silently_accepted(definition: dict[str, Any]) -> None:
    import json

    path = alerting.ROOT / "config/kibana/actions/ransomware-notifications.json"
    installed = copy.deepcopy(definition)
    installed["actions"] = [json.loads(path.read_text(encoding="utf-8"))]
    installed["actions"][0]["frequency"]["notify_when"] = "onActionGroupChange"
    assert not alerting.installed_rule_matches(definition, installed)
