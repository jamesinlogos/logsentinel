"""Regression checks for redacted Kibana status and read-only saved dashboard discovery."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import verify_dashboards as verifier  # noqa: E402


class MemoryReader(verifier.HttpReader):
    """Provide explicit endpoint responses without opening a socket or writing remotely."""

    def __init__(self, responses: dict[str, dict[str, Any] | verifier.HttpReadError]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def get(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        assert body is None
        self.calls.append(path)
        response = self.responses[path]
        if isinstance(response, verifier.HttpReadError):
            raise response
        return copy.deepcopy(response)


class EmptyElasticsearch(verifier.HttpReader):
    """Return complete empty searches, isolating Kibana checks from historical data state."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        assert "/_search?" in path
        assert body is not None and body["size"] == 0
        self.calls.append(path)
        aggregates: dict[str, Any] = {}
        for name, definition in body["aggs"].items():
            if "filters" in definition:
                aggregates[name] = {
                    "buckets": {
                        bucket: {"doc_count": 0} for bucket in definition["filters"]["filters"]
                    }
                }
            elif "terms" in definition:
                aggregates[name] = {"buckets": [], "sum_other_doc_count": 0}
            else:
                aggregates[name] = {"value": None}
        return {
            "_shards": {"total": 0, "successful": 0, "failed": 0},
            "hits": {"total": {"value": 0, "relation": "eq"}},
            "aggregations": aggregates,
        }


class NoIndexElasticsearch(verifier.HttpReader):
    """A freshly built stack: Elasticsearch answers a search over no index without aggregations."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        assert "/_search?" in path
        self.calls.append(path)
        return {
            "took": 0,
            "timed_out": False,
            "_shards": {"total": 0, "successful": 0, "skipped": 0, "failed": 0},
            "hits": {"total": {"value": 0, "relation": "eq"}, "max_score": None, "hits": []},
        }


def messages(report: verifier.Report, level: str) -> list[str]:
    return [check["message"] for check in report.checks if check["level"] == level]


def test_a_stack_without_any_index_warns_instead_of_failing() -> None:
    kibana = MemoryReader(
        {
            "api/status": {
                "status": {"overall": {"level": "available"}},
                "version": {"number": "9.5.3"},
            }
        }
    )
    elasticsearch = NoIndexElasticsearch()
    report = verifier.Report()
    usage = verifier.FieldUsage()
    usage.add(verifier.PATTERNS[1], "host.id")

    verifier.verify_live(elasticsearch, kibana, usage, report)

    assert report.failed == 0
    assert len(elasticsearch.calls) == len(
        verifier.PATTERNS
    )  # no field_caps call for a missing index
    assert len(messages(report, "WARN")) == len(verifier.PATTERNS)
    assert report.observed["indices"] == {
        pattern: {"documents": 0} for pattern in verifier.PATTERNS
    }


def test_redacted_status_uses_stats_version_without_a_false_compatibility_failure() -> None:
    kibana = MemoryReader(
        {
            "api/status": {"status": {"overall": {"level": "available"}}},
            "api/stats?extended=true": {"kibana": {"version": "9.5.3"}},
        }
    )
    elasticsearch = EmptyElasticsearch()
    report = verifier.Report()

    verifier.verify_live(elasticsearch, kibana, verifier.FieldUsage(), report)

    assert report.failed == 0
    assert report.observed["kibana"] == {
        "version": "9.5.3",
        "status": "available",
        "version_source": "api/stats?extended=true",
    }
    assert kibana.calls == ["api/status", "api/stats?extended=true"]
    assert len(elasticsearch.calls) == len(verifier.PATTERNS)
    assert not any("compatibility" in message for message in messages(report, "WARN"))


@pytest.mark.parametrize(
    "stats",
    [{}, {"kibana": {"version": "unknown"}}, verifier.HttpReadError("unavailable")],
    ids=["redacted-stats", "unknown-version", "unavailable-stats"],
)
def test_unavailable_version_warns_that_compatibility_is_unverified(
    stats: dict[str, Any] | verifier.HttpReadError,
) -> None:
    kibana = MemoryReader(
        {
            "api/status": {"status": {"overall": {"level": "available"}}},
            "api/stats?extended=true": stats,
        }
    )
    report = verifier.Report()

    verifier.verify_live(EmptyElasticsearch(), kibana, verifier.FieldUsage(), report)

    assert report.failed == 0
    assert report.observed["kibana"]["version_source"] is None
    assert any(
        "Dashboard API compatibility is unverified" in message
        for message in messages(report, "WARN")
    )
    assert kibana.calls == ["api/status", "api/stats?extended=true"]


@pytest.mark.parametrize("redacted", [False, True], ids=["status-version", "stats-version"])
def test_known_older_kibana_version_fails_even_when_the_service_is_available(
    redacted: bool,
) -> None:
    status: dict[str, Any] = {"status": {"overall": {"level": "available"}}}
    if not redacted:
        status["version"] = {"number": "9.4.9"}
    kibana = MemoryReader(
        {
            "api/status": status,
            "api/stats?extended=true": {"kibana": {"version": "9.4.9"}},
        }
    )
    report = verifier.Report()

    verifier.verify_live(EmptyElasticsearch(), kibana, verifier.FieldUsage(), report)

    assert report.failed == 1
    assert messages(report, "FAIL") == ["portable Dashboard API requires Kibana 9.5 or later"]
    assert kibana.calls == ["api/status"] + (["api/stats?extended=true"] if redacted else [])


@pytest.fixture
def dashboard_repository(tmp_path: Path) -> Path:
    folder = tmp_path / "dashboard"
    folder.mkdir()
    (folder / "example-dashboard.json").write_text(
        json.dumps({"title": "Example dashboard", "panels": [{"id": "evidence-panel"}]}),
        encoding="utf-8",
    )
    return tmp_path


def test_missing_saved_dashboard_is_observed_as_uninstalled_without_a_failure(
    dashboard_repository: Path,
) -> None:
    kibana = MemoryReader(
        {"api/dashboards/example-dashboard": verifier.HttpReadError("HTTP 404", status_code=404)}
    )
    report = verifier.Report()

    verifier.verify_installed(kibana, dashboard_repository, report)

    assert report.failed == 0
    assert report.observed["dashboards"] == {
        "space": "default",
        "definitions": {"example-dashboard": {"installed": False}},
    }
    assert any("not installed" in message for message in messages(report, "WARN"))
    assert kibana.calls == ["api/dashboards/example-dashboard"]


def test_forbidden_saved_dashboard_is_a_failed_check_not_an_absence(
    dashboard_repository: Path,
) -> None:
    kibana = MemoryReader(
        {"api/dashboards/example-dashboard": verifier.HttpReadError("HTTP 403", status_code=403)}
    )
    report = verifier.Report()

    verifier.verify_installed(kibana, dashboard_repository, report)

    assert report.failed == 1
    assert report.observed["dashboards"]["definitions"] == {}
    assert not messages(report, "WARN")
    assert "saved dashboard check incomplete" in messages(report, "FAIL")[0]


@pytest.mark.parametrize(
    ("title", "panels", "level", "fragment"),
    [
        ("Example dashboard", [{"id": "evidence-panel"}], "OK", "browser rendering is unverified"),
        ("Different title", [{"id": "evidence-panel"}], "FAIL", "saved title differs"),
        ("Example dashboard", [], "WARN", "saved panel count differs"),
    ],
    ids=["matching-definition", "different-title", "different-panel-count"],
)
def test_saved_title_and_panel_count_checks_do_not_assert_browser_rendering(
    dashboard_repository: Path,
    title: str,
    panels: list[dict[str, str]],
    level: str,
    fragment: str,
) -> None:
    kibana = MemoryReader(
        {"api/dashboards/example-dashboard": {"data": {"title": title, "panels": panels}}}
    )
    report = verifier.Report()

    verifier.verify_installed(kibana, dashboard_repository, report)

    assert report.failed == int(level == "FAIL")
    assert report.observed["dashboards"]["definitions"]["example-dashboard"] == {
        "installed": True,
        "title": title,
        "panel_count": len(panels),
    }
    assert any(fragment in message for message in messages(report, level))
    assert kibana.calls == ["api/dashboards/example-dashboard"]
