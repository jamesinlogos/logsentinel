"""Regression checks for dashboard meanings and explicit, recoverable Kibana writes."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import sys
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import dashboard_definitions as definitions  # noqa: E402
import dashboard_setup as setup  # noqa: E402
import verify_dashboards as verifier  # noqa: E402


@pytest.fixture
def source_repository(tmp_path: Path) -> Path:
    """Use generated definitions and the real checked-in mappings, without source event data."""
    folder = tmp_path / "dashboard"
    folder.mkdir()
    for name, body in definitions.definitions().items():
        (folder / f"{name}.json").write_text(json.dumps(body), encoding="utf-8")
    shutil.copytree(
        SCRIPTS.parent / "config" / "elasticsearch", tmp_path / "config" / "elasticsearch"
    )
    return tmp_path


def panel_named(body: dict[str, Any], title: str) -> dict[str, Any]:
    return next(
        panel["config"] for panel in body["panels"] if panel["config"].get("title") == title
    )


def in_numeric_filter(value: float, bucket: dict[str, Any], field: str) -> bool:
    clauses = re.split(r"\s+and\s+", bucket["filter"]["expression"], flags=re.IGNORECASE)
    assert len(clauses) == 2
    matched = []
    for clause in clauses:
        comparison = re.fullmatch(re.escape(field) + r"\s*(>=|<=|>|<)\s*(-?\d+(?:\.\d+)?)", clause)
        assert comparison is not None, f"Expected a numeric comparison on {field}: {clause}"
        operation, limit = comparison.groups()
        threshold = float(limit)
        matched.append(
            {
                ">=": value >= threshold,
                ">": value > threshold,
                "<=": value <= threshold,
                "<": value < threshold,
            }[operation]
        )
    return all(matched)


@pytest.mark.parametrize(
    ("pattern", "field", "maximum"),
    [
        (definitions.SCORES, "logsentinel.verdict.scores.model", 1),
        (definitions.DETECTIONS, "event.risk_score_norm", 100),
    ],
)
def test_score_histograms_keep_zero_and_every_boundary_once(
    pattern: str, field: str, maximum: int
) -> None:
    config = definitions.distribution(pattern, "Score", field, maximum)
    layer = config["layers"][0]
    assert layer["data_source"]["index_pattern"] == pattern
    assert layer["x"]["operation"] == "filters"
    buckets = layer["x"]["filters"]
    for value in [0.0, maximum * 0.025, *(maximum * index / 10 for index in range(1, 11))]:
        assert sum(in_numeric_filter(value, bucket, field) for bucket in buckets) == 1
    assert not any(in_numeric_filter(-1, bucket, field) for bucket in buckets)
    assert not any(in_numeric_filter(maximum + 1, bucket, field) for bucket in buckets)


def test_window_states_partition_valid_verdicts_without_a_gate_prefilter() -> None:
    body = definitions.window_scores().body
    config = next(
        panel["config"]
        for panel in body["panels"]
        if panel["config"].get("type") == "pie"
        and panel["config"].get("group_by", [{}])[0].get("operation") == "filters"
        and len(panel["config"]["group_by"][0]["filters"]) == 5
    )
    assert not body["query"]["expression"]
    assert not config.get("query", {}).get("expression")
    buckets = config["group_by"][0]["filters"]
    assert len(buckets) == 5
    valid_verdicts = [(False, False, False)] + [
        (True, reported, suspicious) for reported in (False, True) for suspicious in (False, True)
    ]
    for gated, reported, suspicious in valid_verdicts:
        values = {"gated": gated, "reported": reported, "suspicious": suspicious}
        matching = 0
        for bucket in buckets:
            clauses = bucket["filter"]["expression"].split(" and ")
            matches = []
            for clause in clauses:
                field, value = clause.split(": ")
                assert field.startswith(definitions.VERDICT)
                matches.append(values[field.removeprefix(definitions.VERDICT)] == (value == "true"))
            matching += all(matches)
        assert matching == 1


def test_pie_dimensions_do_not_turn_overlapping_arrays_into_shares() -> None:
    overlapping_fields = {
        "logsentinel.verdict.indicators",
        "threat.tactic.name",
        "threat.technique.id",
        "threat.technique.subtechnique.id",
        "event.category",
        "event.type",
        "tags",
        "host.ip",
    }
    pies = []
    for body in definitions.definitions().values():
        for panel in body["panels"]:
            config = panel["config"]
            if config.get("type") != "pie":
                continue
            pies.append(config)
            usage = verifier.FieldUsage()
            verifier.collect_fields(config, set(), usage)
            referenced = set().union(*usage.fields.values())
            assert not referenced & overlapping_fields
            assert all(metric["operation"] == "count" for metric in config["metrics"])
    assert pies


def test_raw_activity_counts_are_not_summed_or_stacked_across_overlapping_windows() -> None:
    activities = []
    for body in definitions.definitions().values():
        for panel in body["panels"]:
            for layer in panel["config"].get("layers", []):
                values = [
                    value
                    for value in layer.get("y", [])
                    if value.get("field", "").startswith(definitions.ACTIVITY)
                ]
                if values:
                    activities.extend(values)
                    assert all(value["operation"] != "sum" for value in values)
                    assert layer["type"] not in {
                        "area_stacked",
                        "area_percentage",
                        "bar_stacked",
                        "bar_percentage",
                    }
    assert activities


def test_time_series_lines_and_areas_do_not_invent_values_across_gaps() -> None:
    temporal_charts = []
    for body in definitions.definitions().values():
        for panel in body["panels"]:
            config = panel["config"]
            layers = [
                layer
                for layer in config.get("layers", [])
                if layer.get("type") == "line" or layer.get("type", "").startswith("area")
            ]
            if layers:
                temporal_charts.append(config)
                count_only_areas = all(
                    layer["type"].startswith("area")
                    and layer.get("y")
                    and all(value.get("operation") == "count" for value in layer["y"])
                    for layer in layers
                )
                assert config.get("styling", {}).get("fitting") == {
                    "type": "zero" if count_only_areas else "none",
                    "extend": "none",
                }
                if count_only_areas:
                    assert config["styling"].get("interpolation") == "stepped"
    assert temporal_charts


def test_time_breakdowns_keep_empty_date_buckets_inside_each_series() -> None:
    series = []
    for body in definitions.definitions().values():
        for panel in body["panels"]:
            for layer in panel["config"].get("layers", []):
                breakdown = layer.get("breakdown_by")
                if layer.get("x", {}).get("operation") == "date_histogram" and breakdown:
                    series.append(breakdown)
                    assert breakdown.get("aggregate_first") is True
    assert series
    assert {breakdown["operation"] for breakdown in series} >= {"terms", "filters"}


@pytest.mark.parametrize("comparison", [">=", ">", "<=", "<"])
def test_verifier_collects_kql_numeric_fields_without_requiring_aggregation(
    comparison: str,
) -> None:
    usage = verifier.FieldUsage()
    field = "logsentinel.verdict.scores.model"
    verifier.collect_fields(
        {
            "data_source": definitions.source(definitions.SCORES),
            "query": definitions.query(f"{field} {comparison} 0.5"),
        },
        set(),
        usage,
    )
    assert field in usage.fields[definitions.SCORES]
    assert field not in usage.aggregatable.get(definitions.SCORES, set())


def test_all_generated_data_panels_are_independent_of_saved_objects() -> None:
    for body in definitions.definitions().values():
        for node in verifier.walk(body):
            assert "ref_id" not in node
            assert node.get("type") != "data_view_reference"
            assert not node.get("references")
        for panel in body["panels"]:
            if panel["type"] != "markdown":
                sources = [
                    node
                    for node in verifier.walk(panel["config"])
                    if node.get("type") == "data_view_spec"
                ]
                assert sources
                assert all(source["time_field"] == "@timestamp" for source in sources)


def test_rate_denominators_share_the_unfiltered_window_score_stream() -> None:
    ratios = []
    for body in definitions.definitions().values():
        for panel in body["panels"]:
            config = panel["config"]
            for node in verifier.walk(config):
                expression = node.get("formula", "")
                if "/" not in expression:
                    continue
                ratios.append(expression)
                assert config["data_source"]["index_pattern"] == definitions.SCORES
                assert not config.get("query", {}).get("expression")
                denominator = expression.rsplit("/", 1)[1].strip()
                if "reported" in expression or "suspicious" in expression:
                    assert denominator == "count(kql='logsentinel.verdict.gated: true')"
                else:
                    assert denominator == "count()"
    assert ratios


@pytest.mark.parametrize("defect", ["overlap", "outside", "boolean_coordinate"])
def test_static_verifier_rejects_broken_dashboard_layouts(
    source_repository: Path, defect: str
) -> None:
    path = source_repository / "dashboard" / "logsentinel-overview.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    if defect == "overlap":
        body["panels"][1]["grid"] = body["panels"][0]["grid"].copy()
    elif defect == "outside":
        body["panels"][0]["grid"]["w"] = 49
    else:
        body["panels"][0]["grid"]["x"] = False
    path.write_text(json.dumps(body), encoding="utf-8")
    report = verifier.Report()
    verifier.verify_static(source_repository, report)
    assert report.failed
    messages = [check["message"] for check in report.checks if check["level"] == "FAIL"]
    expected = {"overlap": "overlaps", "outside": "48-column", "boolean_coordinate": "integer"}
    assert any(expected[defect] in message for message in messages)


@pytest.mark.parametrize(
    "change",
    [
        {"timed_out": True},
        {"_shards": {"failed": 1}},
        {"hits": {"total": {"value": 10, "relation": "gte"}}},
    ],
)
def test_verifier_rejects_http_success_with_incomplete_searches(change: dict[str, Any]) -> None:
    result = {"_shards": {"failed": 0}, "hits": {"total": {"value": 10, "relation": "eq"}}}
    result.update(change)
    with pytest.raises(verifier.HttpReadError):
        verifier.complete_search(result)


class JsonResponse:
    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body

    def __enter__(self) -> JsonResponse:
        return self

    def __exit__(self, *arguments: Any) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.body).encode("utf-8")


class KibanaTransport:
    """An in-memory HTTP boundary that checks backup durability at the first write."""

    def __init__(
        self,
        root: Path,
        targets: dict[str, dict[str, Any]],
        initial: dict[str, dict[str, Any]],
        fail_id: str | None = None,
        redacted_status: bool = False,
    ) -> None:
        self.root = root
        self.targets = targets
        self.initial = copy.deepcopy(initial)
        self.saved = copy.deepcopy(initial)
        self.calls: list[tuple[str, str]] = []
        self.fail_id = fail_id
        self.redacted_status = redacted_status

    def __call__(self, request: Any, timeout: int) -> JsonResponse:
        method = request.get_method()
        path = request.full_url.removeprefix("http://localhost:5601")
        self.calls.append((method, path))
        assert timeout > 0
        if path == "/api/status":
            assert method == "GET"
            if self.redacted_status:
                return JsonResponse({"status": {"overall": {"level": "available"}}})
            return JsonResponse({"version": {"number": "9.5.3"}})
        if path == "/api/stats?extended=true":
            assert method == "GET"
            return JsonResponse({"kibana": {"version": "9.5.3"}})
        dashboard_id = path.rsplit("/", 1)[-1]
        if method == "GET":
            if dashboard_id not in self.saved:
                raise urllib.error.HTTPError(request.full_url, 404, "missing", Message(), None)
            return JsonResponse({"id": dashboard_id, "data": self.saved[dashboard_id]})
        assert method == "PUT"
        self.check_backup_before_write()
        if dashboard_id == self.fail_id:
            raise urllib.error.HTTPError(
                request.full_url, 502, "controlled failure", Message(), None
            )
        payload = json.loads(request.data)
        assert payload == self.targets[dashboard_id]  # Dashboard API body is flat, not {data: ...}.
        self.saved[dashboard_id] = payload
        return JsonResponse({"id": dashboard_id, "data": payload})

    def check_backup_before_write(self) -> None:
        first_write = next(index for index, call in enumerate(self.calls) if call[0] == "PUT")
        status_calls = [("GET", "/api/status")]
        if self.redacted_status:
            status_calls.append(("GET", "/api/stats?extended=true"))
        assert self.calls[:first_write] == status_calls + [
            ("GET", f"/api/dashboards/{dashboard_id}") for dashboard_id in self.targets
        ]
        folders = list((self.root / "archives" / "backups").glob("*-dashboard-kibana"))
        assert len(folders) == 1
        directory = folders[0]
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        assert {row["id"] for row in manifest["dashboards"]} == set(self.targets)
        for row in manifest["dashboards"]:
            existed = row["id"] in self.initial
            assert row["existed"] is existed
            if existed:
                backed_up = json.loads((directory / row["backup_file"]).read_text(encoding="utf-8"))
                assert backed_up["data"] == self.initial[row["id"]]
        for line in (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            checksum, filename = line.split("  ")
            assert hashlib.sha256((directory / filename).read_bytes()).hexdigest() == checksum


def target_definitions() -> dict[str, dict[str, Any]]:
    return {
        "first": {"title": "First", "description": "Updated first dashboard"},
        "second": {"title": "Second", "description": "New second dashboard"},
        "third": {"title": "Third", "description": "New third dashboard"},
    }


def test_readback_accepts_only_omission_of_an_exactly_empty_kql_query() -> None:
    expected = definitions.chart(
        definitions.SCORES,
        "Scored windows",
        definitions.timeline(),
        [definitions.count("Windows")],
    )
    actual = copy.deepcopy(expected)
    actual.pop("query")
    assert setup.contains_definition(expected, actual)
    for query in (
        {"language": "kql", "expression": "logsentinel.verdict.gated: true"},
        {"language": "lucene", "expression": ""},
        {"language": "kql", "expression": "", "unexpected": True},
    ):
        assert not setup.contains_definition({**expected, "query": query}, actual)
    actual["query"] = {"language": "kql", "expression": "logsentinel.verdict.gated: true"}
    assert not setup.contains_definition(expected, actual)


@pytest.mark.parametrize("defect", ["metric", "query", "order"])
def test_readback_still_rejects_changed_metric_query_or_panel_order(defect: str) -> None:
    expected: dict[str, Any] = {
        "panels": [
            {
                "id": "scored",
                "config": {
                    "query": {"language": "kql", "expression": ""},
                    "metrics": [{"operation": "count", "label": "Windows"}],
                },
            },
            {
                "id": "reported",
                "config": {
                    "query": {
                        "language": "kql",
                        "expression": "logsentinel.verdict.reported: true",
                    },
                    "metrics": [{"operation": "count", "label": "Reported"}],
                },
            },
        ]
    }
    actual = copy.deepcopy(expected)
    actual["panels"][0]["config"].pop("query")
    if defect == "metric":
        actual["panels"][0]["config"]["metrics"][0]["operation"] = "sum"
    elif defect == "query":
        actual["panels"][1]["config"].pop("query")
    else:
        actual["panels"].reverse()
    assert not setup.contains_definition(expected, actual)


def test_readback_accepts_omitted_root_absolute_mode_with_unchanged_date_endpoints() -> None:
    period = {"from": "2026-10-09T03:33:13.817Z", "to": "2026-10-12T04:18:00.001Z"}
    expected = {"time_range": {**period, "mode": "absolute"}}
    assert setup.contains_definition(expected, {"time_range": period})
    for key, value in (
        ("from", "2026-10-10T03:33:13.817Z"),
        ("to", "2026-10-13T04:18:00.001Z"),
        ("mode", "relative"),
    ):
        assert not setup.contains_definition(expected, {"time_range": {**period, key: value}})
    assert not setup.contains_definition(
        {"time_range": {"from": "now-1y", "to": "now", "mode": "absolute"}},
        {"time_range": {"from": "now-1y", "to": "now"}},
    )
    assert not setup.contains_definition(
        {"panels": [{"time_range": {**period, "mode": "absolute"}}]},
        {"panels": [{"time_range": period}]},
    )


def test_default_setup_never_contacts_or_changes_the_stack(
    source_repository: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(setup, "ROOT", source_repository)
    monkeypatch.setattr(
        setup.urllib.request, "urlopen", lambda *args, **kwargs: pytest.fail("HTTP")
    )
    before = {
        path.name: path.read_bytes() for path in (source_repository / "dashboard").glob("*.json")
    }
    assert setup.main([]) == 0
    assert "PLAN PUT /api/dashboards/logsentinel-overview" in capsys.readouterr().out
    assert not (source_repository / "archives").exists()
    assert all(
        (source_repository / "dashboard" / name).read_bytes() == value
        for name, value in before.items()
    )


def test_apply_preflights_all_targets_and_backs_up_before_any_put(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    targets = target_definitions()
    transport = KibanaTransport(
        tmp_path, targets, {"first": {"title": "First", "description": "Original"}}
    )
    monkeypatch.setattr(setup.urllib.request, "urlopen", transport)
    assert (
        setup.apply_definitions(
            tmp_path, targets, setup.JsonHttp("http://localhost:5601"), "default"
        )
        == 0
    )
    assert [call for call in transport.calls if call[0] == "PUT"] == [
        ("PUT", f"/api/dashboards/{dashboard_id}") for dashboard_id in targets
    ]
    manifest_path = next(tmp_path.glob("archives/backups/*/MANIFEST.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "complete"
    assert manifest["applied"] == list(targets)


def test_title_collision_refuses_every_remote_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = KibanaTransport(tmp_path, target_definitions(), {"second": {"title": "Unrelated"}})
    monkeypatch.setattr(setup.urllib.request, "urlopen", transport)
    with pytest.raises(setup.DashboardError, match="existing title differs"):
        setup.apply_definitions(
            tmp_path, target_definitions(), setup.JsonHttp("http://localhost:5601"), "default"
        )
    assert all(method == "GET" for method, _ in transport.calls)
    assert not (tmp_path / "archives").exists()


def test_failed_put_is_journalled_and_remaining_targets_are_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = KibanaTransport(tmp_path, target_definitions(), {}, fail_id="second")
    monkeypatch.setattr(setup.urllib.request, "urlopen", transport)
    assert (
        setup.apply_definitions(
            tmp_path, target_definitions(), setup.JsonHttp("http://localhost:5601"), "default"
        )
        == 1
    )
    manifest_path = next(tmp_path.glob("archives/backups/*/MANIFEST.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "partial_failure"
    assert manifest["applied"] == ["first"]
    assert manifest["failed"][0]["id"] == "second"
    assert manifest["in_progress"] == "second"
    assert not any(path.endswith("/third") and method != "GET" for method, path in transport.calls)
    assert all(method in {"GET", "PUT"} for method, _ in transport.calls)


def test_backup_failure_prevents_every_remote_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = KibanaTransport(tmp_path, target_definitions(), {})
    monkeypatch.setattr(setup.urllib.request, "urlopen", transport)

    def refuse_backup(*arguments: Any, **keywords: Any) -> Any:
        raise OSError("backup storage unavailable")

    monkeypatch.setattr(setup, "backup_definitions", refuse_backup)
    with pytest.raises(OSError, match="backup storage unavailable"):
        setup.apply_definitions(
            tmp_path, target_definitions(), setup.JsonHttp("http://localhost:5601"), "default"
        )
    assert all(method == "GET" for method, _ in transport.calls)


@pytest.mark.parametrize("version", ["9.4.9", "8.19.0"])
def test_unsupported_kibana_stops_before_dashboard_requests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    calls = []

    def respond(request: Any, timeout: int) -> JsonResponse:
        calls.append((request.get_method(), request.full_url))
        return JsonResponse({"version": {"number": version}})

    monkeypatch.setattr(setup.urllib.request, "urlopen", respond)
    with pytest.raises(setup.DashboardError, match="9.5 or later"):
        setup.apply_definitions(
            tmp_path, target_definitions(), setup.JsonHttp("http://localhost:5601"), "default"
        )
    assert calls == [("GET", "http://localhost:5601/api/status")]
    assert not (tmp_path / "archives").exists()


def test_redacted_status_reads_stats_version_before_dashboard_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = KibanaTransport(tmp_path, target_definitions(), {}, redacted_status=True)
    monkeypatch.setattr(setup.urllib.request, "urlopen", transport)
    assert (
        setup.apply_definitions(
            tmp_path, target_definitions(), setup.JsonHttp("http://localhost:5601"), "default"
        )
        == 0
    )
    assert transport.calls[:2] == [
        ("GET", "/api/status"),
        ("GET", "/api/stats?extended=true"),
    ]
    manifest_path = next(tmp_path.glob("archives/backups/*/MANIFEST.json"))
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["kibana_version"] == "9.5.3"


def test_unparseable_status_version_reads_stats_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def respond(request: Any, timeout: int) -> JsonResponse:
        calls.append((request.get_method(), request.full_url))
        if request.full_url.endswith("/api/status"):
            return JsonResponse({"version": {"number": "redacted"}})
        return JsonResponse({"kibana": {"version": "9.5.3"}})

    monkeypatch.setattr(setup.urllib.request, "urlopen", respond)
    assert setup.kibana_version(setup.JsonHttp("http://localhost:5601")) == "9.5.3"
    assert calls == [
        ("GET", "http://localhost:5601/api/status"),
        ("GET", "http://localhost:5601/api/stats?extended=true"),
    ]


@pytest.mark.parametrize("fallback", ["unavailable", "malformed", "unparseable", "old"])
def test_redacted_status_without_supported_stats_version_prevents_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fallback: str
) -> None:
    calls = []

    def respond(request: Any, timeout: int) -> JsonResponse:
        calls.append((request.get_method(), request.full_url))
        if request.full_url.endswith("/api/status"):
            return JsonResponse({"status": {"overall": {"level": "available"}}})
        if fallback == "unavailable":
            raise urllib.error.HTTPError(request.full_url, 503, "unavailable", Message(), None)
        if fallback == "malformed":
            return JsonResponse({"kibana": []})
        return JsonResponse({"kibana": {"version": "9.4.9" if fallback == "old" else "unknown"}})

    monkeypatch.setattr(setup.urllib.request, "urlopen", respond)
    with pytest.raises(setup.DashboardError):
        setup.apply_definitions(
            tmp_path, target_definitions(), setup.JsonHttp("http://localhost:5601"), "default"
        )
    assert calls == [
        ("GET", "http://localhost:5601/api/status"),
        ("GET", "http://localhost:5601/api/stats?extended=true"),
    ]
    assert not (tmp_path / "archives").exists()


def test_historical_range_reads_only_and_includes_latest_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def respond(request: Any, timeout: int) -> JsonResponse:
        assert request.get_method() == "GET"
        assert "/_search?" in request.full_url
        return JsonResponse(
            {
                "_shards": {"failed": 0},
                "aggregations": {"first": {"value": 1000}, "last": {"value": 1001}},
            }
        )

    monkeypatch.setattr(setup.urllib.request, "urlopen", respond)
    assert setup.historical_range(setup.JsonHttp("http://localhost:9200")) == {
        "from": "1970-01-01T00:00:00.999Z",
        "to": "1970-01-01T00:00:01.002Z",
        "mode": "absolute",
    }


@pytest.mark.parametrize("defect", ["missing_shards", "failed_shards", "error", "nan", "no_dates"])
def test_historical_range_rejects_partial_or_missing_data(
    monkeypatch: pytest.MonkeyPatch, defect: str
) -> None:
    response: dict[str, Any] = {
        "_shards": {"failed": 0},
        "aggregations": {"first": {"value": 1000}, "last": {"value": 1001}},
    }
    if defect == "missing_shards":
        response.pop("_shards")
    elif defect == "failed_shards":
        response["_shards"]["failed"] = 1
    elif defect == "error":
        response["error"] = {"reason": "partial"}
    elif defect == "nan":
        response["aggregations"]["last"]["value"] = float("nan")
    else:
        response["aggregations"]["first"]["value"] = None
    monkeypatch.setattr(
        setup.urllib.request, "urlopen", lambda *args, **kwargs: JsonResponse(response)
    )
    with pytest.raises(setup.DashboardError):
        setup.historical_range(setup.JsonHttp("http://localhost:9200"))
