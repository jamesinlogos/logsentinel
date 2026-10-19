"""Verify portable Kibana dashboard definitions and optionally historical stack data.

    python scripts/verify_dashboards.py
    python scripts/verify_dashboards.py --live --es http://localhost:9200 \
        --kibana http://localhost:5601 --report archives/dashboard-verification.json

Only the standard library is needed, including on Windows. HTTP requests use GET only;
Elasticsearch searches and field capabilities do not write records or replay Kafka data.
Exit 1 means a failed check, exit 0 permits warnings about optional or historical data.
Local checks cover portability, layout and mapping references, not Kibana's full API schema.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = (
    "windows-telemetry-*",
    "ransomware-detections-*",
    "ransomware-window-scores-*",
)
REQUIRED_DASHBOARDS = {
    "logsentinel-overview.json",
    "windows-telemetry.json",
    "ransomware-detections.json",
    "window-scores.json",
}
FIELD_EXPRESSION = re.compile(r"(?<![\w.])(@timestamp|[a-z_][\w]*(?:\.[\w@]+)*)\s*(?::|[<>]=?)")
FORMULA_FIELD = re.compile(r"(?<![\w.])(@timestamp|[a-z_][\w]*(?:\.[\w@]+)+)(?=\s*[,):])")
AGGREGATIONS = {
    "average",
    "avg",
    "max",
    "min",
    "sum",
    "median",
    "percentile",
    "percentiles",
    "unique_count",
    "cardinality",
    "date_histogram",
    "histogram",
    "terms",
    "last_value",
}
VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")
NUMERIC_TYPES = {
    "byte",
    "short",
    "integer",
    "long",
    "unsigned_long",
    "half_float",
    "float",
    "double",
    "scaled_float",
}
COMPATIBLE_TYPE_GROUPS = (
    NUMERIC_TYPES,
    {"keyword", "constant_keyword", "wildcard"},
    {"date", "date_nanos"},
)


@dataclass
class Report:
    """Collect printable, machine-readable observations without persisting source documents."""

    checks: list[dict[str, str]] = field(default_factory=list)
    observed: dict[str, Any] = field(default_factory=dict)

    def add(self, level: str, message: str) -> None:
        self.checks.append({"level": level, "message": message})
        print(f"{level:5} {message}")

    def ok(self, message: str) -> None:
        self.add("OK", message)

    def warn(self, message: str) -> None:
        self.add("WARN", message)

    def fail(self, message: str) -> None:
        self.add("FAIL", message)

    @property
    def failed(self) -> int:
        return sum(check["level"] == "FAIL" for check in self.checks)

    def document(self) -> dict[str, Any]:
        return {
            "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "failed": self.failed,
            "warnings": sum(check["level"] == "WARN" for check in self.checks),
            "checks": self.checks,
            "observed": self.observed,
        }


@dataclass
class FieldUsage:
    """Fields read by each index family and the subset requiring aggregatable mappings."""

    fields: dict[str, set[str]] = field(default_factory=dict)
    aggregatable: dict[str, set[str]] = field(default_factory=dict)
    expected_types: dict[str, dict[str, str]] = field(default_factory=dict)

    def add(self, pattern: str, name: str, *, aggregate: bool = False) -> None:
        self.fields.setdefault(pattern, set()).add(name)
        if aggregate:
            self.aggregatable.setdefault(pattern, set()).add(name)


def walk(value: Any) -> Iterator[dict[str, Any]]:
    """Yield nested objects without following or reading external references."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def source_pattern(source: dict[str, Any]) -> str | None:
    """Read the inline data-view pattern of Kibana's portable dashboard API."""
    pattern = source.get("index_pattern")
    return pattern if isinstance(pattern, str) else None


def collect_fields(value: Any, patterns: set[str], usage: FieldUsage) -> None:
    """Collect explicit fields, KQL fields and formula arguments within their data source."""
    if isinstance(value, list):
        for child in value:
            collect_fields(child, patterns, usage)
        return
    if not isinstance(value, dict):
        return
    source = value.get("data_source")
    if isinstance(source, dict) and (pattern := source_pattern(source)):
        patterns = {pattern}
    operation = value.get("operation")
    aggregate = isinstance(operation, str) and operation in AGGREGATIONS
    names: list[str] = []
    if isinstance(value.get("field"), str):
        names.append(value["field"])
    for key in ("fields", "column_order", "columns"):
        if isinstance(value.get(key), list):
            names.extend(name for name in value[key] if isinstance(name, str))
    expression = value.get("expression")
    if isinstance(expression, str) and value.get("language") == "kql":
        names.extend(FIELD_EXPRESSION.findall(expression))
    formula = value.get("formula")
    if isinstance(formula, str):
        names.extend(FORMULA_FIELD.findall(formula))
        names.extend(FIELD_EXPRESSION.findall(formula))
    if "direction" in value and isinstance(value.get("name"), str):
        names.append(value["name"])
    for pattern in patterns:
        for name in names:
            if name not in {"_source", "_score", "_id", "_index", "*"}:
                usage.add(pattern, name, aggregate=aggregate)
    for child in value.values():
        collect_fields(child, patterns, usage)


def mapping_fields(mapping: dict[str, Any], prefix: str = "") -> dict[str, str]:
    """Flatten explicit template mappings, including multi-fields."""
    found: dict[str, str] = {}
    for name, definition in mapping.get("properties", {}).items():
        path = f"{prefix}.{name}" if prefix else name
        if "type" in definition:
            found[path] = definition["type"]
        found.update(mapping_fields(definition, path))
        for child, child_definition in definition.get("fields", {}).items():
            found[f"{path}.{child}"] = child_definition.get("type", "object")
    return found


def local_mappings(root: Path) -> dict[str, dict[str, str]]:
    resources = root / "config" / "elasticsearch"
    component = json.loads(
        (resources / "component-templates" / "logsentinel-window-score.json").read_text("utf-8")
    )
    shared = mapping_fields(component["template"]["mappings"])
    telemetry = json.loads(
        (resources / "index-templates" / "windows-telemetry.json").read_text("utf-8")
    )
    return {
        PATTERNS[0]: mapping_fields(telemetry["template"]["mappings"]),
        PATTERNS[1]: dict(shared),
        PATTERNS[2]: dict(shared),
    }


def rectangles_overlap(first: dict[str, int], second: dict[str, int]) -> bool:
    return (
        first["x"] < second["x"] + second["w"]
        and second["x"] < first["x"] + first["w"]
        and first["y"] < second["y"] + second["h"]
        and second["y"] < first["y"] + first["h"]
    )


def check_gauge(config: dict[str, Any], label: str, report: Report) -> None:
    metric = config.get("metric", {})
    if not isinstance(metric, dict):
        report.fail(f"{label}: gauge metric must be an object")
        return
    bounds = (metric.get("min", {}), metric.get("max", {}))
    if not all(isinstance(bound, dict) for bound in bounds):
        report.fail(f"{label}: gauge bounds must be objects")
        return
    minimum, maximum = (bound.get("value") for bound in bounds)
    if not all(isinstance(value, (int, float)) for value in (minimum, maximum)):
        report.fail(f"{label}: gauge requires static numeric minimum and maximum")
        return
    if not all(math.isfinite(value) for value in (minimum, maximum)) or minimum >= maximum:
        report.fail(f"{label}: gauge bounds must be finite and increasing")
    name = metric.get("field", "")
    expected_max = 100 if name == "event.risk_score_norm" else 1
    if name in {
        "event.risk_score_norm",
        "event.risk_score",
        "logsentinel.verdict.confidence_score",
        "logsentinel.verdict.scores.model",
        "logsentinel.verdict.scores.indicator",
    } and (minimum != 0 or maximum != expected_max):
        report.fail(f"{label}: {name} gauge must span 0 to {expected_max}")


def verify_static(root: Path, report: Report) -> FieldUsage:
    """Validate repository dashboards without contacting Docker, Elasticsearch or Kibana."""
    usage = FieldUsage()
    folder = root / "dashboard"
    paths = sorted(folder.glob("*.json"))
    present = {path.name for path in paths}
    for missing in sorted(REQUIRED_DASHBOARDS - present):
        report.fail(f"dashboard/{missing}: missing required dashboard")
    for path in paths:
        before = report.failed
        try:
            definition = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError) as exc:
            report.fail(f"{path.name}: cannot load JSON ({exc})")
            continue
        if not isinstance(definition, dict):
            report.fail(f"{path.name}: dashboard must be a JSON object")
            continue
        if not definition.get("title") or not definition.get("description"):
            report.fail(f"{path.name}: title and monitoring description are required")
        for node in walk(definition):
            if "ref_id" in node or node.get("type") == "data_view_reference":
                report.fail(f"{path.name}: unresolved saved-object reference")
            if node.get("type") == "data_view_spec":
                pattern = source_pattern(node)
                if pattern not in PATTERNS:
                    report.fail(f"{path.name}: unsupported data-view pattern {pattern!r}")
                if node.get("time_field") != "@timestamp":
                    report.fail(f"{path.name}: data view must use @timestamp as time_field")
            if "references" in node and node["references"]:
                report.fail(f"{path.name}: external saved-object references are not portable")
        panels = definition.get("panels")
        if not isinstance(panels, list) or not panels:
            report.fail(f"{path.name}: panels must be a nonempty array")
            continue
        ids: set[str] = set()
        grids: list[tuple[str, dict[str, int]]] = []
        for index, panel in enumerate(panels):
            label = f"{path.name} panel {index + 1}"
            if not isinstance(panel, dict):
                report.fail(f"{label}: panel must be an object")
                continue
            panel_id = panel.get("id")
            if not isinstance(panel_id, str) or not panel_id or panel_id in ids:
                report.fail(f"{label}: missing or duplicate panel id")
            else:
                ids.add(panel_id)
            grid = panel.get("grid", {})
            if not isinstance(grid, dict) or not all(
                type(grid.get(key)) is int for key in ("x", "y", "w", "h")
            ):
                report.fail(f"{label}: grid requires integer x, y, w, h")
            elif min(grid["x"], grid["y"]) < 0 or min(grid["w"], grid["h"]) <= 0:
                report.fail(f"{label}: grid positions and dimensions are invalid")
            elif grid["x"] + grid["w"] > 48:
                report.fail(f"{label}: panel exceeds the 48-column dashboard grid")
            else:
                for other_label, other in grids:
                    if rectangles_overlap(grid, other):
                        report.fail(f"{label}: overlaps {other_label}")
                grids.append((label, grid))
            config = panel.get("config", {})
            if not isinstance(config, dict):
                report.fail(f"{label}: config must be an object")
                continue
            patterns = {
                pattern
                for node in walk(config)
                if node.get("type") == "data_view_spec" and (pattern := source_pattern(node))
            }
            if panel.get("type") != "markdown" and config.get("type") != "markdown":
                if not patterns:
                    report.fail(f"{label}: data panel has no inline data-view specification")
            collect_fields(config, patterns, usage)
            for node in walk(config):
                if node.get("type") == "gauge":
                    check_gauge(node, label, report)
        if report.failed == before:
            report.ok(f"{path.name}: {len(panels)} panels; portable sources and layout verified")
    try:
        mappings = local_mappings(root)
    except (OSError, ValueError, KeyError) as exc:
        report.fail(f"cannot load repository Elasticsearch mappings ({exc})")
        return usage
    for pattern, names in sorted(usage.fields.items()):
        explicit = mappings.get(pattern, {})
        usage.expected_types[pattern] = {name: explicit[name] for name in names if name in explicit}
        dynamic = []
        for name in sorted(names):
            if name in explicit:
                continue
            if pattern == PATTERNS[0] or (
                pattern == PATTERNS[2] and name.startswith("logsentinel.window.features.")
            ):
                dynamic.append(name)
            else:
                report.fail(f"{pattern}: {name} is absent from the dynamic:false mapping")
        report.ok(f"{pattern}: {len(names)} referenced fields checked against local templates")
        if dynamic:
            report.warn(f"{pattern}: dynamic mappings need live field_caps: {', '.join(dynamic)}")
    return usage


class HttpReadError(Exception):
    """An endpoint could not provide a complete JSON response."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class HttpReader:
    """A GET-only JSON client; endpoint errors never include response bodies or credentials."""

    def __init__(self, host: str) -> None:
        parsed = urllib.parse.urlsplit(host)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("endpoint must be an http(s) URL")
        if parsed.username or parsed.password:
            raise ValueError("use an endpoint without credentials in the URL")
        if parsed.query or parsed.fragment:
            raise ValueError("endpoint URL must not contain a query or fragment")
        try:
            _ = parsed.port
        except ValueError:
            raise ValueError("endpoint URL has an invalid port") from None
        self.host = host.rstrip("/")

    def get(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        request = urllib.request.Request(  # noqa: S310 - operator-provided lab endpoint
            f"{self.host}/{path.lstrip('/')}",
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            method="GET",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
                result = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise HttpReadError(f"HTTP {exc.code}", status_code=exc.code) from None
        except (OSError, ValueError) as exc:
            raise HttpReadError(type(exc).__name__) from None
        if not isinstance(result, dict):
            raise HttpReadError("response is not a JSON object")
        return result


def complete_search(result: dict[str, Any]) -> None:
    """Reject successful HTTP responses carrying partial Elasticsearch search results."""
    if result.get("error") or result.get("timed_out"):
        raise HttpReadError("search error or timeout")
    if not isinstance(result.get("_shards"), dict) or not isinstance(result.get("hits"), dict):
        raise HttpReadError("search response lacks shard or hit metadata")
    if result.get("_shards", {}).get("failed", 0):
        raise HttpReadError("search returned failed shards")
    total = result.get("hits", {}).get("total", {})
    if isinstance(total, dict) and total.get("relation", "eq") != "eq":
        raise HttpReadError("search returned an approximate total")
    if not isinstance(total, dict) or not isinstance(total.get("value"), int):
        raise HttpReadError("search response lacks an exact total")


def verdict_filters() -> dict[str, Any]:
    """Read-only checks of invariant combinations across all retained historical records."""

    def term(name: str, value: Any) -> dict[str, Any]:
        return {"term": {f"logsentinel.verdict.{name}": value}}

    def missing(name: str) -> dict[str, Any]:
        return {"bool": {"must_not": [{"exists": {"field": f"logsentinel.verdict.{name}"}}]}}

    def both(*queries: dict[str, Any]) -> dict[str, Any]:
        return {"bool": {"filter": list(queries)}}

    filters = {
        "gated": term("gated", True),
        "reported": term("reported", True),
        "suspicious": term("suspicious", True),
        "suppressed": both(term("gated", True), term("reported", False)),
        "ungated": term("gated", False),
        "reported_without_gate": both(term("reported", True), term("gated", False)),
        "suspicious_without_gate": both(term("suspicious", True), term("gated", False)),
        "gated_without_confidence": both(term("gated", True), missing("confidence_score")),
        "gated_without_label": both(term("gated", True), missing("label")),
        "ungated_with_confidence": both(
            term("gated", False), {"exists": {"field": "logsentinel.verdict.confidence_score"}}
        ),
        "suspicious_label_mismatch": both(
            term("suspicious", True),
            {"bool": {"must_not": [term("label", "suspicious_ransomware_behavior")]}},
        ),
        "suspicious_label_without_flag": both(
            term("label", "suspicious_ransomware_behavior"), term("suspicious", False)
        ),
    }
    for name in ("gated", "reported", "suspicious", "threshold"):
        filters[f"missing_{name}"] = missing(name)
    return filters


def coverage_filters(pattern: str) -> dict[str, Any]:
    """Coverage filters include documents outside Kibana's timestamp-filtered selection."""

    def missing(name: str) -> dict[str, Any]:
        return {"bool": {"must_not": [{"exists": {"field": name}}]}}

    filters = {"missing_timestamp": missing("@timestamp")}
    if pattern != PATTERNS[0]:
        filters.update(
            {
                "missing_host_id": missing("host.id"),
                "missing_window_id": missing("logsentinel.window.id"),
                "missing_schema_version": missing("logsentinel.schema_version"),
            }
        )
        return filters
    filters.update(
        {
            "missing_host_name": missing("host.name"),
            "missing_event_code": missing("event.code"),
        }
    )
    for name, codes, field_name in (
        ("process_start_without_executable", ["1"], "process.executable"),
        ("file_creation_without_path", ["11"], "file.path"),
        ("network_without_destination_ip", ["3"], "destination.ip"),
        ("registry_without_path", ["12", "13", "14"], "registry.path"),
    ):
        filters[name] = {
            "bool": {"filter": [{"terms": {"event.code": codes}}, missing(field_name)]}
        }
    for name in ("mitre", "hash"):
        filters[f"{name}_parse_failure"] = {"match_phrase": {"tags": f"_{name}_parse_failure"}}
    return filters


def checked_buckets(
    aggregations: dict[str, Any], name: str, expected: dict[str, Any], total: int
) -> dict[str, int]:
    """Require each requested filter bucket, including zero-valued historical checks."""
    aggregate = aggregations.get(name)
    buckets = aggregate.get("buckets") if isinstance(aggregate, dict) else None
    if not isinstance(buckets, dict) or any(key not in buckets for key in expected):
        raise HttpReadError(f"search response lacks required {name} filter buckets")
    counts = {}
    for key in expected:
        bucket = buckets[key]
        count = bucket.get("doc_count") if isinstance(bucket, dict) else None
        if type(count) is not int or not 0 <= count <= total:
            raise HttpReadError(f"search returned invalid {name}.{key} count")
        counts[key] = count
    return counts


def compatible_types(types: set[str]) -> bool:
    """Allow compatible numeric/date/keyword variants but reject conflicting field kinds."""
    return len(types) <= 1 or any(types <= group for group in COMPATIBLE_TYPE_GROUPS)


def verify_live(es: HttpReader, kibana: HttpReader, usage: FieldUsage, report: Report) -> None:
    """Observe existing documents only, over their entire retained historical time extent."""
    try:
        status = kibana.get("api/status")
        version_info = status.get("version")
        version = (
            version_info.get("number", "unknown") if isinstance(version_info, dict) else "unknown"
        )
        level = status.get("status", {}).get("overall", {}).get("level", "unknown")
        match = VERSION.match(version) if isinstance(version, str) else None
        version_source = "api/status"
        if match is None:
            # The public status endpoint can legitimately redact everything except level.
            # Stats is a read-only fallback; never infer Kibana's version from Elasticsearch.
            try:
                stats = kibana.get("api/stats?extended=true")
                version = stats.get("kibana", {}).get("version", "unknown")
                match = VERSION.match(version) if isinstance(version, str) else None
                version_source = "api/stats?extended=true"
            except (HttpReadError, AttributeError, TypeError):
                version = "unknown"
        report.observed["kibana"] = {
            "version": version,
            "status": level,
            "version_source": version_source if match else None,
        }
        if match is None:
            report.warn("Kibana version unavailable; Dashboard API compatibility is unverified")
        elif tuple(map(int, match.groups()[:2])) < (9, 5):
            report.fail("portable Dashboard API requires Kibana 9.5 or later")
        (report.ok if level == "available" else report.warn)(
            f"Kibana version {version}; reported status {level}"
        )
    except (HttpReadError, AttributeError, TypeError) as exc:
        report.fail(f"Kibana status unavailable ({exc}); dashboard API compatibility unverified")
    observed: dict[str, Any] = {}
    report.observed["indices"] = observed
    for pattern in PATTERNS:
        encoded = urllib.parse.quote(pattern, safe="*-_")
        body: dict[str, Any] = {
            "size": 0,
            "track_total_hits": True,
            "aggs": {
                "first_event": {"min": {"field": "@timestamp"}},
                "last_event": {"max": {"field": "@timestamp"}},
                "coverage": {"filters": {"filters": coverage_filters(pattern)}},
            },
        }
        if pattern != PATTERNS[0]:
            body["aggs"].update(
                {
                    "verdicts": {"filters": {"filters": verdict_filters()}},
                    "schema_versions": {
                        "terms": {"field": "logsentinel.schema_version", "size": 100}
                    },
                    "model_versions": {
                        "terms": {"field": "logsentinel.model.version", "size": 100}
                    },
                    "triggers": {"terms": {"field": "logsentinel.window.trigger", "size": 20}},
                }
            )
        try:
            result = es.get(
                f"{encoded}/_search?allow_no_indices=true&ignore_unavailable=true", body
            )
            complete_search(result)
            total = result["hits"]["total"]["value"]
            if total == 0 and "aggregations" not in result:
                # A freshly built stack has no index: the search answers without aggregations.
                observed[pattern] = {"documents": 0}
                report.warn(f"{pattern}: no index yet; no inference about ingestion health")
                continue
            aggregations = result.get("aggregations", {})
            if not isinstance(aggregations, dict) or any(
                not isinstance(aggregations.get(name), dict) or "value" not in aggregations[name]
                for name in ("first_event", "last_event")
            ):
                raise HttpReadError("search response lacks timestamp extent aggregations")
            first = aggregations["first_event"].get("value_as_string")
            last = aggregations["last_event"].get("value_as_string")
            coverage = checked_buckets(aggregations, "coverage", coverage_filters(pattern), total)
            observation: dict[str, Any] = {
                "documents": total,
                "first_event": first,
                "last_event": last,
                "coverage": coverage,
            }
            observed[pattern] = observation
            if total:
                report.ok(f"{pattern}: {total} documents; event time {first} to {last}")
                if first is None or last is None:
                    report.fail(f"{pattern}: documents exist but @timestamp has no date extent")
            else:
                report.warn(
                    f"{pattern}: no retained documents; no inference about ingestion health"
                )
            for name, count in coverage.items():
                if count:
                    required = name.startswith("missing_")
                    (report.fail if required else report.warn)(
                        f"{pattern}: all-time coverage {name}: {count} document(s)"
                    )
            if not any(coverage.values()):
                report.ok(
                    f"{pattern}: all-time required-field and coverage checks found no exceptions"
                )
            if pattern != PATTERNS[0]:
                verdicts = checked_buckets(aggregations, "verdicts", verdict_filters(), total)
                observation["verdicts"] = verdicts
                for name, count in observation["verdicts"].items():
                    if name not in {"gated", "reported", "suspicious", "suppressed", "ungated"}:
                        if count:
                            report.fail(f"{pattern}: {count} document(s) violate {name}")
                if pattern == PATTERNS[1] and verdicts["reported"] != total:
                    report.fail(f"{pattern}: detection documents must all be reported")
                for name in ("schema_versions", "model_versions", "triggers"):
                    aggregate = aggregations.get(name, {})
                    if not isinstance(aggregate, dict) or not isinstance(
                        aggregate.get("buckets"), list
                    ):
                        raise HttpReadError(f"search response lacks required {name} buckets")
                    observation[name] = aggregate["buckets"]
                    if aggregate.get("sum_other_doc_count", 0):
                        report.warn(f"{pattern}: {name} has more values than the report limit")
        except (HttpReadError, KeyError, TypeError, AttributeError) as exc:
            report.fail(f"{pattern}: historical search incomplete ({exc})")
            continue
        fields = sorted(usage.fields.get(pattern, set()))
        if not fields:
            continue
        try:
            query = urllib.parse.urlencode({"fields": ",".join(fields), "include_unmapped": "true"})
            capabilities = es.get(
                f"{encoded}/_field_caps?{query}&allow_no_indices=true&ignore_unavailable=true"
            )
            if capabilities.get("failures") or capabilities.get("error"):
                raise HttpReadError("field capabilities returned failures")
            if not isinstance(capabilities.get("fields"), dict):
                raise HttpReadError("field capability response lacks fields metadata")
            unavailable = []
            partially_unmapped = []
            mapped_types = {}
            for name in fields:
                types = capabilities["fields"].get(name, {})
                if not isinstance(types, dict) or any(
                    not isinstance(settings, dict) for settings in types.values()
                ):
                    raise HttpReadError(f"invalid field capability metadata for {name}")
                mapped = {kind: settings for kind, settings in types.items() if kind != "unmapped"}
                if not mapped:
                    unavailable.append(name)
                    continue
                mapped_types[name] = sorted(mapped)
                if "unmapped" in types:
                    partially_unmapped.append(name)
                if not compatible_types(set(mapped)):
                    report.fail(
                        f"{pattern}: conflicting live types for {name}: {', '.join(sorted(mapped))}"
                    )
                expected = usage.expected_types.get(pattern, {}).get(name)
                if expected and not compatible_types(set(mapped) | {expected}):
                    report.fail(
                        f"{pattern}: live type of {name} conflicts with template type {expected}"
                    )
                if name in usage.aggregatable.get(pattern, set()) and any(
                    not settings.get("aggregatable", False) for settings in mapped.values()
                ):
                    report.fail(
                        f"{pattern}: aggregated field {name} is not aggregatable everywhere"
                    )
                if any(not settings.get("searchable", False) for settings in mapped.values()):
                    report.warn(f"{pattern}: field {name} is not searchable in every mapped index")
            observation["unmapped_referenced_fields"] = unavailable
            observation["partially_unmapped_referenced_fields"] = partially_unmapped
            observation["referenced_field_types"] = mapped_types
            if partially_unmapped:
                report.warn(
                    f"{pattern}: fields absent from some indices: {', '.join(partially_unmapped)}"
                )
            if unavailable:
                report.warn(
                    f"{pattern}: unmapped optional or historical fields: {', '.join(unavailable)}"
                )
            else:
                report.ok(f"{pattern}: all {len(fields)} referenced fields have live mappings")
        except (HttpReadError, TypeError) as exc:
            report.fail(f"{pattern}: field capability verification incomplete ({exc})")
    detections = observed.get(PATTERNS[1], {}).get("documents")
    reported = observed.get(PATTERNS[2], {}).get("verdicts", {}).get("reported")
    if detections is not None and reported is not None:
        message = f"Retained detections {detections}; retained reported window scores {reported}"
        if detections == reported:
            report.ok(message)
        else:
            report.warn(f"{message}; different retention and historical schemas require review")


def verify_installed(kibana: HttpReader, root: Path, report: Report) -> None:
    """Observe saved dashboards in the default space without creating or updating them."""
    observed: dict[str, Any] = {}
    report.observed["dashboards"] = {"space": "default", "definitions": observed}
    for path in sorted((root / "dashboard").glob("*.json")):
        identity = path.stem
        try:
            expected = json.loads(path.read_text(encoding="utf-8"))
            saved = kibana.get(f"api/dashboards/{urllib.parse.quote(identity, safe='')}")
            body = saved.get("data")
            if not isinstance(body, dict) or not isinstance(body.get("panels"), list):
                raise HttpReadError("Dashboard API response lacks data.panels")
            observed[identity] = {
                "installed": True,
                "title": body.get("title"),
                "panel_count": len(body["panels"]),
            }
            if body.get("title") != expected.get("title"):
                report.fail(f"{identity}: saved title differs from the local definition")
            elif len(body["panels"]) != len(expected.get("panels", [])):
                report.warn(f"{identity}: saved panel count differs from the local definition")
            else:
                report.ok(
                    f"{identity}: saved dashboard found; title and panel count match "
                    "(browser rendering is unverified)"
                )
        except HttpReadError as exc:
            if exc.status_code == 404:
                observed[identity] = {"installed": False}
                report.warn(f"{identity}: dashboard is not installed in the default space")
            else:
                report.fail(f"{identity}: saved dashboard check incomplete ({exc})")
        except (OSError, ValueError, TypeError) as exc:
            report.fail(f"{identity}: cannot check saved dashboard ({type(exc).__name__})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument(
        "--live", action="store_true", help="also read existing Elasticsearch/Kibana data"
    )
    parser.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    parser.add_argument(
        "--kibana", default="http://localhost:5601", help="Kibana base URL (omit /s/<space>)"
    )
    parser.add_argument(
        "--report", type=Path, help="write observed results to this local JSON file"
    )
    arguments = parser.parse_args(argv)
    report = Report()
    usage = verify_static(arguments.root.resolve(), report)
    if arguments.live:
        try:
            if re.search(r"/s/[^/]+/?$", urllib.parse.urlsplit(arguments.kibana).path):
                raise ValueError("Kibana status uses the instance base URL; omit /s/<space>")
            kibana = HttpReader(arguments.kibana)
            verify_live(HttpReader(arguments.es), kibana, usage, report)
            verify_installed(kibana, arguments.root.resolve(), report)
        except ValueError as exc:
            report.fail(str(exc))
    else:
        report.warn(
            "Live checks skipped; Kibana acceptance and historical Docker-volume data unverified"
        )
    if arguments.report:
        try:
            arguments.report.parent.mkdir(parents=True, exist_ok=True)
            arguments.report.write_text(
                json.dumps(report.document(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            report.fail(f"cannot write local verification report ({type(exc).__name__})")
    warnings = sum(check["level"] == "WARN" for check in report.checks)
    print(f"Dashboard verification: {report.failed} failed, {warnings} warning(s)")
    return 1 if report.failed else 0


if __name__ == "__main__":
    sys.exit(main())
