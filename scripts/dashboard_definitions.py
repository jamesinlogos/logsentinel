"""Build the portable Kibana dashboards documented in README.md section 9.1.

    python scripts/dashboard_definitions.py          # check generated definitions
    python scripts/dashboard_definitions.py --write  # update definitions after a backup

Only dashboard source files are written. No connection to the stack is made.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

ROOT = Path(__file__).resolve().parents[1]
TELEMETRY = "windows-telemetry-*"
SCORES = "ransomware-window-scores-*"
DETECTIONS = "ransomware-detections-*"
VERDICT = "logsentinel.verdict."
ACTIVITY = "logsentinel.window.activity."
BLUE = "#6092C0"
RED = "#D36086"
GOLD = "#D6BF57"
TEAL = "#54B399"


def query(expression: str = "") -> dict[str, str]:
    return {"language": "kql", "expression": expression}


def source(pattern: str) -> dict[str, str]:
    return {"type": "data_view_spec", "index_pattern": pattern, "time_field": "@timestamp"}


def metric(operation: str, label: str, field: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"operation": operation, "label": label}
    if field:
        result["field"] = field
    if operation == "count":
        result["empty_as_null"] = False
    return result


def count(label: str) -> dict[str, Any]:
    return metric("count", label)


def formula(expression: str, label: str, percent: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"operation": "formula", "formula": expression, "label": label}
    if percent:
        result["format"] = {"type": "percent", "decimals": 1, "compact": False}
    return result


def latest(label: str = "Latest event time") -> dict[str, Any]:
    return {
        **metric("last_value", label, "@timestamp"),
        "time_field": "@timestamp",
        "multi_value": True,
        "filter": query('"@timestamp": *'),
    }


def terms(field: str, label: str, limit: int = 10) -> dict[str, Any]:
    return {
        "operation": "terms",
        "fields": [field],
        "label": label,
        "limit": limit,
        "other_bucket": {"include_documents_without_field": False},
        "rank_by": {"type": "metric", "metric_index": 0, "direction": "desc"},
    }


def filters(items: list[tuple[str, str]]) -> dict[str, Any]:
    return {
        "operation": "filters",
        "filters": [{"label": label, "filter": query(expression)} for label, expression in items],
    }


def timeline() -> dict[str, Any]:
    return {
        "operation": "date_histogram",
        "field": "@timestamp",
        "label": "Event time",
        "suggested_interval": "auto",
        "use_original_time_range": False,
        "include_empty_rows": True,
        "drop_partial_intervals": False,
    }


def visual(kind: str, pattern: str, title: str, expression: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": kind,
        "title": title,
        "data_source": source(pattern),
        "sampling": 1,
        "ignore_global_filters": False,
    }
    if expression:
        result["query"] = query(expression)
    return result


def kpi(pattern: str, title: str, value: dict[str, Any], expression: str = "") -> dict[str, Any]:
    return {
        **visual("metric", pattern, title, expression),
        "metrics": [{"type": "primary", **value, "color": {"type": "auto"}}],
        "styling": {"density": "default"},
    }


def category_colors() -> dict[str, Any]:
    return {
        "mode": "categorical",
        "palette": "elastic_line_optimized",
        "mapping": [
            {"values": [label], "color": {"type": "color_code", "value": color}}
            for label, color in [
                ("Suspicious", RED),
                ("suspicious_ransomware_behavior", RED),
                ("Indicator match", GOLD),
                ("indicator_match", GOLD),
                ("Ungated", BLUE),
                ("Passed gate", TEAL),
                ("Suppressed, below threshold", GOLD),
                ("Suppressed, suspicious", "#AA6556"),
                ("Reported, indicator match", TEAL),
                ("Reported, suspicious", RED),
                ("slide", BLUE),
                ("indicator", GOLD),
            ]
        ],
    }


def chart(
    pattern: str,
    title: str,
    x: dict[str, Any],
    values: list[dict[str, Any]],
    *,
    kind: str = "bar_stacked",
    breakdown: dict[str, Any] | None = None,
    expression: str = "",
    horizontal: bool = False,
) -> dict[str, Any]:
    layer: dict[str, Any] = {
        "type": "bar_horizontal" if horizontal else kind,
        "data_source": source(pattern),
        "sampling": 1,
        "ignore_global_filters": False,
        "x": x,
        "y": values,
    }
    if breakdown:
        # Each series needs its own complete time histogram, including zero buckets.
        # Time-first aggregation omits child-series rows on empty historical days.
        layer["breakdown_by"] = {
            **breakdown,
            "color": category_colors(),
            **({"aggregate_first": True} if x["operation"] == "date_histogram" else {}),
        }
    styling: dict[str, Any] = {}
    if kind == "line" or kind.startswith("area"):
        styling["fitting"] = {"type": "none", "extend": "none"}
    if kind.startswith("area"):
        styling["areas"] = {"fill_opacity": 0.65}
        styling["fitting"] = {"type": "zero", "extend": "none"}
        styling["interpolation"] = "stepped"
    if horizontal or kind.startswith("bar_horizontal"):
        styling["bars"] = {"data_labels": {"visible": True}}
    return {
        "type": "xy",
        "title": title,
        "layers": [layer],
        "query": query(expression),
        **({"styling": styling} if styling else {}),
        "axis": {
            "x": {"title": {"visible": True}, "labels": {"orientation": "horizontal"}},
            "y": {"title": {"visible": True}, "scale": "linear"},
        },
        "legend": {
            "placement": "outside",
            "position": "bottom",
            "layout": {"type": "list"},
            "visibility": "visible" if breakdown or len(values) > 1 else "hidden",
        },
    }


def donut(
    pattern: str, title: str, dimension: dict[str, Any], expression: str = ""
) -> dict[str, Any]:
    dimension = {**dimension, "color": category_colors()}
    return {
        **visual("pie", pattern, title, expression),
        "metrics": [count("Documents")],
        "group_by": [dimension],
        "styling": {
            "donut_hole": "m",
            "labels": {"visible": True, "position": "outside"},
            "values": {"visible": True, "mode": "percentage", "percent_decimals": 1},
        },
        "legend": {"visibility": "visible", "position": "right", "size": "m"},
    }


def heatmap(
    pattern: str,
    title: str,
    x: dict[str, Any],
    y: dict[str, Any],
    expression: str = "",
) -> dict[str, Any]:
    temporal = x["operation"] == "date_histogram"
    return {
        **visual("heatmap", pattern, title, expression),
        "metric": {
            **count("Documents"),
            "color": {"type": "distributed_palette", "palette": "cool"},
        },
        "x": x,
        "y": y,
        "axis": {
            "x": {
                "scale": "ordinal",
                "labels": {"visible": True},
                "title": {"visible": True},
            },
            "y": {"labels": {"visible": True}, "title": {"visible": True}},
        },
        "styling": {"cells": {"labels": {"visible": not temporal}}},
        "legend": {"visibility": "visible", "position": "right"},
    }


def table(
    pattern: str,
    title: str,
    rows: list[dict[str, Any]],
    values: list[dict[str, Any]],
    expression: str = "",
) -> dict[str, Any]:
    return {
        **visual("data_table", pattern, title, expression),
        "rows": rows,
        "metrics": values,
        "styling": {"row_numbers": {"visible": True}},
    }


def distribution(pattern: str, title: str, field: str, maximum: int) -> dict[str, Any]:
    # The 9.5 range operation omits gte; explicit KQL keeps zero inside its bin.
    buckets = [
        (
            f"{'[' if i == 0 else '('}{i * maximum / 10:g}, {(i + 1) * maximum / 10:g}]",
            f"{field} {'>=' if i == 0 else '>'} {i * maximum / 10:g} and "
            f"{field} <= {(i + 1) * maximum / 10:g}",
        )
        for i in range(10)
    ]
    return chart(
        pattern,
        title,
        filters(buckets),
        [count("Windows")],
    )


def activity(title: str, fields: list[tuple[str, str]], pattern: str = SCORES) -> dict[str, Any]:
    return chart(
        pattern,
        title,
        timeline(),
        [metric("max", label, ACTIVITY + field) for field, label in fields],
        kind="line",
    )


class Dashboard:
    def __init__(self, name: str, title: str, description: str) -> None:
        self.name = name
        self.body: dict[str, Any] = {
            "title": title,
            "description": description,
            "options": {
                "auto_apply_filters": True,
                "hide_panel_borders": False,
                "hide_panel_titles": False,
                "sync_colors": False,
                "sync_cursor": True,
                "sync_tooltips": True,
                "use_margins": True,
            },
            "query": query(),
            "filters": [],
            "tags": [],
            "time_range": {"from": "now-1y", "to": "now"},
            "refresh_interval": {"pause": True, "value": 0},
            "panels": [],
            "pinned_panels": [],
        }
        self.y = 0

    def row(self, *configs: dict[str, Any], height: int = 13) -> None:
        width = 48 // len(configs)
        for i, config in enumerate(configs):
            panel_type = config.pop("panel_type", "vis")
            identity = f"logsentinel/{self.name}/{config.get('title', '')}/{self.y}/{i}"
            self.body["panels"].append(
                {
                    "id": str(uuid5(NAMESPACE_URL, identity)),
                    "type": panel_type,
                    "grid": {"x": i * width, "y": self.y, "w": width, "h": height},
                    "config": config,
                }
            )
        self.y += height

    def note(self, title: str, content: str, height: int = 7) -> None:
        if self.y == 0:
            content += (
                "\n\n**Navigate:** [Overview](/app/dashboards#/view/logsentinel-overview) | "
                "[Detections](/app/dashboards#/view/ransomware-detections) | "
                "[Window Scores](/app/dashboards#/view/window-scores) | "
                "[Windows Telemetry](/app/dashboards#/view/windows-telemetry) | "
                "[Telemetry Quality](/app/dashboards#/view/telemetry-quality)"
            )
            height = 6
        self.row({"panel_type": "markdown", "title": title, "content": content}, height=height)

    def evidence(self, pattern: str, title: str, columns: list[str], expression: str = "") -> None:
        self.row(
            {
                "panel_type": "discover_session",
                "title": title,
                "tabs": [
                    {
                        "data_source": source(pattern),
                        "query": query(expression),
                        "column_order": columns,
                        "sort": [{"name": "@timestamp", "direction": "desc"}],
                        "rows_per_page": 25,
                        "view_mode": "documents",
                    }
                ],
            },
            height=18,
        )


def window_states() -> dict[str, Any]:
    states = [
        ("Ungated", "gated: false"),
        ("Suppressed, below threshold", "gated: true and reported: false and suspicious: false"),
        ("Suppressed, suspicious", "gated: true and reported: false and suspicious: true"),
        ("Reported, indicator match", "gated: true and reported: true and suspicious: false"),
        ("Reported, suspicious", "gated: true and reported: true and suspicious: true"),
    ]
    dimension = filters(
        [
            (label, " and ".join(VERDICT + part for part in expression.split(" and ")))
            for label, expression in states
        ]
    )
    return dimension


def overview() -> Dashboard:
    d = Dashboard(
        "logsentinel-overview",
        "LogSentinel Overview",
        "Historical Sysmon activity, window scoring and reported detections. "
        "Separate stream counts; event-time scope follows the selected range.",
    )
    d.note(
        "Monitoring overview",
        "**Historical monitoring** · Filter `host.name` and select a stored session. "
        "Telemetry events → overlapping scored windows → reported detections. "
        "A detection is a reported window, not a confirmed infection or unique incident.",
    )
    d.row(
        kpi(TELEMETRY, "Indexed telemetry events", count("Sysmon events")),
        kpi(SCORES, "All scored windows", count("Windows")),
        kpi(DETECTIONS, "Reported detections", count("Reported windows")),
        kpi(
            SCORES,
            "Phase 2 gate pass rate",
            formula(f"count(kql='{VERDICT}gated: true') / count()", "Gated / all windows", True),
        ),
        height=5,
    )
    d.row(
        chart(
            TELEMETRY,
            "Sysmon activity over time",
            timeline(),
            [count("Events")],
            kind="area_stacked",
            breakdown=terms("event.code", "Event ID", 20),
        ),
        donut(
            DETECTIONS,
            "Reported verdict mix",
            filters(
                [
                    ("Suspicious", VERDICT + "suspicious: true"),
                    ("Indicator match", VERDICT + "suspicious: false"),
                ]
            ),
        ),
        height=15,
    )
    d.row(
        chart(
            SCORES,
            "Window outcomes over time",
            timeline(),
            [count("Windows")],
            kind="area_stacked",
            breakdown=window_states(),
        ),
        donut(
            SCORES,
            "Phase 2 gate coverage",
            filters(
                [
                    ("Passed gate", VERDICT + "gated: true"),
                    ("Ungated", VERDICT + "gated: false"),
                ]
            ),
        ),
        height=15,
    )
    d.row(
        heatmap(
            TELEMETRY,
            "Activity intensity | event ID × time",
            timeline(),
            terms("event.code", "Sysmon event ID", 20),
        ),
        chart(
            DETECTIONS,
            "Detection timeline by verdict",
            timeline(),
            [count("Reported windows")],
            breakdown=terms(VERDICT + "label", "Verdict", 5),
        ),
        height=16,
    )
    d.row(
        chart(
            SCORES,
            "Confidence and stored threshold envelope",
            timeline(),
            [
                metric("max", "Max confidence (gated)", VERDICT + "confidence_score"),
                metric("min", "Min stored threshold", VERDICT + "threshold"),
                metric("max", "Max stored threshold", VERDICT + "threshold"),
            ],
            kind="line",
        ),
        chart(
            DETECTIONS,
            "Indicators in detections | overlapping counts",
            terms(VERDICT + "indicators", "Indicator", 15),
            [count("Reported windows")],
            horizontal=True,
        ),
        height=15,
    )
    d.note(
        "Interpretation",
        "Gate requires a strong indicator; suspicious compares confidence with the stored "
        "threshold; reported also applies suppression. Risk = confidence × 100, not infection "
        "probability. Counts across the three streams are not additive. "
        "Historical activity does not establish VM connectivity or runtime health.",
        height=5,
    )
    d.evidence(
        DETECTIONS,
        "Recent reported windows | expand for complete evidence",
        [
            "@timestamp",
            "host.name",
            VERDICT + "label",
            VERDICT + "confidence_score",
            VERDICT + "threshold",
            VERDICT + "indicators",
            "logsentinel.window.id",
        ],
    )
    return d


def detections() -> Dashboard:
    d = Dashboard(
        "ransomware-detections",
        "Ransomware Detections",
        "Visual triage of reported windows: verdict mix, risk, indicators, ATT&CK, "
        "early-window process context and raw activity peaks.",
    )
    d.note(
        "Detection triage",
        "**Reported windows** · Filter `host.id`, then correlate window ID and "
        "`event.start` / `event.end` with Sysmon. Suspicious meets the stored threshold; "
        "indicator match is below it. Neither verdict confirms infection.",
    )
    d.row(
        kpi(DETECTIONS, "Reported windows", count("Detections")),
        kpi(
            DETECTIONS,
            "Hosts with detections",
            metric("unique_count", "Host IDs (approx.)", "host.id"),
        ),
        kpi(
            DETECTIONS,
            "Maximum normalized risk",
            metric("max", "Confidence × 100", "event.risk_score_norm"),
        ),
        height=5,
    )
    d.row(
        chart(
            DETECTIONS,
            "Detection timeline by verdict",
            timeline(),
            [count("Reported windows")],
            kind="area_stacked",
            breakdown=terms(VERDICT + "label", "Verdict", 5),
        ),
        donut(
            DETECTIONS,
            "Reported verdict mix",
            filters(
                [
                    ("Suspicious", VERDICT + "suspicious: true"),
                    ("Indicator match", VERDICT + "suspicious: false"),
                ]
            ),
        ),
        height=15,
    )
    d.row(
        distribution(
            DETECTIONS, "Normalized risk distribution | 0–100", "event.risk_score_norm", 100
        ),
        donut(
            DETECTIONS,
            "Scheduled vs early reported windows",
            terms("logsentinel.window.trigger", "Trigger", 5),
        ),
        height=15,
    )
    d.row(
        heatmap(
            DETECTIONS,
            "Indicator activity | overlapping windows × time",
            timeline(),
            terms(VERDICT + "indicators", "Indicator", 15),
        ),
        height=17,
    )
    d.row(
        chart(
            DETECTIONS,
            "Indicator prevalence | overlapping counts",
            terms(VERDICT + "indicators", "Indicator", 15),
            [count("Reported windows")],
            horizontal=True,
        ),
        chart(
            DETECTIONS,
            "ATT&CK technique prevalence | overlapping counts",
            terms("threat.technique.id", "Parent technique", 15),
            [count("Reported windows")],
            horizontal=True,
        ),
        height=16,
    )
    d.row(
        chart(
            DETECTIONS,
            "ATT&CK tactics | overlapping counts",
            terms("threat.tactic.name", "Tactic", 10),
            [count("Reported windows")],
            horizontal=True,
        ),
        chart(
            DETECTIONS,
            "Early-window closing executable | top 10",
            terms("process.executable", "Closing event executable", 10),
            [count("Early reported windows")],
            expression='logsentinel.window.trigger: "indicator"',
            horizontal=True,
        ),
        height=16,
    )
    d.row(
        activity(
            "Peak raw file activity per reported window",
            [
                ("created_files", "Max created files / window"),
                ("max_deletes", "Max per-process deletes / window"),
                ("max_replaced_files", "Max per-process replacements / window"),
            ],
            DETECTIONS,
        ),
        activity(
            "Peak raw command activity per reported window",
            [
                ("shadow_commands", "Max shadow commands / window"),
                ("recovery_commands", "Max recovery commands / window"),
                ("stop_commands", "Max stop commands / window"),
                ("log_tamper", "Max log tamper / window"),
            ],
            DETECTIONS,
        ),
        height=15,
    )
    d.note(
        "Evidence context",
        "Indicator/ATT&CK categories overlap. `process.*` identifies only the event closing "
        "an early window; it does not attribute all window activity to that process. "
        "Activity lines show independent maxima from overlapping windows, "
        "not additive event totals. "
        "Expand a row for commands, model version, threshold and the complete document.",
        height=5,
    )
    d.evidence(
        DETECTIONS,
        "Detection evidence | newest window first",
        [
            "@timestamp",
            "host.name",
            "logsentinel.window.trigger",
            VERDICT + "label",
            VERDICT + "confidence_score",
            VERDICT + "threshold",
            VERDICT + "indicators",
            "process.executable",
            "logsentinel.window.id",
        ],
    )
    return d


def window_scores() -> Dashboard:
    d = Dashboard(
        "window-scores",
        "Window Scores",
        "All scored windows: disjoint verdict states, trigger composition, suppression, "
        "score distributions, stored thresholds and raw activity.",
    )
    d.note(
        "Window scoring",
        "**Every scored window** · Scheduled (`slide`) and early (`indicator`) windows "
        "share the scoring flow. Window time is its end; windows overlap. Gate needs a "
        "strong indicator. A high model score alone does not pass the gate.",
    )
    d.row(
        kpi(SCORES, "All scored windows", count("Windows")),
        kpi(SCORES, "Phase 2 gated windows", count("Gated"), VERDICT + "gated: true"),
        kpi(
            SCORES,
            "Suppressed gated windows",
            count("Gated, not reported"),
            VERDICT + "gated: true and " + VERDICT + "reported: false",
        ),
        height=5,
    )
    d.row(
        donut(SCORES, "Mutually exclusive window states", window_states()),
        chart(
            SCORES,
            "Window outcomes over time",
            timeline(),
            [count("Windows")],
            kind="area_stacked",
            breakdown=window_states(),
        ),
        height=17,
    )
    d.row(
        donut(
            SCORES, "Scheduled vs early windows", terms("logsentinel.window.trigger", "Trigger", 5)
        ),
        heatmap(
            SCORES,
            "Trigger intensity × time",
            timeline(),
            terms("logsentinel.window.trigger", "Trigger", 5),
        ),
        height=15,
    )
    d.row(
        distribution(
            SCORES, "Model score distribution | 0–1, includes zero", VERDICT + "scores.model", 1
        ),
        chart(
            SCORES,
            "Score peaks and stored threshold bounds",
            timeline(),
            [
                metric("max", "Max model score", VERDICT + "scores.model"),
                metric("max", "Max indicator score", VERDICT + "scores.indicator"),
                metric("max", "Max confidence (gated)", VERDICT + "confidence_score"),
                metric("min", "Min stored threshold", VERDICT + "threshold"),
                metric("max", "Max stored threshold", VERDICT + "threshold"),
            ],
            kind="line",
        ),
        height=15,
    )
    d.row(
        chart(
            SCORES,
            "Indicators | reported vs suppressed (overlapping counts)",
            terms(VERDICT + "indicators", "Indicator", 15),
            [count("Gated windows")],
            kind="bar_horizontal_stacked",
            breakdown=filters(
                [
                    ("Reported", VERDICT + "reported: true"),
                    ("Suppressed", VERDICT + "reported: false"),
                ]
            ),
            expression=VERDICT + "gated: true",
        ),
        table(
            SCORES,
            "Historical model and threshold context",
            [terms("logsentinel.model.version", "Model version", 10)],
            [
                count("Windows"),
                metric("min", "Min threshold", VERDICT + "threshold"),
                metric("max", "Max threshold", VERDICT + "threshold"),
                metric("min", "First window", "@timestamp"),
                latest("Last window"),
            ],
        ),
        height=16,
    )
    d.row(
        activity(
            "Peak raw file activity per scored window",
            [
                ("created_files", "Max created files / window"),
                ("max_deletes", "Max per-process deletes / window"),
                ("max_replaced_files", "Max per-process replacements / window"),
            ],
        ),
        activity(
            "Peak raw registry and command activity per window",
            [
                ("run_key_writes", "Max Run-key writes / window"),
                ("policy_writes", "Max policy writes / window"),
                ("shadow_commands", "Max shadow commands / window"),
                ("log_tamper", "Max log tamper / window"),
            ],
        ),
        height=15,
    )
    d.note(
        "Score interpretation",
        "Ungated windows normally omit confidence/label. Suspicious compares confidence "
        "with that document's threshold; suppression determines reporting. The five states "
        "partition valid verdicts; Telemetry Quality checks exceptions. Score peaks/threshold "
        "bounds can come from different windows. Raw activity maxima are not additive totals.",
        height=5,
    )
    d.evidence(
        SCORES,
        "Window evidence | flags, confidence and threshold on one row",
        [
            "@timestamp",
            "host.name",
            "logsentinel.window.trigger",
            VERDICT + "gated",
            VERDICT + "suspicious",
            VERDICT + "reported",
            VERDICT + "scores.model",
            VERDICT + "confidence_score",
            VERDICT + "threshold",
            "logsentinel.window.id",
        ],
    )
    return d


def telemetry() -> Dashboard:
    d = Dashboard(
        "windows-telemetry",
        "Windows Telemetry",
        "Historical Sysmon investigation: event composition, time density, process starts, "
        "file and registry activity, network destinations and configured ATT&CK tags.",
    )
    d.note(
        "Sysmon investigation",
        "Indexed Sysmon events in the selected period; filter `host.name`, then narrow event "
        "time around a detection window. Counts describe events, not unique files or attacks. "
        "Expand evidence rows for the complete source document.",
        height=5,
    )
    d.row(
        kpi(TELEMETRY, "Indexed Sysmon events", count("Events")),
        kpi(
            TELEMETRY,
            "Observed host names",
            metric("unique_count", "Distinct names (approx.)", "host.name"),
        ),
        kpi(TELEMETRY, "Latest telemetry in selected range", latest()),
        height=5,
    )
    d.row(
        chart(
            TELEMETRY,
            "Event volume by Sysmon ID | top 20 IDs",
            timeline(),
            [count("Events")],
            kind="area_stacked",
            breakdown=terms("event.code", "Sysmon event ID", 20),
        ),
        donut(
            TELEMETRY,
            "Sysmon event composition",
            filters(
                [
                    ("Process creation (1)", 'event.code: "1"'),
                    ("File creation (11)", 'event.code: "11"'),
                    ("File deletion (26)", 'event.code: "26"'),
                    ("Registry (12/13/14)", 'event.code: ("12" or "13" or "14")'),
                    ("Network connections (3)", 'event.code: "3"'),
                    (
                        "Other events",
                        'NOT event.code: ("1" or "3" or "11" or "12" or "13" or "14" or "26")',
                    ),
                ]
            ),
        ),
    )
    d.row(
        heatmap(
            TELEMETRY,
            "Event-time density by Sysmon ID | top 20 IDs",
            timeline(),
            terms("event.code", "Sysmon event ID", 20),
        ),
        chart(
            TELEMETRY,
            "Process starts by executable | event ID 1",
            terms("process.executable", "Executable", 12),
            [count("Process creation events")],
            expression='event.code: "1"',
            horizontal=True,
        ),
    )
    d.row(
        chart(
            TELEMETRY,
            "Created file names | event ID 11",
            terms("file.name", "File name", 12),
            [count("File creation events")],
            expression='event.code: "11"',
            horizontal=True,
        ),
        chart(
            TELEMETRY,
            "Registry paths | event IDs 12, 13, 14",
            terms("registry.path", "Registry path", 12),
            [count("Registry change events")],
            expression='event.code: ("12" or "13" or "14")',
            horizontal=True,
        ),
    )
    d.row(
        heatmap(
            TELEMETRY,
            "Connection events by destination IP and port | top destinations",
            terms("destination.port", "Destination port", 10),
            terms("destination.ip", "Destination IP", 12),
            'event.code: "3"',
        ),
        chart(
            TELEMETRY,
            "Configured ATT&CK tags | overlapping event counts",
            terms("threat.technique.id", "Parent technique", 15),
            [count("Events containing technique tag")],
            horizontal=True,
        ),
    )
    d.row(
        chart(
            TELEMETRY,
            "File activity over event time",
            timeline(),
            [count("Events")],
            kind="line",
            breakdown=filters(
                [
                    ("Timestamp change (2)", 'event.code: "2"'),
                    ("File creation (11)", 'event.code: "11"'),
                    ("Delete detected (26)", 'event.code: "26"'),
                ]
            ),
        ),
        chart(
            TELEMETRY,
            "Registry activity over event time",
            timeline(),
            [count("Events")],
            kind="line",
            breakdown=filters(
                [
                    ("Object create/delete (12)", 'event.code: "12"'),
                    ("Value set (13)", 'event.code: "13"'),
                    ("Object rename (14)", 'event.code: "14"'),
                ]
            ),
        ),
    )
    d.note(
        "Evidence context",
        "Charts showing top values can omit less frequent values; event-ID slices form "
        "disjoint categories, including Other events. ATT&CK tags come from named Sysmon rules, "
        "can overlap, and do not confirm an attack. Event 23 archival deletion is disabled; "
        "event 26 records deletion without archival. Missing DNS, process-access or tags can "
        "follow collection rules. Historical activity does not establish current connectivity. "
        "Expand evidence rows for complete commands, ancestry and raw Sysmon fields.",
        height=6,
    )
    d.evidence(
        TELEMETRY,
        "Process creation evidence | commands, ancestry and identity",
        [
            "@timestamp",
            "host.name",
            "host.id",
            "user.name",
            "process.entity_id",
            "process.executable",
            "process.command_line",
            "process.parent.entity_id",
            "process.parent.executable",
            "process.parent.command_line",
            "rule.name",
            "threat.technique.id",
        ],
        'event.code: "1"',
    )
    d.evidence(
        TELEMETRY,
        "File, registry and network evidence | expand rows for full context",
        [
            "@timestamp",
            "host.name",
            "event.code",
            "process.entity_id",
            "process.executable",
            "file.path",
            "file.extension",
            "registry.path",
            "source.ip",
            "source.port",
            "destination.ip",
            "destination.port",
            "network.transport",
            "dns.question.name",
            "rule.name",
            "threat.technique.id",
        ],
        'event.code: ("2" or "3" or "11" or "12" or "13" or "14" or "22" or "26")',
    )
    return d


def quality() -> Dashboard:
    d = Dashboard(
        "telemetry-quality",
        "Telemetry Quality",
        "Historical stream volume, event density, model and schema composition, "
        "field coverage and document-contract exceptions; separate from runtime health.",
    )
    d.note(
        "Data quality scope",
        "Compare the three retained streams in event time. Telemetry events, overlapping "
        "window scores and reported detections count different things. "
        "These charts describe retained data, not current service health.",
        height=5,
    )
    d.row(
        kpi(TELEMETRY, "Retained telemetry events in selection", count("Events")),
        kpi(SCORES, "Retained window scores in selection", count("Scored windows")),
        kpi(DETECTIONS, "Retained detections in selection", count("Reported windows")),
        height=5,
    )
    d.row(
        chart(
            TELEMETRY,
            "Telemetry coverage over event time",
            timeline(),
            [count("Events")],
            kind="area_stacked",
        ),
        chart(
            SCORES,
            "Window-score coverage over event time",
            timeline(),
            [count("Windows")],
            kind="area_stacked",
        ),
        chart(
            DETECTIONS,
            "Detection coverage over event time",
            timeline(),
            [count("Detections")],
            kind="area_stacked",
        ),
    )
    d.row(
        heatmap(
            TELEMETRY,
            "Telemetry collection density | event time by Sysmon ID",
            timeline(),
            terms("event.code", "Sysmon event ID", 20),
        ),
        donut(
            SCORES,
            "Model-version share | top 10 recorded versions",
            terms("logsentinel.model.version", "Model version", 10),
        ),
    )
    failures = [
        ("Reported without gate", VERDICT + "reported: true and NOT " + VERDICT + "gated: true"),
        ("Ungated marked suspicious", VERDICT + "gated: false and " + VERDICT + "suspicious: true"),
        (
            "Missing verdict flags",
            "NOT "
            + VERDICT
            + "gated: * or NOT "
            + VERDICT
            + "reported: * or NOT "
            + VERDICT
            + "suspicious: *",
        ),
        ("Missing window ID", "NOT logsentinel.window.id: *"),
        ("Missing host ID", "NOT host.id: *"),
        ("Missing schema version", "NOT logsentinel.schema_version: *"),
        (
            "Gated without confidence",
            VERDICT + "gated: true and NOT " + VERDICT + "confidence_score: *",
        ),
        ("Gated without label", VERDICT + "gated: true and NOT " + VERDICT + "label: *"),
    ]
    d.row(
        chart(
            SCORES,
            "Window-score contract exceptions | overlapping checks",
            filters(failures),
            [count("Window scores matching condition")],
            horizontal=True,
        ),
        chart(
            DETECTIONS,
            "Detection contract exceptions | overlapping checks",
            filters(
                failures
                + [
                    ("Detection not reported", "NOT " + VERDICT + "reported: true"),
                    ("Detection not gated", "NOT " + VERDICT + "gated: true"),
                ]
            ),
            [count("Detections matching condition")],
            horizontal=True,
        ),
        height=16,
    )
    coverage = [
        ("Missing timestamp", "NOT @timestamp: *"),
        ("Missing host name", "NOT host.name: *"),
        ("Missing event code", "NOT event.code: *"),
        ("Process start without executable", 'event.code: "1" and NOT process.executable: *'),
        ("File creation without path", 'event.code: "11" and NOT file.path: *'),
        ("Network event without destination IP", 'event.code: "3" and NOT destination.ip: *'),
        (
            "Registry change without path",
            'event.code: ("12" or "13" or "14") and NOT registry.path: *',
        ),
        ("MITRE parse failure tag", 'tags: "_mitre_parse_failure"'),
        ("Hash parse failure tag", 'tags: "_hash_parse_failure"'),
    ]
    d.row(
        chart(
            TELEMETRY,
            "Telemetry field coverage | overlapping exception checks",
            filters(coverage),
            [count("Events matching condition")],
            horizontal=True,
        ),
        heatmap(
            SCORES,
            "Recorded schema and model combinations",
            terms("logsentinel.schema_version", "Schema version", 10),
            terms("logsentinel.model.version", "Model version", 10),
        ),
        height=16,
    )
    d.row(
        table(
            SCORES,
            "Scored windows | model, stored threshold and time bounds",
            [terms("logsentinel.model.version", "Model version", 20)],
            [
                count("Windows"),
                metric("min", "Minimum stored threshold", VERDICT + "threshold"),
                metric("max", "Maximum stored threshold", VERDICT + "threshold"),
                metric("min", "First window end", "@timestamp"),
                latest("Last window end"),
            ],
        ),
        height=12,
    )
    d.note(
        "Reading coverage and exceptions",
        "Stream charts have independent count scales; retention and replay affect coverage. "
        "Exception categories can overlap; zero exceptions in an empty selection proves "
        "nothing about runtime health. The time filter can exclude documents missing "
        "`@timestamp`; use `verify_dashboards.py --live` for all-time checks and field mappings. "
        "Old schema/model versions can coexist; absent ATT&CK and scheduled-window process "
        "fields can be valid. These charts do not join window IDs or measure Docker health, "
        "Kafka lag, VM connectivity or detection latency.",
        height=6,
    )
    d.evidence(
        SCORES,
        "Window-score exceptions | inspect schema and source document",
        [
            "@timestamp",
            "host.name",
            "host.id",
            "logsentinel.schema_version",
            "logsentinel.window.id",
            VERDICT + "gated",
            VERDICT + "suspicious",
            VERDICT + "reported",
            VERDICT + "confidence_score",
            VERDICT + "label",
            "logsentinel.model.version",
        ],
        " or ".join(f"({expression})" for _, expression in failures),
    )
    return d


def definitions() -> dict[str, dict[str, Any]]:
    dashboards = [overview(), detections(), window_scores(), telemetry(), quality()]
    return {dashboard.name: dashboard.body for dashboard in dashboards}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--write", action="store_true", help="write generated source definitions")
    args = parser.parse_args(argv)
    differences = []
    for name, body in definitions().items():
        target = ROOT / "dashboard" / f"{name}.json"
        content = json.dumps(body, ensure_ascii=False, indent=2) + "\n"
        if args.write:
            target.write_text(content, encoding="utf-8", newline="\n")
        elif not target.exists() or target.read_text(encoding="utf-8") != content:
            differences.append(target.name)
        print(f"{target.name}: {len(body['panels'])} panels")
    if differences:
        print("Definitions differ: " + ", ".join(differences))
        return 1
    print(
        "Dashboard definitions written" if args.write else "Dashboard definitions match generator"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
