"""Human-readable rendering of query and evaluation results."""

from __future__ import annotations

import json
from typing import Any


def render(result: dict[str, Any], *, fmt: str, kind: str | None = None) -> str:
    if fmt == "json":
        return json.dumps(result, indent=2, sort_keys=False, default=str)
    resolved = kind or _infer_kind(result)
    if resolved == "stack" or ("quality" in result and "components" in result):
        return _render_stack(result)
    if resolved == "captures":
        return _render_captures(result)
    if resolved == "performance":
        return _render_performance(result)
    if resolved == "full_report" or result.get("kind") == "full_report":
        return _render_full(result)
    return json.dumps(result, indent=2, default=str)


def _infer_kind(result: dict[str, Any]) -> str | None:
    if result.get("kind") == "full_report":
        return "full_report"
    if "classification" in result and "model_auc" in result:
        return "captures"
    if "pipeline_throughput" in result and "docker_stats" in result:
        return "performance"
    if "quality" in result and "components" in result:
        return "stack"
    return None


def _render_stack(result: dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    lines: list[str] = [
        f"SentinelBench {result.get('version')} — stack evaluation",
        f"evaluated_at={result.get('evaluated_at')}  since={result.get('since')}  "
        f"sample_size={result.get('sample_size')}",
        "",
        f"SUMMARY: {'PASS' if summary.get('ok') else 'FAIL'}",
    ]
    failed = summary.get("failed") or []
    if failed:
        lines.append(f"  failed: {', '.join(failed)}")
    lines.append("")
    lines.append("Components:")
    for name, ok in (summary.get("component_ok") or {}).items():
        body = (result.get("components") or {}).get(name) or {}
        lines.append(f"  {'OK  ' if ok else 'FAIL'}  {name}{_component_detail(name, body)}")
    lines.append("")
    lines.append("Quality:")
    quality = result.get("quality") or {}
    for name in (
        "completeness",
        "latency",
        "detection",
        "consistency",
        "coverage",
        "operations",
    ):
        body = quality.get(name) or {}
        ok = body.get("ok")
        mark = "OK  " if ok else ("FAIL" if ok is False else "INFO")
        lines.append(f"  {mark}  {name}{_quality_detail(name, body)}")
    lines.append("")
    lines.append("Latency stages (seconds):")
    stages = ((quality.get("latency") or {}).get("stages")) or {}
    for stage_name, stage in stages.items():
        stats = stage.get("stats") or {}
        if not stats:
            lines.append(f"  - {stage_name}: no samples")
            continue
        lines.append(
            f"  - {stage_name}: n={int(stats.get('count', 0))}  "
            f"p50={_fmt(stats.get('p50'))}  p95={_fmt(stats.get('p95'))}  "
            f"max={_fmt(stats.get('max'))}"
        )
    ops = quality.get("operations") or {}
    e2e = ops.get("end_to_end_latency") or {}
    if e2e.get("stats"):
        stats = e2e["stats"]
        lines.append(
            f"  - end_to_end_live: n={int(stats.get('count', 0))}  "
            f"p50={_fmt(stats.get('p50'))}  p95={_fmt(stats.get('p95'))}"
        )
    thr = (ops.get("telemetry_throughput") or {}).get("events_per_sec") or {}
    if thr:
        lines.append(
            f"Telemetry throughput (evt/s): p50={_fmt(thr.get('p50'))}  "
            f"p95={_fmt(thr.get('p95'))}  max={_fmt(thr.get('max'))}"
        )
    detection = quality.get("detection") or {}
    funnel = detection.get("funnel") or {}
    if funnel:
        lines.append("")
        lines.append(
            "Detection funnel: "
            f"windows={funnel.get('window_scores')} → "
            f"gated={funnel.get('gated')} → "
            f"suspicious={funnel.get('suspicious')} → "
            f"reported={funnel.get('reported_window_scores')} / "
            f"detections={funnel.get('detections')}"
        )
    coverage = quality.get("coverage") or {}
    if coverage:
        lines.append(
            "Alert example coverage (sampled): "
            f"{coverage.get('sampled_detections_cited')}/"
            f"{coverage.get('detection_sample_size')} "
            f"(rate={coverage.get('sample_example_coverage_rate')})"
        )
    return "\n".join(lines)


def _render_captures(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        return f"CAPTURES: FAIL\n  error={result.get('error')}\n  hint={result.get('hint')}"
    session = ((result.get("classification") or {}).get("at_threshold") or {}).get("session") or {}
    alerts = result.get("operational_false_alerts") or {}
    ttfd = result.get("time_to_first_detection") or {}
    lines = [
        "SentinelBench — offline capture evaluation",
        f"source={result.get('source')}  generated_at={result.get('generated_at')}",
        f"threshold={result.get('threshold')}  model_auc={result.get('model_auc')}",
        "",
        "Classification (session, at threshold):",
        f"  TP={session.get('tp')} FN={session.get('fn')} "
        f"FP={session.get('fp')} TN={session.get('tn')}",
        f"  recall={session.get('recall')}  precision={session.get('precision')}  "
        f"F2={session.get('f2')}  MCC={session.get('mcc')}  FPR={session.get('fpr')}",
        f"  recall Wilson 95%={_wilson(session.get('recall_wilson'))}",
        "",
        "Operational false alerts:",
        f"  goodware_hours={alerts.get('goodware_hours')}  "
        f"suspicious/hour={alerts.get('suspicious_detections_per_hour')}  "
        f"CI={_poisson(alerts.get('suspicious_detections_per_hour_ci'))}",
        "",
        "TTFD (seconds):",
        f"  sessions={ttfd.get('sessions')}  median={ttfd.get('median_sec')}  "
        f"p90={ttfd.get('p90_sec')}  max={ttfd.get('max_sec')}",
        "",
        "Baseline false:true ratios (illustration):",
    ]
    for row in result.get("baseline_rates") or []:
        lines.append(
            f"  Y={row.get('incidents_per_year')}/yr → "
            f"{row.get('false_to_true_ratio')}:1  (πh={row.get('pi_h')})"
        )
    return "\n".join(lines)


def _render_performance(result: dict[str, Any]) -> str:
    pipe = result.get("pipeline_throughput") or {}
    stats = result.get("docker_stats") or {}
    rate = result.get("logstash_rate") or {}
    lines = [
        "SentinelBench — performance probe",
        f"Pipeline: skipped={pipe.get('skipped')}  "
        f"evt/s={pipe.get('events_per_sec')}  "
        f"µs/evt p50={_fmt((pipe.get('microseconds_per_event') or {}).get('p50'))}  "
        f"vs_lab_peak={pipe.get('vs_lab_peak')}",
        f"Docker stats containers={len(stats.get('containers') or [])}",
        f"Logstash rate sample_sec={rate.get('sample_sec')}",
    ]
    for container, pipes in (rate.get("services") or {}).items():
        for name, body in (pipes or {}).items():
            lines.append(
                f"  {container}/{name}: in/s={body.get('events_in_per_sec')}  "
                f"out/s={body.get('events_out_per_sec')}"
            )
    ref = result.get("reference") or {}
    lines.append(
        f"Reference: lab peak={ref.get('observed_peak_events_per_sec_lab')} evt/s  "
        f"reported inference={ref.get('reported_inference_events_per_sec')} evt/s"
    )
    return "\n".join(lines)


def _render_full(result: dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    lines = [
        f"SentinelBench {result.get('version')} — full report (statistics.md groups)",
        f"evaluated_at={result.get('evaluated_at')}",
        f"SUMMARY: {'PASS' if summary.get('ok') else 'FAIL'}",
    ]
    if summary.get("failed"):
        lines.append(f"  failed: {', '.join(summary['failed'])}")
    lines.append(f"  groups: {', '.join(summary.get('groups_present') or [])}")
    lines.append("")
    groups = result.get("groups") or {}
    labels = {
        "classification": "Classification (F2/MCC)",
        "ranking_auc": "Ranking (AUC)",
        "operational_false_alerts": "False alerts / hour",
        "detection_latency": "Detection latency (TTFD + stack)",
        "indicator_coverage": "Indicator coverage",
        "system_scores": "System scores",
        "inference_intervals": "Inference intervals",
        "baseline_rates": "Baseline rates",
        "stack_reliability_performance": "Stack reliability & performance",
    }
    for key, title in labels.items():
        body = groups.get(key)
        if body is None:
            lines.append(f"{title}: (absent)")
            continue
        lines.append(f"{title}: present")
        if key == "classification":
            session = ((body.get("at_threshold") or {}).get("session")) or {}
            lines.append(
                f"  session F2={session.get('f2')}  MCC={session.get('mcc')}  "
                f"recall={session.get('recall')}"
            )
        elif key == "ranking_auc":
            lines.append(f"  model_auc={body.get('model_auc')}")
        elif key == "operational_false_alerts":
            lines.append(
                f"  suspicious/hour={body.get('suspicious_detections_per_hour')}  "
                f"hours={body.get('goodware_hours')}"
            )
        elif key == "detection_latency":
            ttfd = body.get("ttfd_offline") or {}
            lines.append(f"  TTFD median={ttfd.get('median_sec')}  p90={ttfd.get('p90_sec')}")
        elif key == "stack_reliability_performance":
            perf = body.get("performance_probe") or {}
            pipe = perf.get("pipeline_throughput") or {}
            lines.append(f"  pipeline evt/s={pipe.get('events_per_sec')}")
    sources = result.get("sources") or {}
    lines.append("")
    lines.append(
        f"sources: stack={sources.get('stack')}  "
        f"captures={sources.get('captures')}  "
        f"performance={sources.get('performance')}"
    )
    return "\n".join(lines)


def _component_detail(name: str, body: dict[str, Any]) -> str:
    if name == "elasticsearch":
        counts = body.get("document_counts") or {}
        return (
            f"  status={body.get('status')}  "
            f"detections={counts.get('detections')}  "
            f"window_scores={counts.get('window_scores')}  "
            f"notifications={counts.get('notifications')}"
        )
    if name == "kafka":
        groups = body.get("consumer_groups") or []
        lag = sum(g.get("lag_total") or 0 for g in groups if g.get("lag_total") is not None)
        missing = body.get("missing_topics") or []
        extra = f"  lag_total={lag}"
        if missing:
            extra += f"  missing={missing}"
        return extra
    if name == "kibana":
        rule = body.get("alerting_rule") or {}
        return (
            f"  level={body.get('overall_level')}  "
            f"rule={rule.get('name') or rule.get('id')}  "
            f"enabled={rule.get('enabled')}"
        )
    if name == "inference":
        status = body.get("status") or {}
        return (
            f"  healthy={status.get('healthy')}  model={status.get('model_version')}  "
            f"detections={status.get('detections')}"
        )
    if name == "notifications":
        health = body.get("health") or {}
        stats = health.get("stats") or {}
        return (
            f"  status={health.get('status')}  queued={stats.get('queued')}  "
            f"sent={stats.get('sent')}  pending={stats.get('pending')}"
        )
    if name == "logstash":
        services = body.get("services") or {}
        bits = [
            f"{svc}={meta.get('status')}"
            for svc, meta in services.items()
            if isinstance(meta, dict)
        ]
        return "  " + " ".join(bits) if bits else ""
    return ""


def _quality_detail(name: str, body: dict[str, Any]) -> str:
    if name == "completeness":
        families = body.get("families") or []
        bad = [f["index"] for f in families if not f.get("ok")]
        return f"  bad_families={bad or 'none'}"
    if name == "consistency":
        pair = body.get("detection_window_pairs") or {}
        notify = body.get("notification_deliveries") or {}
        return (
            f"  missing_scores={pair.get('missing_window_scores')}  "
            f"verdict_mismatches={pair.get('verdict_mismatches')}  "
            f"replay_drift={pair.get('likely_replay_drift')}  "
            f"notify_incomplete={notify.get('missing_any_channel')}"
        )
    if name == "detection":
        rates = body.get("rates") or {}
        return (
            f"  gate_rate={rates.get('gate_rate')}  "
            f"report_rate={rates.get('report_rate_given_suspicious')}"
        )
    if name == "coverage":
        return f"  example_coverage={body.get('sample_example_coverage_rate')}"
    if name == "latency":
        return f"  measured={body.get('measured_stages')}"
    if name == "operations":
        early = body.get("early_window_share") or {}
        ooo = body.get("timestamp_order") or {}
        return f"  early_rate={early.get('early_rate')}  ts_inversions={ooo.get('inversions')}"
    return ""


def _wilson(value: Any) -> str:
    if not isinstance(value, dict):
        return "-"
    return f"[{value.get('low')}, {value.get('high')}]"


def _poisson(value: Any) -> str:
    if not isinstance(value, dict):
        return "-"
    return f"{value.get('rate_per_hour')} [{value.get('low')}, {value.get('high')}]"


def _fmt(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)
