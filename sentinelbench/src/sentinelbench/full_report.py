"""Combine stack / captures / performance into the nine statistics.md groups."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelbench import __version__
from sentinelbench.captures import evaluate_captures
from sentinelbench.config import StackEndpoints
from sentinelbench.metrics.evaluate import evaluate_stack
from sentinelbench.performance import probe_performance


def build_full_report(
    endpoints: StackEndpoints,
    *,
    evaluation_json: Path | None = None,
    logsentinel_root: Path | None = None,
    run_evaluate: bool = False,
    skip_stack: bool = False,
    skip_performance: bool = False,
    sample_events: int = 5000,
) -> dict[str, Any]:
    stack = None if skip_stack else evaluate_stack(endpoints)
    captures = evaluate_captures(
        evaluation_json=evaluation_json,
        logsentinel_root=logsentinel_root,
        run_evaluate=run_evaluate,
    )
    performance = (
        None
        if skip_performance
        else probe_performance(
            endpoints, logsentinel_root=logsentinel_root, sample_events=sample_events
        )
    )
    groups = _nine_groups(stack=stack, captures=captures, performance=performance)
    failed: list[str] = []
    if stack and not (stack.get("summary") or {}).get("ok"):
        failed.extend(f"stack:{name}" for name in (stack.get("summary") or {}).get("failed") or [])
    if captures and not captures.get("ok"):
        failed.append("captures")
    return {
        "tool": "sentinelbench",
        "version": __version__,
        "kind": "full_report",
        "evaluated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "ok": not failed,
            "failed": failed,
            "groups_present": [key for key, body in groups.items() if body is not None],
        },
        "groups": groups,
        "sources": {
            "stack": None if stack is None else "query stack",
            "captures": captures.get("source") if captures else None,
            "performance": None if performance is None else "probe performance",
        },
        "raw": {
            "stack": stack,
            "captures": captures,
            "performance": performance,
        },
    }


def _nine_groups(
    *,
    stack: dict[str, Any] | None,
    captures: dict[str, Any] | None,
    performance: dict[str, Any] | None,
) -> dict[str, Any]:
    quality = (stack or {}).get("quality") or {}
    ops = quality.get("operations") or {}
    cap_ok = bool(captures and captures.get("ok"))
    return {
        "classification": (captures or {}).get("classification") if cap_ok else None,
        "ranking_auc": (captures or {}).get("ranking") if cap_ok else None,
        "operational_false_alerts": (
            (captures or {}).get("operational_false_alerts") if cap_ok else None
        ),
        "detection_latency": {
            "ttfd_offline": (captures or {}).get("time_to_first_detection") if cap_ok else None,
            "stack_stages": (quality.get("latency") or {}).get("stages"),
            "end_to_end_live": ops.get("end_to_end_latency"),
        },
        "indicator_coverage": (captures or {}).get("indicator_coverage") if cap_ok else None,
        "system_scores": {
            "offline": (captures or {}).get("scores") if cap_ok else None,
            "live_gated_distribution": ops.get("score_distribution"),
        },
        "inference_intervals": (captures or {}).get("inference_intervals") if cap_ok else None,
        "baseline_rates": (captures or {}).get("baseline_rates") if cap_ok else None,
        "stack_reliability_performance": {
            "components": (stack or {}).get("components"),
            "completeness": quality.get("completeness"),
            "consistency": quality.get("consistency"),
            "alert_coverage": quality.get("coverage"),
            "detection_funnel_live": quality.get("detection"),
            "operations": ops,
            "performance_probe": performance,
        },
    }
