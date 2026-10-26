"""Offline capture metrics from ``evaluation.json`` (statistics.md groups 1–7)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from sentinelbench.repo import find_logsentinel_root
from sentinelbench.stats import (
    enrich_confusion,
    false_to_true_ratio,
    poisson_rate_ci,
    rule_of_three,
    wilson_interval,
)


def evaluate_captures(
    *,
    evaluation_json: Path | None = None,
    logsentinel_root: Path | None = None,
    run_evaluate: bool = False,
    captures_dir: Path | None = None,
    holdout: list[str] | None = None,
    incident_years: tuple[float, ...] = (1.0, 10.0, 100.0),
) -> dict[str, Any]:
    root = find_logsentinel_root(logsentinel_root)
    path = evaluation_json
    if path is None and root is not None:
        path = root / "inference" / "artifacts" / "evaluation.json"
    if run_evaluate:
        if root is None:
            return {"ok": False, "error": "logsentinel root not found for --run-evaluate"}
        run_result = _run_inference_evaluate(
            root,
            captures_dir=captures_dir or root / "sentinelcap" / "captures",
            holdout=holdout or [],
        )
        if run_result.get("error"):
            return {"ok": False, **run_result}
        path = Path(run_result["evaluation_json"])
    if path is None or not path.is_file():
        return {
            "ok": False,
            "error": f"evaluation.json not found ({path})",
            "hint": "pass --evaluation-json or run inference evaluate / --run-evaluate",
        }
    raw = json.loads(path.read_text(encoding="utf-8"))
    return normalize_evaluation(raw, source=str(path), incident_years=incident_years)


def normalize_evaluation(
    raw: dict[str, Any],
    *,
    source: str,
    incident_years: tuple[float, ...] = (1.0, 10.0, 100.0),
) -> dict[str, Any]:
    cv = raw.get("cross_validation") or {}
    at = cv.get("at_threshold") or {}
    gate = cv.get("gate_only") or {}
    session = enrich_confusion(at.get("session"))
    window = enrich_confusion(at.get("window"))
    gate_session = enrich_confusion(gate.get("session"))
    gate_window = enrich_confusion(gate.get("window"))
    alerts = dict(cv.get("goodware_alerts") or {})
    hours = float(alerts.get("goodware_hours") or 0.0)
    for key_count, key_rate in (
        ("flagged_windows", "flagged_windows_per_hour"),
        ("detections_after_suppression", "detections_per_hour"),
        ("suspicious_detections", "suspicious_detections_per_hour"),
    ):
        count = int(alerts.get(key_count) or 0)
        alerts[f"{key_rate}_ci"] = poisson_rate_ci(count, hours)
    flagged = cv.get("flagged_goodware") or []
    goodware_sessions = int((raw.get("coverage") or {}).get("goodware", {}).get("sessions") or 0)
    ransomware_sessions = int(
        (raw.get("coverage") or {}).get("ransomware", {}).get("sessions") or 0
    )
    fp_sessions = len(flagged) if flagged else int((session or {}).get("fp") or 0)
    goodware_fp_rate = (
        wilson_interval(fp_sessions, goodware_sessions) if goodware_sessions else None
    )
    held = raw.get("held_out") or {}
    held_ci = None
    if isinstance(held, dict):
        held_ransomware = held.get("ransomware")
        if isinstance(held_ransomware, dict):
            detected = held_ransomware.get("detected")
            total = held_ransomware.get("sessions")
            if isinstance(detected, int) and isinstance(total, int) and total > 0:
                held_ci = wilson_interval(detected, total)
                if detected == total:
                    held_ci = {
                        **(held_ci or {}),
                        "rule_of_three_miss_upper": rule_of_three(total),
                    }
        if held_ci is None:
            sessions = held.get("sessions") or []
            if isinstance(sessions, list) and sessions:
                detected_n = sum(1 for s in sessions if (s or {}).get("detected"))
                held_ci = wilson_interval(detected_n, len(sessions))

    tpr = float((session or {}).get("recall") or 0.0)
    lambda_susp = float(alerts.get("suspicious_detections_per_hour") or 0.0)
    baselines = [
        false_to_true_ratio(lambda_susp, tpr, years) for years in incident_years if years > 0
    ]
    coverage = _coverage_with_rates(raw.get("coverage") or {})
    return {
        "ok": True,
        "source": source,
        "generated_at": raw.get("generated_at"),
        "threshold": raw.get("threshold"),
        "model_auc": cv.get("model_auc"),
        "classification": {
            "at_threshold": {"session": session, "window": window},
            "gate_only": {"session": gate_session, "window": gate_window},
            "missed_ransomware": cv.get("missed_ransomware") or [],
            "flagged_goodware": flagged,
        },
        "ranking": {"model_auc": cv.get("model_auc")},
        "operational_false_alerts": {
            **alerts,
            "goodware_session_false_alert_rate": goodware_fp_rate,
        },
        "time_to_first_detection": cv.get("time_to_first_detection"),
        "indicator_coverage": coverage,
        "scores": {
            "threshold": raw.get("threshold"),
            "scoring": raw.get("scoring"),
            "concurrent_goodware": cv.get("concurrent_goodware"),
        },
        "inference_intervals": {
            "session_recall": (session or {}).get("recall_wilson"),
            "session_precision": (session or {}).get("precision_wilson"),
            "goodware_false_alert_sessions": goodware_fp_rate,
            "held_out": held_ci,
            "ransomware_sessions_in_coverage": ransomware_sessions,
            "goodware_sessions_in_coverage": goodware_sessions,
        },
        "baseline_rates": baselines,
        "held_out": held if isinstance(held, dict) else {"raw": held},
        "window": raw.get("window"),
        "holdout_runs": raw.get("holdout"),
    }


def _coverage_with_rates(coverage: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for cls in ("ransomware", "goodware"):
        block = coverage.get(cls) or {}
        n = int(block.get("sessions") or 0)
        indicators = {}
        for name, stats in (block.get("indicators") or {}).items():
            hit = int((stats or {}).get("sessions") or 0)
            indicators[name] = {
                **(stats or {}),
                "rate": round(hit / n, 6) if n else None,
                "wilson": wilson_interval(hit, n) if n else None,
            }
        out[cls] = {
            "sessions": n,
            "families": block.get("families"),
            "indicators": indicators,
        }
    return out


def _run_inference_evaluate(
    root: Path, *, captures_dir: Path, holdout: list[str]
) -> dict[str, Any]:
    artifacts = root / "inference" / "artifacts"
    cmd = [
        sys.executable,
        "-m",
        "training.evaluate",
        "--captures",
        str(captures_dir),
        "--artifacts",
        str(artifacts),
        "--no-write",
    ]
    for run in holdout:
        cmd.extend(["--holdout", run])
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(root / "inference"),
            capture_output=True,
            text=True,
            check=False,
            timeout=3600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": f"evaluate subprocess failed: {exc}"}
    if completed.returncode != 0:
        return {
            "error": f"evaluate exited {completed.returncode}",
            "stderr": (completed.stderr or "")[-2000:],
        }
    # --no-write prints JSON to stdout; also refresh from file if train wrote earlier.
    text = completed.stdout.strip()
    try:
        # evaluate prints the full report as the last JSON object
        start = text.find("{")
        report = json.loads(text[start:]) if start >= 0 else None
    except json.JSONDecodeError:
        report = None
    out_path = artifacts / "evaluation.sentinelbench.json"
    if report is None:
        fallback = artifacts / "evaluation.json"
        if not fallback.is_file():
            return {"error": "evaluate produced no JSON", "stdout_tail": text[-1000:]}
        return {"evaluation_json": str(fallback), "note": "used existing evaluation.json"}
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return {"evaluation_json": str(out_path), "ran_evaluate": True}
