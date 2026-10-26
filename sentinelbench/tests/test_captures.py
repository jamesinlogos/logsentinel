"""Normalize evaluation.json into report groups."""

from __future__ import annotations

from sentinelbench.captures import normalize_evaluation


def test_normalize_evaluation_enriches_metrics() -> None:
    raw = {
        "generated_at": "2026-10-20T18:40:20+00:00",
        "threshold": 0.6,
        "scoring": {"weight_indicator": 0.5},
        "coverage": {
            "ransomware": {
                "sessions": 50,
                "families": 11,
                "indicators": {"gate": {"sessions": 48, "families": 11}},
            },
            "goodware": {
                "sessions": 70,
                "families": 1,
                "indicators": {"gate": {"sessions": 7, "families": 1}},
            },
        },
        "cross_validation": {
            "model_auc": 0.9251,
            "at_threshold": {
                "session": {
                    "tp": 48,
                    "fp": 3,
                    "tn": 69,
                    "fn": 2,
                    "recall": 0.96,
                    "precision": 0.9412,
                    "f2": 0.9562,
                    "mcc": 0.9157,
                },
                "window": {
                    "tp": 442,
                    "fp": 29,
                    "tn": 3303,
                    "fn": 382,
                    "recall": 0.5364,
                    "precision": 0.9384,
                    "f2": 0.5867,
                    "mcc": 0.6637,
                },
            },
            "gate_only": {"session": {}, "window": {}},
            "goodware_alerts": {
                "goodware_hours": 22.03,
                "suspicious_detections": 8,
                "suspicious_detections_per_hour": 0.36,
            },
            "time_to_first_detection": {
                "sessions": 48,
                "median_sec": 2.4,
                "p90_sec": 39.2,
                "max_sec": 186.7,
            },
            "flagged_goodware": ["a", "b", "c"],
        },
        "held_out": {"ransomware": {"sessions": 45, "detected": 44}},
    }
    report = normalize_evaluation(raw, source="memory")
    assert report["ok"] is True
    session = report["classification"]["at_threshold"]["session"]
    assert session["f2"] == 0.9562
    assert session["fpr"] is not None
    assert report["model_auc"] == 0.9251
    assert report["operational_false_alerts"]["suspicious_detections_per_hour_ci"] is not None
    assert report["indicator_coverage"]["ransomware"]["indicators"]["gate"]["wilson"] is not None
    assert report["baseline_rates"]
    assert report["inference_intervals"]["held_out"]["successes"] == 44.0
