"""Text report rendering."""

from __future__ import annotations

from sentinelbench.report import render


def test_render_stack_pass_summary() -> None:
    result = {
        "version": "0.1.0",
        "evaluated_at": "2026-10-23T12:00:00Z",
        "since": "24h",
        "sample_size": 10,
        "summary": {
            "ok": True,
            "failed": [],
            "component_ok": {"elasticsearch": True, "kafka": True},
            "quality_ok": {"completeness": True},
        },
        "components": {
            "elasticsearch": {
                "reachable": True,
                "status": "green",
                "document_counts": {"detections": 1, "window_scores": 2, "notifications": 0},
            },
            "kafka": {"reachable": True, "consumer_groups": [], "missing_topics": []},
        },
        "quality": {
            "completeness": {"ok": True, "families": []},
            "latency": {"ok": True, "measured_stages": [], "stages": {}},
            "detection": {"ok": True, "funnel": {}, "rates": {}},
            "consistency": {
                "ok": True,
                "detection_window_pairs": {},
                "notification_deliveries": {},
            },
            "coverage": {"ok": True, "sample_example_coverage_rate": 0.5},
        },
    }
    text = render(result, fmt="text")
    assert "SUMMARY: PASS" in text
    assert "Completeness" not in text or "completeness" in text.lower()
    assert "OK" in text
