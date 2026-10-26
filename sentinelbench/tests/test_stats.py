"""Statistical helpers used in the offline report."""

from __future__ import annotations

from sentinelbench.stats import (
    enrich_confusion,
    false_to_true_ratio,
    poisson_rate_ci,
    wilson_interval,
)


def test_wilson_known_range() -> None:
    interval = wilson_interval(48, 50)
    assert interval is not None
    assert 0.85 < interval["low"] < interval["value"] < interval["high"] < 1.0


def test_poisson_rate() -> None:
    ci = poisson_rate_ci(8, 22.03)
    assert ci is not None
    assert ci["rate_per_hour"] == round(8 / 22.03, 6)


def test_false_to_true_ratio_illustration() -> None:
    row = false_to_true_ratio(0.39, 0.96, 1.0)
    assert row["false_to_true_ratio"] is not None
    assert row["false_to_true_ratio"] > 1000


def test_enrich_confusion_adds_fpr() -> None:
    enriched = enrich_confusion({"tp": 48, "fp": 3, "tn": 69, "fn": 2, "recall": 0.96})
    assert enriched is not None
    assert enriched["fpr"] == round(3 / 72, 6)
