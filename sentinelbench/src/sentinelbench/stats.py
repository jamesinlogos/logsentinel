"""Binomial / Poisson intervals and baseline-rate illustrations (statistics.md §2.7–2.8)."""

from __future__ import annotations

import math
from typing import Any


def wilson_interval(successes: int, trials: int, *, z: float = 1.96) -> dict[str, float] | None:
    """Wilson score interval for a binomial proportion."""
    if trials <= 0:
        return None
    p = successes / trials
    z2 = z * z
    denom = 1.0 + z2 / trials
    centre = (p + z2 / (2 * trials)) / denom
    half = (z / denom) * math.sqrt(p * (1.0 - p) / trials + z2 / (4 * trials * trials))
    return {
        "value": round(p, 6),
        "low": round(max(0.0, centre - half), 6),
        "high": round(min(1.0, centre + half), 6),
        "successes": float(successes),
        "trials": float(trials),
    }


def fpr(fp: int, tn: int) -> float | None:
    denom = fp + tn
    return round(fp / denom, 6) if denom else None


def poisson_rate_ci(count: int, hours: float, *, z: float = 1.96) -> dict[str, float] | None:
    """Normal approximation to the Poisson rate CI (count / hours)."""
    if hours <= 0:
        return None
    rate = count / hours
    # Garwood-style via normal on sqrt is heavier; report ±z·√count / hours.
    se = math.sqrt(count) / hours if count > 0 else z / hours
    return {
        "rate_per_hour": round(rate, 6),
        "low": round(max(0.0, rate - z * se), 6),
        "high": round(rate + z * se, 6),
        "count": float(count),
        "hours": round(hours, 4),
    }


def rule_of_three(trials: int) -> float | None:
    """Approximate one-sided 95% upper bound on a zero-event rate (3/n)."""
    if trials <= 0:
        return None
    return round(3.0 / trials, 6)


def ppv(tpr: float, fpr_value: float, prevalence: float) -> float | None:
    """Positive predictive value from TPR, FPR and prior π."""
    if not 0.0 <= prevalence <= 1.0:
        return None
    numerator = tpr * prevalence
    denominator = numerator + fpr_value * (1.0 - prevalence)
    if denominator <= 0:
        return None
    return round(numerator / denominator, 8)


def false_to_true_ratio(
    lambda_per_hour: float, tpr: float, incidents_per_year: float
) -> dict[str, Any]:
    """Illustrative λ / (TPR · πh) with πh = 1 / (8760 · Y) (statistics.md §2.8)."""
    hours_per_year = 8760.0
    pi_h = 1.0 / (hours_per_year * incidents_per_year) if incidents_per_year > 0 else 0.0
    expected_true = tpr * pi_h
    ratio = (lambda_per_hour / expected_true) if expected_true > 0 else None
    return {
        "incidents_per_year": incidents_per_year,
        "pi_h": pi_h,
        "lambda_per_hour": lambda_per_hour,
        "tpr": tpr,
        "false_to_true_ratio": round(ratio, 3) if ratio is not None else None,
        "note": "arithmetic illustration, not a live measurement",
    }


def enrich_confusion(block: dict[str, Any] | None) -> dict[str, Any] | None:
    """Add FPR and Wilson intervals on recall / precision / session FP rate."""
    if not block:
        return None
    tp = int(block.get("tp", 0))
    fp = int(block.get("fp", 0))
    tn = int(block.get("tn", 0))
    fn = int(block.get("fn", 0))
    out = dict(block)
    out["fpr"] = fpr(fp, tn)
    out["recall_wilson"] = wilson_interval(tp, tp + fn)
    out["precision_wilson"] = wilson_interval(tp, tp + fp)
    return out
