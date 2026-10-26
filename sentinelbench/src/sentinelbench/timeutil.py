"""UTC timestamp parsing and percentile helpers."""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from datetime import UTC, datetime

_FRAC = re.compile(
    r"^(?P<head>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)


def parse_utc(value: str | None) -> datetime | None:
    """Parse an Elasticsearch / ISO-8601 instant; nanoseconds are truncated to microseconds."""
    if not value or not isinstance(value, str):
        return None
    match = _FRAC.match(value.strip())
    if match is None:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            return None
    frac = (match.group("frac") or "")[:6].ljust(6, "0")
    tz = match.group("tz") or "Z"
    if tz == "Z":
        tz = "+00:00"
    elif len(tz) == 5 and tz[0] in "+-":
        tz = f"{tz[:3]}:{tz[3:]}"
    text = (
        f"{match.group('head')}.{frac}{tz}" if match.group("frac") else f"{match.group('head')}{tz}"
    )
    try:
        return datetime.fromisoformat(text).astimezone(UTC)
    except ValueError:
        return None


def lag_sec(later: datetime | None, earlier: datetime | None) -> float | None:
    if later is None or earlier is None:
        return None
    return (later - earlier).total_seconds()


def percentiles(
    values: Sequence[float], points: Sequence[float] = (50, 90, 95, 99)
) -> dict[str, float]:
    """Nearest-rank percentiles; empty input yields an empty dict."""
    if not values:
        return {}
    ordered = sorted(values)
    n = len(ordered)
    out: dict[str, float] = {
        "count": float(n),
        "min": ordered[0],
        "max": ordered[-1],
        "mean": sum(ordered) / n,
    }
    for point in points:
        rank = max(1, math.ceil(point / 100 * n)) - 1
        out[f"p{int(point)}"] = ordered[rank]
    return out
