"""Phase 3 features of one window (inference/README.md section 8), shared by training and serving.

Counts are log1p-scaled; ratios and means are kept as they are. The order of
``FEATURE_NAMES`` is part of the model contract: it is stored with the trained
model and checked when the model is loaded.
"""

from __future__ import annotations

import math

from inference.indicators import INDICATORS, IndicatorResult
from inference.summary import WindowSummary

CODES = ("1", "2", "3", "11", "12", "13", "17", "26")
"""One column per Sysmon event code."""

FEATURE_NAMES: tuple[str, ...] = (
    "events",
    *(f"code_{code}" for code in CODES),
    "max_name_dirs",
    "max_name_branches",
    "distinct_extensions",
    "max_same_extension",
    "max_deletes",
    "file_name_entropy",
    "suspicious_path_ratio",
    "non_system_executable_ratio",
    "command_line_length",
    "lolbin_runs",
    "stop_commands",
    "max_cmd_children",
    "run_key_writes",
    "connections",
    "destination_ips",
    *(f"ind_{name}" for name in INDICATORS),
)


def compute(summary: WindowSummary, result: IndicatorResult) -> dict[str, float]:
    s = summary
    features: dict[str, float] = {
        "events": math.log1p(s.events),
        **{f"code_{code}": math.log1p(s.codes[code]) for code in CODES},
        "max_name_dirs": math.log1p(s.max_name_dirs),
        "max_name_branches": math.log1p(s.max_name_branches),
        "distinct_extensions": math.log1p(s.distinct_extensions),
        "max_same_extension": math.log1p(s.max_same_extension),
        "max_deletes": math.log1p(s.max_deletes),
        "file_name_entropy": s.name_entropy_sum / s.created_files if s.created_files else 0.0,
        "suspicious_path_ratio": _ratio(s.suspicious_paths, s.process_starts),
        "non_system_executable_ratio": _ratio(s.non_system_executables, s.process_starts),
        "command_line_length": _ratio(s.command_line_chars, s.process_starts),
        "lolbin_runs": math.log1p(s.lolbin_runs),
        "stop_commands": math.log1p(s.stop_commands),
        "max_cmd_children": math.log1p(s.max_cmd_children),
        "run_key_writes": math.log1p(s.run_key_writes),
        "connections": math.log1p(s.connections),
        "destination_ips": math.log1p(s.destination_ips),
    }
    for name in INDICATORS:
        features[f"ind_{name}"] = 1.0 if name in result.fired else 0.0
    return features


def _ratio(part: float, whole: int) -> float:
    return part / whole if whole else 0.0
