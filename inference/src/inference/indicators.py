"""Phase 2 - Indicator Engine (inference/README.md sections 4.1, 4.2).

Rules run over every event of one host window, not over "the sample's
processes": at inference time nothing says which process is malicious
(section 4.0). They read the counts of ``summary.py`` and count nothing themselves. A window
goes to Phase 3 only when at least one strong indicator fires (section 4.2).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

STRONG: dict[str, float] = {
    "mass_note_drop": 0.6,
    # The impact itself, and never seen in goodware (inference/README.md section 4.1): the
    # highest weight.
    "mass_file_replace": 0.8,
    "shadow_copy_deletion": 0.5,
    "recovery_disable": 0.4,
    "service_stop_burst": 0.4,
    "event_log_tamper": 0.5,
}
SUPPORT: dict[str, float] = {
    "ransom_note_keyword": 0.1,
    "cmd_burst": 0.2,
    "run_key_persistence": 0.2,
    "lolbins_execution": 0.2,
    "security_policy_tamper": 0.3,
    "remote_thread_injection": 0.3,
    "process_tampering": 0.8,
}
WEIGHTS: dict[str, float] = {**STRONG, **SUPPORT}
INDICATORS: tuple[str, ...] = tuple(WEIGHTS)
COMBOS: tuple[tuple[str, str, float], ...] = (
    ("mass_note_drop", "shadow_copy_deletion", 0.3),
    ("shadow_copy_deletion", "recovery_disable", 0.2),
    ("mass_note_drop", "event_log_tamper", 0.2),
    ("mass_note_drop", "service_stop_burst", 0.2),
    ("shadow_copy_deletion", "run_key_persistence", 0.15),
)

# MITRE ATT&CK technique ids and tactics reported for each indicator.
MITRE: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "mass_note_drop": (("T1486",), ("Impact",)),
    "mass_file_replace": (("T1486",), ("Impact",)),
    "shadow_copy_deletion": (("T1490",), ("Impact",)),
    "recovery_disable": (("T1490",), ("Impact",)),
    "service_stop_burst": (("T1489",), ("Impact",)),
    "event_log_tamper": (("T1070.001", "T1562.002"), ("Defense Evasion",)),
    "ransom_note_keyword": (("T1486",), ("Impact",)),
    "cmd_burst": (("T1059.003",), ("Execution",)),
    "run_key_persistence": (("T1547.001",), ("Persistence", "Privilege Escalation")),
    "lolbins_execution": (("T1218",), ("Defense Evasion",)),
    "security_policy_tamper": (
        ("T1548.002", "T1562.001"),
        ("Privilege Escalation", "Defense Evasion"),
    ),
    "remote_thread_injection": (("T1055",), ("Defense Evasion", "Privilege Escalation")),
    "process_tampering": (("T1055",), ("Defense Evasion", "Privilege Escalation")),
}

# Thresholds of section 4.1 that compare a count (the thresholds that decide a count are in
# summary.py).
STOP_MIN_COMMANDS = 5
CMD_MIN_CHILDREN = 10


class RuleFacts(Protocol):
    """The counts the rules read: a frozen ``WindowSummary`` or a live ``Summarizer``."""

    @property
    def codes(self) -> Counter[str]: ...

    @property
    def mass_note(self) -> bool: ...

    @property
    def mass_replace(self) -> bool: ...

    @property
    def shadow_commands(self) -> int: ...

    @property
    def recovery_commands(self) -> int: ...

    @property
    def stop_commands(self) -> int: ...

    @property
    def log_tamper(self) -> int: ...

    @property
    def note_keyword_files(self) -> int: ...

    @property
    def max_cmd_children(self) -> int: ...

    @property
    def run_key_writes(self) -> int: ...

    @property
    def lolbin_runs(self) -> int: ...

    @property
    def policy_writes(self) -> int: ...


@dataclass(frozen=True)
class IndicatorResult:
    fired: frozenset[str]
    score: float
    """Sum of single weights and pair bonuses, clipped to [0, 1]."""
    gated: bool
    """At least one strong indicator fired: the window goes to Phase 3."""


def fired(facts: RuleFacts) -> frozenset[str]:
    """The indicators that fire on ``facts``."""
    return frozenset(name for name, hit in _rules(facts) if hit)


def evaluate(facts: RuleFacts) -> IndicatorResult:
    names = fired(facts)
    return IndicatorResult(fired=names, score=score(names), gated=gated(names))


def gated(names: frozenset[str]) -> bool:
    """At least one strong indicator: the window goes to Phase 3."""
    return not names.isdisjoint(STRONG)


def score(fired: frozenset[str]) -> float:
    total = sum(WEIGHTS[name] for name in fired)
    total += sum(bonus for a, b, bonus in COMBOS if a in fired and b in fired)
    return min(total, 1.0)


def ordered(fired: Iterable[str]) -> list[str]:
    """Strong indicators first, then by weight (the ``explain`` order)."""
    return sorted(fired, key=lambda name: (name not in STRONG, -WEIGHTS[name], name))


def _rules(s: RuleFacts) -> list[tuple[str, bool]]:
    return [
        ("mass_note_drop", s.mass_note),
        ("mass_file_replace", s.mass_replace),
        ("shadow_copy_deletion", s.shadow_commands > 0),
        ("recovery_disable", s.recovery_commands > 0),
        ("service_stop_burst", s.stop_commands >= STOP_MIN_COMMANDS),
        ("event_log_tamper", s.log_tamper > 0),
        ("ransom_note_keyword", s.note_keyword_files > 0),
        ("cmd_burst", s.max_cmd_children >= CMD_MIN_CHILDREN),
        ("run_key_persistence", s.run_key_writes > 0),
        ("lolbins_execution", s.lolbin_runs > 0),
        ("security_policy_tamper", s.policy_writes > 0),
        ("remote_thread_injection", s.codes["8"] > 0),
        ("process_tampering", s.codes["25"] > 0),
    ]
