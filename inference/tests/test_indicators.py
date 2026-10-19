"""Phase 2 rules (inference/README.md sections 4.1, 4.2) on real sentinelcap events."""

from __future__ import annotations

import copy
import time
from collections import Counter
from collections.abc import Iterable
from typing import Any

import pytest

from inference.events import Event, parse_event
from inference.indicators import evaluate, ordered, score
from inference.summary import WindowSummary, summarize
from training.sentinelcap_dataset import Session


def fired(events: Iterable[Event]) -> frozenset[str]:
    return evaluate(summarize(events)).fired


def test_conti_shadow_copy_and_service_stops(sessions: dict[str, Session]) -> None:
    result = evaluate(summarize(sessions["conti/b14cde37"].events))
    assert {"shadow_copy_deletion", "service_stop_burst"} <= result.fired
    assert result.gated


def test_blackbasta_mass_note_drop(sessions: dict[str, Session]) -> None:
    summary = summarize(sessions["blackbasta/11129aad"].events)
    assert summary.max_name_dirs >= 10 and summary.max_name_branches >= 5
    assert {"mass_note_drop", "shadow_copy_deletion"} <= evaluate(summary).fired


def test_akira_replaces_files_by_copies_with_an_appended_extension(
    sessions: dict[str, Session],
) -> None:
    summary = summarize(sessions["akira/c974d8c6"].events)
    assert summary.max_replaced_files >= 2_000  # <file>.crinal written, <file> deleted
    assert "mass_file_replace" in evaluate(summary).fired


def test_replacing_files_in_one_directory_is_no_mass_file_replace(
    sessions: dict[str, Session],
) -> None:
    located = [
        (e.file_path.rsplit("\\", 1)[0], e)
        for e in sessions["akira/c974d8c6"].events
        if e.code in ("11", "26") and e.file_path is not None
    ]
    busiest, _ = Counter(directory for directory, _ in located).most_common(1)[0]
    summary = summarize(e for directory, e in located if directory == busiest)
    assert summary.max_replaced_files >= 50  # enough files, but a single directory
    assert "mass_file_replace" not in evaluate(summary).fired
    assert summarize(sessions["goodware/9923a8b2"].events).max_replaced_files == 0


def test_note_in_nine_directories_is_no_mass_note_drop(sessions: dict[str, Session]) -> None:
    summary = summarize(sessions["lockbit/032690f1"].events)
    assert summary.max_name_dirs == 9
    result = evaluate(summary)
    assert "mass_note_drop" not in result.fired
    assert not result.gated


def test_medusa_recovery_and_bursts(sessions: dict[str, Session]) -> None:
    assert {
        "recovery_disable",
        "shadow_copy_deletion",
        "service_stop_burst",
        "cmd_burst",
        "lolbins_execution",
    } <= fired(sessions["medusa/49c9b3dd"].events)


def test_misspelled_recovery_option_does_not_count(sessions: dict[str, Session]) -> None:
    typo = [
        e
        for e in sessions["medusa/49c9b3dd"].events
        if e.code == "1" and "recoverynabled" in (e.command_line or "")
    ]
    assert typo
    assert "recovery_disable" not in fired(typo)


def test_goodware_installer_stays_below_the_gate(sessions: dict[str, Session]) -> None:
    result = evaluate(summarize(sessions["goodware/9923a8b2"].events))
    assert result.fired == {"run_key_persistence", "lolbins_execution"}
    assert not result.gated


@pytest.mark.parametrize(
    ("name", "indicator"),
    [
        ("wmic_shadowcopy_delete", "shadow_copy_deletion"),
        ("wevtutil_clear_log", "event_log_tamper"),
        ("sysmon_channel_disabled", "event_log_tamper"),
        ("enable_linked_connections", "security_policy_tamper"),
        ("create_remote_thread", "remote_thread_injection"),
    ],
)
def test_single_event_rules(single_events: dict[str, Any], name: str, indicator: str) -> None:
    assert indicator in fired([parse_event(single_events[name])])


def test_windows_servicing_registering_a_disabled_channel_is_not_log_tampering(
    single_events: dict[str, Any],
) -> None:
    servicing = single_events["servicing_channel_disabled"]
    assert "event_log_tamper" not in fired([parse_event(servicing)])
    # The same write by any other executable (the sample, or a copy named like TiWorker) counts.
    elsewhere = copy.deepcopy(servicing)
    elsewhere["process"]["executable"] = r"C:\Users\Public\TiWorker.exe"
    assert "event_log_tamper" in fired([parse_event(elsewhere)])


def test_process_tampering_rule() -> None:
    # No Event 25 in sentinelcap data yet; the rule is on the event code alone.
    summary = WindowSummary()
    summary.codes["25"] = 1
    assert evaluate(summary).fired == {"process_tampering"}


def test_support_indicators_never_open_the_gate() -> None:
    summary = WindowSummary(policy_writes=1, lolbin_runs=1)
    summary.codes.update({"8": 1, "25": 1})
    result = evaluate(summary)
    assert result.score >= 0.3
    assert not result.gated


def test_score_adds_pair_bonus_and_clips() -> None:
    assert score(frozenset({"mass_note_drop"})) == pytest.approx(0.6)
    assert score(frozenset({"shadow_copy_deletion", "run_key_persistence"})) == pytest.approx(0.85)
    assert score(frozenset({"mass_note_drop", "shadow_copy_deletion"})) == 1.0


def test_explain_order_puts_strong_indicators_first() -> None:
    names = {"ransom_note_keyword", "recovery_disable", "mass_note_drop", "process_tampering"}
    assert ordered(names) == [
        "mass_note_drop",
        "recovery_disable",
        "process_tampering",
        "ransom_note_keyword",
    ]


def test_a_very_long_repetitive_command_line_is_cheap(single_events: dict[str, Any]) -> None:
    """Unbounded ``.*`` in the rules took a second on a 33 KB line, per event and window."""
    doc = copy.deepcopy(single_events["wmic_shadowcopy_delete"])
    doc["process"]["command_line"] = "shadowcopy " * 3_000 + "win32_shadowcopy " * 1_000
    event = parse_event(doc)
    started = time.perf_counter()
    result = evaluate(summarize([event]))
    assert time.perf_counter() - started < 0.5
    assert "shadow_copy_deletion" not in result.fired


def test_tokens_of_one_command_may_be_a_few_hundred_characters_apart(
    single_events: dict[str, Any],
) -> None:
    doc = copy.deepcopy(single_events["wmic_shadowcopy_delete"])
    for gap, expected in ((20, True), (200, True), (400, False)):
        doc["process"]["command_line"] = "wmic shadowcopy " + "x " * (gap // 2) + "delete"
        assert ("shadow_copy_deletion" in fired([parse_event(doc)])) is expected
