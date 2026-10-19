"""The detection pipeline without Kafka (inference/README.md sections 2-7), with real events."""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from inference.artifacts import load_artifacts, resolve_threshold
from inference.config import ScoringConfig, ServiceConfig
from inference.events import Event, parse_event
from inference.indicators import fired
from inference.logs import ECS_ATTR, Action
from inference.model import GlobalModel, new_classifier
from inference.pipeline import Emission, Pipeline
from inference.windowing import INDICATOR, SLIDE
from tests.fakes import emissions_of, fail_second_evaluation, numbered, raw_lines
from tests.reference_summary import reference_summarize
from training.evaluate import replay
from training.sentinelcap_dataset import Session, session_windows, window_label

CONFIG = ServiceConfig()
EVERY_WINDOW = ServiceConfig(scoring=ScoringConfig(reemit_after_sec=0))
"""No suppression: every gated window is reported, so tests compare windows, not policy."""
SHIPPED = Path(__file__).resolve().parents[1] / "artifacts"
"""The trained model and threshold that ``docker-compose.yml`` mounts into the service."""


def detections_of(pipeline: Pipeline, events: Sequence[Event]) -> list[Emission]:
    return [emission for emission in emissions_of(pipeline, events) if emission.reported]


def idle_flush_every(pipeline: Pipeline, events: Sequence[Event], count: int) -> list[Emission]:
    """Like ``emissions_of``, but the host goes quiet after every ``count`` events: the idle flush
    closes the window early, and the next event of the same bucket closes it again."""
    found: list[Emission] = []
    now = 0.0
    for index, event in enumerate(events):
        found.extend(pipeline.process(event, now))
        if index % count == count - 1:
            now += CONFIG.window.idle_flush_sec + 1
            found.extend(pipeline.tick(now))
        else:
            now += 0.001
    found.extend(pipeline.drain())
    return found


def by_window(emissions: Sequence[Emission]) -> dict[str, list[Emission]]:
    """The emissions of each ``logsentinel.window.id``, oldest first."""
    groups: dict[str, list[Emission]] = {}
    for emission in emissions:
        groups.setdefault(emission.score.window_id, []).append(emission)
    return groups


def test_gated_sessions_are_reported_and_goodware_is_not(sessions: dict[str, Session]) -> None:
    reported = {
        name
        for name, session in sessions.items()
        if detections_of(Pipeline(CONFIG, None, 0.75), session.events)
    }
    assert reported == {
        "akira/c974d8c6",
        "conti/b14cde37",
        "blackbasta/11129aad",
        "medusa/49c9b3dd",
    }


def test_repeated_windows_are_suppressed(sessions: dict[str, Session]) -> None:
    pipeline = Pipeline(CONFIG, None, 0.75)
    detections = detections_of(pipeline, sessions["blackbasta/11129aad"].events)
    assert 0 < len(detections) < pipeline.stats.gated
    assert pipeline.stats.detections == len(detections)
    assert pipeline.stats.suppressed == pipeline.stats.gated - len(detections)


def test_a_window_reported_early_stays_reported_when_it_closes_again(
    sessions: dict[str, Session],
) -> None:
    pipeline = Pipeline(CONFIG, None, 0.75)
    emissions = idle_flush_every(pipeline, sessions["blackbasta/11129aad"].events, 3)
    again = [group for group in by_window(emissions).values() if len(group) > 1]
    # Some window was reported before its last snapshot: the snapshot must not un-report it.
    assert any(any(emission.reported for emission in group[:-1]) for group in again)
    for group in again:
        first, last = group[0], group[-1]
        assert last.reported == any(emission.reported for emission in group)
        assert last.score.activity["events"] >= first.score.activity["events"]
    stats = pipeline.stats
    assert stats.gated == stats.detections + stats.suppressed
    assert stats.detections == sum(emission.reported for emission in emissions)


def test_quiet_host_is_flushed_then_forgotten(sessions: dict[str, Session]) -> None:
    pipeline = Pipeline(CONFIG, None, 0.75)
    for event in sessions["conti/b14cde37"].events:
        pipeline.process(event, now=0.0)
    windows = pipeline.stats.windows
    pipeline.tick(now=CONFIG.window.idle_flush_sec - 1)
    assert pipeline.stats.windows == windows
    pipeline.tick(now=CONFIG.window.idle_flush_sec)
    assert pipeline.stats.windows == windows + 1
    pipeline.tick(now=CONFIG.window.host_evict_sec)
    assert pipeline.windower.hosts() == []


def test_evicted_host_leaves_no_state(sessions: dict[str, Session]) -> None:
    pipeline = Pipeline(CONFIG, None, 0.75)
    for event in sessions["conti/b14cde37"].events:
        pipeline.process(event, now=0.0)
    # The pending window is scored on eviction, and then nothing of the host is left.
    pipeline.tick(now=CONFIG.window.host_evict_sec)
    assert pipeline.stats.windows > 0
    assert pipeline.windower.hosts() == []
    assert pipeline.tick(now=CONFIG.window.host_evict_sec + 1) == []


def test_the_service_scores_a_session_like_the_replay_of_the_evaluation(
    sessions: dict[str, Session],
) -> None:
    """``evaluate.replay`` runs a session through the same ``Pipeline`` as the service, early
    windows included: what was evaluated is what runs."""
    model = load_artifacts(SHIPPED, CONFIG.window).model
    threshold = resolve_threshold(CONFIG.scoring, model).value
    compared = gated = early = 0
    for name, session in sessions.items():
        outcome = replay(session, "fold", model, CONFIG)
        emissions = emissions_of(Pipeline(CONFIG, model, threshold), session.events)
        assert len(emissions) == len(outcome.windows), name
        for emission, window in zip(emissions, outcome.windows, strict=True):
            score = emission.score
            assert score.end == window.end, name
            assert score.gated == (window.confidence is not None), name
            assert set(score.indicators) == window.fired, name
            assert score.model_score == window.model_score, name
            assert score.confidence_score == window.confidence, name
            assert window.label == window_label(session, emission.window), name
            compared += 1
            gated += window.confidence is not None
            early += emission.window.trigger == INDICATOR
    assert compared > 50 and gated > 10 and early > 0  # the comparison is not vacuous


def test_every_scored_window_gives_a_window_score(sessions: dict[str, Session]) -> None:
    pipeline = Pipeline(CONFIG, GlobalModel(new_classifier(1)), 0.75)
    emissions = emissions_of(pipeline, sessions["conti/b14cde37"].events)
    assert len(emissions) == pipeline.stats.windows
    assert len({e.score.window_id for e in emissions}) == len(emissions)  # one id per window
    assert any(not e.score.gated for e in emissions) and any(e.score.gated for e in emissions)
    # The model scores every window, so a person can see what it thought of the ones the gate
    # held back; only a gated window gets a confidence and a label.
    assert all(e.score.model_score is not None for e in emissions)
    for emission in emissions:
        score = emission.score
        assert (score.confidence_score is None) == (score.label is None) == (not score.gated)
        assert not emission.reported or score.gated  # a detection passed the gate


def test_emission_carries_the_oldest_offset_of_its_window(sessions: dict[str, Session]) -> None:
    lines = raw_lines(sessions["conti/b14cde37"])
    emissions = emissions_of(Pipeline(CONFIG, None, 0.75), numbered(lines))
    assert emissions
    for emission in emissions:
        assert 0 <= emission.offsets[0] < len(lines)


def test_sysmon_queue_drops_are_counted(single_events: dict[str, Any]) -> None:
    pipeline = Pipeline(CONFIG, None, 0.75)
    pipeline.process(parse_event(single_events["sysmon_queue_drop"]), 0.0)
    assert pipeline.stats.sysmon_dropped == 63


@pytest.mark.parametrize("step", [365 * 86400.0, -3600.0], ids=["future", "clock-step-back"])
def test_host_follows_a_moved_clock(sessions: dict[str, Session], step: float) -> None:
    """One future-dated event, or a clock that steps back, must not blind the host for good."""
    events = sessions["conti/b14cde37"].events
    limit = CONFIG.window.late_reset_events
    pipeline = Pipeline(CONFIG, None, 0.75)
    pipeline.process(events[0], 0.0)
    if step > 0:  # a single event from far in the future, then the real clock
        pipeline.process(dataclasses.replace(events[1], timestamp=events[1].timestamp + step), 1.0)
        later = events[2 : 2 + limit + 5]
    else:  # the host's clock itself moves back
        later = [
            dataclasses.replace(e, timestamp=e.timestamp + step) for e in events[1 : 1 + limit + 5]
        ]
    for index, event in enumerate(later):
        pipeline.process(event, 2.0 + index)
    windower = pipeline.windower
    assert windower.clock_resets == 1
    assert windower.late_events == limit  # the 5 events after the reset were not late
    windows = pipeline.stats.windows
    pipeline.drain()
    assert pipeline.stats.windows == windows + 1  # the host has a window on its new clock


def test_a_window_that_cannot_be_scored_is_counted_and_skipped(
    sessions: dict[str, Session], monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    events = sessions["conti/b14cde37"].events
    clean = Pipeline(CONFIG, None, 0.75)
    expected = len(emissions_of(clean, events))
    fail_second_evaluation(monkeypatch)
    pipeline = Pipeline(CONFIG, None, 0.75)
    with caplog.at_level(logging.ERROR, logger="inference.pipeline"):
        found = emissions_of(pipeline, events)  # nothing is raised
    stats = pipeline.stats
    assert stats.internal_errors == 1
    assert len(found) == stats.windows == expected - 1
    assert stats.gated == stats.detections + stats.suppressed  # the failed window is in no count
    (record,) = caplog.records
    assert record.levelno == logging.ERROR and record.exc_info is not None
    assert getattr(record, ECS_ATTR)["event.action"] == Action.SCORING_ERROR


def early_emissions(emissions: Sequence[Emission]) -> list[Emission]:
    return [e for e in emissions if e.window.trigger == INDICATOR]


def test_a_window_closes_early_at_the_event_that_brings_a_new_indicator(
    sessions: dict[str, Session],
) -> None:
    for name in ("conti/b14cde37", "blackbasta/11129aad", "medusa/49c9b3dd", "akira/c974d8c6"):
        pipeline = Pipeline(CONFIG, None, 0.75)
        emissions = emissions_of(pipeline, sessions[name].events)
        early = early_emissions(emissions)
        assert early and pipeline.stats.early_windows == len(early), name
        for emission in early:
            window, score = emission.window, emission.score
            trigger = window.trigger_event
            assert trigger is not None and trigger in window.events, name
            assert window.end == (round(trigger.timestamp * 1000) + 1) / 1000, name
            assert score.gated and score.trigger == INDICATOR, name
            # The event is what brought the indicator: without it the window lacks something.
            others = [e for e in window.events if e is not trigger]
            new = fired(window.summary) - fired(reference_summarize(others))
            assert new, name


def test_the_first_alert_of_a_session_comes_before_the_scheduled_window_closes(
    sessions: dict[str, Session],
) -> None:
    for name in ("conti/b14cde37", "blackbasta/11129aad", "medusa/49c9b3dd"):
        emissions = emissions_of(Pipeline(CONFIG, None, 0.75), sessions[name].events)
        gated = [e for e in emissions if e.score.gated]
        assert gated[0].window.trigger == INDICATOR, name
        scheduled = [e for e in gated if e.window.trigger == SLIDE]
        assert gated[0].score.end < scheduled[0].score.end, name


def test_early_windows_do_not_disturb_the_scheduled_ones(sessions: dict[str, Session]) -> None:
    for name in ("conti/b14cde37", "blackbasta/11129aad", "akira/c974d8c6"):
        session = sessions[name]
        emissions = emissions_of(Pipeline(CONFIG, None, 0.75), session.events)
        scheduled = [e.window for e in emissions if e.window.trigger == SLIDE]
        alone = session_windows(session, CONFIG.window)
        assert [(w.end, w.events, w.summary) for w in scheduled] == [
            (w.end, w.events, w.summary) for w in alone
        ], name


def test_a_restart_reproduces_every_window_that_comes_after_the_crash(
    sessions: dict[str, Session],
) -> None:
    """Whether a window closes early depends only on the host's last minute of events, which a
    restart re-reads: after a crash at any event, every window the first run would have written
    from there on (scheduled or early, same ``logsentinel.window.id``) is written again. The
    replay starts at the offset the service would commit, with all earlier records acknowledged,
    which is the shortest history a replay ever has."""
    early_total = 0
    for name in ("conti/b14cde37", "blackbasta/11129aad", "medusa/49c9b3dd"):
        events = numbered(raw_lines(sessions[name]))
        reference = Pipeline(EVERY_WINDOW, None, 0.75)
        windows: list[tuple[int, str, str]] = []  # (event that wrote it, id, trigger)
        resume_at: list[int] = []  # the offset a restart after event i reads from
        for index, event in enumerate(events):
            for emission in reference.process(event, float(index)):
                windows.append((index, emission.score.window_id, emission.window.trigger))
            resume_at.append(reference.windower.oldest_offsets().get(0, index + 1))
        for emission in reference.drain():
            windows.append((len(events), emission.score.window_id, emission.window.trigger))
        early_total += sum(trigger == INDICATOR for _, _, trigger in windows)
        for crash_after in range(1, len(events), max(1, len(events) // 60)):
            restarted = Pipeline(EVERY_WINDOW, None, 0.75)
            written: set[str] = set()
            for event in events[resume_at[crash_after - 1] :]:
                written |= {e.score.window_id for e in restarted.process(event, 0.0)}
            written |= {e.score.window_id for e in restarted.drain()}
            lost = {wid for index, wid, _ in windows if index >= crash_after} - written
            assert not lost, f"{name}: crash after event {crash_after} loses {len(lost)} windows"
    assert early_total > 0
