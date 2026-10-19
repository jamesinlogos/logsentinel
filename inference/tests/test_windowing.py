"""Sliding windows on event time, with real events (timestamps shifted where noted)."""

from __future__ import annotations

import gc
import math
import random
import tracemalloc
from collections import deque
from collections.abc import Sequence
from dataclasses import replace

import pytest

from inference.config import WindowConfig
from inference.events import Event
from inference.windowing import (
    INDICATOR,
    SLIDE,
    Window,
    Windower,
    format_timestamp,
    window_id,
)
from tests.reference_summary import assert_same_counts, reference_summarize
from training.sentinelcap_dataset import Session

LATE_RESET = WindowConfig().late_reset_events


def all_windows(events: Sequence[Event], windower: Windower) -> list[Window]:
    windows: list[Window] = []
    for event in events:
        windows.extend(windower.add(event))
    for host_id in windower.hosts():
        last = windower.flush(host_id)
        if last is not None:
            windows.append(last)
    return windows


def test_windows_are_aligned_and_bounded(sessions: dict[str, Session]) -> None:
    windows = all_windows(
        sessions["blackbasta/11129aad"].events, Windower(60, 10, 200_000, LATE_RESET)
    )
    assert windows
    for window in windows:
        assert window.end % 10 == 0
        assert window.end - window.start == 60
        assert all(window.start <= e.timestamp < window.end for e in window.events)
    ends = [w.end for w in windows]
    assert ends == sorted(set(ends))


def test_every_event_lands_in_a_closed_window(sessions: dict[str, Session]) -> None:
    events = sessions["conti/b14cde37"].events
    seen = {
        id(e) for w in all_windows(events, Windower(60, 10, 200_000, LATE_RESET)) for e in w.events
    }
    assert all(id(e) in seen for e in events)


def test_a_gap_closes_one_window_and_no_empty_ones(sessions: dict[str, Session]) -> None:
    first, second = sessions["conti/b14cde37"].events[:2]
    windower = Windower(60, 10, 1000, LATE_RESET)
    assert windower.add(first) == []
    closed = windower.add(replace(second, timestamp=first.timestamp + 3600))
    assert len(closed) == 1
    assert closed[0].events == (first,)


def test_event_too_old_for_any_window_is_dropped(sessions: dict[str, Session]) -> None:
    first, second = sessions["conti/b14cde37"].events[:2]
    windower = Windower(60, 10, 1000, LATE_RESET)
    windower.add(replace(first, timestamp=first.timestamp + 3600))
    assert windower.add(second) == []
    assert windower.late_events == 1


def test_flush_closes_the_pending_window_once(sessions: dict[str, Session]) -> None:
    event = sessions["conti/b14cde37"].events[0]
    windower = Windower(60, 10, 1000, LATE_RESET)
    windower.add(event)
    window = windower.flush(event.host_id)
    assert window is not None and window.events == (event,)
    assert windower.flush(event.host_id) is None


def test_buffer_overflow_is_counted(sessions: dict[str, Session]) -> None:
    events = sessions["conti/b14cde37"].events
    first = events[0]
    windower = Windower(60, 10, 5, LATE_RESET)
    for event in events[:10]:
        windower.add(replace(event, timestamp=first.timestamp))
    assert windower.overflow_events == 5


def test_drop_forgets_the_host(sessions: dict[str, Session]) -> None:
    event = sessions["conti/b14cde37"].events[0]
    windower = Windower(60, 10, 1000, LATE_RESET)
    windower.add(event)
    windower.drop(event.host_id)
    assert windower.hosts() == []
    assert windower.flush(event.host_id) is None


def numbered(events: Sequence[Event], partition: int = 0, start: int = 0) -> list[Event]:
    return [replace(e, partition=partition, offset=start + i) for i, e in enumerate(events)]


def test_a_run_of_old_events_moves_the_window_to_the_new_clock(
    sessions: dict[str, Session],
) -> None:
    events = sessions["conti/b14cde37"].events
    windower = Windower(60, 10, 1000, late_reset_events=3)
    first = events[0]
    windower.add(replace(first, timestamp=first.timestamp + 3600))
    # Two old events are dropped as late ...
    assert windower.add(events[1]) == [] and windower.add(events[2]) == []
    assert (windower.late_events, windower.clock_resets) == (2, 0)
    # ... the third in a row is the clock having moved: the pending window closes, the host follows.
    closed = windower.add(events[3])
    assert len(closed) == 1 and len(closed[0].events) == 1
    assert (windower.late_events, windower.clock_resets) == (3, 1)
    assert windower.add(events[4]) == []
    assert windower.late_events == 3
    window = windower.flush(first.host_id)
    assert window is not None and window.events == (events[3], events[4])


def test_an_in_window_event_interrupts_the_late_streak(sessions: dict[str, Session]) -> None:
    events = sessions["conti/b14cde37"].events
    windower = Windower(60, 10, 1000, late_reset_events=3)
    windower.add(replace(events[0], timestamp=events[0].timestamp + 3600))
    windower.add(events[1])
    windower.add(events[2])
    windower.add(replace(events[3], timestamp=events[0].timestamp + 3600))  # current again
    windower.add(events[4])
    windower.add(events[5])
    assert (windower.late_events, windower.clock_resets) == (4, 0)


def test_late_reset_events_must_be_positive() -> None:
    with pytest.raises(ValueError):
        Windower(60, 10, 1000, late_reset_events=0)


def test_oldest_offset_is_what_a_restart_must_re_read(sessions: dict[str, Session]) -> None:
    events = numbered(sessions["conti/b14cde37"].events)
    windower = Windower(60, 10, 200_000, LATE_RESET)
    assert windower.oldest_offsets() == {}
    windower.add(events[0])
    assert windower.oldest_offsets() == {0: 0}
    for event in events[1:]:
        windower.add(event)
    # What is still buffered is what falls in the last 60 s counted from the newest event: the
    # trailing window starts before the scheduled one, which ends at the next boundary.
    newest = events[-1].timestamp
    next_end = (math.floor(newest / 10) + 1) * 10
    floor = min(next_end - 60, (round(newest * 1000) + 1) / 1000 - 60)
    expected = min(e.offset for e in events if e.offset is not None and e.timestamp >= floor)
    assert expected > 0
    assert windower.oldest_offsets() == {0: expected}
    # A real event ten minutes later evicts everything before it.
    late = replace(events[-1], timestamp=events[-1].timestamp + 600, offset=999)
    windower.add(late)
    assert windower.oldest_offsets() == {0: 999}


def test_events_without_a_kafka_position_hold_nothing(sessions: dict[str, Session]) -> None:
    windower = Windower(60, 10, 1000, LATE_RESET)
    windower.add(sessions["conti/b14cde37"].events[0])
    assert windower.oldest_offsets() == {}


def test_oldest_offsets_are_kept_per_partition(sessions: dict[str, Session]) -> None:
    events = sessions["conti/b14cde37"].events
    windower = Windower(60, 10, 1000, LATE_RESET)
    windower.add(replace(events[0], partition=0, offset=40))
    windower.add(replace(events[1], partition=1, offset=7))
    windower.add(replace(events[2], partition=0, offset=41))
    assert windower.oldest_offsets() == {0: 40, 1: 7}
    # Partition 1 no longer has a buffered event after the window moves on.
    windower.add(replace(events[3], partition=0, offset=42, timestamp=events[3].timestamp + 600))
    assert windower.oldest_offsets() == {0: 42}


def test_a_flush_is_a_snapshot_the_next_close_of_the_same_bucket_extends_it(
    sessions: dict[str, Session],
) -> None:
    events = sessions["conti/b14cde37"].events
    bucket = [e for e in events if e.timestamp // 10 == events[0].timestamp // 10]
    assert len(bucket) >= 2
    windower = Windower(60, 10, 1000, LATE_RESET)
    windower.add(bucket[0])
    first = windower.flush(bucket[0].host_id)
    windower.add(bucket[1])
    second = windower.flush(bucket[0].host_id)
    assert first is not None and second is not None
    assert (len(first.events), len(second.events)) == (1, 2)
    assert first.end == second.end  # same window, so the same window id
    assert window_id(first.host_id, format_timestamp(first.end)) == window_id(
        second.host_id, format_timestamp(second.end)
    )


def test_window_id_depends_on_host_and_window_end() -> None:
    assert window_id("host", "t1") == window_id("host", "t1")
    assert window_id("host", "t1") != window_id("host", "t2")
    assert window_id("host", "t1") != window_id("other", "t1")


def test_format_timestamp_is_utc_with_milliseconds() -> None:
    assert format_timestamp(0.0) == "1970-01-01T00:00:00.000Z"
    assert format_timestamp(1_760_000_000.123456) == "2025-10-09T08:53:20.123Z"


def counted_in(events: Sequence[Event], start: float, end: float) -> list[Event]:
    return [e for e in events if start <= e.timestamp < end]


def test_every_closed_window_holds_the_counts_of_its_events(
    sessions: dict[str, Session],
) -> None:
    checked = 0
    for session in sessions.values():
        windower = Windower(60, 10, 200_000, LATE_RESET)
        for window in all_windows(session.events, windower):
            assert window.trigger == SLIDE and window.trigger_event is None
            assert_same_counts(window.summary, reference_summarize(window.events))
            checked += 1
        assert windower.late_events == 0
    assert checked > 50


def test_the_trailing_window_is_the_last_minute_up_to_the_newest_event(
    sessions: dict[str, Session],
) -> None:
    for session in sessions.values():
        windower = Windower(60, 10, 200_000, LATE_RESET)
        host = session.events[0].host_id
        assert windower.trailing(host) is None
        for index, event in enumerate(session.events):
            windower.add(event)
            if index % 61:
                continue
            trailing = windower.trailing(host)
            assert trailing is not None
            assert trailing.end == (round(event.timestamp * 1000) + 1) / 1000
            held = counted_in(session.events[: index + 1], trailing.end - 60, trailing.end)
            assert event in held
            assert_same_counts(trailing.summary.snapshot(), reference_summarize(held))
        assert windower.late_events == 0


def test_the_trailing_window_stays_exact_when_events_arrive_out_of_order(
    sessions: dict[str, Session],
) -> None:
    """Events of a host can arrive out of order (the input is untrusted): the window must not
    keep an event that left it, or lose one that is still in it."""
    jitter = random.Random(9)
    for session in sessions.values():
        keyed = [(e.timestamp + jitter.uniform(-5, 5), e) for e in session.events]
        events = [e for _, e in sorted(keyed, key=lambda pair: pair[0])]
        assert events != session.events
        windower = Windower(60, 10, 200_000, LATE_RESET)
        host = events[0].host_id
        newest = -math.inf
        for index, event in enumerate(events):
            windower.add(event)
            newest = max(newest, event.timestamp)
            if index % 61:
                continue
            trailing = windower.trailing(host)
            assert trailing is not None
            assert trailing.end == (round(newest * 1000) + 1) / 1000
            held = counted_in(events[: index + 1], trailing.end - 60, trailing.end)
            assert_same_counts(trailing.summary.snapshot(), reference_summarize(held))
        assert windower.late_events == 0


def test_an_early_window_ends_one_millisecond_after_its_event(
    sessions: dict[str, Session],
) -> None:
    events = sessions["medusa/49c9b3dd"].events
    windower = Windower(60, 10, 200_000, LATE_RESET)
    closed: list[Window] = []
    for event in events[:300]:
        closed.extend(windower.add(event))
    trigger = events[299]
    early = windower.close_early(trigger.host_id, trigger)
    assert early.trigger == INDICATOR and early.trigger_event is trigger
    assert early.end == (round(trigger.timestamp * 1000) + 1) / 1000
    assert early.end - early.start == 60
    assert trigger in early.events
    assert all(early.start <= e.timestamp < early.end for e in early.events)
    assert early.events == tuple(counted_in(events[:300], early.start, early.end))
    assert_same_counts(early.summary, reference_summarize(early.events))
    # The scheduled window of the bucket is not disturbed: it closes later, with the event.
    rest = all_windows(events[300:], windower)
    scheduled = [w for w in [*closed, *rest] if trigger in w.events and w.trigger == SLIDE]
    assert scheduled and all(w.end > trigger.timestamp for w in scheduled)


def test_an_early_window_can_share_its_id_with_a_scheduled_one(
    sessions: dict[str, Session],
) -> None:
    """An event just before a boundary makes the early window end on the boundary: the window is
    the same one, so the same ``logsentinel.window.id`` (the later record replaces the earlier)."""
    event = sessions["conti/b14cde37"].events[0]
    boundary = (math.floor(event.timestamp / 10) + 1) * 10
    last = replace(event, timestamp=boundary - 0.001)
    windower = Windower(60, 10, 1000, LATE_RESET)
    windower.add(last)
    early = windower.close_early(last.host_id, last)
    scheduled = windower.flush(last.host_id)
    assert scheduled is not None
    assert early.end == scheduled.end == boundary
    assert window_id(early.host_id, format_timestamp(early.end)) == window_id(
        scheduled.host_id, format_timestamp(scheduled.end)
    )


def test_the_buffer_keeps_every_event_of_the_trailing_window(
    sessions: dict[str, Session],
) -> None:
    """A restart re-reads from ``oldest_offsets``: it must not start after an event that the
    trailing window (which begins before the scheduled one) still holds."""
    earlier = 0
    for session in sessions.values():
        events = numbered(session.events)
        windower = Windower(60, 10, 200_000, LATE_RESET)
        host = events[0].host_id
        for index, event in enumerate(events):
            windower.add(event)
            if index % 53:
                continue
            trailing = windower.trailing(host)
            assert trailing is not None
            fed = events[: index + 1]
            held = counted_in(fed, trailing.end - 60, trailing.end)
            oldest = windower.oldest_offsets()[0]
            assert oldest <= min(e.offset for e in held if e.offset is not None)
            next_end = (math.floor(event.timestamp / 10) + 1) * 10
            scheduled = counted_in(fed, next_end - 60, next_end)
            earlier += oldest < min(e.offset for e in scheduled if e.offset is not None)
    assert earlier > 0  # the trailing window did reach back further than the scheduled one


def test_an_event_pushed_out_of_the_buffer_leaves_every_count(
    sessions: dict[str, Session],
) -> None:
    events = sessions["conti/b14cde37"].events
    windower = Windower(60, 10, 5, LATE_RESET)
    for event in events[:10]:
        windower.add(replace(event, timestamp=events[0].timestamp))
    trailing = windower.trailing(events[0].host_id)
    assert trailing is not None and trailing.summary.snapshot().events == 5
    early = windower.close_early(events[0].host_id, events[9])
    scheduled = windower.flush(events[0].host_id)
    assert scheduled is not None
    assert len(early.events) == len(scheduled.events) == 5
    assert early.summary.events == scheduled.summary.events == 5
    assert_same_counts(early.summary, reference_summarize(early.events))


def test_a_stalled_clock_cannot_make_the_buffer_grow(sessions: dict[str, Session]) -> None:
    """Event time standing still expires nothing, so the size limit alone must bound the memory."""
    events = sessions["medusa/49c9b3dd"].events
    windower = Windower(60, 10, 50, LATE_RESET)
    moment = events[0].timestamp
    last: deque[Event] = deque(maxlen=50)

    def feed(count: int) -> int:
        for index in range(count):
            last.append(replace(events[index % len(events)], timestamp=moment))
            windower.add(last[-1])
        gc.collect()
        return tracemalloc.get_traced_memory()[0]

    tracemalloc.start()
    try:
        warm = feed(2_000)
        grown = feed(20_000) - warm
    finally:
        tracemalloc.stop()
    assert windower.overflow_events > 20_000
    assert grown < 200_000  # kept in the expiry heap, 20,000 events would take about 7 MB
    trailing = windower.trailing(events[0].host_id)
    assert trailing is not None
    assert_same_counts(trailing.summary.snapshot(), reference_summarize(last))


def test_a_clock_reset_starts_the_counts_again(sessions: dict[str, Session]) -> None:
    events = sessions["conti/b14cde37"].events
    windower = Windower(60, 10, 1000, late_reset_events=3)
    first = events[0]
    windower.add(replace(first, timestamp=first.timestamp + 3600))
    for event in events[1:4]:
        windower.add(event)  # the third old event in a row: the host follows its new clock
    assert windower.clock_resets == 1
    windower.add(events[4])
    trailing = windower.trailing(first.host_id)
    assert trailing is not None and trailing.summary.snapshot().events == 2
    window = windower.flush(first.host_id)
    assert window is not None and window.events == (events[3], events[4])
    assert_same_counts(window.summary, reference_summarize(window.events))
