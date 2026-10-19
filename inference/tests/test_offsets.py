"""Which input offsets may be committed (inference/README.md section 9.2)."""

from __future__ import annotations

from inference.offsets import OffsetTracker


def test_nothing_is_stored_before_a_message_was_processed() -> None:
    assert OffsetTracker().advance({}) == {}


def test_without_holds_the_commit_follows_the_last_processed_message() -> None:
    tracker = OffsetTracker()
    for offset in range(5):
        tracker.processed(0, offset)
    assert tracker.advance({}) == {0: 5}
    assert tracker.advance({}) == {}  # nothing new


def test_a_buffered_event_holds_the_commit_at_its_offset() -> None:
    tracker = OffsetTracker()
    for offset in range(10):
        tracker.processed(0, offset)
    assert tracker.advance({0: 3}) == {0: 3}
    assert tracker.advance({0: 3}) == {}
    assert tracker.advance({0: 7}) == {0: 7}  # the window moved on
    assert tracker.advance({}) == {0: 10}


def test_an_unacknowledged_detection_holds_the_commit_until_it_is_acknowledged() -> None:
    tracker = OffsetTracker()
    for offset in range(10):
        tracker.processed(0, offset)
    first = tracker.output_enqueued({0: 2})
    second = tracker.output_enqueued({0: 6})
    assert tracker.pending_outputs == 2
    assert tracker.advance({}) == {0: 2}
    tracker.output_acked(second)  # out of order: the older one still holds
    assert tracker.advance({}) == {}
    tracker.output_acked(first)
    assert tracker.advance({}) == {0: 10}
    assert tracker.pending_outputs == 0


def test_the_commit_never_moves_backwards() -> None:
    tracker = OffsetTracker()
    for offset in range(10):
        tracker.processed(0, offset)
    assert tracker.advance({0: 8}) == {0: 8}
    tracker.output_enqueued({0: 4})  # an older need appears late: nothing is un-committed
    assert tracker.advance({0: 8}) == {}


def test_partitions_are_independent() -> None:
    tracker = OffsetTracker()
    for offset in range(10):
        tracker.processed(0, offset)
    for offset in range(100, 104):
        tracker.processed(1, offset)
    tracker.output_enqueued({1: 101})
    assert tracker.advance({0: 4}) == {0: 4, 1: 101}


def test_a_detection_without_input_offsets_holds_nothing() -> None:
    tracker = OffsetTracker()
    tracker.processed(0, 4)
    tracker.output_enqueued({})
    assert tracker.advance({}) == {0: 5}
