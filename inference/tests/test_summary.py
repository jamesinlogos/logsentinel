"""Counting (inference/README.md sections 4.0 and 8): the counts every rule and feature reads.

The ``Summarizer`` keeps the counts of a changing set of events; ``reference_summarize`` counts a
list from scratch. They must agree after any sequence of ``add`` and ``remove``.
"""

from __future__ import annotations

import dataclasses
import random
from collections import deque
from collections.abc import Iterator, Sequence

import pytest

from inference.events import Event
from inference.summary import Summarizer, WindowSummary, file_name_entropy, summarize
from tests.reference_summary import assert_same_counts, reference_summarize
from training.sentinelcap_dataset import Session

CHECK_EVERY = 97
"""Compare with the reference after this many steps: it counts from scratch, so it is slow."""


def leftovers(summarizer: Summarizer) -> dict[str, object]:
    """The state a summarizer that holds no event must not hold."""
    return {
        name: value
        for name, value in vars(summarizer).items()
        if (isinstance(value, dict) and value) or (isinstance(value, int) and value)
    }


def sliding(
    events: Sequence[Event], size: float = 60.0
) -> Iterator[tuple[int, list[Event], Summarizer]]:
    """A summarizer that follows the last ``size`` seconds of ``events``, at checkpoints."""
    members: deque[Event] = deque()
    summarizer = Summarizer()
    for index, event in enumerate(events):
        summarizer.add(event)
        members.append(event)
        while members[0].timestamp < event.timestamp - size:
            summarizer.remove(members.popleft())
        if index % CHECK_EVERY == 0:
            yield index, list(members), summarizer


def test_file_name_entropy() -> None:
    assert file_name_entropy("") == 0.0
    assert file_name_entropy("aaaa") == 0.0
    assert file_name_entropy("ab") == pytest.approx(1.0)
    assert file_name_entropy("aab") == pytest.approx(0.9183, abs=1e-4)


def test_a_session_is_counted_like_the_reference(sessions: dict[str, Session]) -> None:
    for name, session in sessions.items():
        assert_same_counts(summarize(session.events), reference_summarize(session.events))
        assert summarize(session.events).events == len(session.events), name


def test_a_sliding_window_is_counted_like_the_reference(sessions: dict[str, Session]) -> None:
    checked = 0
    for session in sessions.values():
        for _, members, summarizer in sliding(session.events):
            assert_same_counts(summarizer.snapshot(), reference_summarize(members))
            checked += 1
    assert checked > 50


def test_events_can_be_removed_in_any_order(sessions: dict[str, Session]) -> None:
    chooser = random.Random(7)
    for session in sessions.values():
        events = chooser.sample(session.events, min(len(session.events), 1_500))
        summarizer = Summarizer()
        for event in events:
            summarizer.add(event)
        order = list(range(len(events)))
        chooser.shuffle(order)
        left = set(order)
        for step, index in enumerate(order):
            summarizer.remove(events[index])
            left.discard(index)
            if step % 211 == 0:
                rest = [events[i] for i in sorted(left)]
                assert_same_counts(summarizer.snapshot(), reference_summarize(rest))
        assert summarizer.snapshot() == WindowSummary()
        assert leftovers(summarizer) == {}  # nothing is kept for events that are gone


def test_a_summarizer_that_took_everything_back_keeps_no_state(
    sessions: dict[str, Session],
) -> None:
    for session in sessions.values():
        summarizer = Summarizer()
        for event in session.events:
            summarizer.add(event)
        for event in session.events:
            summarizer.remove(event)
        assert leftovers(summarizer) == {}


def test_replaced_files_do_not_depend_on_the_order_of_the_events(
    sessions: dict[str, Session],
) -> None:
    """A copy counts once its original is deleted, whichever of the two came first."""
    events = [
        e for e in sessions["akira/c974d8c6"].events if e.code in ("11", "26") and e.file_path
    ][:4_000]
    reference = reference_summarize(events)
    assert reference.max_replaced_files > 0
    created = [e for e in events if e.code == "11"]
    deleted = [e for e in events if e.code == "26"]
    shuffled = list(events)
    random.Random(3).shuffle(shuffled)
    for order in (created + deleted, deleted + created, shuffled):
        summarizer = Summarizer()
        for event in order:
            summarizer.add(event)
        assert_same_counts(summarizer.snapshot(), reference)
        # Taking the deletions back un-counts the replacements, the copies stay.
        for event in deleted:
            summarizer.remove(event)
        assert_same_counts(summarizer.snapshot(), reference_summarize(created))
        assert summarizer.snapshot().max_replaced_files == 0


def test_the_same_event_can_be_added_twice(sessions: dict[str, Session]) -> None:
    event = next(e for e in sessions["blackbasta/11129aad"].events if e.code == "11")
    summarizer = Summarizer()
    summarizer.add(event)
    summarizer.add(event)
    assert_same_counts(summarizer.snapshot(), reference_summarize([event, event]))
    summarizer.remove(event)
    assert_same_counts(summarizer.snapshot(), reference_summarize([event]))


@pytest.mark.parametrize("code", ["1", "3", "11", "13", "26"])
def test_removing_an_event_that_was_not_added_is_an_error(
    sessions: dict[str, Session], code: str
) -> None:
    event = next(e for s in sessions.values() for e in s.events if e.code == code)
    with pytest.raises(ValueError, match="never added"):
        Summarizer().remove(event)


def test_the_largest_group_of_cmd_children_follows_every_step(
    sessions: dict[str, Session],
) -> None:
    """The rule ``cmd_burst`` reads the maximum after every event, so it is kept, not recounted."""
    template = next(
        e
        for e in sessions["medusa/49c9b3dd"].events
        if e.code == "1" and (e.executable or "").endswith("\\cmd.exe")
    )
    parents = ("a", "b", "c")
    chooser = random.Random(11)
    summarizer = Summarizer()
    held: list[str] = []
    for _ in range(3_000):
        if held and chooser.random() < 0.45:
            parent = held.pop(chooser.randrange(len(held)))
            summarizer.remove(dataclasses.replace(template, parent_entity_id=parent))
        else:
            parent = chooser.choice(parents)
            held.append(parent)
            summarizer.add(dataclasses.replace(template, parent_entity_id=parent))
        expected = max((held.count(p) for p in parents), default=0)
        assert summarizer.max_cmd_children == expected


def test_the_entropy_sum_does_not_depend_on_the_order(sessions: dict[str, Session]) -> None:
    events = [e for e in sessions["conti/b14cde37"].events if e.code == "11"]
    assert events
    shuffled = list(events)
    random.Random(5).shuffle(shuffled)
    assert summarize(events).name_entropy_sum == summarize(shuffled).name_entropy_sum
