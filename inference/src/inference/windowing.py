"""Windows per host.id on event time (``@timestamp``): scheduled ones and early ones.

A *scheduled* window is ``[end - size, end)`` with ``end`` on a multiple of ``slide``. It is
closed (returned) only when it holds events that no earlier window closed, so a quiet host
produces no empty windows and a gap jumps straight to the boundary of the next event. An
*early* window is the host's last ``size`` seconds up to its newest event: ``end`` is one
millisecond after that event, so the event is inside and ``format_timestamp`` tells windows of
consecutive events apart. ``close_early`` returns it whenever the caller asks (the rules look at
``trailing`` after every event); the scheduled window of the bucket still closes later.

Both kinds are counted by a :class:`~inference.summary.Summarizer` that only moves forward, so
no window is ever recounted from scratch: the scheduled one drops the events older than its
start at each boundary, the trailing one after every event, with a heap on the event time, so
the cost stays O(log n) per event whatever the order events arrive in (the input is untrusted).
Nothing here reads a clock: the service decides when a silent host is flushed, and training
replays sessions through the same code (inference/README.md section 8: one feature path for
training and serving).

Per-host order is guaranteed by the pipeline (README.md section 7.1). An event too old for every
future window is counted in ``late_events`` and dropped. A run of ``late_reset_events`` such
events in a row means the host's clock moved (a clock step back, or one future-dated event pushed
the window ahead): the host's window then follows the new time (``clock_resets``) instead of
dropping its events until the old time is reached again.

``flush`` closes the pending scheduled window without waiting for the next event. If more events
of the same bucket arrive afterwards, the next close yields a window with the same ``end`` and
more events: the earlier one was a snapshot.

The buffer keeps every event that a window still open or still to come needs: back to the start
of the trailing window, which begins earlier than the scheduled one. ``oldest_offsets`` reports
the oldest of them, so a restart that reads from there rebuilds both.
"""

from __future__ import annotations

import hashlib
import heapq
import itertools
import math
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime

from inference.events import Event
from inference.summary import Summarizer, WindowSummary

SLIDE = "slide"
"""``Window.trigger`` of a scheduled window (closed on its boundary or by an idle flush)."""
INDICATOR = "indicator"
"""``Window.trigger`` of an early window (closed at the event that brought a new indicator)."""


@dataclass(frozen=True)
class Window:
    host_id: str
    host_name: str | None
    start: float
    end: float
    events: tuple[Event, ...]
    summary: WindowSummary
    """The counts of ``events``."""
    trigger: str = SLIDE
    trigger_event: Event | None = None
    """The event an early window closed at (None for a scheduled window)."""


@dataclass(frozen=True)
class Trailing:
    """A host's last ``size`` seconds up to its newest event, as the rules read them."""

    end: float
    summary: Summarizer
    """Live: it changes with the next event of the host."""


class _Slot:
    """One buffered event and the windows that count it."""

    __slots__ = ("event", "scheduled", "trailing")

    def __init__(self, event: Event) -> None:
        self.event = event
        self.scheduled = False
        self.trailing = False


class _HostState:
    __slots__ = (
        "expiry",
        "late_streak",
        "latest",
        "host_name",
        "next_end",
        "partitions",
        "pending",
        "scheduled",
        "slots",
        "trailing",
    )

    def __init__(self) -> None:
        self.slots: deque[_Slot] = deque()
        """Buffered events in arrival order."""
        self.next_end = 0.0
        self.pending = False
        self.host_name: str | None = None
        self.late_streak = 0
        self.partitions: set[int] = set()
        """Kafka partitions that buffered events of this host came from."""
        self.scheduled = Summarizer()
        """The events of the scheduled window ``[next_end - size, next_end)``."""
        self.trailing = Summarizer()
        """The events of the trailing window, up to the newest event of the host."""
        self.expiry: list[tuple[float, int, _Slot]] = []
        """Heap of ``(event time, arrival number, slot)`` for the trailing window's events."""
        self.latest = -math.inf
        """Time of the newest event of the host (it only moves forward, but for a clock reset)."""

    def clear(self) -> None:
        self.slots.clear()
        self.partitions.clear()
        self.scheduled = Summarizer()
        self.trailing = Summarizer()
        self.expiry.clear()
        self.latest = -math.inf


class Windower:
    def __init__(
        self,
        size_sec: float,
        slide_sec: float,
        max_events_per_host: int,
        late_reset_events: int,
    ) -> None:
        if not 0 < slide_sec <= size_sec:
            raise ValueError("slide_sec must be in (0, size_sec]")
        if late_reset_events < 1:
            raise ValueError("late_reset_events must be at least 1")
        self.size = size_sec
        self.slide = slide_sec
        self.max_events = max_events_per_host
        self.late_reset_events = late_reset_events
        self.late_events = 0
        self.overflow_events = 0
        self.clock_resets = 0
        self._hosts: dict[str, _HostState] = {}
        self._arrivals = itertools.count()

    def add(self, event: Event) -> list[Window]:
        """Buffer ``event``; return the scheduled windows it closed (at most two)."""
        state = self._hosts.get(event.host_id)
        if state is None:
            state = self._hosts[event.host_id] = _HostState()
            state.next_end = self._boundary_after(event.timestamp)
        closed: list[Window] = []
        if event.timestamp >= state.next_end:
            state.late_streak = 0
            if state.pending:
                closed.append(self._close(event.host_id, state))
            state.next_end = self._boundary_after(event.timestamp)
            self._slide_scheduled(state)
        elif event.timestamp < state.next_end - self.size:
            self.late_events += 1
            state.late_streak += 1
            if state.late_streak < self.late_reset_events:
                return closed
            if state.pending:
                closed.append(self._close(event.host_id, state))
            state.clear()
            state.next_end = self._boundary_after(event.timestamp)
            state.late_streak = 0
            self.clock_resets += 1
        else:
            state.late_streak = 0
        if event.host_name:
            state.host_name = event.host_name
        if event.partition is not None:
            state.partitions.add(event.partition)
        self._buffer(state, event)
        state.pending = True
        return closed

    def flush(self, host_id: str) -> Window | None:
        """Close the pending scheduled window of ``host_id`` without waiting for a later event."""
        state = self._hosts.get(host_id)
        if state is None or not state.pending:
            return None
        return self._close(host_id, state)

    def trailing(self, host_id: str) -> Trailing | None:
        """The trailing window of ``host_id`` (None before its first buffered event)."""
        state = self._hosts.get(host_id)
        if state is None or state.latest == -math.inf:
            return None
        return Trailing(self._trailing_end(state.latest), state.trailing)

    def close_early(self, host_id: str, trigger_event: Event) -> Window:
        """The trailing window of ``host_id`` as a window, closed at ``trigger_event``.

        The scheduled window is not touched: it closes on its own boundary.
        """
        state = self._hosts[host_id]
        end = self._trailing_end(state.latest)
        return Window(
            host_id,
            state.host_name,
            end - self.size,
            end,
            tuple(slot.event for slot in state.slots if slot.trailing),
            state.trailing.snapshot(),
            INDICATOR,
            trigger_event,
        )

    def drop(self, host_id: str) -> None:
        self._hosts.pop(host_id, None)

    def hosts(self) -> list[str]:
        return list(self._hosts)

    def oldest_offsets(self) -> dict[int, int]:
        """Oldest buffered input offset per Kafka partition.

        Everything from these offsets on must be re-read to rebuild the buffers
        after a restart, so the service may not commit past them.
        """
        oldest: dict[int, int] = {}
        for state in self._hosts.values():
            missing = set(state.partitions)
            if not missing:
                continue
            for slot in state.slots:
                partition, offset = slot.event.partition, slot.event.offset
                if partition is None or offset is None or partition not in missing:
                    continue
                missing.discard(partition)
                if partition not in oldest or offset < oldest[partition]:
                    oldest[partition] = offset
                if not missing:
                    break
            state.partitions -= missing  # nothing of these partitions is buffered any more
        return oldest

    def _buffer(self, state: _HostState, event: Event) -> None:
        """Keep ``event`` and count it in the scheduled and in the trailing window."""
        if len(state.slots) == self.max_events:
            self.overflow_events += 1
            self._retire(state, state.slots.popleft())
        slot = _Slot(event)
        state.slots.append(slot)
        state.scheduled.add(event)
        slot.scheduled = True
        timestamp = event.timestamp
        if timestamp > state.latest:
            state.latest = timestamp
        start = self._trailing_end(state.latest) - self.size
        self._slide_trailing(state, start)
        if timestamp >= start:
            state.trailing.add(event)
            slot.trailing = True
            heapq.heappush(state.expiry, (timestamp, next(self._arrivals), slot))
            self._compact(state)
        # Events older than both windows are of no use any more.
        floor = min(state.next_end - self.size, start)
        while state.slots and state.slots[0].event.timestamp < floor:
            self._retire(state, state.slots.popleft())

    def _close(self, host_id: str, state: _HostState) -> Window:
        end = state.next_end
        events = tuple(slot.event for slot in state.slots if slot.scheduled)
        state.pending = False
        return Window(
            host_id, state.host_name, end - self.size, end, events, state.scheduled.snapshot()
        )

    def _slide_scheduled(self, state: _HostState) -> None:
        """The scheduled window moved on: stop counting what it no longer holds."""
        start = state.next_end - self.size
        for slot in state.slots:
            if slot.scheduled and slot.event.timestamp < start:
                state.scheduled.remove(slot.event)
                slot.scheduled = False

    def _slide_trailing(self, state: _HostState, start: float) -> None:
        """The trailing window moved on: stop counting what it no longer holds."""
        expiry = state.expiry
        while expiry and expiry[0][0] < start:
            slot = heapq.heappop(expiry)[2]
            if slot.trailing:  # not already retired by the size limit
                state.trailing.remove(slot.event)
                slot.trailing = False

    def _compact(self, state: _HostState) -> None:
        """Drop the heap entries of events the size limit pushed out of the buffer.

        The heap forgets an event when event time moves past it; one pushed out earlier stays
        (and keeps its event in memory) for as long as event time stands still or the host sends
        more than ``max_events`` events in a window. A quarter of the limit in such entries
        triggers a rebuild from the live ones, so the heap never holds more than
        ``1.25 * max_events`` entries and the rebuild costs O(1) per event on average.
        """
        if len(state.expiry) > len(state.slots) + self.max_events // 4:
            state.expiry = [entry for entry in state.expiry if entry[2].trailing]
            heapq.heapify(state.expiry)

    @staticmethod
    def _retire(state: _HostState, slot: _Slot) -> None:
        """``slot`` leaves the buffer: no window counts its event any more."""
        if slot.scheduled:
            state.scheduled.remove(slot.event)
            slot.scheduled = False
        if slot.trailing:
            state.trailing.remove(slot.event)
            slot.trailing = False

    @staticmethod
    def _trailing_end(latest: float) -> float:
        """One millisecond after ``latest`` (rounded to the millisecond, as times are written)."""
        return (round(latest * 1000) + 1) / 1000

    def _boundary_after(self, timestamp: float) -> float:
        return (math.floor(timestamp / self.slide) + 1) * self.slide


def window_id(host_id: str, window_end: str) -> str:
    """The identity of a window: one host and one end (as ``format_timestamp``) give one id."""
    return hashlib.sha256(f"{host_id}|{window_end}".encode()).hexdigest()


def format_timestamp(epoch: float) -> str:
    """UTC with milliseconds, as the documents write times."""
    moment = datetime.fromtimestamp(epoch, UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
