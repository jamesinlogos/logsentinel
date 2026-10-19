"""Which input offsets may be committed (at-least-once, with replay).

The service keeps windows in memory and produces its output records (a window score
per window, a detection for the reported ones) asynchronously. The offset of an
input message may be committed only when nothing derived from it is still needed:

* its event is no longer buffered in a window (a restart would lose that window), and
* every record built from a window that holds it was acknowledged by the broker.

After a crash or restart the consumer re-reads from the committed offset,
rebuilds the open windows and produces the unacknowledged records again.
They keep their ``logsentinel.window.id``, so Elasticsearch ends up with one document.
The price is a replay of up to one window (longer for a host that stopped
sending, until the host is evicted) and duplicate records on the topics.
"""

from __future__ import annotations

from collections.abc import Mapping


class OffsetTracker:
    def __init__(self) -> None:
        self._next: dict[int, int] = {}
        """Per partition: the offset after the last message that went through the pipeline."""
        self._stored: dict[int, int] = {}
        self._pending: dict[int, dict[int, int]] = {}
        """Records not acknowledged yet: sequence -> oldest needed offset per partition."""
        self._sequence = 0

    @property
    def pending_outputs(self) -> int:
        return len(self._pending)

    def processed(self, partition: int, offset: int) -> None:
        self._next[partition] = offset + 1

    def output_enqueued(self, needed: Mapping[int, int]) -> int:
        """Register an output record whose window needs input from ``needed`` on; returns its id."""
        self._sequence += 1
        self._pending[self._sequence] = dict(needed)
        return self._sequence

    def output_acked(self, sequence: int) -> None:
        self._pending.pop(sequence, None)

    def advance(self, buffered: Mapping[int, int]) -> dict[int, int]:
        """Offsets that can be stored now: ``{partition: next offset to read}``.

        ``buffered`` is the oldest offset per partition still held by a window
        buffer. Only partitions whose safe offset moved forward are returned.
        """
        holds = dict(buffered)
        for needed in self._pending.values():
            for partition, offset in needed.items():
                if partition not in holds or offset < holds[partition]:
                    holds[partition] = offset
        moved: dict[int, int] = {}
        for partition, following in self._next.items():
            safe = min(following, holds.get(partition, following))
            if safe > self._stored.get(partition, -1):
                self._stored[partition] = safe
                moved[partition] = safe
        return moved
