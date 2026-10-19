"""When a window closes before its boundary (inference/README.md section 4.0).

The service waits for a window to end before it says anything, so an attack shows up one window
length late. ``EarlyClose`` shortens that: after every event of a host the rules look at the
host's trailing window (``windowing.Trailing``), and the window is closed at once, at that
event, when an indicator fires in it that did not fire after the host's previous event and the
window passes the gate.

The decision depends only on the host's last minute of events. That is what a replay after a
restart rebuilds (``windowing.oldest_offsets`` keeps those events), so the replay closes the same
windows, under the same ``logsentinel.window.id``. Every indicator is monotone in the events
(more events never switch one off), so a replay that starts with a shorter history can only see a
new indicator earlier, never later: it may close an early window the first run did not, never
miss one the first run closed.
"""

from __future__ import annotations

from inference.indicators import gated


class EarlyClose:
    def __init__(self) -> None:
        self._fired: dict[str, frozenset[str]] = {}
        """Per host: the indicators that fired in its trailing window after its previous event."""

    def due(self, host_id: str, fired: frozenset[str]) -> bool:
        """Whether the trailing window of ``host_id`` must close now.

        ``fired`` are the indicators that fire in it after the event just added; call this once
        per event, in order.
        """
        previous = self._fired.get(host_id, frozenset())
        self._fired[host_id] = fired
        return gated(fired) and not fired <= previous

    def forget(self, host_id: str) -> None:
        """The host's window state is gone (evicted, or its clock moved): start from nothing."""
        self._fired.pop(host_id, None)
