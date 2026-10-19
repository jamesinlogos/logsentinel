"""Which scored windows are reported as detections (inference/README.md section 2).

A host is reported again only for a new indicator, a raised label, or after a pause. The window
scores are written for every window; this policy decides which of the gated ones also become
detections.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _Emitted:
    fired: frozenset[str]
    suspicious: bool
    end: float


class EmissionPolicy:
    """Report a host again only for new indicators, a raised label, or after a pause.

    ``reemit_after_sec`` is the pause; 0 switches the suppression off, every gated window is
    reported (the tests and ``training.e2e_restart`` compare windows, not the policy). ``size_sec``
    is the window length.

    A window that closes again with the same ``end`` is not a repeat but the same window, flushed
    early and completed by later events (``windowing.py``). It stays reported, so that the new
    record replaces the earlier one under the same ``logsentinel.window.id`` and the detection and
    the window score of that id never disagree about ``reported``.

    A window may end before the last reported one: an idle flush closed the window of a bucket,
    an early window was reported, and the events of the bucket close it once more. Ending less
    than ``size_sec`` before is the same activity seen again, judged like a window inside the
    pause; ending ``size_sec`` or more before means the host's clock moved back, and what the host
    reported before says nothing now.
    """

    def __init__(self, reemit_after_sec: float, size_sec: float) -> None:
        self.reemit_after_sec = reemit_after_sec
        self.size_sec = size_sec
        self._last: dict[str, _Emitted] = {}

    def allow(self, host_id: str, end: float, fired: frozenset[str], suspicious: bool) -> bool:
        last = self._last.get(host_id)
        if last is not None and last.end - end >= self.size_sec:
            last = None  # the host's clock moved back by a window or more
        if last is not None:
            same_window = end == last.end
            if same_window or (
                self.reemit_after_sec > 0 and end - last.end < self.reemit_after_sec
            ):
                if not same_window and fired <= last.fired and (last.suspicious or not suspicious):
                    return False
                fired = fired | last.fired
                suspicious = suspicious or last.suspicious
                end = max(end, last.end)
        self._last[host_id] = _Emitted(fired, suspicious, end)
        return True

    def forget(self, host_id: str) -> None:
        self._last.pop(host_id, None)
