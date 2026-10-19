"""When a window closes before its boundary (inference/README.md section 4.0)."""

from __future__ import annotations

from inference.trigger import EarlyClose

SHADOW = frozenset({"shadow_copy_deletion"})
SUPPORT = frozenset({"lolbins_execution"})


def test_a_new_indicator_in_a_gated_window_closes_it() -> None:
    early = EarlyClose()
    assert early.due("h", SHADOW)  # the first strong indicator
    assert not early.due("h", SHADOW)  # still there: nothing new
    assert early.due("h", SHADOW | {"service_stop_burst"})  # another one
    assert not early.due("h", SHADOW | {"service_stop_burst"})
    assert early.due("h", SHADOW | {"service_stop_burst", "lolbins_execution"})  # a support one


def test_a_window_that_does_not_pass_the_gate_is_not_closed() -> None:
    early = EarlyClose()
    assert not early.due("h", frozenset())
    assert not early.due("h", SUPPORT)  # support indicators never open the gate
    assert early.due("h", SUPPORT | SHADOW)  # the strong one does, and it is new


def test_an_indicator_that_left_the_window_counts_as_new_when_it_returns() -> None:
    early = EarlyClose()
    assert early.due("h", SHADOW)
    assert not early.due("h", frozenset())  # its events aged out of the trailing window
    assert early.due("h", SHADOW)  # a new burst


def test_a_shrinking_window_never_closes() -> None:
    """Fewer indicators than the event before: nothing new, whatever else changed."""
    early = EarlyClose()
    both = SHADOW | {"service_stop_burst"}
    assert early.due("h", both)
    assert not early.due("h", SHADOW)


def test_hosts_are_independent_and_can_be_forgotten() -> None:
    early = EarlyClose()
    assert early.due("a", SHADOW)
    assert early.due("b", SHADOW)
    assert not early.due("a", SHADOW)
    early.forget("a")
    assert early.due("a", SHADOW)  # its window state started again
    early.forget("unknown")  # nothing to forget is fine
