"""Which scored windows become detections (inference/README.md section 2)."""

from __future__ import annotations

from inference.emission import EmissionPolicy


def test_emission_policy() -> None:
    policy = EmissionPolicy(reemit_after_sec=60, size_sec=60)
    shadow = frozenset({"shadow_copy_deletion"})
    both = shadow | {"service_stop_burst"}
    assert policy.allow("h", 100, shadow, suspicious=False)
    assert not policy.allow("h", 110, shadow, suspicious=False)  # nothing new
    assert policy.allow("h", 120, shadow, suspicious=True)  # label raised
    assert policy.allow("h", 130, both, suspicious=True)  # new indicator
    assert not policy.allow("h", 140, shadow, suspicious=False)  # remembered union
    assert policy.allow("h", 200, shadow, suspicious=False)  # after the pause
    assert policy.allow("other", 110, shadow, suspicious=False)  # per host
    policy.forget("h")
    assert policy.allow("h", 210, shadow, suspicious=False)


def test_a_window_that_closes_again_is_not_a_repeat() -> None:
    policy = EmissionPolicy(reemit_after_sec=60, size_sec=60)
    shadow = frozenset({"shadow_copy_deletion"})
    both = shadow | {"service_stop_burst"}
    assert policy.allow("h", 100, shadow, suspicious=False)
    # An idle flush closed the window early; later events of the bucket close it once more.
    assert policy.allow("h", 100, shadow, suspicious=False)
    assert policy.allow("h", 100, both, suspicious=True)
    assert not policy.allow("h", 110, both, suspicious=True)  # the next window adds nothing new


def test_emission_policy_follows_a_host_clock_that_moved_back() -> None:
    policy = EmissionPolicy(reemit_after_sec=60, size_sec=60)
    shadow = frozenset({"shadow_copy_deletion"})
    assert policy.allow("h", 1000, shadow, suspicious=True)
    assert policy.allow("h", 500, shadow, suspicious=True)  # not held back by the old clock
    assert not policy.allow("h", 510, shadow, suspicious=True)  # the new clock is remembered


def test_a_window_ending_before_the_last_reported_one_is_the_same_activity() -> None:
    """An idle flush, then an early window, then the events of the bucket close the first again."""
    policy = EmissionPolicy(reemit_after_sec=60, size_sec=60)
    shadow = frozenset({"shadow_copy_deletion"})
    both = shadow | {"service_stop_burst"}
    assert policy.allow("h", 1010, shadow, suspicious=False)  # an early window
    assert not policy.allow("h", 1000, shadow, suspicious=False)  # earlier, nothing new
    assert policy.allow("h", 1000, both, suspicious=False)  # earlier, but a new indicator
    assert policy.allow("h", 1005, both, suspicious=True)  # earlier, but the label is raised
    # The last reported end did not move back: 1070 is a minute after 1010 only by the clock.
    assert not policy.allow("h", 1015, both, suspicious=True)
    assert policy.allow("h", 1070, both, suspicious=True)


def test_a_window_a_whole_window_earlier_means_the_clock_moved_back() -> None:
    policy = EmissionPolicy(reemit_after_sec=60, size_sec=60)
    shadow = frozenset({"shadow_copy_deletion"})
    assert policy.allow("h", 1000, shadow, suspicious=True)
    assert not policy.allow("h", 941, shadow, suspicious=True)  # 59 s earlier: same activity
    assert policy.allow("h", 940, shadow, suspicious=True)  # 60 s earlier: a clock that moved back


def test_without_a_pause_every_window_is_reported() -> None:
    """``reemit_after_sec`` 0 switches the suppression off (tests and the restart check use it)."""
    policy = EmissionPolicy(reemit_after_sec=0, size_sec=60)
    shadow = frozenset({"shadow_copy_deletion"})
    for end in (100, 110, 120, 120, 105, 110):  # later, the same, and earlier than the last one
        assert policy.allow("h", end, shadow, suspicious=False)
