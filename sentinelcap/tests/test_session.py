"""t_exec detection and the quiet-window rule (pure logic, no Kafka/VM)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from sentinelcap.errors import SentinelcapError
from sentinelcap.session import (
    EventInfo,
    ExecuteSession,
    find_exec_event,
    format_timestamp,
    parse_event,
)

PATH = r"C:\Users\sysmaint\Downloads\Akira\abc.exe"
SHA = "ab" * 32
OTHER_SHA = "cd" * 32
SVCHOST = r"C:\Windows\System32\svchost.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
T0 = datetime(2026, 9, 24, 5, 0, 0, tzinfo=timezone.utc)


def make(
    ts_offset: float,
    at: float,
    *,
    code="1",
    exe=PATH,
    sha=SHA,
    eid="{ROOT}",
    parent="{P}",
    host="h",
    file=None,
) -> EventInfo:
    ts = format_timestamp(datetime.fromtimestamp(T0.timestamp() + ts_offset, timezone.utc))
    proc = {"executable": exe, "entity_id": eid, "parent": {"entity_id": parent}}
    if sha is not None:
        proc["hash"] = {"sha256": sha}
    doc = {"@timestamp": ts, "host": {"id": host}, "event": {"code": code}, "process": proc}
    if file is not None:
        doc["file"] = {"path": file}
    return parse_event(json.dumps(doc).encode(), at, T0)


def test_match_is_case_insensitive_on_path_and_hash() -> None:
    ev = make(1, 10, exe=PATH.upper(), sha=SHA.upper())
    assert find_exec_event([ev], PATH.lower(), SHA) is ev


def test_first_matching_event1_wins_and_others_ignored() -> None:
    other_hash = make(0, 1, sha="cd" * 32)
    not_event1 = make(0, 2, code="11")
    other_path = make(0, 3, exe=r"C:\Windows\x.exe")
    first = make(1, 4, eid="{A}")
    second = make(2, 5, eid="{B}")
    assert find_exec_event([other_hash, not_event1, other_path, first, second], PATH, SHA) is first


def test_no_valid_event1_returns_none() -> None:
    assert find_exec_event([make(0, 1, sha="cd" * 32), make(0, 2, code="3")], PATH, SHA) is None


def test_timestamp_without_timezone_rejected() -> None:
    with pytest.raises(SentinelcapError):
        parse_event(b'{"@timestamp":"2026-09-24T05:00:00"}', 0.0, T0)


def session(**kw) -> ExecuteSession:
    exec_ev = make(0, 100, eid="{ROOT}")
    return ExecuteSession(
        exec_ev,
        settle=kw.get("settle", 300),
        quiet=kw.get("quiet", 90),
        max_wait=kw.get("max_wait", 300),
    )


def test_never_stops_before_settle() -> None:
    s = session()
    assert not s.should_stop(100 + 299)  # silent, but still inside settle
    # Silence before the end of settle does not count: quiet starts at 300.
    assert not s.should_stop(100 + 300 + 89)
    assert s.should_stop(100 + 300 + 90)


def test_activity_inside_settle_does_not_shorten_quiet_after_it() -> None:
    s = session()
    s.observe(make(250, 100 + 250, code="11", eid="{ROOT}"))  # last activity before settle ends
    assert not s.should_stop(100 + 300 + 89)
    assert s.should_stop(100 + 300 + 90)


def test_quiet_extends_on_root_and_descendants_not_others() -> None:
    s = session()
    s.observe(make(310, 100 + 310, code="1", eid="{CHILD}", parent="{ROOT}"))
    s.observe(make(320, 100 + 320, code="11", eid="{CHILD}", parent="{ROOT}"))
    s.observe(make(330, 100 + 330, code="1", eid="{GRAND}", parent="{CHILD}"))
    assert not s.should_stop(100 + 330 + 89)
    assert s.should_stop(100 + 330 + 90)
    s2 = session()
    s2.observe(make(390, 100 + 390, eid="{OTHER}", parent="{X}", exe=SVCHOST, sha=OTHER_SHA))
    assert not s2.should_stop(100 + 300 + 89)
    assert s2.should_stop(100 + 300 + 90)  # the unrelated event at 390 did not reset quiet


def test_wmi_spawned_process_not_counted() -> None:
    s = session()
    s.observe(
        make(300, 400, code="1", eid="{WMI}", parent="{WmiPrvSE}", exe=POWERSHELL, sha=OTHER_SHA)
    )
    s.observe(
        make(395, 495, code="11", eid="{WMI}", parent="{WmiPrvSE}", exe=POWERSHELL, sha=OTHER_SHA)
    )
    assert s.should_stop(100 + 300 + 90)
    assert s.entity_ids == ["{ROOT}"]


def test_relaunch_through_dllhost_is_a_sample_process() -> None:
    # UAC elevation: same file, new process, parent dllhost.exe (not in the tree).
    s = session()
    s.observe(make(310, 100 + 310, code="1", eid="{ELEVATED}", parent="{DLLHOST}"))
    s.observe(make(380, 100 + 380, code="11", eid="{ELEVATED}", parent="{DLLHOST}"))
    assert not s.should_stop(100 + 380 + 89)
    assert s.should_stop(100 + 380 + 90)
    assert s.entity_ids == ["{ROOT}", "{ELEVATED}"]


def test_executable_path_containing_hash_counts_without_event1() -> None:
    # e.g. "<hash>_online.paf.exe" re-launched by the portable launcher.
    s = session()
    renamed = rf"C:\Users\sysmaint\Downloads\{SHA}_online.paf.exe"
    s.observe(
        make(350, 100 + 350, code="11", eid="{PAF}", parent="{EXPLORER}", exe=renamed, sha=None)
    )
    assert not s.should_stop(100 + 350 + 89)
    assert "{PAF}" in s.entity_ids


def test_renamed_copy_with_same_sha256_and_its_children_count() -> None:
    s = session()
    copy = r"C:\Users\sysmaint\AppData\Roaming\svhost.exe"
    s.observe(make(305, 100 + 305, code="1", eid="{COPY}", parent="{SVC}", exe=copy))
    s.observe(
        make(340, 100 + 340, code="1", eid="{KID}", parent="{COPY}", exe=POWERSHELL, sha=OTHER_SHA)
    )
    assert s.entity_ids == ["{ROOT}", "{COPY}", "{KID}"]
    assert not s.should_stop(100 + 340 + 89)


def test_same_hash_in_non_event1_without_path_match_is_not_enough() -> None:
    # Event 23 also carries process.hash; only Event 1 hashes identify a new sample process.
    s = session()
    s.observe(make(310, 100 + 310, code="23", eid="{DEL}", parent="{X}", exe=SVCHOST))
    assert s.entity_ids == ["{ROOT}"]


DROPPED = r"C:\ProgramData\rl\LB3.exe"
DLLHOST = r"C:\Windows\SysWOW64\dllhost.exe"


@pytest.mark.parametrize("code", ["11", "29"])
def test_dropped_payload_launched_by_anyone_counts(code: str) -> None:
    # The sample writes a payload with another hash; dllhost.exe (UAC) launches it later.
    s = session()
    s.observe(make(1, 101, code=code, eid="{ROOT}", file=DROPPED))
    s.observe(
        make(310, 100 + 310, eid="{DROP}", parent="{DLLHOST}", exe=DROPPED.upper(), sha=OTHER_SHA)
    )
    s.observe(
        make(
            380,
            100 + 380,
            code="11",
            eid="{DROP}",
            parent="{DLLHOST}",
            exe=DROPPED,
            sha=None,
            file=r"C:\Users\Public\a.txt.lockbit",
        )
    )
    assert s.entity_ids == ["{ROOT}", "{DROP}"]
    assert not s.should_stop(100 + 380 + 89)


def test_dropped_payload_child_counts_and_long_path_prefix_matches() -> None:
    s = session()
    s.observe(make(1, 101, code="1", eid="{KID}", parent="{ROOT}", exe=POWERSHELL, sha=OTHER_SHA))
    s.observe(
        make(
            2, 102, code="11", eid="{KID}", parent="{ROOT}", exe=POWERSHELL, sha=None, file=DROPPED
        )
    )
    s.observe(make(3, 103, eid="{DROP}", parent="{SVC}", exe="\\\\?\\" + DROPPED, sha=OTHER_SHA))
    assert "{DROP}" in s.entity_ids


def test_file_written_by_unrelated_process_does_not_count() -> None:
    s = session()
    s.observe(
        make(1, 101, code="11", eid="{OTHER}", parent="{X}", exe=SVCHOST, sha=None, file=DROPPED)
    )
    s.observe(make(2, 102, eid="{DROP}", parent="{DLLHOST}", exe=DROPPED, sha=OTHER_SHA))
    assert s.entity_ids == ["{ROOT}"]


def test_launch_before_the_write_does_not_count() -> None:
    s = session()
    s.observe(make(1, 101, eid="{EARLY}", parent="{X}", exe=DROPPED, sha=OTHER_SHA))
    s.observe(make(2, 102, code="11", eid="{ROOT}", file=DROPPED))
    assert s.entity_ids == ["{ROOT}"]


def test_non_event1_of_written_executable_does_not_count() -> None:
    s = session()
    s.observe(make(1, 101, code="11", eid="{ROOT}", file=DROPPED))
    s.observe(make(2, 102, code="3", eid="{DROP}", parent="{X}", exe=DROPPED, sha=None))
    assert s.entity_ids == ["{ROOT}"]


def test_max_wait_cap() -> None:
    s = session()
    for k in range(0, 600, 30):  # constant root activity
        s.observe(make(k, 100 + k, code="11", eid="{ROOT}"))
    assert not s.should_stop(100 + 599)
    assert s.should_stop(100 + 600)


def test_events_before_t_exec_ignored_and_t_end_uses_elapsed() -> None:
    s = session()
    s.observe(make(-5, 100 + 500, eid="{ROOT}"))  # ts < t_exec -> ignored
    assert s.should_stop(100 + 300 + 90)
    assert s.t_end(100 + 305) == datetime.fromtimestamp(T0.timestamp() + 305, timezone.utc)
