"""Collection pipelines: revert -> start -> (execute | interactive | validate) -> export.

The tool never launches a sample. In ``--execute`` / ``--validate`` the operator
double-clicks the executable(s) in the VM; in ``--interactive`` the operator
performs the scenario between two Enter presses.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath

from sentinelcap.capture import KafkaCapture, prepare_session_dir
from sentinelcap.config import SentinelcapConfig
from sentinelcap.errors import SentinelcapError
from sentinelcap.logging_utils import get_logger
from sentinelcap.manifest import ManifestEntry, Mode, group_validate_pairs
from sentinelcap.session import (
    EventInfo,
    ExecuteSession,
    find_exec_event,
    format_timestamp,
    run_stamp,
)
from sentinelcap.vm import VMwareController

logger = get_logger(__name__)

VM_STOP_PAUSE_SEC = 5
"""Pause after powering the VM off, before the next session reverts it."""


@dataclass(frozen=True)
class SessionWindow:
    """What a collection mode hands to ``export_session`` (guest time)."""

    t_start: datetime
    t_end: datetime
    process_entity_id: str | None = None
    """``--execute`` / ``--validate`` only."""
    sample_entity_ids: list[str] | None = None
    """``--execute`` / ``--validate`` only."""
    scenario: str | None = None
    """``--interactive`` only."""
    clock_offset_sec: float = 0.0


def new_run_dir(cfg: SentinelcapConfig) -> Path:
    """``<capture.out_dir>/<YYYYMMDDTHHMMSSZ>``: one directory per collection run (UTC)."""
    return Path(cfg.capture.out_dir) / run_stamp(datetime.now(timezone.utc))


def _guest_sample_path(entry: ManifestEntry) -> str:
    if entry.path is None:
        raise SentinelcapError(f"{entry.session_name}: needs the guest path of the sample")
    return entry.path


def detect_exec(capture: KafkaCapture, entry: ManifestEntry, timeout_sec: float) -> EventInfo:
    """Buffer host events until the sample's Event 1 appears, else fail."""
    path = _guest_sample_path(entry)
    deadline = time.monotonic() + timeout_sec
    checked = 0
    while (remaining := deadline - time.monotonic()) > 0:
        capture.poll_event(timeout=min(1.0, remaining))
        found = find_exec_event(capture.events[checked:], path, entry.sample)
        checked = len(capture.events)
        if found is not None:
            return found
    raise SentinelcapError(
        f"No Sysmon Event 1 for {path} with SHA-256 {entry.sample} within {timeout_sec:g}s; "
        "the sample did not run or the manifest sample/path is wrong"
    )


def detect_exec_pair(
    capture: KafkaCapture,
    ransomware: ManifestEntry,
    goodware: ManifestEntry,
    timeout_sec: float,
) -> tuple[EventInfo, EventInfo]:
    """Buffer until Event 1 of both samples appears, else fail."""
    rw_path = _guest_sample_path(ransomware)
    gw_path = _guest_sample_path(goodware)
    deadline = time.monotonic() + timeout_sec
    checked = 0
    found_rw: EventInfo | None = None
    found_gw: EventInfo | None = None
    while (remaining := deadline - time.monotonic()) > 0:
        capture.poll_event(timeout=min(1.0, remaining))
        new_events = capture.events[checked:]
        checked = len(capture.events)
        if found_rw is None:
            found_rw = find_exec_event(new_events, rw_path, ransomware.sample)
        if found_gw is None:
            found_gw = find_exec_event(new_events, gw_path, goodware.sample)
        if found_rw is not None and found_gw is not None:
            return found_rw, found_gw
    missing = []
    if found_rw is None:
        missing.append(f"ransomware {rw_path} SHA-256 {ransomware.sample}")
    if found_gw is None:
        missing.append(f"goodware {gw_path} SHA-256 {goodware.sample}")
    raise SentinelcapError(
        f"No Sysmon Event 1 for {' and '.join(missing)} within {timeout_sec:g}s; "
        "a sample did not run or the manifest sample/path is wrong"
    )


def _collect_execute(
    cfg: SentinelcapConfig, capture: KafkaCapture, vm: VMwareController, entry: ManifestEntry
) -> SessionWindow:
    """Session window and sample processes of an ``--execute`` session."""
    path = _guest_sample_path(entry)
    vm.open_explorer(str(PureWindowsPath(path).parent))
    logger.warning(
        "Open the VMware console and double-click '%s' (waiting up to %ss).",
        path,
        cfg.capture.exec_detect_timeout_sec,
    )
    exec_event = detect_exec(capture, entry, cfg.capture.exec_detect_timeout_sec)
    logger.info(
        "Sample started: t_exec = %s, entity_id = %s",
        format_timestamp(exec_event.timestamp),
        exec_event.entity_id,
    )

    session = ExecuteSession(
        exec_event,
        settle=cfg.capture.settle_sec,
        quiet=cfg.capture.quiet_window_sec,
        max_wait=cfg.capture.max_wait_sec,
    )
    for buffered in capture.events:
        session.observe(buffered)
    while True:
        polled = capture.poll_event(timeout=1.0)
        if polled is not None:
            session.observe(polled)
        now = time.monotonic()
        if session.should_stop(now):
            break
    t_end = session.t_end(now)
    logger.info(
        "Stopping: %.0fs since t_exec, t_end = %s", session.elapsed(now), format_timestamp(t_end)
    )
    observed = len(capture.events)
    capture.poll_for(cfg.kafka.post_capture_drain_sec)
    # Late-delivered events inside the window can still reveal sample processes.
    for event in capture.events[observed:]:
        if event.timestamp <= t_end:
            session.observe(event)
    return SessionWindow(
        session.t_exec,
        t_end,
        process_entity_id=session.root_entity_id,
        sample_entity_ids=session.entity_ids,
    )


def _wait_enter(capture: KafkaCapture, prompt: str) -> datetime:
    """Block on Enter while still polling Kafka; return the host wall clock at Enter."""
    pressed = threading.Event()

    def _read() -> None:
        input(prompt)
        pressed.set()

    threading.Thread(target=_read, daemon=True).start()
    while not pressed.is_set():
        capture.poll_event(timeout=0.5)
    return datetime.now(timezone.utc)


def _collect_interactive(
    cfg: SentinelcapConfig, capture: KafkaCapture, entry: ManifestEntry
) -> SessionWindow:
    """Session window (guest time) and clock offset of an ``--interactive`` session."""
    logger.info("Scenario %s: perform the scenario in the VM console.", entry.scenario)
    host_start = _wait_enter(capture, "Press Enter to START the session... ")
    logger.info("Recording. Perform the scenario now.")
    host_end = _wait_enter(capture, "Press Enter to END the session... ")
    capture.poll_for(cfg.kafka.post_capture_drain_sec)

    offset = capture.clock_offset_sec(cfg.capture.clock_offset_median_events)
    delta = timedelta(seconds=offset)
    return SessionWindow(
        host_start - delta, host_end - delta, scenario=entry.scenario, clock_offset_sec=offset
    )


def _collect_validate_pair(
    cfg: SentinelcapConfig,
    capture: KafkaCapture,
    vm: VMwareController,
    ransomware: ManifestEntry,
    goodware: ManifestEntry,
) -> tuple[SessionWindow, SessionWindow]:
    """Run ransomware and goodware together; stop when both quiet rules are met."""
    rw_path = _guest_sample_path(ransomware)
    gw_path = _guest_sample_path(goodware)
    shared_dir = str(PureWindowsPath(rw_path).parent)
    if (
        str(PureWindowsPath(gw_path).parent).casefold()
        != str(PureWindowsPath(rw_path).parent).casefold()
    ):
        raise SentinelcapError(
            f"validate pair must share a guest directory: {rw_path} vs {gw_path}"
        )
    vm.open_explorer(shared_dir)
    logger.warning(
        "Open the VMware console and double-click BOTH samples in '%s' "
        "(waiting up to %ss for Event 1 of each):\n  ransomware: %s\n  goodware:   %s",
        shared_dir,
        cfg.capture.exec_detect_timeout_sec,
        rw_path,
        gw_path,
    )
    rw_exec, gw_exec = detect_exec_pair(
        capture, ransomware, goodware, cfg.capture.exec_detect_timeout_sec
    )
    logger.info(
        "Both samples started: ransomware t_exec=%s entity=%s; goodware t_exec=%s entity=%s",
        format_timestamp(rw_exec.timestamp),
        rw_exec.entity_id,
        format_timestamp(gw_exec.timestamp),
        gw_exec.entity_id,
    )

    sessions = {
        "ransomware": ExecuteSession(
            rw_exec,
            settle=cfg.capture.settle_sec,
            quiet=cfg.capture.quiet_window_sec,
            max_wait=cfg.capture.max_wait_sec,
        ),
        "goodware": ExecuteSession(
            gw_exec,
            settle=cfg.capture.settle_sec,
            quiet=cfg.capture.quiet_window_sec,
            max_wait=cfg.capture.max_wait_sec,
        ),
    }
    for buffered in capture.events:
        for session in sessions.values():
            session.observe(buffered)
    while True:
        polled = capture.poll_event(timeout=1.0)
        if polled is not None:
            for session in sessions.values():
                session.observe(polled)
        now = time.monotonic()
        if all(session.should_stop(now) for session in sessions.values()):
            break
    t_end_now = now
    logger.info(
        "Stopping pair: ransomware elapsed=%.0fs, goodware elapsed=%.0fs",
        sessions["ransomware"].elapsed(t_end_now),
        sessions["goodware"].elapsed(t_end_now),
    )
    observed = len(capture.events)
    capture.poll_for(cfg.kafka.post_capture_drain_sec)
    windows: dict[str, SessionWindow] = {}
    for key, session in sessions.items():
        t_end = session.t_end(t_end_now)
        for event in capture.events[observed:]:
            if event.timestamp <= t_end:
                session.observe(event)
        windows[key] = SessionWindow(
            session.t_exec,
            t_end,
            process_entity_id=session.root_entity_id,
            sample_entity_ids=session.entity_ids,
        )
    return windows["ransomware"], windows["goodware"]


def run_session(
    cfg: SentinelcapConfig,
    entry: ManifestEntry,
    mode: Mode,
    force: bool = False,
    run_dir: Path | None = None,
) -> Path:
    """Collect one session into ``<run_dir>/<family>/<sample>`` and return that directory.

    ``run_dir`` defaults to a new ``<capture.out_dir>/<UTC timestamp>``.
    ``Mode.VALIDATE`` is only used through ``run_validate_pair`` / ``run_batch``.
    """
    if mode is Mode.VALIDATE:
        raise SentinelcapError("validate sessions run as pairs via batch --validate")
    run_dir = run_dir if run_dir is not None else new_run_dir(cfg)
    prepare_session_dir(run_dir, entry.family, entry.sample, force)  # before touching the VM

    vm = VMwareController(cfg.vmware)
    capture = KafkaCapture(cfg.kafka)
    session_id = str(uuid.uuid4())
    vm_started = False

    logger.info("=== %s (%s) ===", entry.session_name, mode.value)
    try:
        vm.revert_to_baseline()
        vm.start()
        vm_started = True
        vm.wait_tools_ready()
        time.sleep(cfg.vmware.start_boot_wait_sec)

        # Subscribe at the topic tail before anything can happen in the guest.
        capture.start()
        logger.info("session_id = %s", session_id)

        if mode is Mode.EXECUTE:
            window = _collect_execute(cfg, capture, vm, entry)
        else:
            window = _collect_interactive(cfg, capture, entry)
        return capture.export_session(
            mode=mode.value,
            family=entry.family,
            sample=entry.sample,
            label=entry.label,
            t_start=window.t_start,
            t_end=window.t_end,
            out_dir=run_dir,
            session_id=session_id,
            process_entity_id=window.process_entity_id,
            sample_entity_ids=window.sample_entity_ids,
            scenario=window.scenario,
            clock_offset_sec=window.clock_offset_sec,
            snapshot=cfg.vmware.baseline_snapshot,
            force=force,
        )
    finally:
        capture.close()
        if vm_started:
            vm.stop_hard()
            time.sleep(VM_STOP_PAUSE_SEC)


def run_validate_pair(
    cfg: SentinelcapConfig,
    ransomware: ManifestEntry,
    goodware: ManifestEntry,
    force: bool = False,
    run_dir: Path | None = None,
) -> tuple[Path, Path]:
    """Collect one ransomware+goodware pair simultaneously from the ``validate`` snapshot."""
    run_dir = run_dir if run_dir is not None else new_run_dir(cfg)
    prepare_session_dir(run_dir, ransomware.family, ransomware.sample, force)
    prepare_session_dir(run_dir, goodware.family, goodware.sample, force)

    vm = VMwareController(cfg.vmware)
    capture = KafkaCapture(cfg.kafka)
    vm_started = False

    logger.info("=== validate pair %s + %s ===", ransomware.session_name, goodware.session_name)
    try:
        vm.revert_to(cfg.vmware.validate_snapshot)
        vm.start()
        vm_started = True
        vm.wait_tools_ready()
        time.sleep(cfg.vmware.start_boot_wait_sec)

        capture.start()
        rw_window, gw_window = _collect_validate_pair(cfg, capture, vm, ransomware, goodware)
        rw_dir = capture.export_session(
            mode=Mode.VALIDATE.value,
            family=ransomware.family,
            sample=ransomware.sample,
            label=ransomware.label,
            t_start=rw_window.t_start,
            t_end=rw_window.t_end,
            out_dir=run_dir,
            session_id=str(uuid.uuid4()),
            process_entity_id=rw_window.process_entity_id,
            sample_entity_ids=rw_window.sample_entity_ids,
            snapshot=cfg.vmware.validate_snapshot,
            force=force,
        )
        gw_dir = capture.export_session(
            mode=Mode.VALIDATE.value,
            family=goodware.family,
            sample=goodware.sample,
            label=goodware.label,
            t_start=gw_window.t_start,
            t_end=gw_window.t_end,
            out_dir=run_dir,
            session_id=str(uuid.uuid4()),
            process_entity_id=gw_window.process_entity_id,
            sample_entity_ids=gw_window.sample_entity_ids,
            snapshot=cfg.vmware.validate_snapshot,
            force=force,
        )
        return rw_dir, gw_dir
    finally:
        capture.close()
        if vm_started:
            vm.stop_hard()
            time.sleep(VM_STOP_PAUSE_SEC)


def run_capture(
    cfg: SentinelcapConfig, entry: ManifestEntry, duration: float, force: bool = False
) -> Path:
    """Record the victim host for ``duration`` seconds without touching the VM.

    Writes the same ``<out_dir>/<UTC timestamp>/<family>/<sample>/`` session as
    ``run_session`` with ``mode = "capture"``. The window is measured on the
    host clock and converted to guest time with ``clock_offset_sec``.
    ``environment.snapshot`` is null because the VM state is not managed here.
    """
    run_dir = new_run_dir(cfg)
    prepare_session_dir(run_dir, entry.family, entry.sample, force)

    capture = KafkaCapture(cfg.kafka)
    session_id = str(uuid.uuid4())
    try:
        capture.start()
        logger.info("session_id = %s; recording %ss", session_id, duration)
        host_start = datetime.now(timezone.utc)
        capture.poll_for(duration)
        host_end = datetime.now(timezone.utc)
        capture.poll_for(cfg.kafka.post_capture_drain_sec)
        offset = capture.clock_offset_sec(cfg.capture.clock_offset_median_events)
        delta = timedelta(seconds=offset)
        return capture.export_session(
            mode=Mode.CAPTURE.value,
            family=entry.family,
            sample=entry.sample,
            label=entry.label,
            t_start=host_start - delta,
            t_end=host_end - delta,
            out_dir=run_dir,
            session_id=session_id,
            clock_offset_sec=offset,
            force=force,
        )
    finally:
        capture.close()


@dataclass
class BatchResult:
    entry: ManifestEntry
    session_dir: Path | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def run_batch(
    cfg: SentinelcapConfig, entries: list[ManifestEntry], mode: Mode, force: bool = False
) -> list[BatchResult]:
    """Collect manifest rows sequentially into one run directory.

    A failed row (or validate pair) is recorded and the batch continues.
    ``Mode.VALIDATE`` groups rows into ransomware/goodware pairs and runs each
    pair simultaneously from the ``validate`` snapshot.
    """
    run_dir = new_run_dir(cfg)
    logger.info("Run directory: %s", run_dir)
    results: list[BatchResult] = []
    if mode is Mode.VALIDATE:
        pairs = group_validate_pairs(entries)
        for i, (ransomware, goodware) in enumerate(pairs, start=1):
            logger.info("--- Pair %d/%d ---", i, len(pairs))
            try:
                rw_dir, gw_dir = run_validate_pair(
                    cfg, ransomware, goodware, force, run_dir=run_dir
                )
                results.append(BatchResult(ransomware, session_dir=rw_dir))
                results.append(BatchResult(goodware, session_dir=gw_dir))
            except Exception as e:  # one failed pair must not stop the batch
                logger.error(
                    "Failed to process pair '%s' + '%s': %s",
                    ransomware.session_name,
                    goodware.session_name,
                    e,
                )
                logger.debug("Traceback of the failed pair", exc_info=True)
                err = str(e)
                results.append(BatchResult(ransomware, error=err))
                results.append(BatchResult(goodware, error=err))
        return results

    for i, entry in enumerate(entries, start=1):
        logger.info("--- Session %d/%d ---", i, len(entries))
        try:
            results.append(
                BatchResult(
                    entry, session_dir=run_session(cfg, entry, mode, force, run_dir=run_dir)
                )
            )
        except Exception as e:  # one failed row must not stop the batch
            logger.error("Failed to process '%s': %s", entry.session_name, e)
            logger.debug("Traceback of the failed row", exc_info=True)
            results.append(BatchResult(entry, error=str(e)))
    return results
