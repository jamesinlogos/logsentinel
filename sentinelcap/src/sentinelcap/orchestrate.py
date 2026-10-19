"""Collection pipelines: revert -> start -> (execute | interactive) -> export.

The tool never launches a sample. In ``--execute`` the operator double-clicks the
executable in the VM; in ``--interactive`` the operator performs the scenario
between two Enter presses.
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
from sentinelcap.manifest import ManifestEntry, Mode
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
    """``--execute`` only."""
    sample_entity_ids: list[str] | None = None
    """``--execute`` only."""
    scenario: str | None = None
    """``--interactive`` only."""
    clock_offset_sec: float = 0.0


def new_run_dir(cfg: SentinelcapConfig) -> Path:
    """``<capture.out_dir>/<YYYYMMDDTHHMMSSZ>``: one directory per collection run (UTC)."""
    return Path(cfg.capture.out_dir) / run_stamp(datetime.now(timezone.utc))


def _guest_sample_path(entry: ManifestEntry) -> str:
    if entry.path is None:
        raise SentinelcapError(
            f"{entry.session_name}: --execute needs the guest path of the sample"
        )
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


def run_session(
    cfg: SentinelcapConfig,
    entry: ManifestEntry,
    mode: Mode,
    force: bool = False,
    run_dir: Path | None = None,
) -> Path:
    """Collect one session into ``<run_dir>/<family>/<sample>`` and return that directory.

    ``run_dir`` defaults to a new ``<capture.out_dir>/<UTC timestamp>``.
    """
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

    A failed row is recorded and the batch continues.
    """
    run_dir = new_run_dir(cfg)
    logger.info("Run directory: %s", run_dir)
    results: list[BatchResult] = []
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
