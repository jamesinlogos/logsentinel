"""The detection pipeline without Kafka (inference/README.md sections 2-7).

``Pipeline`` reads no clock (the caller passes ``now``) and talks to no broker: events in,
:class:`Emission` objects out. ``service.py`` moves messages between Kafka and the pipeline;
``training.evaluate`` replays sessions through the same scoring code.

Per window the phases run in order: windowing and counting (``windowing.py``, ``summary.py``),
rules (``indicators.py``), features (``features.py``), scores (``model.py``, ``scoring.py``) and
the decision whether the window is reported (``emission.py``). A window closes on its boundary
or, earlier, at the event that brings a new indicator (``trigger.py``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from inference.config import ServiceConfig
from inference.emission import EmissionPolicy
from inference.events import Event
from inference.features import compute
from inference.indicators import evaluate, fired
from inference.logs import Action, Throttle, ecs
from inference.model import GlobalModel
from inference.scoring import WindowScore, score_window
from inference.trigger import EarlyClose
from inference.windowing import INDICATOR, Window, Windower, format_timestamp

logger = logging.getLogger(__name__)


@dataclass
class Stats:
    consumed: int = 0
    invalid: int = 0
    consumer_errors: int = 0
    windows: int = 0
    early_windows: int = 0
    """Windows closed before their boundary, at the event that brought a new indicator."""
    gated: int = 0
    suppressed: int = 0
    detections: int = 0
    produced: int = 0
    acked: int = 0
    delivery_errors: int = 0
    sysmon_dropped: int = 0
    """Events Sysmon reported as dropped from its driver queue (Event 255 QUEUE)."""
    internal_errors: int = 0
    """Windows that could not be scored (a bug): counted and skipped, the service keeps running."""


@dataclass(frozen=True)
class Emission:
    score: WindowScore
    reported: bool
    """Also sent as a detection: it passed the gate and the suppression of ``EmissionPolicy``."""
    offsets: dict[int, int]
    """Oldest input offset per partition among the window's events: a replay re-reads from here."""
    window: Window
    """The window that was scored (the service does not use it; the evaluation labels it)."""


def window_offsets(window: Window) -> dict[int, int]:
    """Oldest input offset per partition among the events of ``window``."""
    oldest: dict[int, int] = {}
    for event in window.events:
        if event.partition is not None and event.offset is not None:
            known = oldest.get(event.partition)
            if known is None or event.offset < known:
                oldest[event.partition] = event.offset
    return oldest


class Pipeline:
    def __init__(
        self,
        config: ServiceConfig,
        model: GlobalModel | None,
        threshold: float,
    ) -> None:
        self.config = config
        self.model = model
        self.threshold = threshold
        window = config.window
        self.windower = Windower(
            window.size_sec, window.slide_sec, window.max_events_per_host, window.late_reset_events
        )
        self.stats = Stats()
        self._policy = EmissionPolicy(config.scoring.reemit_after_sec, window.size_sec)
        self._early = EarlyClose()
        self._last_seen: dict[str, float] = {}
        self._throttle = Throttle(config.stats_interval_sec)
        self._resets = 0
        self._overflow = 0

    def process(self, event: Event, now: float) -> list[Emission]:
        """Feed one event; ``now`` is the receiving host's monotonic clock."""
        self._last_seen[event.host_id] = now
        if event.drops:
            self.stats.sysmon_dropped += sum(count for _, count in event.drops)
            if self._throttle.ready(f"sysmon-drops:{event.host_id}", now):
                logger.warning(
                    "Sysmon on host %s dropped events: %.200r",
                    event.host_id,
                    event.sysmon_error_detail,
                    extra=ecs({"logsentinel.monitored_host.id": event.host_id}),
                )
        resets = self.windower.clock_resets
        windows = self.windower.add(event)
        if self.windower.clock_resets != resets:
            self._early.forget(event.host_id)  # its window state started again
        self._report_anomalies(event.host_id, now)
        emissions = self._emit(windows, now)
        emissions.extend(self._close_early(event, now))
        return emissions

    def tick(self, now: float) -> list[Emission]:
        """Close the window of hosts that went quiet; forget hosts silent for long."""
        windows: list[Window] = []
        evict: list[str] = []
        for host_id, seen in self._last_seen.items():
            idle = now - seen
            if idle >= self.config.window.idle_flush_sec:
                window = self.windower.flush(host_id)
                if window is not None:
                    windows.append(window)
            if idle >= self.config.window.host_evict_sec:
                evict.append(host_id)
        emissions = self._emit(windows, now)
        for host_id in evict:
            self.windower.drop(host_id)
            del self._last_seen[host_id]
            self._policy.forget(host_id)
            self._early.forget(host_id)
        return emissions

    def drain(self) -> list[Emission]:
        """Close every pending window (shutdown, end of a replayed session)."""
        windows = [self.windower.flush(host_id) for host_id in self.windower.hosts()]
        return self._emit([w for w in windows if w is not None], None)

    def _close_early(self, event: Event, now: float) -> list[Emission]:
        """The host's trailing window as a window, if ``event`` made a new indicator fire in it."""
        trailing = self.windower.trailing(event.host_id)
        if trailing is None or not self._early.due(event.host_id, fired(trailing.summary)):
            return []
        return self._emit([self.windower.close_early(event.host_id, event)], now)

    def _emit(self, windows: list[Window], now: float | None) -> list[Emission]:
        """One emission per scored window; ``reported`` marks the ones that are detections.

        A window that cannot be scored is counted and skipped (``Stats.internal_errors``): stopping
        the service would only make Docker restart it, and the replay would meet the same window
        again, so one odd event could silence every host. ``now`` is the receiving host's
        monotonic clock for the log throttle (``None`` at shutdown: always log).
        """
        emissions = []
        for window in windows:
            try:
                score = self._score(window)
            except Exception:  # noqa: BLE001 - a bug on one window must not stop all detection
                self._window_failed(window, now)
                continue
            reported = False
            if score.gated:
                if self._policy.allow(
                    window.host_id, window.end, frozenset(score.indicators), score.suspicious
                ):
                    reported = True
                    self.stats.detections += 1
                else:
                    self.stats.suppressed += 1
            emissions.append(Emission(score, reported, window_offsets(window), window))
            if logger.isEnabledFor(logging.DEBUG):
                self._trace(score, reported)
        return emissions

    def _score(self, window: Window) -> WindowScore:
        summary = window.summary
        result = evaluate(summary)
        features = compute(summary, result)
        # Every window gets a model score so that a human can see what the model thought of a
        # window the gate held back; only a gated window uses it for its confidence.
        model_score = self.model.score(features) if self.model is not None else None
        score = score_window(
            window,
            result,
            features,
            model_score,
            scoring=self.config.scoring,
            threshold=self.threshold,
            model=self.model,
        )
        # Counted only now: a window that raised above is an internal error, not a scored window.
        self.stats.windows += 1
        if window.trigger == INDICATOR:
            self.stats.early_windows += 1
        if result.gated:
            self.stats.gated += 1
        return score

    def _window_failed(self, window: Window, now: float | None) -> None:
        """Count a window that raised while being scored and log it (from an ``except`` block)."""
        self.stats.internal_errors += 1
        if now is not None and not self._throttle.ready("window-error", now):
            return
        logger.error(
            "Cannot score the window of host %s ending %s (%d events): skipped, %d so far",
            window.host_name or window.host_id,
            format_timestamp(window.end),
            len(window.events),
            self.stats.internal_errors,
            exc_info=True,
            extra=ecs(
                {
                    "event.action": Action.SCORING_ERROR,
                    "logsentinel.monitored_host.id": window.host_id,
                    "event.end": format_timestamp(window.end),
                    "logsentinel.stats.internal_errors": self.stats.internal_errors,
                }
            ),
        )

    def _trace(self, score: WindowScore, reported: bool) -> None:
        """DEBUG: one record per scored window."""
        if not score.gated:
            verdict = "not gated"
        else:
            verdict = f"gated, confidence {score.confidence_score}, {score.label}"
            verdict += ", reported" if reported else ", suppressed"
        fields: dict[str, Any] = {
            "logsentinel.monitored_host.id": score.host_id,
            "logsentinel.monitored_host.name": score.host_name,
            "logsentinel.window.id": score.window_id,
            "logsentinel.window.trigger": score.trigger,
            "logsentinel.window.activity.events": score.activity["events"],
            "logsentinel.verdict.gated": score.gated,
            "logsentinel.verdict.suspicious": score.suspicious,
            "logsentinel.verdict.reported": reported,
            "logsentinel.verdict.indicators": score.indicators,
        }
        if score.confidence_score is not None:
            fields["logsentinel.verdict.confidence_score"] = score.confidence_score
        logger.debug(
            "Window %.12s of host %s: %d events, %s",
            score.window_id,
            score.host_name or score.host_id,
            score.activity["events"],
            verdict,
            extra=ecs(fields),
        )

    def _report_anomalies(self, host_id: str, now: float) -> None:
        resets = self.windower.clock_resets
        if resets != self._resets:
            self._resets = resets
            logger.warning(
                "Host %s sent %d events in a row older than its window: following its new clock "
                "(%d such resets so far)",
                host_id,
                self.config.window.late_reset_events,
                resets,
                extra=ecs(
                    {
                        "logsentinel.monitored_host.id": host_id,
                        "logsentinel.stats.clock_resets": resets,
                    }
                ),
            )
        overflow = self.windower.overflow_events
        if overflow != self._overflow:
            self._overflow = overflow
            if self._throttle.ready("overflow", now):
                logger.warning(
                    "Window buffer full (max_events_per_host=%d): %d events pushed out so far, "
                    "windows of busy hosts are incomplete",
                    self.config.window.max_events_per_host,
                    overflow,
                    extra=ecs({"logsentinel.stats.overflow_events": overflow}),
                )
