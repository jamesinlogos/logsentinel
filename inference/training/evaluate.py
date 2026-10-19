"""Evaluate Phase 2 coverage and the Phase 3 model on sentinelcap captures.

    python -m training.evaluate --captures ../sentinelcap/captures [--artifacts artifacts] \
        [--holdout RUN ...]

1. Indicator coverage: sessions (and families) where an indicator fired in at
   least one of the service's scheduled windows. Section 4.1 of inference/README.md counts whole
   sessions, so differences there come from the window length.
2. Cross-validation grouped by family (inference/README.md section 9.1, rule 6): one fold
   per ransomware family; goodware sessions are spread over the same folds,
   and every capture of one goodware sample stays in one fold. A fold's model
   is trained on the other folds only (as in ``training.train``); held-out
   sessions are replayed window by window.
3. Threshold: swept over the out-of-fold confidence of gated windows. The
   value with the best session-level F2 (ties: window-level MCC, then the
   higher threshold) goes to ``model-meta.json`` (with what it was chosen for)
   and ``evaluation.json``. It is tuned on the same outcomes the report shows,
   so the metrics are optimistic until checked on captures taken later; it is
   written only when the model in ``--artifacts`` was trained with the same
   settings.
4. Concurrent goodware (rule 9): every held-out ransomware session is scored
   again with a held-out goodware session of its fold running at the same
   time (``overlay``), with the same fold model.
5. Goodware alerts per hour of goodware capture: the detections the service
   would emit (after its suppression, ``EmissionPolicy``) and how many are
   labelled suspicious. Only as representative as the goodware captured.
6. Time to first detection: from the first event of a sample process to the
   end of the first window that reaches the threshold (event time; an early window
   ends at the event that brings the indicator, a scheduled one on its boundary,
   which the service emits at the next event or the idle flush).
7. Held-out runs (``--holdout``, inference/README.md section 9.1 rule 10): left out of 1-6
   and of the threshold, then scored session by session with the model in
   ``--artifacts`` at the chosen threshold, when that model was trained with the
   same settings and the same held-out runs. This is the only report that the
   threshold choice has not seen.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inference.artifacts import load_artifacts, threshold_basis
from inference.config import ServiceConfig, load_config
from inference.emission import EmissionPolicy
from inference.indicators import INDICATORS
from inference.model import (
    META_FILE,
    ArtifactError,
    GlobalModel,
    read_meta,
    write_meta,
)
from inference.pipeline import Emission, Pipeline
from training.sentinelcap_dataset import Session, overlay, window_label
from training.train import (
    SessionExamples,
    build_examples,
    fit_classifier,
    held_out_runs,
    load_sessions,
    training_rows,
)

THRESHOLDS = [i / 100 for i in range(101)]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Scores:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def f2(self) -> float:
        denominator = 5 * self.tp + 4 * self.fn + self.fp
        return 5 * self.tp / denominator if denominator else 0.0

    @property
    def mcc(self) -> float:
        tp, fp, tn, fn = self.tp, self.fp, self.tn, self.fn
        denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        return (tp * tn - fp * fn) / denominator if denominator else 0.0

    def report(self) -> dict[str, float | int]:
        return {
            **asdict(self),
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "f2": round(self.f2, 4),
            "mcc": round(self.mcc, 4),
        }


@dataclass(frozen=True)
class WindowOutcome:
    label: int | None
    confidence: float | None
    """None when the window did not pass the Phase 2 gate."""
    model_score: float
    """Global Model score, computed for every window (AUC)."""
    end: float
    fired: frozenset[str]


@dataclass(frozen=True)
class SessionOutcome:
    name: str
    fold: str
    label: int
    duration_sec: float
    windows: list[WindowOutcome]
    first_sample_ts: float | None = None

    @property
    def max_confidence(self) -> float | None:
        values = [w.confidence for w in self.windows if w.confidence is not None]
        return max(values) if values else None

    def detected(self, threshold: float) -> bool:
        best = self.max_confidence
        return best is not None and best >= threshold


def coverage(sessions: Sequence[SessionExamples]) -> dict[str, Any]:
    report: dict[str, Any] = {}
    for label, cls in ((1, "ransomware"), (0, "goodware")):
        group = [s for s in sessions if s.label == label]
        rows: dict[str, Any] = {}
        for name in (*INDICATORS, "gate"):
            hit = [
                s
                for s in group
                if any(
                    (w.result.gated if name == "gate" else name in w.result.fired)
                    for w in s.windows
                )
            ]
            rows[name] = {"sessions": len(hit), "families": len({s.family for s in hit})}
        report[cls] = {
            "sessions": len(group),
            "families": len({s.family for s in group}),
            "indicators": rows,
        }
    return report


def folds(sessions: Sequence[SessionExamples]) -> dict[str, list[SessionExamples]]:
    """One fold per ransomware family; goodware samples spread round-robin over them.

    All captures of one goodware sample (same hash, any run) go to the same fold,
    so a held-out session never has a copy of itself in the training folds.
    """
    families = sorted({s.family for s in sessions if s.label == 1})
    result: dict[str, list[SessionExamples]] = {f"family:{f}": [] for f in families}
    for session in sessions:
        if session.label == 1:
            result[f"family:{session.family}"].append(session)
    names = list(result) or ["goodware"]
    by_sample: dict[str, list[SessionExamples]] = {}
    for session in sorted(sessions, key=lambda s: s.session_path):
        if session.label == 0:
            by_sample.setdefault(session.sample_id, []).append(session)
    for index, sample_id in enumerate(sorted(by_sample)):
        result.setdefault(names[index % len(names)], []).extend(by_sample[sample_id])
    return result


def replay(
    session: Session, fold: str, model: GlobalModel, config: ServiceConfig
) -> SessionOutcome:
    """Score a session as the service does: events in order through the ``Pipeline``.

    Windows close on their boundary or early, at the event that brings a new indicator; the last
    pending window is closed at the end (``drain``). Confidence and model score are the rounded
    values the service writes. The threshold of the ``Pipeline`` is not used: the sweep below
    compares the confidence itself.
    """
    pipeline = Pipeline(config, model, threshold=0.5)
    emissions: list[Emission] = []
    for event in session.events:
        emissions.extend(pipeline.process(event, event.timestamp))
    emissions.extend(pipeline.drain())
    windows = []
    for emission in emissions:
        score = emission.score
        assert score.model_score is not None
        windows.append(
            WindowOutcome(
                window_label(session, emission.window),
                score.confidence_score,
                score.model_score,
                score.end,
                frozenset(score.indicators),
            )
        )
    return SessionOutcome(
        session.key, fold, session.label, session.duration_sec, windows, session.first_sample_ts
    )


def cross_validate(
    raw: Sequence[Session],
    sessions: Sequence[SessionExamples],
    config: ServiceConfig,
    max_windows: int,
    seed: int,
) -> tuple[list[SessionOutcome], list[tuple[SessionOutcome, SessionOutcome]]]:
    """Out-of-fold outcomes, and (alone, with concurrent goodware) pairs of ransomware sessions."""
    by_id = {s.session_path: s for s in raw}
    outcomes: list[SessionOutcome] = []
    concurrent: list[tuple[SessionOutcome, SessionOutcome]] = []
    for fold, held_out in folds(sessions).items():
        held = {s.session_path for s in held_out}
        train = [s for s in sessions if s.session_path not in held]
        rows = training_rows(train, max_windows, seed)
        if all(label == 1 for _, label in rows):
            raise SystemExit(f"Fold {fold}: no goodware outside it to train the model")
        model = GlobalModel(fit_classifier(rows, seed))
        scored = {s.key: replay(by_id[s.session_path], fold, model, config) for s in held_out}
        outcomes.extend(scored.values())
        partners = [by_id[s.session_path] for s in held_out if s.label == 0]
        ransomware = [s for s in held_out if s.label == 1] if partners else []
        for index, session in enumerate(ransomware):
            together = overlay(by_id[session.session_path], partners[index % len(partners)])
            concurrent.append((scored[session.key], replay(together, fold, model, config)))
        logger.info("Fold %s: %d held-out sessions", fold, len(held_out))
    return outcomes, concurrent


def window_scores(outcomes: Sequence[SessionOutcome], threshold: float) -> Scores:
    tp = fp = tn = fn = 0
    for outcome in outcomes:
        for w in outcome.windows:
            if w.label is None:
                continue
            predicted = w.confidence is not None and w.confidence >= threshold
            tp += predicted and w.label == 1
            fp += predicted and w.label == 0
            tn += not predicted and w.label == 0
            fn += not predicted and w.label == 1
    return Scores(tp, fp, tn, fn)


def session_scores(outcomes: Sequence[SessionOutcome], threshold: float) -> Scores:
    tp = fp = tn = fn = 0
    for outcome in outcomes:
        predicted = outcome.detected(threshold)
        tp += predicted and outcome.label == 1
        fp += predicted and outcome.label == 0
        tn += not predicted and outcome.label == 0
        fn += not predicted and outcome.label == 1
    return Scores(tp, fp, tn, fn)


def choose_threshold(outcomes: Sequence[SessionOutcome]) -> float:
    return max(
        THRESHOLDS,
        key=lambda t: (session_scores(outcomes, t).f2, window_scores(outcomes, t).mcc, t),
    )


def auc(pairs: Sequence[tuple[float, int]]) -> float | None:
    """ROC AUC (Mann-Whitney U, average ranks for ties); None without both classes."""
    ordered = sorted(pairs, key=lambda p: p[0])
    positives = sum(label for _, label in ordered)
    negatives = len(ordered) - positives
    if not positives or not negatives:
        return None
    rank_sum = 0.0
    start = 0
    while start < len(ordered):
        end = start
        while end + 1 < len(ordered) and ordered[end + 1][0] == ordered[start][0]:
            end += 1
        average_rank = (start + end) / 2 + 1
        rank_sum += average_rank * sum(label for _, label in ordered[start : end + 1])
        start = end + 1
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def model_auc(outcomes: Sequence[SessionOutcome]) -> float | None:
    return auc(
        [(w.model_score, w.label) for o in outcomes for w in o.windows if w.label is not None]
    )


def concurrency_report(
    pairs: Sequence[tuple[SessionOutcome, SessionOutcome]], threshold: float
) -> dict[str, Any]:
    def summary(outcomes: list[SessionOutcome]) -> dict[str, Any]:
        labelled = [w for o in outcomes for w in o.windows if w.label == 1]
        detected = [w for w in labelled if w.confidence is not None and w.confidence >= threshold]
        return {
            "gated_sessions": sum(o.max_confidence is not None for o in outcomes),
            "detected_sessions": sum(o.detected(threshold) for o in outcomes),
            "detected_windows": f"{len(detected)}/{len(labelled)}",
            "mean_model_score": (
                round(sum(w.model_score for w in labelled) / len(labelled), 4) if labelled else None
            ),
        }

    return {
        "sessions": len(pairs),
        "alone": summary([alone for alone, _ in pairs]),
        "with_goodware": summary([together for _, together in pairs]),
        "pairs": [together.name for _, together in pairs],
    }


def emitted_detections(
    outcome: SessionOutcome, threshold: float, config: ServiceConfig
) -> tuple[int, int]:
    """``(detections the service emits, how many are labelled suspicious)`` for one session."""
    policy = EmissionPolicy(config.scoring.reemit_after_sec, config.window.size_sec)
    emitted = suspicious = 0
    for w in outcome.windows:
        if w.confidence is None:
            continue
        flagged = w.confidence >= threshold
        if policy.allow("host", w.end, w.fired, flagged):
            emitted += 1
            suspicious += flagged
    return emitted, suspicious


def goodware_alert_rate(
    outcomes: Sequence[SessionOutcome], threshold: float, config: ServiceConfig
) -> dict[str, Any]:
    goodware = [o for o in outcomes if o.label == 0]
    hours = sum(o.duration_sec for o in goodware) / 3600
    flagged = sum(
        1
        for o in goodware
        for w in o.windows
        if w.confidence is not None and w.confidence >= threshold
    )
    counts = [emitted_detections(o, threshold, config) for o in goodware]
    detections = sum(c[0] for c in counts)
    suspicious = sum(c[1] for c in counts)

    def per_hour(count: int) -> float | None:
        return round(count / hours, 2) if hours else None

    return {
        "goodware_hours": round(hours, 2),
        "flagged_windows": flagged,
        "flagged_windows_per_hour": per_hour(flagged),
        "detections_after_suppression": detections,
        "detections_per_hour": per_hour(detections),
        "suspicious_detections": suspicious,
        "suspicious_detections_per_hour": per_hour(suspicious),
    }


def first_detection_delay(outcome: SessionOutcome, threshold: float) -> float | None:
    """Seconds from the first sample event to the end of the first window at the threshold."""
    if outcome.label != 1 or outcome.first_sample_ts is None:
        return None
    first = next(
        (w for w in outcome.windows if w.confidence is not None and w.confidence >= threshold),
        None,
    )
    return None if first is None else max(0.0, first.end - outcome.first_sample_ts)


def time_to_first_detection(outcomes: Sequence[SessionOutcome], threshold: float) -> dict[str, Any]:
    seconds = sorted(
        delay for o in outcomes if (delay := first_detection_delay(o, threshold)) is not None
    )
    if not seconds:
        return {"sessions": 0}
    return {
        "sessions": len(seconds),
        "median_sec": round(seconds[len(seconds) // 2], 1),
        "p90_sec": round(seconds[min(len(seconds) - 1, int(0.9 * len(seconds)))], 1),
        "max_sec": round(seconds[-1], 1),
    }


def meta_mismatches(
    meta: dict[str, Any],
    config: ServiceConfig,
    max_windows: int,
    seed: int,
    captures: Path,
    holdout: Sequence[str],
) -> list[str]:
    """Settings of this evaluation that differ from the run that trained the model in ``meta``."""
    expected = {
        "window": config.window.training_fields(),
        "seed": seed,
        "max_windows_per_session": max_windows,
        "captures": str(captures),
        "holdout": list(holdout),
    }
    return [name for name, value in expected.items() if not _recorded(meta.get(name), value)]


def _recorded(recorded: Any, expected: Any) -> bool:
    """A recorded dict agrees when it holds every expected key with the same value."""
    if isinstance(expected, dict):
        return isinstance(recorded, dict) and all(recorded.get(k) == v for k, v in expected.items())
    return bool(recorded == expected)


def held_out_report(
    sessions: Sequence[Session],
    artifacts_dir: Path,
    config: ServiceConfig,
    threshold: float,
    mismatches: list[str] | None,
) -> dict[str, Any]:
    """The held-out sessions scored by the trained model at ``threshold`` (rule 10)."""
    if mismatches is None:
        return {"skipped": f"no trained model in {artifacts_dir}"}
    if mismatches:
        return {
            "skipped": f"the model in {artifacts_dir} was trained with other "
            f"{', '.join(mismatches)}"
        }
    try:
        artifacts = load_artifacts(artifacts_dir, config.window)
    except ArtifactError as exc:
        return {"skipped": str(exc)}
    outcomes = [replay(s, "held_out", artifacts.model, config) for s in sessions]
    ransomware = [o for o in outcomes if o.label == 1]
    goodware = [o for o in outcomes if o.label == 0]
    return {
        "model_version": artifacts.model.version,
        "threshold": threshold,
        "ransomware": {
            "sessions": len(ransomware),
            "detected": sum(o.detected(threshold) for o in ransomware),
            "time_to_first_detection": time_to_first_detection(ransomware, threshold),
        },
        "goodware": goodware_alert_rate(goodware, threshold, config) if goodware else None,
        "sessions": [
            {
                "name": o.name,
                "label": o.label,
                "max_confidence": (
                    round(o.max_confidence, 4) if o.max_confidence is not None else None
                ),
                "detected": o.detected(threshold),
                "first_detection_sec": (
                    round(delay, 1)
                    if (delay := first_detection_delay(o, threshold)) is not None
                    else None
                ),
            }
            for o in outcomes
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate indicators and the Global Model.")
    parser.add_argument("--captures", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--max-windows", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-write", action="store_true", help="only print the report")
    parser.add_argument(
        "--holdout",
        action="append",
        default=[],
        metavar="RUN",
        help="capture run kept out of training and threshold selection (repeatable)",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    config = load_config(args.config)
    runs = held_out_runs(args.captures, args.holdout)
    raw, held = load_sessions(args.captures, runs)
    sessions = [build_examples(s, config.window) for s in raw]
    outcomes, concurrent = cross_validate(raw, sessions, config, args.max_windows, args.seed)
    threshold = choose_threshold(outcomes)
    auc_value = model_auc(outcomes)
    report = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "captures": str(args.captures),
        "holdout": runs,
        "window": config.window.model_dump(),
        "scoring": config.scoring.model_dump(),
        "coverage": coverage(sessions),
        "threshold": threshold,
        "threshold_selection": "tuned on the same out-of-fold outcomes reported below",
        "cross_validation": {
            "model_auc": round(auc_value, 4) if auc_value is not None else None,
            "gate_only": {
                "window": window_scores(outcomes, 0.0).report(),
                "session": session_scores(outcomes, 0.0).report(),
            },
            "at_threshold": {
                "window": window_scores(outcomes, threshold).report(),
                "session": session_scores(outcomes, threshold).report(),
            },
            "missed_ransomware": [
                o.name for o in outcomes if o.label == 1 and not o.detected(threshold)
            ],
            "flagged_goodware": [
                o.name for o in outcomes if o.label == 0 and o.detected(threshold)
            ],
            "goodware_alerts": goodware_alert_rate(outcomes, threshold, config),
            "time_to_first_detection": time_to_first_detection(outcomes, threshold),
            "concurrent_goodware": concurrency_report(concurrent, threshold),
        },
    }
    meta = read_meta(args.artifacts) if (args.artifacts / META_FILE).is_file() else None
    mismatches = (
        meta_mismatches(meta, config, args.max_windows, args.seed, args.captures, runs)
        if meta is not None
        else None
    )
    if held:
        report["held_out"] = held_out_report(held, args.artifacts, config, threshold, mismatches)
    print(json.dumps(report, indent=2))
    if args.no_write:
        return 0
    args.artifacts.mkdir(parents=True, exist_ok=True)
    (args.artifacts / "evaluation.json").write_text(json.dumps(report, indent=2), "utf-8")
    if meta is None or mismatches is None:
        logger.warning("No %s in %s: run training.train first", META_FILE, args.artifacts)
        return 0
    if mismatches:
        logger.error(
            "Threshold not written: the model in %s was trained with other %s. "
            "Run training.train and training.evaluate with the same settings.",
            args.artifacts,
            ", ".join(mismatches),
        )
        return 1
    meta["threshold"] = threshold
    meta["threshold_basis"] = {
        **threshold_basis(config),
        "evaluated_at": report["generated_at"],
        "seed": args.seed,
        "max_windows_per_session": args.max_windows,
    }
    write_meta(args.artifacts, meta)
    logger.info("Threshold %.2f written to %s", threshold, args.artifacts / META_FILE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
