"""Train the Global Model from sentinelcap captures.

    python -m training.train --captures ../sentinelcap/captures [--artifacts artifacts] \
        [--holdout RUN ...]

Windows, indicators and features come from the service code (``inference``),
so training sees exactly what the service computes. Rules of inference/README.md
section 9.1: labels as in ``training.sentinelcap_dataset``; at most ``--max-windows``
labelled windows per session so every session weighs about the same (rule 5).
All training windows are shuffled: the data is stationary, so the model is
trained on an i.i.d. stream (inference/README.md section 5.1). Windows with concurrent
goodware are only used by ``training.evaluate`` (rule 9). Sessions of a
``--holdout`` run are left out (rule 10): they are the independent check that
``training.evaluate`` scores at the end. Run
``training.evaluate`` afterwards: it picks the threshold and stores it in
``model-meta.json``.
"""

from __future__ import annotations

import argparse
import logging
import random
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from inference.config import WindowConfig, load_config
from inference.features import compute
from inference.indicators import IndicatorResult, evaluate
from inference.model import Classifier, new_classifier, save
from training.sentinelcap_dataset import Session, iter_sessions, session_windows, window_label

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WindowExample:
    features: dict[str, float]
    result: IndicatorResult
    label: int | None
    """None: not used for training (ransomware window without a sample event)."""
    end: float
    """End of the window in event time (epoch seconds)."""


@dataclass
class SessionExamples:
    session_path: str
    name: str
    family: str
    sample_id: str
    label: int
    events_dropped: bool
    duration_sec: float
    windows: list[WindowExample]
    first_sample_ts: float | None = None
    """Event time of the first event of a tracked sample process (ransomware sessions)."""
    partner: str | None = None
    """Goodware session overlaid on this ransomware session, if any."""

    @property
    def key(self) -> str:
        """Unique within a run of train/evaluate, also for a session captured in several runs."""
        return f"{self.session_path}+{self.partner}" if self.partner else self.session_path


def build_examples(session: Session, config: WindowConfig) -> SessionExamples:
    windows = []
    for window in session_windows(session, config):
        summary = window.summary
        result = evaluate(summary)
        windows.append(
            WindowExample(
                compute(summary, result), result, window_label(session, window), window.end
            )
        )
    return SessionExamples(
        session_path=session.session_path,
        name=session.name,
        family=session.family,
        sample_id=session.sample_id,
        label=session.label,
        events_dropped=session.events_dropped,
        duration_sec=session.duration_sec,
        windows=windows,
        first_sample_ts=session.first_sample_ts,
        partner=session.partner,
    )


def held_out_runs(captures: Path, holdout: Sequence[str]) -> list[str]:
    """Names of the held-out runs; one that is not a run directory stops the program.

    A typo must not send the reference sessions into training.
    """
    runs = sorted({Path(run).name for run in holdout})
    missing = [run for run in runs if not run or not (captures / run).is_dir()]
    if missing:
        raise SystemExit(f"Held-out run not found under {captures}: {', '.join(missing)}")
    return runs


def load_sessions(
    captures: Path, holdout: Sequence[str] = ()
) -> tuple[list[Session], list[Session]]:
    """``(sessions to train and evaluate on, sessions of the held-out runs)``.

    A sample of a held-out run that another run captured again stops the program: trained
    on, it would no longer be an independent check.
    """
    runs = set(held_out_runs(captures, holdout))
    used: list[Session] = []
    held: list[Session] = []
    for session in iter_sessions(captures):
        (held if session.session_path.split("/", 1)[0] in runs else used).append(session)
    if not used:
        raise SystemExit(f"No sentinelcap session found under {captures}")
    held_samples = {s.sample_id for s in held}
    again = {s.session_path.split("/", 1)[0] for s in used if s.sample_id in held_samples}
    if again:
        raise SystemExit(
            f"Run(s) {', '.join(sorted(again))} hold samples of the held-out runs: "
            "add them to --holdout so no reference sample is trained on"
        )
    return used, held


def training_rows(
    sessions: Sequence[SessionExamples], max_windows: int, seed: int
) -> list[tuple[dict[str, float], int]]:
    rows: list[tuple[dict[str, float], int]] = []
    for session in sorted(sessions, key=lambda s: s.key):
        labelled = [(w.features, w.label) for w in session.windows if w.label is not None]
        if len(labelled) > max_windows:
            picker = random.Random(f"{seed}:{session.key}")
            labelled = [labelled[i] for i in picker.sample(range(len(labelled)), max_windows)]
        rows.extend(labelled)
    random.Random(seed).shuffle(rows)
    return rows


def fit_classifier(rows: Sequence[tuple[dict[str, float], int]], seed: int) -> Classifier:
    classifier = new_classifier(seed)
    for features, label in rows:
        classifier.learn_one(features, label)
    return classifier


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the Global Model.")
    parser.add_argument("--captures", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--max-windows", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
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
    used, held = load_sessions(args.captures, args.holdout)
    if held:
        logger.info("%d sessions of held-out runs left out of training", len(held))
    sessions = [build_examples(s, config.window) for s in used]
    rows = training_rows(sessions, args.max_windows, args.seed)
    if {label for _, label in rows} != {0, 1}:
        raise SystemExit("The model needs training windows of ransomware and of goodware sessions")
    classifier = fit_classifier(rows, args.seed)
    positives = sum(label == 1 for _, label in rows)
    trained_at = datetime.now(UTC)
    version = trained_at.strftime("%Y%m%dT%H%M%SZ")
    meta = {
        "version": version,
        "trained_at": trained_at.isoformat(timespec="seconds"),
        "captures": str(args.captures),
        "holdout": held_out_runs(args.captures, args.holdout),
        "seed": args.seed,
        "max_windows_per_session": args.max_windows,
        "window": config.window.training_fields(),
        "sessions": {
            "ransomware": sum(s.label == 1 for s in sessions),
            "goodware": sum(s.label == 0 for s in sessions),
            "events_dropped": [s.name for s in sessions if s.events_dropped],
        },
        "training_windows": {
            "ransomware": positives,
            "goodware": len(rows) - positives,
            "unlabelled_skipped": sum(w.label is None for s in sessions for w in s.windows),
        },
        "threshold": None,
    }
    save(args.artifacts, classifier, meta)
    logger.info(
        "Model %s: %d sessions, %d training windows (%d ransomware)",
        version,
        len(sessions),
        len(rows),
        positives,
    )
    logger.info("Next: training.evaluate with the same --captures and --holdout")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
