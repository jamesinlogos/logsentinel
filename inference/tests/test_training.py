"""Loader rules (inference/README.md section 9.1), training artifacts and evaluation."""

from __future__ import annotations

import dataclasses
import json
import re
import shutil
from pathlib import Path

import pytest
from river import forest

from inference.artifacts import load_artifacts, resolve_threshold
from inference.config import ServiceConfig, WindowConfig, load_config
from inference.model import (
    ArtifactError,
    load,
    new_classifier,
    read_meta,
    save,
    write_meta,
)
from training import evaluate, train
from training.evaluate import (
    Scores,
    SessionOutcome,
    WindowOutcome,
    auc,
    choose_threshold,
    concurrency_report,
    cross_validate,
    emitted_detections,
    folds,
    goodware_alert_rate,
    meta_mismatches,
    model_auc,
    session_scores,
    time_to_first_detection,
)
from training.sentinelcap_dataset import (
    Session,
    iter_sessions,
    load_session,
    overlay,
    session_windows,
    window_label,
)
from training.train import (
    SessionExamples,
    build_examples,
    fit_classifier,
    held_out_runs,
    load_sessions,
    training_rows,
)

SESSIONS_DIR = Path(__file__).parent / "fixtures" / "sessions"
# A second goodware sample (a copy of the fixtures' only one): a fold's model is trained on the
# goodware outside the fold, so every fold of a cross-validation needs some.
SECOND_GOODWARE = "f" * 64


@pytest.fixture(scope="module")
def examples(sessions: dict[str, Session]) -> list[SessionExamples]:
    return [build_examples(session, WindowConfig()) for session in sessions.values()]


def test_sessions_carry_label_and_sample_processes(sessions: dict[str, Session]) -> None:
    assert {s.label for s in sessions.values()} == {0, 1}
    assert all(s.sample_ids for s in sessions.values())
    assert all(s.duration_sec > 0 for s in sessions.values())
    assert not any(s.events_dropped for s in sessions.values())


def test_a_session_of_another_format_is_an_error(
    sessions: dict[str, Session], tmp_path: Path
) -> None:
    source = sessions["conti/b14cde37"].directory
    target = tmp_path / "conti" / source.name
    shutil.copytree(source, target)
    meta = json.loads((target / "metadata.json").read_text(encoding="utf-8"))
    meta["format"] = "logsentinel.normalized-sysmon.jsonl/v0"
    (target / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(ValueError, match="expected logsentinel.normalized-sysmon.jsonl/v1"):
        load_session(target)


def test_an_export_that_did_not_finish_is_not_a_session(
    sessions: dict[str, Session], tmp_path: Path
) -> None:
    """sentinelcap writes ``.<sample>.partial`` and ``.<sample>.old``: loaders skip them."""
    source = sessions["conti/b14cde37"].directory
    family = tmp_path / "20261001T000000Z" / "conti"
    shutil.copytree(source, family / source.name)
    shutil.copytree(source, family / f".{source.name}.partial")
    shutil.copytree(source, family / f".{source.name}.old")
    assert [s.sample_id for s in iter_sessions(tmp_path)] == [source.name]


def test_a_sample_captured_in_two_runs_stays_two_sessions(
    sessions: dict[str, Session], tmp_path: Path
) -> None:
    source = sessions["conti/b14cde37"].directory
    for run in ("20261001-a", "20261002-b"):
        shutil.copytree(source, tmp_path / run / "conti" / source.name)
    loaded = list(iter_sessions(tmp_path))
    assert len(loaded) == 2
    assert len({s.session_path for s in loaded}) == 2
    assert {s.session_path.split("/")[0] for s in loaded} == {"20261001-a", "20261002-b"}
    assert {s.name for s in loaded} == {"conti/b14cde37"}  # the short label is for display only
    examples = [build_examples(s, WindowConfig()) for s in loaded]
    assert len({e.key for e in examples}) == 2


def test_ransomware_windows_without_sample_events_are_not_labelled(
    sessions: dict[str, Session],
) -> None:
    lockbit = sessions["lockbit/032690f1"]
    labels = [window_label(lockbit, w) for w in session_windows(lockbit, WindowConfig())]
    assert 1 in labels and None in labels
    goodware = sessions["goodware/9923a8b2"]
    assert {window_label(goodware, w) for w in session_windows(goodware, WindowConfig())} == {0}


def test_overlay_runs_goodware_alongside_ransomware(sessions: dict[str, Session]) -> None:
    conti, keepass = sessions["conti/b14cde37"], sessions["goodware/9923a8b2"]
    together = overlay(conti, keepass)
    assert len(together.events) == len(conti.events) + len(keepass.events)
    assert [e.timestamp for e in together.events] == sorted(e.timestamp for e in together.events)
    assert together.events[0].timestamp == conti.events[0].timestamp
    assert together.sample_ids == conti.sample_ids
    assert together.label == 1
    assert together.partner == "goodware/9923a8b2"
    assert together.session_path == conti.session_path
    labels = {window_label(together, w) for w in session_windows(together, WindowConfig())}
    assert 1 in labels
    with pytest.raises(ValueError):
        overlay(keepass, conti)


def test_training_rows_are_capped_and_shuffled(examples: list[SessionExamples]) -> None:
    rows = training_rows(examples, max_windows=2, seed=1)
    assert len(rows) <= 2 * len(examples)
    assert {label for _, label in rows} == {0, 1}
    assert rows == training_rows(examples, max_windows=2, seed=1)
    in_session_order = [
        (w.features, w.label) for s in sorted(examples, key=lambda s: s.key) for w in s.windows
    ]
    labelled = [r for r in in_session_order if r[1] is not None]
    all_rows = training_rows(examples, max_windows=1000, seed=1)
    assert sorted(map(str, all_rows)) == sorted(map(str, labelled))
    assert all_rows != labelled


def test_classifier_runs_without_drift_detection(examples: list[SessionExamples]) -> None:
    classifier = fit_classifier(training_rows(examples, 30, seed=1), seed=1)
    assert isinstance(classifier, forest.ARFClassifier)
    assert classifier.n_drifts_detected() == 0
    assert classifier.n_warnings_detected() == 0


def test_model_round_trip(examples: list[SessionExamples], tmp_path: Path) -> None:
    classifier = fit_classifier(training_rows(examples, 30, seed=1), seed=1)
    window = WindowConfig()
    save(tmp_path, classifier, {"version": "test", "threshold": 0.6, "window": window.model_dump()})
    model = load(tmp_path, window)
    assert model.threshold == 0.6
    assert model.version == "test"
    gated = next(w for s in examples for w in s.windows if w.result.gated)
    assert 0.0 <= model.score(gated.features) <= 1.0


def test_model_with_other_features_is_refused(tmp_path: Path) -> None:
    save(tmp_path, new_classifier(1), {"version": "t", "window": WindowConfig().model_dump()})
    meta = read_meta(tmp_path)
    meta["feature_names"] = meta["feature_names"][:-1]
    write_meta(tmp_path, meta)
    with pytest.raises(ArtifactError, match="other features"):
        load(tmp_path, WindowConfig())


def test_missing_model_is_an_artifact_error(tmp_path: Path) -> None:
    with pytest.raises(ArtifactError, match="no trained model"):
        load(tmp_path, WindowConfig())


def test_folds_hold_one_family_each(examples: list[SessionExamples]) -> None:
    grouped = folds(examples)
    for name, members in grouped.items():
        assert {s.family for s in members if s.label == 1} == {name.removeprefix("family:")}
    assert sorted(s.key for m in grouped.values() for s in m) == sorted(s.key for s in examples)


def test_captures_of_one_goodware_sample_share_a_fold(examples: list[SessionExamples]) -> None:
    import dataclasses

    keepass = next(s for s in examples if s.label == 0)
    copies = [
        dataclasses.replace(keepass, session_path=f"run{n}/{keepass.session_path}")
        for n in range(3)
    ]
    other = dataclasses.replace(keepass, session_path="x", sample_id="0" * 64)
    ransomware = [s for s in examples if s.label == 1]
    grouped = folds([*ransomware, *copies, other])
    homes = {name for name, members in grouped.items() for s in members if s in copies}
    assert len(homes) == 1


def second_goodware_sample(goodware: Session) -> Session:
    return dataclasses.replace(
        goodware,
        directory=goodware.directory.parent / SECOND_GOODWARE,
        session_path=goodware.session_path.replace(goodware.sample_id, SECOND_GOODWARE),
        sample_id=SECOND_GOODWARE,
    )


def fixture_corpus(parent: Path) -> Path:
    """The fixture sessions with a second goodware sample, as a captures directory."""
    root = parent / "captures"
    shutil.copytree(SESSIONS_DIR, root)
    [first] = (root / "goodware").iterdir()
    shutil.copytree(first, first.parent / SECOND_GOODWARE)
    return root


def test_cross_validation_needs_goodware_outside_every_fold(
    sessions: dict[str, Session], examples: list[SessionExamples]
) -> None:
    # The fixtures have one goodware sample; its fold (akira) is left with none to fit on.
    with pytest.raises(SystemExit, match="Fold family:akira: no goodware outside it"):
        cross_validate(list(sessions.values()), examples, ServiceConfig(), 30, seed=1)


def test_cross_validation_on_fixtures(
    sessions: dict[str, Session], examples: list[SessionExamples]
) -> None:
    twin = second_goodware_sample(sessions["goodware/9923a8b2"])
    window = WindowConfig()
    corpus = [*examples, build_examples(twin, window)]
    outcomes, concurrent = cross_validate(
        [*sessions.values(), twin], corpus, ServiceConfig(), 30, seed=1
    )
    assert sorted(o.name for o in outcomes) == sorted(s.key for s in corpus)
    gate_only = session_scores(outcomes, 0.0)
    # Phase 2 alone: Akira, Conti, BlackBasta, Medusa pass the gate; LockBit 032690f1 does not.
    assert (gate_only.tp, gate_only.fn, gate_only.fp, gate_only.tn) == (4, 1, 0, 2)
    threshold = choose_threshold(outcomes)
    assert 0.0 <= threshold <= 1.0
    # The goodware samples are held out with the first two families (akira, blackbasta).
    assert [together.name for _, together in concurrent] == [
        f"{sessions['akira/c974d8c6'].session_path}+{sessions['goodware/9923a8b2'].name}",
        f"{sessions['blackbasta/11129aad'].session_path}+{twin.name}",
    ]
    report = concurrency_report(concurrent, threshold)
    assert report["alone"]["gated_sessions"] == report["with_goodware"]["gated_sessions"] == 2
    assert model_auc(outcomes) is not None
    rate = goodware_alert_rate(outcomes, threshold, ServiceConfig())
    assert rate["goodware_hours"] > 0
    assert rate["flagged_windows"] == rate["detections_after_suppression"] == 0
    ttfd = time_to_first_detection(outcomes, threshold)
    assert ttfd["sessions"] == session_scores(outcomes, threshold).tp  # every detected session
    assert 0 <= ttfd["median_sec"] <= ttfd["max_sec"]


def _window(end: float, confidence: float | None, *fired: str) -> WindowOutcome:
    return WindowOutcome(None, confidence, 0.5, end, frozenset(fired))


def test_alerts_are_counted_after_the_service_suppression() -> None:
    windows = [
        _window(100, 0.9, "shadow_copy_deletion"),
        _window(110, 0.9, "shadow_copy_deletion"),  # nothing new within the pause: suppressed
        _window(120, 0.2, "mass_note_drop"),  # new indicator: emitted, below the threshold
        _window(130, None),  # not gated: never a detection
        _window(300, 0.9, "mass_note_drop"),  # after the pause: emitted again
    ]
    outcome = SessionOutcome("s", "f", 0, 3600.0, windows)
    assert emitted_detections(outcome, 0.5, ServiceConfig()) == (3, 2)
    rate = goodware_alert_rate([outcome], 0.5, ServiceConfig())
    assert rate["flagged_windows"] == 3
    assert rate["detections_after_suppression"] == 3
    assert rate["detections_per_hour"] == 3.0
    assert rate["suspicious_detections_per_hour"] == 2.0


def test_time_to_first_detection() -> None:
    fast = SessionOutcome("a", "f", 1, 100, [_window(160, 0.9)], first_sample_ts=100.0)
    slow = SessionOutcome("b", "f", 1, 100, [_window(160, 0.1), _window(200, 0.8)], 100.0)
    missed = SessionOutcome("c", "f", 1, 100, [_window(160, 0.1)], 100.0)
    unknown = SessionOutcome("d", "f", 1, 100, [_window(160, 0.9)], None)
    result = time_to_first_detection([fast, slow, missed, unknown], 0.5)
    assert result == {"sessions": 2, "median_sec": 100.0, "p90_sec": 100.0, "max_sec": 100.0}
    assert time_to_first_detection([missed], 0.5) == {"sessions": 0}


def test_auc() -> None:
    assert auc([(0.1, 0), (0.9, 1)]) == 1.0
    assert auc([(0.9, 0), (0.1, 1)]) == 0.0
    assert auc([(0.5, 0), (0.5, 1)]) == 0.5
    assert auc([(0.5, 1)]) is None


def test_scores() -> None:
    scores = Scores(tp=8, fp=2, tn=5, fn=1)
    assert scores.recall == pytest.approx(8 / 9)
    assert scores.precision == pytest.approx(0.8)
    assert scores.f2 == pytest.approx(40 / 46)
    assert scores.mcc == pytest.approx((8 * 5 - 2 * 1) / (10 * 9 * 7 * 6) ** 0.5)
    assert Scores(0, 0, 0, 0).mcc == 0.0


def test_meta_mismatches_name_the_settings_that_differ(tmp_path: Path) -> None:
    config = ServiceConfig()
    meta = {
        "window": config.window.model_dump(),
        "seed": 42,
        "max_windows_per_session": 30,
        "captures": "c",
        "holdout": ["r2"],
    }
    assert meta_mismatches(meta, config, 30, 42, Path("c"), ["r2"]) == []
    assert meta_mismatches(meta, config, 20, 7, Path("c"), ["r2"]) == [
        "seed",
        "max_windows_per_session",
    ]
    assert meta_mismatches(meta, config, 30, 42, Path("d"), ["r2"]) == ["captures"]
    assert meta_mismatches(meta, config, 30, 42, Path("c"), []) == ["holdout"]


def test_a_model_does_not_depend_on_when_the_service_flushes_a_silent_host() -> None:
    config = ServiceConfig()
    meta = {
        "window": config.window.model_dump(),  # older records hold every setting
        "seed": 42,
        "max_windows_per_session": 30,
        "captures": "c",
        "holdout": [],
    }
    quicker = ServiceConfig(window=WindowConfig(idle_flush_sec=3, host_evict_sec=600))
    assert meta_mismatches(meta, quicker, 30, 42, Path("c"), []) == []
    wider = ServiceConfig(window=WindowConfig(size_sec=120))
    assert meta_mismatches(meta, wider, 30, 42, Path("c"), []) == ["window"]
    assert set(config.window.training_fields()) == {
        "size_sec",
        "slide_sec",
        "max_events_per_host",
        "late_reset_events",
    }


def test_train_then_evaluate_leaves_one_consistent_artifact_set(tmp_path: Path) -> None:
    config = Path(__file__).resolve().parents[1] / "config.yaml"
    artifacts = tmp_path / "artifacts"
    common = [
        "--captures",
        str(fixture_corpus(tmp_path)),
        "--artifacts",
        str(artifacts),
        "--config",
        str(config),
    ]
    assert train.main(common) == 0
    assert read_meta(artifacts)["window"] == load_config(config).window.training_fields()
    trained = load_artifacts(artifacts, ServiceConfig().window)
    assert re.fullmatch(r"\d{8}T\d{6}Z", trained.model.version or "")  # UTC, AGENTS.md section 11
    with pytest.raises(ArtifactError, match="make evaluate"):  # trained, not evaluated yet
        resolve_threshold(ServiceConfig().scoring, trained.model)

    assert evaluate.main(common) == 0
    after = load_artifacts(artifacts, ServiceConfig().window)
    assert after.model.version == trained.model.version
    threshold = resolve_threshold(ServiceConfig().scoring, after.model)
    assert threshold.source == "calibrated"
    assert json.loads((artifacts / "evaluation.json").read_text(encoding="utf-8"))["threshold"] == (
        threshold.value
    )


def test_evaluate_does_not_write_a_threshold_for_another_model(tmp_path: Path) -> None:
    config = Path(__file__).resolve().parents[1] / "config.yaml"
    artifacts = tmp_path / "artifacts"
    base = [
        "--captures",
        str(fixture_corpus(tmp_path)),
        "--artifacts",
        str(artifacts),
        "--config",
        str(config),
    ]
    assert train.main(base) == 0
    assert evaluate.main([*base, "--seed", "7"]) == 1  # the model was trained with seed 42
    assert read_meta(artifacts)["threshold"] is None
    assert (artifacts / "evaluation.json").is_file()


def two_runs(tmp_path: Path) -> Path:
    """The fixture sessions as two capture runs, with BlackBasta alone in ``check-run``."""
    root = tmp_path / "captures"
    for session in fixture_corpus(tmp_path / "flat").glob("*/*"):
        run = "check-run" if session.parent.name == "blackbasta" else "train-run"
        shutil.copytree(session, root / run / session.parent.name / session.name)
    return root


def test_a_held_out_run_is_kept_apart(tmp_path: Path) -> None:
    root = two_runs(tmp_path)
    used, held = load_sessions(root, ["check-run/"])  # a trailing separator names the same run
    assert [s.session_path.split("/")[1] for s in held] == ["blackbasta"]
    assert not {s.session_path for s in used} & {s.session_path for s in held}
    assert held_out_runs(root, ["check-run", "check-run"]) == ["check-run"]
    with pytest.raises(SystemExit, match="not found"):
        load_sessions(root, ["chek-run"])  # a typo must not train on the reference sessions


def test_a_reference_sample_captured_again_must_be_held_out_too(tmp_path: Path) -> None:
    root = two_runs(tmp_path)
    [sample] = (root / "check-run" / "blackbasta").iterdir()
    shutil.copytree(sample, root / "train-run" / "blackbasta" / sample.name)
    with pytest.raises(SystemExit, match="Run.s. train-run hold samples of the held-out"):
        load_sessions(root, ["check-run"])


def test_evaluate_scores_the_held_out_run_with_the_trained_model(tmp_path: Path) -> None:
    root = two_runs(tmp_path)
    config = Path(__file__).resolve().parents[1] / "config.yaml"
    artifacts = tmp_path / "artifacts"
    base = ["--captures", str(root), "--artifacts", str(artifacts), "--config", str(config)]
    held = [*base, "--holdout", "check-run"]
    assert train.main(held) == 0
    meta = read_meta(artifacts)
    assert meta["holdout"] == ["check-run"]
    assert meta["sessions"] == {"ransomware": 4, "goodware": 2, "events_dropped": []}

    assert evaluate.main(held) == 0
    report = json.loads((artifacts / "evaluation.json").read_text(encoding="utf-8"))
    assert report["holdout"] == ["check-run"]
    assert report["coverage"]["ransomware"]["sessions"] == 4  # BlackBasta is not among them
    check = report["held_out"]
    assert check["model_version"] == meta["version"] and check["threshold"] == report["threshold"]
    assert check["ransomware"]["sessions"] == 1 and check["goodware"] is None
    [session] = check["sessions"]
    assert session["name"].startswith("check-run/blackbasta/") and session["label"] == 1
    assert session["detected"] == (session["first_detection_sec"] is not None)


def test_a_model_trained_on_the_held_out_run_is_not_used_to_score_it(tmp_path: Path) -> None:
    root = two_runs(tmp_path)
    config = Path(__file__).resolve().parents[1] / "config.yaml"
    artifacts = tmp_path / "artifacts"
    base = ["--captures", str(root), "--artifacts", str(artifacts), "--config", str(config)]
    assert train.main(base) == 0  # trained on every run
    assert evaluate.main([*base, "--holdout", "check-run"]) == 1
    report = json.loads((artifacts / "evaluation.json").read_text(encoding="utf-8"))
    assert "holdout" in report["held_out"]["skipped"]
    assert read_meta(artifacts)["threshold"] is None
