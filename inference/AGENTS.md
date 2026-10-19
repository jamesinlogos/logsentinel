# AGENTS.md — inference development guide

## Context
`inference` is the ransomware detector of LogSentinel (`../README.md`): a Kafka consumer and producer that NEVER writes to Elasticsearch directly; all index writes go through `logstash-detection-sink`. Phases 2 and 3 are fully implemented (`README.md`). Each window yields one result and two streams: a window score (every window) and a detection (reported windows). New names follow `../AGENTS.md` section 11.

## Required reading before changing code
1. `README.md` sections 2.1 (modules), 3 (input), 4 (Indicator Engine, windows), 5 (Phase 3, contextual scoring), 7 (output), 8 (features), 9.1 (loader rules).
2. `../README.md` — architecture (topics, Logstash, Elasticsearch).
3. `../sentinelcap/README.md` — the only source of training and evaluation data.

## Mandatory principles
- **One definition per quantity.** `summary.py` counts everything (`Summarizer`: `add` and `remove` are one code path); `indicators.py` and `features.py` only read the counts. Training, evaluation and the service run the same `Pipeline`; never duplicate a formula (training-serving skew).
- **One module per phase, imports one way** (`README.md` section 2.1). A change goes into the module of its phase; `service.py` holds only Kafka, delivery and shutdown, `pipeline.py` runs without a broker.
- **One flow.** Scheduled and early windows are one flow with no switch to turn the early ones off (`README.md` section 4.0); no compatibility shims, fallbacks or degraded modes.
- **Early close decides from the host's last minute of events only** (`trigger.py`). State that a restart would not rebuild (a memory of earlier closes or of reported indicators) makes a replay lose or change window ids.
- **Model contract.** `FEATURE_NAMES` (fixed order) and the river version live in `model-meta.json`; `model.load()` rejects a mismatch. Changing a feature means retraining (`make model`).
- **Train offline on static data:** shuffled windows, ADWIN off in ARF, no "concurrent goodware" windows (`overlay`) in training (an `evaluate` test only); rationale: `README.md` sections 5.1 and 9.1 rule 9. No class-balancing resampling: measure flagged goodware windows per hour (`README.md` section 6).
- **Kafka input is untrusted.** Only `events.py` reads raw JSON; every anomaly (size, overlong numbers, deep nesting, timestamp, counts) becomes an `InvalidEventError`, never an exception escaping the loop. Regexes on such data must be linear-time (bounded token gap; tested).
- **Offset commits** (`offsets.py`) are a contract: never commit past an event still in a window buffer or a record (window score or detection) not yet ACKed. After changing window, trigger or emission logic, rerun `tests/test_service.py` and `tests/test_pipeline.py` (replay tests).
- **Artifacts are one unit, with one way to start** (`artifacts.py`): the service runs only with a complete model and threshold from one training run that match `config.yaml`, otherwise it exits with code 2. No degraded mode, no default threshold. A new metadata field needs a matching check. `Pipeline` takes an empty model only to test the Phase 2 gate and suppression: the missing model score is left out of the confidence (not counted as 0) and its field is absent from the document (never `null`).
- **Output schema is a three-way contract** (`documents.py`, `config/elasticsearch/`, `config/logstash/detection-sink/`). `document()` builds the detection and the window score from one `WindowScore`. To add or rename a field: edit the component-template mapping, keep `dynamic: false`, bump `SCHEMA_VERSION` and run `tests/test_documents.py` (mapping must cover every field of every document shape, with no extras; workflow: `../AGENTS.md` section 4). New fields go under `logsentinel.*` or are ECS fields with their ECS meaning (`../AGENTS.md` section 11.9). Changing `logsentinel.window.id` or its computation changes the `_id` of every existing document.
- No family-specific strings (extension `.akira`, note names, …) in rules; use statistical features as designed.
- **Training and evaluation data come only from SentinelCap captures;** never load external datasets.
- No synthetic test data: fixtures come from real captures via `tests/fixtures/build_fixtures.py` (edit its list of sessions/events and rerun).

## Common tasks
- **Add/change an indicator:** `indicators.py` (rule, `WEIGHTS`, `MITRE`); test on real events in `tests/test_indicators.py`; update `README.md` sections 4.1/4.2 with figures from `make evaluate`. A new indicator adds a column `ind_<name>` to `FEATURE_NAMES` → retrain. A rule reads counts through `RuleFacts`; a count it needs goes into `summary.py`.
- **Add a feature:** count in `summary.py` (`Summarizer` and `WindowSummary`; `tests/test_summary.py` checks it against the recount of `tests/reference_summary.py`), transform in `features.compute()`, add to `FEATURE_NAMES`, retrain.
- **Change window/weights/threshold:** `config.yaml` (unknown keys are rejected); `make evaluate` re-reports F2/MCC.
- **New SentinelCap data:** `make model CAPTURES=<captures directory>`, read `artifacts/evaluation.json`, update the figures in `README.md`. A control run (held-out run) goes into `HOLDOUT` before training so it never trains the model or picks the threshold; so does a run recapturing held-out samples (`train` and `evaluate` stop if it is forgotten).

## Code conventions
- Python ≥ 3.12; type hints on every public function; identifiers and comments in English.
- A module docstring names the `README.md` section it implements.
- Logging: only `logging.getLogger(__name__)`, no `print`; structured fields via `extra=ecs({...})` (`logs.py`), message stays a readable sentence; `logsentinel.stats.*` names are shared from `ServiceLoop._counters()`. Changing a record means updating the table in `README.md` section 9.4.
- Kafka sits behind `run_loop()`, which accepts any consumer/producer: tests use fakes (`tests/test_service.py`), no broker.

## Definition of done
- `make check` is clean (ruff, ruff format, mypy, pytest).
- New logic has a test on real data.
- Indicator, feature or scoring change: `make model` was run and the matching figures in `README.md` are updated.
