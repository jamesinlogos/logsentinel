# SentinelBench

Python CLI that queries the LogSentinel lab stack and builds a monitoring-quality report
aligned with `archives/statistics.md`. Lives at `sentinelbench/` in the product tree.

```
Winlogbeat → Kafka → Logstash → ES / inference → detections → Kibana rule → notifications
```

## Install

```bash
cd sentinelbench
python -m pip install -e ".[dev]"
```

Python ≥ 3.12. Live probes need a reachable stack and Docker CLI. Offline capture metrics need
`inference/artifacts/evaluation.json` (or `--run-evaluate`). Pipeline throughput tries
in-process → repo `.venv` → `docker exec` into `logsentinel-inference` (container path is the
reliable lab default).

## Commands

```bash
# Live stack (completeness, latency, detection funnel, consistency, coverage, operations)
sentinelbench query stack
sentinelbench query stack --since 6h --format json
sentinelbench query elasticsearch|kafka|logstash|kibana|inference|notifications

# Offline labelled metrics (F2/MCC/AUC/TTFD/λ/CI/indicator coverage/baseline rates)
sentinelbench evaluate captures
sentinelbench evaluate captures --evaluation-json path/to/evaluation.json
# optional, slow: re-run inference training.evaluate
sentinelbench evaluate captures --run-evaluate --holdout 20261009T033557Z

# Performance (docker stats, Logstash in/out rate, local Pipeline µs/event)
sentinelbench probe performance
sentinelbench probe performance --sample-events 5000

# Combined report → statistics.md groups 1–9
sentinelbench report
sentinelbench report --skip-performance --format json -o report.json
```

| Flag | Applies to | Meaning |
|---|---|---|
| `--es` / `--kibana` | query, probe, report | HTTP endpoints |
| `--since` / `--sample-size` | query, report | ES lookback / sample |
| `--skip-docker` | query, probe, report | skip container probes |
| `--evaluation-json` | evaluate, report | path to evaluation.json |
| `--logsentinel-root` | evaluate, probe, report | repo root (auto-detected) |
| `--run-evaluate` | evaluate, report | run `training.evaluate` first |
| `--skip-stack` / `--skip-performance` | report | omit live sections |
| `--format` | all | `text` or `json` |
| `-o` / `--output` | all | write the rendered report to a file (UTF-8) instead of stdout |

## What is measured

| Layer | Groups (`statistics.md`) | Source |
|---|---|---|
| `query stack` | ops part of 4, 6, 9 | Elasticsearch, Kafka, Logstash, Kibana, inference, notifications |
| `evaluate captures` | 1–8 | `evaluation.json` (+ Wilson/Poisson/baseline enrichment) |
| `probe performance` | 9 | docker stats, Logstash counter delta, local `Pipeline` |
| `report` | 1–9 combined | all of the above |

**Live (`query stack`)**

- Completeness / schema correctness, consistency (detection ↔ window-score, notices ↔ receipts)
- Stage latency + end-to-end (window end → notice), telemetry evt/s, `@timestamp` inversions
- Detection funnel, score distributions on gated windows, early-window share, notice gaps

**Offline (`evaluate captures`)**

- Session/window TP/FN/FP/TN, Recall, Precision, **F2**, **MCC**, FPR + Wilson 95%
- **AUC**, goodware alerts/hour (+ Poisson CI), **TTFD**, indicator coverage by session class
- Held-out detection rate CI, illustrative false:true ratios (group 8)

**Not in scope** (lab intentional / infrastructure): backup, recovery, TLS/ACL, kill-broker chaos.

## Tests

```bash
cd sentinelbench
python -m pytest -q
python -m ruff check src tests
```

Smoke against a live lab:

```bash
sentinelbench evaluate captures
sentinelbench probe performance --sample-events 2000
sentinelbench report --since 24h
```

Development rules: `AGENTS.md`.
