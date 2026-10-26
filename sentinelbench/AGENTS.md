# AGENTS.md — SentinelBench development guide

## Context

`sentinelbench` is the lab monitoring-quality CLI for LogSentinel: it reads the running stack
(Elasticsearch, Kafka, Logstash, Kibana, `inference`, `notifications`) and the offline
`inference/artifacts/evaluation.json` / SentinelCap captures, and builds a report aligned with
`archives/statistics.md`. It never writes to Elasticsearch, Kafka, or capture data. New names
follow `../AGENTS.md` section 11.

## Required reading

1. `README.md` — install, commands, metrics.
2. `../AGENTS.md` — data contract, invariants, approvals (section 7).
3. `../inference/README.md` sections 6 and 9 — evaluation figures and reliability.

## Mandatory principles

- **Read-only against the live stack.** Queries and probes only; never install rules, restart
  services, or enqueue notification tests unless the user asks and section 7 allows it.
- **Numbers come from tool output.** Report figures must trace to Elasticsearch replies,
  `evaluation.json`, docker stats, or a re-run of `training.evaluate` — no invented values.
- **One package, one CLI.** Entry point `sentinelbench` (`cli.py`); metrics live under
  `metrics/`, live HTTP/Docker under `clients/`.
- **Training data stay in `sentinelcap`.** This tool scores and summarizes; it does not capture.
- Do not read `sentinelcap/samples/` (malware; antivirus blocks).

## Common tasks

- **New live metric:** add a function in the matching `metrics/` or `clients/` module; wire it
  through `query_components` / `full_report`; cover it with a unit test on fixtures or fakes.
- **New offline figure:** extend `metrics/evaluate.py` from `evaluation.json` fields; keep
  names aligned with `inference` evaluation keys.
- **CLI flag:** kebab-case, one concept (`--since`, `--evaluation-json`); update `README.md`.

## Definition of done

- `python -m pytest` and `python -m ruff check src tests` are clean in this directory.
- `python ../scripts/check_naming.py` is clean from the repo root.
- Live smoke (optional, stack up): `sentinelbench report --skip-performance --since 1h`.
