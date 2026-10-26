# LogSentinel

Ransomware monitoring and detection for Windows Server by machine-learning analysis of system logs, on the ELK Stack: Sysmon → Winlogbeat → Kafka → Logstash → `inference` → Elasticsearch → Kibana.

**Status:** the baseline infrastructure (Kafka, Elasticsearch, Kibana, Logstash) is operational; `inference` (Indicator Engine + contextual scoring) is implemented and runs monitor-only (`inference/README.md`). Dashboards, a Kibana alert rule and a Telegram/Gmail notification worker complete the stack (section 9).

## Documentation

Exactly seven markdown files:

| File | Content |
|---|---|
| `README.md` | This file: architecture, data sources, Logstash/Elasticsearch/Kibana (dashboards, alerting), Docker, Sysmon configuration, limits |
| `AGENTS.md` | For AI agents and operators: component map, data contract, invariants, procedures, runbooks, approvals, naming (`AGENTS.md` section 11) |
| `inference/README.md` | Detection service: indicators, model, evaluation, output schema, reliability |
| `inference/AGENTS.md` | Rules for developing `inference` |
| `notifications/README.md` | Telegram and Gmail notification worker: behaviour, configuration, operation |
| `sentinelcap/README.md` | CLI capturing labelled Sysmon data through VMware: usage, output format, goodware scenarios |
| `sentinelcap/AGENTS.md` | Mandatory behaviour and development rules for `sentinelcap` |

## Quick start

### Backend stack
1. `.env` is provided. Never set a version to `latest` (`docker.elastic.co` has no such tag). Set `LOGSENTINEL_KAFKA_ADVERTISED_HOST` to the Docker host's real IP if it is not `192.168.110.1` (the `.env` default). Fill in the Kibana encryption key and the Telegram and Gmail settings (section 9.2, `notifications/README.md`): `docker compose` stops at a missing key, and `notifications` restarts without credentials.
2. `docker compose up -d` starts the backend: the init services run first, then `logstash-ingest` (3 pipelines: `ingest`, `sink-es`, `sink-inference`), `logstash-detection-sink`, `inference` and `notifications` (section 10.2). No manual step, even on new volumes (`kibana-init` also installs the Kibana rule and its notification action, which waits for Kibana: allow a few minutes); `scripts/create-topics.sh`, `scripts/init-elasticsearch.sh` and `scripts/init-kibana.sh` can still be run by hand.
3. `bash scripts/healthcheck-all.sh` checks the containers, the Kafka consumer lag and the notification worker.
4. Install Sysmon and Winlogbeat on the Windows Server (sections 10.3 and 10.4; `config/winlogbeat/winlogbeat.yml`).
5. Kibana: `http://localhost:5601`.

### inference
```bash
cd inference
make setup && make check        # install + ruff + mypy + tests
make model                      # train + evaluate on ../sentinelcap/captures → artifacts/
cd .. && docker compose up -d --build inference
```
The model is in `inference/artifacts/` (mounted read-only). A missing or mismatched model or threshold makes the container exit with code 2 and restart: there is no degraded mode. Usage, reliability, evaluation: `inference/README.md`; development rules: `inference/AGENTS.md`.

## Repository layout

| Path | Content |
|---|---|
| `docker-compose.yml`, `.env` | Backend infrastructure; `.env` also holds the Kibana key and the Telegram/Gmail credentials |
| `config/` | Logstash (`ingest/`, `detection-sink/`: `pipelines.yml` + one `.conf` per pipeline), Elasticsearch (ingest pipeline, ILM, component and index templates), Kibana (`kibana/`: alert rule, connector, action; section 9.2), Winlogbeat, Sysmon (`sysmonconfig-with-filedelete.xml`, section 10.4) |
| `scripts/` | Deployment and checks (`create-topics.sh`, `init-elasticsearch.sh`, `init-kibana.sh`, `healthcheck-all.sh`, `verify_detections.py`), backup (`backup_project.py`), stack move (`migrate_stack.py`), naming (`check_naming.py`), Logstash config (`check_logstash_config.py`), dashboards (`dashboard_definitions.py`, `dashboard_setup.py`, `verify_dashboards.py`), alerting (`alerting_setup.py`, `notification_setup.py`, `notification_test.py`) |
| `sentinelcap/` | Sysmon dataset capture CLI over VMware (`sentinelcap/README.md`) |
| `inference/` | Detection service: code, test/train/evaluate harness, Dockerfile (`inference/README.md`) |
| `notifications/` | Telegram and Gmail notification worker: code, tests, Dockerfile (`notifications/README.md`) |
| `dashboard/` | Kibana dashboards as Dashboard API JSON (section 9.1) |
| `archives/` | Backups (`archives/backups/`); not part of the product |

---

## 1. Overview

**LogSentinel** monitors Windows Server through Sysmon, streams the logs through Kafka, normalizes them with Logstash, classifies them in a standalone service (`inference`), stores them in Elasticsearch, visualizes them in Kibana and notifies by Telegram and Gmail. `inference` never writes to Elasticsearch: it talks only to Kafka, and Logstash writes the telemetry, detection and window-score indices (settled, `AGENTS.md` section 3). The two notification indices are written by Kibana's Index connector and the `notifications` worker (section 9.2). The backend runs entirely in Docker; services are named by function, not by number.

---

## 2. Architecture

```
┌────────────────────────────────────┐
│ Windows Server                     │  Sysmon (Operational channel), NOT in Docker (section 10.3)
└──────────────────┬─────────────────┘
                   │ Winlogbeat (native agent on the Windows Server itself)
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│ kafka (KRaft, single broker, Docker)                   │
│ topic: telemetry.windows.sysmon.raw                    │
└────────────────────────────┬───────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ logstash-ingest: 3 pipelines (ingest → sink-es + sink-inference, section 7.1)            │
│ parse Sysmon → normalize to ECS → tag MITRE ATT&CK → split into 2 branches               │
└────────────────┬───────────────────────────────────────────┬─────────────────────────────┘
                 │ sink-es                                   │ sink-inference
                 │                                           │
                 ▼                                           ▼
┌──────────────────────────────────┐        ┌────────────────────────────────────────────┐
│ elasticsearch                    │        │ kafka                                      │  read by inference and sentinelcap
│ index: windows-telemetry-*       │        │ topic: telemetry.windows.normalized        │
└─────────────────┬────────────────┘        └──────────────────────┬─────────────────────┘
                  │                                                │
                  │                                                ▼
                  │                         ┌────────────────────────────────────────────┐
                  │                         │ inference (monitor-only, section 5)        │
                  │                         └──────────────────────┬─────────────────────┘
                  │                                                │
                  │                                                ▼
                  │                         ┌────────────────────────────────────────────┐
                  │                         │ kafka                                      │
                  │                         │ topic: security.ransomware.detections      │
                  │                         │        security.ransomware.window-scores   │
                  │                         └──────────────────────┬─────────────────────┘
                  │                                                │
                  │                                                ▼
                  │                         ┌────────────────────────────────────────────┐
                  │                         │ logstash-detection-sink                    │
                  │                         │ simple pipelines: Kafka → Elasticsearch    │
                  │                         └──────────────────────┬─────────────────────┘
                  │                                                │
                  │                                                ▼
                  ▼                         ┌────────────────────────────────────────────┐
┌──────────────────────────────────┐        │ elasticsearch                              │
│ kibana                           │◄───────│ index: ransomware-detections-*             │
└──────────────────────────────────┘        │        ransomware-window-scores-*          │
                                            └────────────────────────────────────────────┘
```

> The `inference` branch (`sink-inference`) is split from the Elasticsearch branch (`sink-es`) by pipeline-to-pipeline, so a slow or stopped Elasticsearch does not stop detection. Per-host event order is guaranteed by configuration (Winlogbeat `key`, `pipeline.workers: 1`; section 7.1).
>
> Alerting is a separate branch from Elasticsearch: a Kibana rule on `ransomware-detections-*` writes notice envelopes that the `notifications` worker sends to Telegram and Gmail (section 9.2).

---

## 3. Data sources

### 3.1 Sysmon on Windows Server — required Event IDs

| Event ID | Meaning | Role in ransomware detection |
|---|---|---|
| 1 | Process Create | Encrypting process launch, command line, parent-child relation |
| 2 | File creation time changed | "Timestomp" sign |
| 3 | Network Connection | Outbound connections (C2, exfiltration, IP probing); network features (section 4) |
| 11 | FileCreate | Core: bulk creation or renaming of encrypted files |
| 13 | Registry value set | Persistence (Run key), disabling Shadow Copy |
| 22 | DNS query | Domain queries (DGA); no data yet: 0 events in SentinelCap data (section 4) |
| 23 / 26 | FileDelete / FileDeleteDetected | Deletion of originals after encryption. The current configuration fires only 26 (23 off, its rules moved to 26; section 10.4) |

### 3.2 Training and evaluation data from SentinelCap

Training and evaluation use real Sysmon documents from `telemetry.windows.normalized` with session labels in a `metadata.json` sidecar (`sentinelcap/README.md`). SentinelCap captured the ransomware, installer and admin-scenario sessions through the lab Windows VM and the production ingest pipeline (Sysmon to Winlogbeat to Kafka to `logstash-ingest`). The two operations goodware sessions in `20261020T172719Z` were a user-authorized historical query of the same normalized Kafka topic, stored in SentinelCap's capture format without running the SentinelCap CLI or VM. Their collection details are in `source-manifest.json`. Training and online data use the same normalized event schema.

**Current capture data:** 197 sessions and 1,606,636 events across 11 runs, counted from `metadata.json` under `sentinelcap/captures/<run>/<family>/<sample>/` (each session has `session.jsonl`):
- 125 ransomware sessions from 16 families: 50 original training sessions and 75 held-out sessions that repeat 15 samples across five runs. The held-out runs do not train the current model or select its threshold.
- 72 goodware sessions: 50 installers or portable apps (`--execute`), 20 admin scenarios (`--interactive`), and two operator-labelled operations sessions collected from Kafka over one 49-minute interval. One of the new sessions reports dropped Sysmon source events.

The current model (`20261026T071635Z`, threshold 0.60) trains on 50 ransomware and all 72 goodware sessions; its evaluation is in `inference/README.md` section 6.

The volume is still small by design (section 12). Loader rules (labels per session, event-volume balance, split by family, encryption without bulk file traces): `inference/README.md` section 9.1.

---

## 4. Features

Computed per `host.id` over 60 s windows (scheduled every 10 s, or closed early at the event that brings a new indicator), on the event JSON of `telemetry.windows.normalized` (SentinelCap data, section 3.2). List and formulas: `inference/README.md` section 8.

| Group | Features | Event IDs |
|---|---|---|
| Volume | event count in the window and per `event.code` (1, 2, 3, 11, 12, 13, 17, 26) | all |
| Process | ratio of suspicious paths; ratio of processes outside system directories; command-line length; LOLBin runs (certutil, bitsadmin, mshta…); service-stop commands; max child `cmd.exe` of one parent | 1 |
| File | directories and directory branches where a file name is created; distinct extensions; max files with one extension; max files deleted by one process; file-name entropy | 11, 26 (23) |
| Registry | Run/RunOnce key writes | 13 |
| Network | outbound connections; distinct destination IPs | 3 |
| Indicator flags | 13 flags (0/1) from the Indicator Engine | — |

- **Network features (real data):** the `sentinelcap` lab VM is deliberately Internet-connected. In run `20261001T011932Z` the sample's process has Event 3 in 14/50 ransomware and 21/50 goodware sessions (`inference/README.md` section 3); an Akira sample (`c974d8c6…`) opens 2,196 connections, 2,195 to port 443. Event 3 is therefore a feature, not an indicator.
- **Event 22 (DNS): 0 events** in 167 captured sessions despite outbound connections (cause undetermined: Sysmon/`DnsQuery` configuration or fixed-IP samples); domain features (domain entropy, DGA) wait for Event 22 data.
- **Limit:** Sysmon exposes no file content, so no true Shannon entropy; features are behaviour/frequency based, including **file-name** entropy.

---

## 5. `inference` — summary

Full design: `inference/README.md` (3-phase architecture with Indicator Engine + contextual scoring, indicators, Global Model, explainable output schema, evaluation, reliability).

- Two kinds of 60 s window per host: scheduled every 10 s, and early, closed at the event that brings a new indicator (`logsentinel.window.trigger`; `inference/README.md` section 4.0).
- Kafka only, never Elasticsearch. Input: `telemetry.windows.normalized`. Output: `security.ransomware.detections` (reported windows) and `security.ransomware.window-scores` (every scored window).
- Trained on `sentinelcap` captures (section 3.2). **Deployed** monitor-only: emits detections, takes no action.

---

## 6. Kafka topics

Naming: `<domain>.<subject>.<dataset>` (`AGENTS.md` section 11.7).

| Topic | Producer | Consumer | Content |
|---|---|---|---|
| `telemetry.windows.sysmon.raw` | Winlogbeat | `logstash-ingest` | Raw Sysmon events |
| `telemetry.windows.normalized` | `logstash-ingest` (pipeline `sink-inference`) | `inference`, `sentinelcap` | Events normalized to ECS, MITRE in `threat.*`; no `message`, `event.original` or `@version` (format `v1`) |
| `security.ransomware.detections` | `inference` | `logstash-detection-sink` (pipeline `detections`) | Windows that pass the Phase 2 gate and are reported, with label, confidence score and indicators |
| `security.ransomware.window-scores` | `inference` | `logstash-detection-sink` (pipeline `window-scores`) | Every scored window with its feature vector; `logsentinel.verdict.reported` tells whether it became a detection |

---

## 7. Logstash

### 7.1 `logstash-ingest` — parse/normalize/enrich
Reads `telemetry.windows.sysmon.raw`, normalizes to ECS, tags MITRE ATT&CK, then splits into two independent branches with pipeline-to-pipeline (`config/logstash/ingest/pipelines.yml`):

| Pipeline | File | Role | Workers / queue |
|---|---|---|---|
| `ingest` | `ingest.conf` | Kafka raw input, all filters (including dropping `event.original`), `send_to` both branches | 1 worker, `pipeline.ordered: true` |
| `sink-es` | `sink-es.conf` | Writes `windows-telemetry-*`, keeps `message` for threat hunting, `document_id` = raw Kafka topic-partition-offset | default (20 workers), `queue.type: persisted` |
| `sink-inference` | `sink-inference.conf` | Drops `message`, writes `telemetry.windows.normalized` keyed by `host.name` | 1 worker, `pipeline.ordered: true` |

- **Why split:** in one pipeline a blocked Elasticsearch also blocks the Kafka output and stops detection; `sink-es` has its own persisted queue (volume `logstash-ingest-data`).
- **`sink-inference` payload:** no `message` (only repeats `winlog.event_data`) and no `event.original` (JSON copy added on the Logstash side by the `json` codec in ECS mode; absent from the raw topic).
- **Per-host event order** needs all three: Winlogbeat `key: '%{[host.name]}'` (`config/winlogbeat/winlogbeat.yml`); `ingest` and `sink-inference` at 1 worker; `sink-inference` keyed by `host.name`. Measured on SentinelCap: the default (no host key, 20 workers) gives 112–132 `@timestamp` decreases per capture; the current setup gives 0 on a 565-event capture. Re-measure after changing the worker count or adding a Winlogbeat source.
- **`ingest` cost per event** (one worker: per-event time = capacity):
  - First stack, Logstash statistics (162,806 events): 0.629 ms/event ≈ 1.59 thousand events/s against a real peak of 1,875; by plugin type: grok 38%, `mutate` 23%, `pipeline` fork 16%, ruby 6%, kv 5%.
  - Per-event blocks now use `dissect` and `mutate` instead of grok, ruby and kv (only the MITRE grok remains). Temporary container, 80,000 events rebuilt from captures (one worker, ordered): filter 0.337 → 0.174 ms/event (2.97 → 5.76 thousand events/s, 1.94×); identical documents to the old filter for 171,473 events (all event codes) and to the stored ones for 61,457 events except `sysmon.file.is_executable` (bug fixed).
  - Whole pipeline (filter 0.527 ms + fork 0.101 ms from the statistics): ≈ 0.37 ms/event ≈ 2.7 thousand events/s.
  - Every grok, dissect, translate and kv plugin has an `id`; `GET :9600/_node/stats/pipelines/ingest` gives per-filter time.
- **Fields without data:** Sysmon writes `"-"` for no value (e.g. a PE without a version resource). Derived fields (`rule.name`, domain, `process.pe.*`, `file.pe.*`, `user.name`, `process.parent.{name,executable,command_line}`) are normalized to absent; `winlog.event_data.*` keeps `"-"` for audit.
- **Syntax check:** `logstash -t -f <file>` per file (`pipelines.yml` is ignored with `-f`). Full configuration: `config/logstash/ingest/`.

> **MITRE tagging:** Sysmon-Modular puts strings like `technique_id=T1204,technique_name=User Execution` in `rule.name`; `logstash-ingest` parses it with `grok` into ECS (`threat.framework`, `threat.technique.id` = parent technique, `threat.technique.subtechnique.*` for a sub-technique); there is no static Event ID → tactic table. It is the only supported Sysmon configuration (not SwiftOnSecurity or others); see section 10.4.

### 7.2 `logstash-detection-sink` — detection result sink
Two pipelines (`config/logstash/detection-sink/pipelines.yml`), one consumer group each, almost no transform:

| Pipeline | Reads | Writes | Group |
|---|---|---|---|
| `detections` (`detections.conf`) | `security.ransomware.detections` | `ransomware-detections-YYYY.MM` | `logstash-detection-sink` |
| `window-scores` (`window-scores.conf`) | `security.ransomware.window-scores` | `ransomware-window-scores-YYYY.MM` | `logstash-detection-sink-window-scores` |

`document_id` is `logsentinel.window.id`: a replay overwrites, and a detection joins the window score of the same window by that id. A document without it is not indexed with an auto-generated `_id`; it is printed to the container log.

---

## 8. Elasticsearch

| Index | Content | Template |
|---|---|---|
| `windows-telemetry-*` (daily; kept 30 days) | Normalized Sysmon events, for threat hunting | `config/elasticsearch/index-templates/windows-telemetry.json` |
| `ransomware-detections-*` (monthly; kept 365 days) | Detections of `inference` | `config/elasticsearch/index-templates/ransomware-detections.json` |
| `ransomware-window-scores-*` (monthly; kept 90 days) | Every scored window, with features | `config/elasticsearch/index-templates/ransomware-window-scores.json` |
| `ransomware-notifications-*` (monthly; kept 90 days) | Notice envelopes written by Kibana's Index connector, read by `notifications` | `config/elasticsearch/index-templates/ransomware-notifications.json` |
| `ransomware-notification-deliveries-*` (monthly; kept 90 days) | One delivery receipt per envelope and channel, written by `notifications` | `config/elasticsearch/index-templates/ransomware-notification-deliveries.json` |

- Detections and window scores share the component template `logsentinel-window-score` (mapping, one shard, no replica, ingest pipeline `logsentinel-event-ingested` setting `event.ingested`); each index has its own ILM policy with a delete phase only.
- `scripts/init-elasticsearch.sh` installs everything in `config/elasticsearch/` in dependency order. `elasticsearch-init` runs it before Logstash writes the first document, so an index never exists before its template. Naming: `AGENTS.md` section 11.8.

---

## 9. Kibana

### 9.1 Dashboards

Five dashboards in `dashboard/`, written as bodies of the Kibana Dashboard API (9.5 or later, `PUT /api/dashboards/<id>`), not as NDJSON saved objects. Every chart carries an inline data view, so no data-view or Discover-session ID depends on the machine. `scripts/dashboard_definitions.py` generates the JSON.

| ID | Title | Panels | Shows |
|---|---|---|---|
| `logsentinel-overview` | LogSentinel Overview | 15 | The three streams side by side: telemetry over time, window outcomes, gate coverage, verdict mix, confidence against the stored threshold, indicators |
| `ransomware-detections` | Ransomware Detections | 17 | Triage of reported windows: verdict mix, risk, scheduled against early windows, indicators, ATT&CK, executable that closed an early window, activity peaks |
| `window-scores` | Window Scores | 16 | Gate, verdict and suppression of every scored window: five states, trigger, model score, reported against suppressed |
| `windows-telemetry` | Windows Telemetry | 17 | Sysmon activity: event IDs, process, file, registry, network and DNS, ATT&CK |
| `telemetry-quality` | Telemetry Quality | 16 | Stored coverage and data-contract exceptions: per-stream volume, schema and model versions, missing fields |

Each dashboard opens with a note, has 3 or 4 KPI panels and the charts, then an interpretation note and Discover tables of the underlying documents. Panel counts: output of `python scripts/dashboard_definitions.py`.

```bash
python scripts/dashboard_definitions.py       # the JSON equals the generator output (--write regenerates; back up first)
python scripts/verify_dashboards.py           # layout, portability, mapped fields; no network
python scripts/verify_dashboards.py --live    # GET only: counts, time extent, field types, installed dashboards (--report FILE)
python scripts/dashboard_setup.py             # plan only
python scripts/dashboard_setup.py --apply --historical-range
```

- `--live` warns, but does not fail, for optional or historical fields that are not mapped (for example `tags`) and for dashboards that are not installed.
- `--apply` checks that Kibana is 9.5 or later, reads every target ID, refuses to overwrite a dashboard with another title, backs the existing definitions up to `archives/backups/<UTC>-dashboard-kibana/`, writes each ID, reads it back, stops at the first failure and records the state per ID in `MANIFEST.json`. It never deletes and writes Kibana saved objects only (no restart, no index write, no Kafka). It needs the user's consent (`AGENTS.md` section 7); running it again updates the same IDs.
- The files default to the last year with auto-refresh paused; `--historical-range` replaces the range in the request by the timestamps of the stored data. `--space <id>` installs into another space (the navigation links inside the dashboards point to the default space); `--kibana` and `--es` set the addresses.
- URL: `http://localhost:5601/app/dashboards#/view/<ID>`.

Reading the charts:

- A detection is a reported window, not a confirmed infection or a unique incident. Detections and window scores share `logsentinel.window.id` and windows overlap: do not add counts across streams or sum activity across windows.
- Gate needs a strong indicator; suspicious compares confidence with the threshold **stored in that document**; reported also passed suppression. The dashboards never apply the current model threshold to old data. Risk is `event.risk_score_norm` = confidence × 100, not a calibrated probability.
- Activity charts plot the maximum raw count per window in each time bucket; `features.*` are model inputs, not counts.
- `process.*` of an early window is the process of the event that closed it, not of every indicator in the window. Indicators, tactics and techniques are arrays: a document counts under each of its values.
- Registry events are 12-14; event 23 is off in the Sysmon configuration. A wildcard on command lines does not prove a mass service stop or a shadow-copy deletion.
- Stored coverage is not runtime health: an empty range or a zero chart says nothing about the VM, Kafka lag or latency. For old data widen the range or use `--historical-range`.

### 9.2 Alerting and notifications

One rule, one connector and one action, as bodies of the Kibana APIs in `config/kibana/`; `scripts/alerting_setup.py` and `scripts/notification_setup.py` install them. The `notifications` worker delivers the notices (`notifications/README.md`).

```
rule ─> action ─> Index connector ─> ransomware-notifications-YYYY.MM ─> notifications ─┬─> Telegram
                                                                                         └─> Gmail (SMTP)
```

| File in `config/kibana/` | Kibana object |
|---|---|
| `rules/ransomware-detections.json` | Rule `ransomware-detections` (`.es-query`), base definition with `actions: []` |
| `connectors/ransomware-notifications.json` | Index connector `ransomware-notifications` (no secrets) |
| `actions/ransomware-notifications.json` | The rule's only action: one envelope document per rule run |

- **Rule:** every minute it counts the documents of `ransomware-detections-*` whose `event.ingested` lies in the last 5 minutes and that have `event.dataset: logsentinel.detection`, `logsentinel.verdict.reported: true` and `logsentinel.verdict.gated: true`; it fires when the count is above 0. Both verdicts count; the threshold of the current model is not applied to stored data. `event.ingested` is when Elasticsearch received the document (`@timestamp` stays the window end): a detection of an old session that is written now matches, and a replay that overwrites documents can match again, so the rule is not exactly-once per window ID.
- **Summary alert:** no grouping, one alert per run rather than per host or window. `excludeHitsFromPreviousRun: true` skips the hits of the previous run; `size: 10` limits the examples given to the action, not the count; after a rule outage longer than 5 minutes the older detections are not caught up.
- **Action:** fires on every run that still matches (`onActiveAlert`, `summary: false`) and makes the connector write one document to `<ransomware-notifications-{now/M{yyyy.MM}}>`: `event.id` = `{{rule.id}}:{{alert.uuid}}:{{context.date}}`, `event.created`, `logsentinel.notification.count` and `message` (the count and up to 10 examples with host, verdict, confidence, indicators, window ID and window end; no process or command line). A notice can cover several overlapping windows. `notifications/tests` check that the rule and the message use mapped fields only.
- **Install:** `docker compose up -d` does it. The one-shot service `kibana-init` waits for a healthy Kibana, runs `scripts/init-kibana.sh` (`alerting_setup.py --apply`, then `notification_setup.py --apply`, retrying a `failed` run 5 times) and exits 0 only when both end `created`, `applied` or `unchanged`; the `notifications` worker starts after it. A second `up` changes nothing. It fails, and `up -d` reports it, when a rule, connector or action exists and differs, when Kibana has no license for the rule type or no permanent key, or when less than 5 GB is free for the backup (`docker compose logs kibana-init`); the backup of the public state goes to `./archives/backups/`. By hand (needs Kibana started with the key below, the init services finished and the worker configured):

  ```bash
  python scripts/alerting_setup.py               # preflight, report archives/kibana-alerting.json
  python scripts/alerting_setup.py --apply       # creates the rule when it is absent
  python scripts/notification_setup.py           # preflight, report archives/kibana-notifications.json
  python scripts/notification_setup.py --apply   # backs up, then installs policies, templates, connector, action
  ```

  Without `--apply` they only read (health, license of the rule type, exact counts, existing objects). `--apply` creates only what is absent, reads each object back and refuses to update or delete a rule, connector, action, template or policy that differs; `notification_setup.py --apply` first writes and verifies `archives/backups/<UTC>-kibana-notifications/` (public state before and after, no secrets). Both end with status `unchanged` when everything is installed. `--space`, `--es` and `--kibana` select another space or address. `--apply` changes Kibana and needs the user's consent, as does `notification_test.py --enqueue`, which sends real messages (`AGENTS.md` section 7).
- **Check in Kibana:** Rules, "Ransomware detections", execution status. No alert while no new detection arrives is normal; the execution status tells it from a failing rule.
- **Encryption key:** alerting needs a permanent `xpack.encryptedSavedObjects.encryptionKey`; without it Kibana reports `has_permanent_encryption_key: false`, the preflight stays `blocked` and alerting APIs can fail (HTTP 500 on `GET /api/actions/connector_types` on such a stack). Compose passes `LOGSENTINEL_KIBANA_ENCRYPTION_KEY` from `.env` (at least 32 characters) as `XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY`. Keep it private and unchanged: objects saved with another key cannot be decrypted. Setting it recreates Kibana (`docker compose up -d --no-deps kibana`; ask first). `docker compose config` prints it: use `--quiet`.

---

## 10. Docker deployment

### 10.1 Containerization scope
The whole backend (`kafka`, `elasticsearch`, `kibana`, `logstash-ingest`, `logstash-detection-sink`, `inference`, `notifications`) runs in Docker using Linux containers on one host. The Windows Server (log source) stays outside: Winlogbeat needs direct access to its own machine's Windows Event Log API, and Windows containers would add complexity (a different runtime from the Linux containers) without matching benefit.

### 10.2 `docker-compose.yml`
- **Services:** `kafka` (KRaft mode) → `elasticsearch` → `kibana` + `logstash-ingest` + `logstash-detection-sink`; `inference` and `notifications` are built from their component directories. Configured through `.env` (`LOGSENTINEL_*`); `name: logsentinel`, one `backend` network, volumes `<service>-data` (`AGENTS.md` section 11.10).
- **Healthchecks:** `kafka`, `elasticsearch`, `kibana`, both Logstash (API `:9600`, status green or yellow), `inference` (in its `Dockerfile`) and `notifications` (a local heartbeat file, in its `Dockerfile` and in Compose); `stop_grace_period: 30s` for stateful services.
- **Init services (run once, after a healthy broker and Elasticsearch):** `kafka-init` creates the 4 topics (raw, normalized, detections, window-scores) with `scripts/create-topics.sh`; `elasticsearch-init` installs the ingest pipeline, 5 ILM policies, component template and 5 index templates (`windows-telemetry`, `ransomware-detections`, `ransomware-window-scores`, `ransomware-notifications`, `ransomware-notification-deliveries`) with `scripts/init-elasticsearch.sh`; `kibana-init` (after a healthy `kibana` and `elasticsearch-init`) installs the alerting rule, the notification connector and its action with `scripts/init-kibana.sh` (section 9.2); it mounts `./config` read-only and writes its reports and backup to `./archives`.
- **Ordering:** `logstash-ingest` and `logstash-detection-sink` wait for `kafka-init` and `elasticsearch-init` to exit with code 0 (`service_completed_successfully`), `inference` for `kafka-init` and `notifications` for `elasticsearch-init` and `kibana-init` (and a healthy `elasticsearch`), so `docker compose up -d` leaves a ready stack.
- **`inference`:** mounts `inference/artifacts` read-only; exits with code 2 on a missing or mismatched model or threshold (no degraded mode).
- **`kibana`:** takes the permanent encryption key from `.env` (section 9.2); `docker compose` refuses an empty key.
- **`notifications`:** starts with plain `docker compose up -d` and sends every envelope that has no receipt yet; credentials and recipients come from `.env`, and without them it exits with code 2 (`notifications/README.md`).
- **Logstash mounts:** `logstash-ingest`: `pipelines.yml`, three conf files (section 7.1), volume `logstash-ingest-data` (persisted queue); `logstash-detection-sink`: `pipelines.yml`, two conf files (section 7.2).

### 10.3 Windows Server — native install (outside Docker)
1. Install Sysmon with the Sysmon-Modular configuration (section 10.4; required Event IDs: section 3.1).
2. Install Winlogbeat with output to the Kafka broker (sample: `config/winlogbeat/winlogbeat.yml`). **`key: '%{[host.name]}'` in `output.kafka` is mandatory**; otherwise a host's events spread over partitions and lose their order (section 7.1).
3. Confirm logs reach the topic: `docker exec logsentinel-kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:29092 --topic telemetry.windows.sysmon.raw --from-beginning --max-messages 1`.
4. **`sentinelcap` lab VM:** the Winlogbeat configuration lives in the `original`, `baseline` and `validate` snapshots. After editing it on the guest, restart Winlogbeat and re-take the snapshots, or every revert returns to the snapshot's configuration. After a revert Winlogbeat may resend events from before the snapshot (`@timestamp` older than the run); `sentinelcap` drops them as outside `[t0, t1]`. Best to snapshot after Winlogbeat has sent all its events. Stack-validation pairs use `build validate` / `batch --validate` (`sentinelcap/README.md`).

### 10.4 Sysmon configuration (Sysmon-Modular)

LogSentinel uses **Sysmon-Modular** (https://github.com/olafhartong/sysmon-modular) as its only Sysmon configuration: `rule.name` carries the MITRE ATT&CK mapping that `logstash-ingest` parses directly (section 7.1). SwiftOnSecurity and others are not used.

#### Configuration in use: `config/sysmon/sysmonconfig-with-filedelete.xml`

- In the repo; built from Sysmon-Modular, schema 4.91, restructured build with config layering + MITRE ATT&CK mapping (see the file's header comment). Nothing else to download.
- `config/logstash/ingest/ingest.conf` is written against this file (its header section "Sysmon configuration this pipeline is written against": fired/not-fired Event IDs, `HashAlgorithms` and `DnsLookup` must match it).
- After any change (rules, Sysmon-Modular version, extra modules...), **re-review the parts marked "verified" in that header**: they rely on exactly the Event IDs and fields this file produces.

**On the Windows Server** (PowerShell as Administrator; copy the file over first, e.g. with `vmrun copyFileFromHostToGuest` or a shared folder):
```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-with-filedelete.xml
# Sysmon already installed, update the configuration only:
.\Sysmon64.exe -c sysmonconfig-with-filedelete.xml
```

#### LogSentinel modifications

A **catch-all** below is an unnamed `Rule groupRelation="and" name=""` matching a process whose `Image` (or `ParentImage`, where stated) is outside `C:\Windows\`, `C:\Program Files\`, `C:\Program Files (x86)\`.

| Modification | Location | Reason |
|---|---|---|
| `FileCreate` (Event 11) also logs `D:\`, `E:\`, `F:\` (except `System Volume Information`) | RuleGroup right after the `\Videos\` rule | Original rules cover only user-profile directories and dangerous extensions, so notes and renamed encrypted files on data drives (shares, backups) went unlogged. No new Event ID or field. |
| `ProcessCreate` (Event 1): catch-all on `Image` | LogSentinel `ProcessCreate` RuleGroup (see row "Location") | Original `Image` rules cover only some directories (`\Downloads\`, `\Desktop\`, `\Temp\`, `\Appdata\Local\`, `C:\Users\Public\`…), so payloads such as LockBit's `C:\ProgramData\rl\LB3.exe` had no Event 1; `ExecuteSession` still links them to the process tree via `file.path` of Event 11/29. Events matching only a catch-all have `RuleName` = `-`, so `logstash-ingest` sets no `rule.name`/`threat.*`. No new Event ID or field. |
| Catch-all for `FileCreateTime` (2), `NetworkConnect` (3), `ProcessTerminate` (5), `ImageLoad` (7), `RawAccessRead` (9), `ProcessAccess` (10, by `SourceImage`), `FileCreate` (11), `RegistryEvent` (12–14), `FileCreateStreamHash` (15), `PipeEvent` (17–18), `FileDeleteDetected` (26), `FileExecutableDetected` (29) | One LogSentinel RuleGroup per event type (see row "Location") | Original includes cover only some paths/names; original excludes still apply. **Enables Event 9** (never fired by the original). Not extended: `FileDelete` (23, off; last row), `CreateRemoteThread` (original include already matches all `C:\` and `\\`), `DnsQuery`/`DriverLoad`/`ProcessTampering` (exclude only, all logged), `WmiEvent` (no `Image`), `ClipboardChange` (privacy). Added log volume not measured. |
| `ProcessCreate` (Event 1): catch-all on `ParentImage` | Same RuleGroup as the `Image` catch-all of `ProcessCreate` | Logs system binaries called **directly** by a sample or payload even when no rule matches the command line (e.g. `arp.exe`, `choice.exe`, `notepad.exe`). Not covered: chains through a system binary (sample → `cmd.exe` → X), as X's direct parent is in `C:\Windows\`. |
| `ProcessCreate` (Event 1) logs every run of `cipher.exe`, `mountvol.exe`, `wbadmin.exe`, `bcdedit.exe`, `wmic.exe`, `diskshadow.exe`, `nltestrk.exe` (by `OriginalFileName`). Rule names reuse the original technique names: `bcdedit`/`wbadmin`/`wmic` → T1490, `diskshadow` → T1218, `nltestrk` → T1482; `cipher`/`mountvol` have no original rule and keep `LogSentinel: cipher and mountvol` | Same RuleGroup as above | Original rules fire only on specific arguments (`wmic` with `delete`+`shadowcopy` or `useraccount`/`service`+`call`+`create`, `wbadmin` with `delete`, `bcdedit` with `/set`, `nltest` with `/domain_trusts`); `diskshadow` only as `ParentImage`; none for `cipher`, `mountvol`. A freely named LogSentinel rule that also matches would drop T1490 (`threat.technique.id`) from `bcdedit` and `wmic`. |
| `RegistryEvent` (12–14) logs the key `…\Control Panel\Desktop\Wallpaper` and keys containing `Classes\.` + `\DefaultIcon` (rules `LogSentinel: desktop wallpaper`, `LogSentinel: file extension icon`) | LogSentinel `RegistryEvent` RuleGroup | No original rule matches these keys when `reg.exe` or `explorer.exe` writes them. Sysmon has no wildcards, so `\Classes\.<ext>\DefaultIcon` is written as `contains all`; `Classes\.` (no leading `\`) also matches `HKU\<SID>_Classes\.<ext>`. Icons set through a ProgID (`Classes\<progid>\DefaultIcon`) are not covered. |
| Every catch-all also excludes `\\?\C:\Windows\`, `\\?\C:\Program Files\`, `\\?\C:\Program Files (x86)\` | Inside each rule above | Otherwise system processes such as `\\?\C:\Windows\system32\wbem\WMIADAP.EXE` are logged redundantly. |
| **Location of the LogSentinel RuleGroups:** each RuleGroup holding the catch-alls sits **right before the first include RuleGroup** of the same event type; inside it, specific entries (technique names, `cipher and mountvol`, `desktop wallpaper`, `file extension icon`) precede the two catch-all `Rule`s | Start of the include section of each event type | Sysmon writes the `RuleName` of the **last matching include RuleGroup in the file**, then of the **first matching entry** in it. LogSentinel RuleGroups placed after the original one make events matching both lose the original technique tag (e.g. T1059.003, T1036, T1490 for Event 1; T1547.001, T1553.004 for Event 12/13). Position decides only the rule name, not whether the event is logged. **A new rule's RuleGroup goes before the original RuleGroups of the same event type.** |
| `FileDeleteDetected` (Event 26) excludes `Image is System` + `TargetFilename begin with C:\Windows\System32\LogFiles\WMI\RtBackup\` | Exclude RuleGroup right after the `FileDeleteDetected` exclude `C:\Windows\Prefetch;.pf` | The `Image` catch-all makes `System` (not under `C:\Windows\`) log a delete of `EtwRTAdmin_PS_Provider.etl` every session, ransomware and goodware alike; the original does not. Other `System` deletes stay (e.g. `C:\System Volume Information\{…}` in sessions with `vssadmin`). |
| **Turn off `FileDelete` (Event 23), move all rules to `FileDeleteDetected` (Event 26)** | All 9 `FileDelete` RuleGroups (5 include, 4 exclude) re-tagged `FileDeleteDetected`; an empty `<FileDelete onmatch="include">` right after the LogSentinel RuleGroups | Event 23 archives deleted files into `C:\Sysmon\` (`ArchiveDirectory`); Event 26 logs the same fields (`Image`, `TargetFilename`, `Hashes`, `IsExecutable`) without archiving. An empty include turns the event off, as the original does for `RawAccessRead`. Every original `FileDelete` rule has a `FileDeleteDetected` counterpart; the re-tagged excludes also apply to the original `FileDeleteDetected` rules. |

#### Updating to a newer Sysmon-Modular (optional)

Sysmon-Modular no longer ships a static `sysmonconfig.xml`; the prebuilt ("Balanced") configuration is built by a separate Go CLI and published per version as a GitHub Release asset: `https://github.com/olafhartong/sysmon-modular/releases`. Do not auto-fetch "latest" for a real deployment: pin **exactly 1 version** (also the project's recommendation). After downloading a new one, re-check the "verified" parts above before replacing `sysmonconfig-with-filedelete.xml`.

#### Required Event IDs

Section 3.1 has the full table. At minimum confirm the configuration does not filter out Event IDs 1, 2, 3, 11, 13, 22, 25, 26 (23 is off; file deletion is 26).

### 10.5 Move the stack to a Windows host

The generic procedure is in `AGENTS.md` section 5 (`scripts/migrate_stack.py`); the Windows specifics:

- Windows 10/11 x64, Python 3.12 or later (`py -3`) and Docker Desktop with WSL 2 and **Linux containers**, started before the import (`docker info --format '{{.OSType}}'` prints `linux`).
- Elasticsearch needs `vm.max_map_count` raised in the Docker Desktop VM; set it as Elastic's [Windows/WSL 2 instructions](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-prod) say.
- On the source: `python scripts/migrate_stack.py export --out <directory outside the project>` (optional `--images`, `--leave-stopped`), then `python scripts/migrate_stack.py verify <directory>` (prints `export intact`). `--leave-stopped` keeps the source off, so two copies with the same credentials do not both send notifications; keep the source volumes until the target is verified. Export directories must stay outside the project (for example `..\logsentinel-export`).
- Copy the whole directory, then on the target (the export carries `.env`, so the Kibana key and the Telegram/Gmail credentials come along; keep it private):

  ```powershell
  py -3 ..\logsentinel-export\tools\migrate_stack.py verify ..\logsentinel-export
  py -3 ..\logsentinel-export\tools\migrate_stack.py import --source ..\logsentinel-export --target C:\logsentinel --kafka-host 192.168.110.1
  ```

  `--kafka-host` is the address of the new host that the monitored VM can reach (not loopback). `import` refuses existing containers or volumes and compares document counts and Kafka offsets with the source.
- From the new project directory: `docker compose ps -a`, `py -3 scripts/verify_detections.py`, `py -3 scripts/verify_dashboards.py --live`, `py -3 scripts/alerting_setup.py` and `py -3 scripts/notification_setup.py`. Status `unchanged` means the Kibana objects came across in the Elasticsearch volume; `ready` means they must be installed with `--apply`. Open the dashboards with a range that covers the stored data.
- By hand: the Winlogbeat output host of the VM (also in its snapshots) and, in `sentinelcap/config.yaml`, the VMware paths and `kafka.bootstrap_servers`.

---

## 11. Rollout phases

| Phase | Content | Deliverable |
|---|---|---|
| Phase 1 | Docker infrastructure (`kafka`, `elasticsearch`, `kibana`, `logstash-ingest`, `logstash-detection-sink`) | `docker compose up -d`; seven runtime services healthy, all three init services exit with code 0 |
| Phase 2 | Kafka topics; Elasticsearch configuration (ingest pipeline, ILM, component and index templates) | Done by `kafka-init` and `elasticsearch-init` in `docker compose up -d` (every `up`, idempotent); `create-topics.sh` and `init-elasticsearch.sh` still run by hand. The topic must exist before `sentinelcap` subscribes to `telemetry.windows.normalized`, otherwise `UNKNOWN_TOPIC_OR_PART` |
| Phase 3 | Sysmon + Winlogbeat on the Windows Server | Real events flow into `telemetry.windows.sysmon.raw` |
| Phase 4 | Full parse/enrich of ECS fields in `logstash-ingest` | `telemetry.windows.normalized` is clean: per-host order, no `message`/`event.original` |
| Phase 5 | Training dataset via SentinelCap, with the authorized historical Kafka operations backfill documented in section 3.2 | Labelled JSONL + metadata sidecar in `sentinelcap/captures/` |
| Phase 6 | **Develop `inference`** (`inference/README.md`) | Done: service meeting the section 5 contract; model trained and threshold selected with the `make model` workflow on `sentinelcap` captures (ransomware and goodware, including admin scenarios). Remaining: an independent ransomware holdout batch and longer operational goodware outside training (`inference/README.md` section 6) |
| Phase 7 | Connect `logstash-detection-sink`, build the Kibana dashboards | Five dashboards (section 9.1); the "Ransomware Detections" dashboard works |
| Phase 8 | Kibana Alerting and notifications | Done: rule `ransomware-detections`, Index connector, `notifications` worker (Telegram, Gmail); install: section 9.2 |

---

## 12. Limits and risks

- Alerting only, no automatic response. A notice summarises one rule run (a count and up to 10 examples); detections are reported windows, not confirmed infections. Delivery is at-least-once: a stop between a send and its receipt sends the notice again (`notifications/README.md`).
- The Basic license is in use: notices go through the Index connector and the `notifications` worker. The Kibana key, the Telegram token and the Gmail App Password sit in `.env`, which backups and stack exports include.
- Real Telegram and Gmail delivery is exercised only by `notification_test.py --enqueue` (one synthetic notice); the tests of the worker use recording providers.
- Sysmon gives no file-content entropy: features are behaviour/frequency based.
- The capture dataset (section 3.2: 167 sessions, 95 ransomware from 16 families, 72 goodware) is small and comes from one lab environment: more samples, families and capture time are needed before results count as reliable.
- `ingest` and `sink-inference` run 1 worker to keep event order, so detection throughput is one thread (≈ 2.7 thousand events/s after the filter cost reduction, section 7.1; real peak 1,875). Fine for a one-host lab VM; if load grows, partition by host instead of adding workers.
- Single node everywhere (`kafka` 1 broker, `elasticsearch` 1 node): PoC, not production architecture.
- `inference` delivers detections and window scores at-least-once with replay (offset committed only after every record of the window is acknowledged and its events leave the window buffer): a restart duplicates records on the topic with the same `logsentinel.window.id`, so Elasticsearch keeps one document per index (`inference/README.md` section 9.2). Run a single instance: no rebalance/scale-out handling, and the `sink-inference` partition key is `host.name` while windows are per `host.id`.
- `logstash-detection-sink` has a memory queue and no volume: a crash can lose detections or window scores already in Kafka (`sink-es` has a persisted queue). Acceptable in the lab; production needs a persisted queue for the sink, replication factor above 1 for the detection topic, and an RPO.
- Elasticsearch/Kibana security is off (`xpack.security.enabled=false`) to simplify the lab; enable it for a real deployment.

---

## 13. Roadmap

- Automatic response to a detection (alerting exists: section 9.2).
- Elasticsearch Data Streams + ILM policy instead of fixed index patterns.
- Schema Registry if Kafka moves from JSON to Avro.
- Dead Letter Queue (dedicated topic) for failed messages in `logstash-ingest`/`inference`.
- Elastic ML native / Eland if the final model is simple enough to export straight into an ingest pipeline.
- Enable `xpack.security` (TLS + authentication) when leaving the lab scope.

---

## References
- Apache Kafka — KRaft mode Docker image: https://hub.docker.com/r/apache/kafka
- Elastic — Winlogbeat Reference: https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html
- Elastic — Logstash Kafka Input/Output Plugin: https://www.elastic.co/guide/en/logstash/current/plugins-inputs-kafka.html
- Elastic Common Schema (ECS): https://www.elastic.co/guide/en/ecs/current/index.html
- Sysmon config — Sysmon-Modular (embeds MITRE ATT&CK in `rule.name`, section 7.1): https://github.com/olafhartong/sysmon-modular
- MITRE ATT&CK: https://attack.mitre.org/
