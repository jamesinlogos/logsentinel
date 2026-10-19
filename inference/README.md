# inference

Ransomware detection service of LogSentinel. Kafka in, Kafka out: it reads `telemetry.windows.normalized` and writes `security.ransomware.window-scores` (every scored window) and `security.ransomware.detections` (reported windows). It never writes to Elasticsearch; `logstash-detection-sink` does.

- **Phase 2 — Indicator Engine:** rules over 60 s windows of a host, scheduled every 10 s or closed early at the event that brings a new indicator; the result gates Phase 3.
- **Phase 3 — contextual scoring:** Global Model (River ARF) combined with the indicator score.
- **Data:** trained and evaluated on SentinelCap captures only (`../sentinelcap/captures/`).

**Status:** Phases 2 and 3 are implemented and run monitor-only (detections are emitted, no response action). The true/false-positive feedback loop is not implemented (section 5.4). Development rules: `AGENTS.md`; architecture: `../README.md`; naming: `../AGENTS.md` section 11.

---

## 1. Run and configure

### 1.1 Setup, checks, training
```bash
make setup    # pip install -e ".[dev]" (Python >= 3.12)
make check    # ruff + mypy + pytest (real fixtures, no Kafka)
make model    # train + evaluate on ../sentinelcap/captures -> artifacts/ (HOLDOUT runs excluded)
make run      # run the service (Kafka from config.yaml / environment)
```
Without `make` (Windows) run the commands of the `Makefile`, e.g. `python -m training.train --captures ../sentinelcap/captures --holdout 20261009T033557Z --holdout 20261009T120629Z`.

- `make model` = `train` then `evaluate`, with the same `--seed`/`--max-windows`/`--config`/`--holdout`. `train` writes `model.pkl` and `model-meta.json` (one `version`). `evaluate` picks the threshold and stores it in `model-meta.json` (with `threshold_basis`, the settings it was chosen for) and `artifacts/evaluation.json`; it refuses to write a threshold for a model trained with other settings.
- Held-out runs (`HOLDOUT` in the `Makefile`, section 9.1 rule 10) never train the model or pick the threshold; `evaluate` scores them last (`held_out`). Sessions added to such a run need only `make evaluate`. A run that recaptures held-out samples (same hashes) must be in `HOLDOUT` too, otherwise `train` and `evaluate` stop.
- Training: scheduled windows only, at most 30 labelled windows per session, windows shuffled, ARF without ADWIN (sections 5.1, 9.1).

### 1.2 Docker
The `inference` service of `../docker-compose.yml` builds the image from this directory, mounts `artifacts/` read-only and sets `stop_grace_period: 30s`.
```bash
cd ..
docker compose up -d --build inference logstash-detection-sink   # kafka-init and elasticsearch-init run first (depends_on)
docker compose logs -f inference
docker exec logsentinel-inference python -m inference.healthcheck; echo $?
docker exec logsentinel-inference cat /tmp/inference.status.json
```
The image is based on `python:3.14-slim`; `river` is pinned to `0.26.1` because the model is a River pickle. The service starts only with a complete model + threshold set that matches `config.yaml` (section 9.2); otherwise it exits with code 2 (the container restarts and shows in `docker ps`).

### 1.3 Configuration
`config.yaml` (other path: `INFERENCE_CONFIG`; the file must exist). `INFERENCE__<SECTION>__<KEY>` overrides one key, e.g. `INFERENCE__KAFKA__BOOTSTRAP_SERVERS`, `INFERENCE__KAFKA__INPUT_TOPIC`, `INFERENCE__KAFKA__DETECTIONS_TOPIC`, `INFERENCE__KAFKA__WINDOW_SCORES_TOPIC`. Empty values are ignored; the `LOG` section is read by `logs.py` (section 9.4). Unknown keys, `inf` and `NaN` are rejected at startup.

`scoring.weight_*` are the weights of section 5.3. `scoring.threshold: null` uses the threshold chosen by `evaluate`; the service exits with code 2 if the weights differ from the ones it was chosen for, or if the model has not been through `evaluate`. `kafka.*_timeout_sec`: see `config.yaml`.

---

## 2. Architecture

| Phase | In `inference` |
|---|---|
| 1. Normalization | Outside the service: `logstash-ingest` |
| 2. Indicator Engine | Rules (regex, counts) over 60 s host windows: scheduled windows when they close, early windows at the event that brings a new indicator (section 4.0); no model, no labels. Gate of Phase 3 |
| 3. Contextual scoring | Global Model + indicator score give the verdict for windows that pass the gate; the model score of other windows is only recorded (section 7) |

### 2.1 Modules
One module per step, in the order an event travels. Imports run one way, down the table; `config.py` and `logs.py` are used by any of them.

| Step | Module (`src/inference/`) | Section |
|---|---|---|
| Message → `Event`; anything abnormal becomes `InvalidEventError` | `events.py` | 3, 9.2 |
| Counts of a window: the one definition of every count, kept up to date as events enter and leave | `summary.py` | 4.0, 8 |
| Indicators and combination score; gate = at least 1 strong indicator | `indicators.py` | 4.1, 4.2 |
| Windows per `host.id` on `@timestamp`: scheduled (60 s, slide 10 s) and early; follows a host's new clock | `windowing.py` | 4.0, 9.2 |
| When a window closes before its boundary | `trigger.py` | 4.0 |
| Window features (shared by training and serving) | `features.py` | 8 |
| Global Model ARF (offline training, ADWIN off) | `model.py` | 5.1 |
| Model + threshold as one set | `artifacts.py` | 9.2 |
| `WindowScore`: the verdict of one window, its confidence | `scoring.py` | 5.3 |
| Which gated windows are reported (suppression) | `emission.py` | 2 |
| `WindowScore` → detection and window-score documents | `documents.py` | 7 |
| Pure pipeline: events in, `Emission` out | `pipeline.py` | 2 |
| Which offsets may be committed | `offsets.py` | 9.2 |
| Status file and healthcheck | `status.py`, `healthcheck.py` | 9.2 |
| Kafka loop, delivery, shutdown | `service.py` | 9.2 |
| Configuration | `config.py` | 1.3 |
| Logging | `logs.py` | 9.4 |

`Pipeline.process` takes one event: `windowing` adds it and returns the scheduled windows it closes, each is scored and judged by the suppression; then the rules look at the host's trailing window and, if `trigger` finds a new indicator, the window closes early and is scored the same way. `Pipeline.tick` (once per poll of the service loop) closes the pending window of a host that went quiet (`idle_flush_sec`) and forgets hosts silent for `host_evict_sec`. `training/` replays sessions through the same `Pipeline`.

Every scored window yields a **window score**; a window that passes the gate and survives suppression also yields a **detection**. Scheduled and early windows are scored and reported alike. `logsentinel.verdict.label` (gated windows only) is `suspicious_ransomware_behavior` when confidence ≥ threshold, else `indicator_match`. A host is reported again only on a new indicator, a higher label, or after 60 s. Format and filtering: section 7.

---

## 3. Input contract

Each message of `telemetry.windows.normalized` is one nested JSON event normalized to ECS by `logstash-ingest`. The Sysmon event code is `event.code` (in ECS `event.id` is a record UUID); `host.name` is added by Winlogbeat. `logstash-ingest` maps `process.command_line` and `process.parent.command_line` (Event 1) from `winlog.event_data.CommandLine`/`ParentCommandLine` (`config/logstash/ingest/ingest.conf`), so indicators can tell `vssadmin delete shadows` from `vssadmin list shadows`.

```json
{
  "@timestamp": "2026-09-12T10:15:23.123Z",
  "event": { "code": "1", "category": ["process"], "action": "Process Create (rule: ProcessCreate)" },
  "user": { "domain": "WIN-SRV01", "name": "SYSTEM" },
  "process": {
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "working_directory": "C:\\Users\\...",
    "hash": { "md5": "..." },
    "parent": { "pid": 3312, "executable": "C:\\Windows\\explorer.exe" }
  },
  "file": { "path": "C:\\Users\\...\\file1.docx.locked", "name": "file1.docx.locked" },
  "registry": { "path": "..." },
  "source": { "ip": "...", "port": 0 },
  "destination": { "ip": "...", "port": 443 },
  "network": { "transport": "tcp", "direction": "outbound" },
  "winlog": {
    "event_data": {
      "TargetImage": "...", "GrantedAccess": "0x1fffff", "CallTrace": "...",
      "IntegrityLevel": "High", "Signed": "true", "SignatureStatus": "Valid",
      "Company": "...", "TargetProcessId": "..."
    }
  }
}
```

**Checked on real SentinelCap data** (run 2026-10-01: 100 sessions, 50 ransomware and 50 goodware, 689,094 events):
- `process.command_line` is in 9,715/9,715 Event 1; `process.parent.command_line` in 9,676/9,715 (the other 39 have no identifiable parent).
- Real payloads carry more fields than the example (`agent.*`, `host.*` incl. `host.id`/`host.ip`/`host.mac`, `ecs`, `log`, full `winlog.*`) in 689,094/689,094 events; never assume only the example fields.
- Branch `sink-inference` has no `message` and no `event.original` (`../README.md` section 7.1): 0/689,094 events have them, or a top-level `type` or `@metadata`.
- Per-host order comes from configuration (Winlogbeat `key` by `host.name`; `ingest` and `sink-inference` with `pipeline.workers: 1`): `@timestamp` goes backwards 112–132 times per capture with default settings, 0 times over all 100 sessions with the current ones.
- **No data means the field is absent, never `"-"`.** `logstash-ingest` removes Sysmon's `"-"` from derived fields (`rule.name`, `source.domain`, `destination.domain`, `process.pe.*` and `file.pe.*` (5 fields each), `user.name`, `process.parent.{name,executable,command_line}`); `winlog.event_data.*` keeps raw values. These fields are `Optional` in `events.py`, features use presence (e.g. `pe_metadata_present`), validators reject `"-"` in derived fields (test: `tests/test_input_contract.py`, fixture `tests/fixtures/sentinelcap-normalized-events.json`). PE strings, `process.hash.*`, `imphash` and `entity_id` are not features: the `--execute` goodware is vendor software only (all 5 PE fields present in 43/50 goodware, absent in 43/50 ransomware), which cannot separate "ransomware" from "exe without version resource".
- `process.hash.*` exists only in Event 1 (9,715 events); file hashes are in `file.hash.*`: Event 7 (50,937), 26 (31,329), 29 (11,505).
- Network: the sample's processes have Event 3 in 14/50 ransomware sessions (6/11 families) and 21/50 goodware sessions, so it is a feature group, not an indicator (`../README.md` section 4). Event 22 (`dns.*`): 0 events in 150 sessions, so no domain features.
- **Event 10 has no data:** 0 events in 150 sessions although the Sysmon configuration has rules for it; on the guest, `C:\Users\Public\taskkill.exe /F /IM notepad.exe` produced none either. Cause unknown. No indicator or feature may use Event 10.
- Sysmon RuleName `"-"`: 577,164/689,094 events (83.8%); `rule.name` (111,913) and `threat.*` (95,566) exist only on the rest.

---

## 4. Phase 2 — Indicator Engine

### 4.0 Basis and principles

Measured on run 2026-10-01: **50 ransomware sessions** (11 families: akira, blackbasta, blackmatter, conti, embargo, hellokitty, lockbit, lynx, medusa, nitrogen, trigona) and **50 goodware sessions** (`--execute`; installers and portable apps). That goodware has no admin task touching the strong group, so its 0/50 false alarms hold for installers only; admin-scenario goodware is in section 9.5. The windows are the ones described at the end of this section.

- Count over **all events of the host** in the window, not over "the sample's processes": the service cannot know which process is malicious, and samples inject code, write over SMB (`System`) or drop renamed payloads (section 9.1).
- Do not rely on Event 11 of encrypted files: Sysmon logs neither renames nor in-place overwrites (only 1/11 families leaves Event 11 for them: Akira, 2/5 sessions). The stable file signal is the **bulk-dropped note**. Prefer command lines (Event 1).
- Fire early: median first firing after sample start is 1.1 s (service stop), 1.4 s (shadow copy deletion), 1.9 s (recovery disabled), 4.0 s (note drop), 4.1 s (log clearing); BlackMatter `8c047ba0…` and LockBit `3c4fb5a1…` disable the Sysmon channel at 92.4 s and 86.9 s.
- The thresholds N below are constants in `indicators.py` (those that compare a count) and `summary.py` (those that decide what a count counts), seeded from the data. Changing one changes the `ind_*` columns: retrain (`make model`) and re-measure section 4.1.

**Windows** (`windowing.py`, `summary.py`, `trigger.py`). The rules, features and model see 60 s windows of one host in event time (`@timestamp`; `config.yaml`, section `window`). There are two kinds, scored in the same way (same rules, features, model and weights):

| | Scheduled | Early |
|---|---|---|
| `logsentinel.window.trigger` | `slide` | `indicator` |
| Span | `[end − 60 s, end)`, `end` a multiple of 10 s | the host's last 60 s up to its newest event; `end` is 1 ms after that event |
| Closes | when an event passes `end`, or after `idle_flush_sec` without events (section 9.2) | at the event that brings a new indicator (rule below) |
| `process.*` in the documents | none | the process of that event (section 7) |
| Training windows | yes | no; the model scores them like any window (section 5.2) |

- **Early-close rule** (`trigger.EarlyClose`). After every event of a host the rules look at its trailing window (its last 60 s). The window closes at that event when it passes the gate and an indicator fires in it that did not fire after the host's previous event (a rising edge of the set of fired indicators). The scheduled window of the same bucket still closes later and is scored on its own; suppression (`EmissionPolicy`) decides which of the two become detections.
- **Why the rule looks only at the last minute.** The commit rule keeps the events of every open window and of every unacknowledged record (section 9.2), and the trailing window is among them. After a restart the replay sees the same last minute, decides each early close in the same way and writes it under the same `logsentinel.window.id`. More events never switch an indicator off in a given window, so a replay that starts with less history can close more early windows than the first run, not fewer. A rule that remembered earlier closes would not survive a restart.
- **Counting** (`summary.py`). A `Summarizer` holds the counts of a set of events and moves forward only: `add` and `remove` share one code path with a step of +1 or −1, so a window is never recounted from scratch. Each host has two (the scheduled window and the trailing window). Counts are multiset counts, so the result does not depend on the order of events; the entropy sum uses `math.fsum` for the same reason. The facts the rules read after every event (`mass_note`, `mass_replace`, `max_cmd_children`, the command counts) are kept up to date in O(1) per event; maxima and distinct counts are computed from per-key counts when a snapshot is taken. `tests/reference_summary.py` recounts a window from scratch to check the incremental counts. A heap on event time expires the trailing window's events, so an event costs O(log n) whatever the order in which events arrive.
- **Buffer.** The host keeps every event that a scheduled or trailing window still needs, at most `max_events_per_host` (section 9.2). `oldest_offsets` reports the oldest input offset of that buffer.

### 4.1 Indicators

"Ransomware" = sessions with at least one firing / 50 (families / 11); "Goodware" = sessions / 50; counted over all events of the host in the session.

**Strong group** (at least one opens the Phase 3 gate, section 4.2):

| Indicator | Condition | Event | Ransomware | Goodware | Score |
|---|---|---|---|---|---|
| `mass_note_drop` | One process creates the **same file name** in ≥ 10 directories spread over ≥ 5 level-4 directory branches (e.g. `c:\users\<u>\documents`, `d:\shares\finance`) | 11 | 46/50 (11/11) | 3/50: XAMPP (shallow tree `C:\xampp\…`, so `c:\xampp\<a>\<b>` already counts as ≥ 5 branches), MDaemon (`hiwater.mrk`, 13 directories / 5 branches), Windows Admin Center (language directories such as `de-de`, 51 directories) | 0.6 |
| `mass_file_replace` | One process creates `<file>.<new extension>` and deletes `<file>` for ≥ 50 files with the same appended extension in ≥ 10 directories within the window | 11, 23/26 | 1/50 (1/11: Akira `c974d8c6…`) | 0/50 | 0.8 |
| `shadow_copy_deletion` | Command line that deletes or shrinks shadow copies or the backup catalog: `delete shadows`, `Win32_Shadowcopy` + `Remove-WmiObject`/`Delete`, `wmic shadowcopy … delete`, `resize shadowstorage`, `wbadmin delete` (also via `cmd.exe`, PowerShell, WMI; the parent is not traced) | 1 | 24/50 (7/11) | 0/50 | 0.5 |
| `recovery_disable` | `bcdedit … recoveryenabled no`, `bootstatuspolicy ignoreallfailures`, `reagentc /disable` | 1 | 13/50 (6/11) | 0/50 | 0.4 |
| `service_stop_burst` | ≥ 5 stop commands for services/processes in the window: `net stop`/`net1 stop`, `sc stop`, `sc config … start= disabled`, `Stop-Service`, `taskkill` | 1 | 9/50 (5/11) | 0/50 | 0.4 |
| `event_log_tamper` | Write of `…\WINEVT\Channels\<channel>\Enabled = 0` (Event 13) by a process other than Windows servicing (`c:\windows\winsxs\<dir>\tiworker.exe`), or `wevtutil cl`/`sl … /e:false`, `Clear-EventLog` (Event 1) | 13, 1 | 7/50 (4/11) | 0/50 | 0.5 |

- With the service's 60 s windows (`training/evaluate.py`) the ransomware counts are the same; goodware `mass_note_drop` drops to 2/50 (Windows Admin Center fails inside one window). `wmic shadowcopy … delete` (8 sessions: BlackBasta `a1202037…`, 5 LockBit, 2 Trigona) is part of `shadow_copy_deletion`. Narrowing `mass_note_drop` further does not separate: requiring an extension removes only Windows Admin Center; counting by level-2 root puts 2 ransomware sessions in one root.
- **`mass_file_replace`** came from WhiteLock `a501583b…` (held-out run): 5,070 `<name>.jpg.fbin` files written, 4,980 originals deleted, no note, no other indicator. On run 2026-10-01 and held-out run `20261009T033557Z`: 5 ransomware sessions of 5 families (Akira 2,569 files / 78 directories; BQTLock, Nebula, WhiteLock, Yurei 630–9,717 files / 19–1,966 directories) against 70 goodware sessions with at most 101 files (one installer, 1 directory) and at most 5 directories. Weight 0.8 (highest): it is the destructive act itself and never appeared in goodware, while the other five strong indicators all did in admin-scenario goodware. With this weight WhiteLock's lowest maximum confidence is 0.5803 against the threshold 0.58 (section 9.5). Rule and weight were chosen after seeing that run, so it no longer checks them independently (section 9.5).
- **`event_log_tamper` servicing exception:** `TiWorker.exe` (from `c:\windows\winsxs\…`) registers log channels as disabled during updates and role installs. It is the only source of such writes in goodware (2 scenario sessions: Windows Update, AD DS install); ransomware disables channels with the sample itself (4 sessions). Only that exact path is skipped. `wevtutil` has no exception (the log-archival scenario uses `wevtutil cl`; Phase 3 separates it, section 9.5).

**Support group** (adds to `indicator_score`, never opens the gate alone):

| Indicator | Condition | Event | Ransomware | Goodware | Score |
|---|---|---|---|---|---|
| `ransom_note_keyword` | File name contains `readme`, `read_me`, `decrypt`, `recover`, `restore`, `instruction`, `how_to` | 11 | 45/50 (11/11) | 23/50 (installer files) | 0.1 |
| `cmd_burst` | ≥ 10 `cmd.exe` processes spawned by one parent in the window | 1 | 10/50 (4/11) | 4/50 (XAMPP, 3 ManageEngine products) | 0.2 |
| `run_key_persistence` | Write to `…\CurrentVersion\Run` or `RunOnce` | 13 | 12/50 (4/11) | 10/50 (installers registering autostart: Firefox, Docker Desktop, KeePass, Java, Jellyfin, VC++ Redistributable, …) | 0.2 |
| `lolbins_execution` | Runs `certutil`, `bitsadmin`, `mshta`, `regsvr32`, `rundll32`, `wscript`, `cscript`, `wmic`, `installutil`, `msbuild` | 1 | 13/50 (5/11) | 10/50 (installers calling `regsvr32`, `certutil`, `cscript`, `wmic`, `rundll32`) | 0.2 |
| `security_policy_tamper` | Write to `…\Policies\System\EnableLUA`/`ConsentPromptBehaviorAdmin`/`EnableLinkedConnections` or Windows Defender policy keys | 13 | 1/50 (1/11) | 0/50 | 0.3 |
| `remote_thread_injection` | Event 8 (CreateRemoteThread) | 8 | 0/50 | 1/50 (Sysinternals VMMap creating threads in `explorer.exe`, `AggregatorHost.exe`) | 0.3 |
| `process_tampering` | Event 25 | 25 | 0/50 | 0/50 | 0.8 (theoretical, no data yet) |

**Dropped candidates** (kept as Phase 3 features where useful):

| Candidate | Reason from the data |
|---|---|
| `new_extension_burst` | ≥ 50 new files with the same "uncommon" extension from one process: 4/50 ransomware (2/11: Akira, Trigona `.hta`) but 20/50 goodware (installers creating `.jar`, `.php`, `.woff2`, `.rels`, `.conda`, …): wrong direction; depends on a still undefined "common extensions" list (numbers use a temporary one). Phase 3 feature |
| `mass_file_rename` | Sysmon logs no renames; Event 11 of encrypted files exists only for Akira, as new files. Covered by `mass_note_drop` and `mass_file_replace` |
| `mass_file_delete` | ≥ 50 Event 26 from one process: 42/50 ransomware vs 36/50 goodware (installers deleting temp files): no separation |
| `timestomp_activity` | ≥ 50 Event 2 from one process: 5/50 ransomware (2/11: LockBit, Trigona) vs 11/50 goodware: wrong direction |
| `high_filename_entropy` | Note names have low entropy (`readme`); goodware has many hex/high-entropy names: no separation |
| Outbound connections (Event 3) | 14/50 ransomware vs 21/50 goodware sessions: network feature only (`../README.md` section 4) |

### 4.2 Combinations and the Phase 3 gate

Only combinations that co-occur in ransomware and appear in 0/50 goodware sessions are kept:

| Combination | Ransomware | Goodware | Bonus |
|---|---|---|---|
| `mass_note_drop` + `shadow_copy_deletion` | 22/50 | 0/50 | +0.3 |
| `shadow_copy_deletion` + `recovery_disable` | 11/50 | 0/50 | +0.2 |
| `mass_note_drop` + `event_log_tamper` | 7/50 | 0/50 | +0.2 |
| `mass_note_drop` + `service_stop_burst` | 7/50 | 0/50 | +0.2 |
| `shadow_copy_deletion` + `run_key_persistence` | 11/50 | 0/50 | +0.15 |

`lolbins_execution` + `run_key_persistence` is dropped: 11/50 ransomware but 6/50 goodware (installers).

- **Coverage** (5 strong indicators, without `mass_file_replace`, which only adds an Akira session that already passes): the strong group fires in 48/50 ransomware sessions; strong indicators per session: 0 (2 sessions), 1 (17), 2 (19), 3 (6), 4 (4), 5 (2). The 2 sessions without one rely on Phase 3: BlackBasta `17205c43…` (65 events, no file or command-line trace; section 9.1 rule 4) and LockBit `032690f1…` (note in only 9 directories, threshold 10). Goodware: 3/50 sessions have a strong indicator over the whole session, all `mass_note_drop`; with 60 s windows 2/50 (XAMPP, MDaemon).
- **Gate: the window has at least one strong indicator.** `indicator_score` = sum of single scores + combination bonuses, clamped to [0, 1]; it is always computed and reported (sections 5.3, 7) but is not a filter. The rule `indicator_score ≥ 0.3` was rejected: it passes 25/50 goodware sessions (22 without any strong indicator) and lets support indicators open the gate alone (`security_policy_tamper`, `remote_thread_injection` 0.3; `process_tampering` 0.8). The current rule gives 48/50 ransomware and 3/50 goodware (60 s windows: 48/50 and 2/50), and `explain` always contains a strong indicator. Event 25 alone no longer opens the gate; revisit when real Event 25 data exists.
- Scores, bonuses and thresholds N are starting values; recalibrate after collecting admin scenarios (section 4.0).

---

## 5. Phase 3 — contextual scoring

### 5.1 Global Model
- **Algorithm:** Adaptive Random Forest (ARF), a voting ensemble of decision trees that learns one sample at a time (`learn_one`/`predict_one`). **Library:** River, pinned to `0.26.1`; the service rejects a model saved with another version.
- **Drift detection:** ADWIN is off (`river.drift.NoDrift`): the service trains offline on static data and does not learn online. Measured on run 2026-10-01 (family-grouped CV, 3 seeds): fed session by session, ADWIN reports 97–106 false drifts over the 16 CV models (7 for the first model trained on all data) because it treats a change of session/family as drift, and replaces trees:

  | Training order | ADWIN | Mean AUC (3 seeds) |
  |---|---|---|
  | Session by session | on | 0.881 (0.828 – 0.911) |
  | Session by session | off | 0.907 |
  | Shuffled windows | on | 0.911 |
  | **Shuffled windows** | **off** | **0.924** (0.923 – 0.926) |

  (Folds: one family per fold, goodware in 5 separate folds; section 6 uses another split, so the AUCs are not comparable.) ADWIN would only return if the service learned online from feedback (section 5.4).
- **Training data:** SentinelCap captures (`../sentinelcap/README.md`, `../README.md` section 3.2), the same `logstash-ingest` output used at inference, no schema mapping: run 2026-10-01 (50 ransomware sessions of 11 families, 50 installer/portable goodware sessions) and 20 admin-scenario goodware sessions (`manifest-scenarios.csv`, section 9.5). More samples are needed before the model can be called reliable (`../README.md` section 12). Loader rules: section 9.1.
- **Implementation** (`model.py`, `training/train.py`): `river.forest.ARFClassifier(n_models=10, seed=42)` with `NoDrift` detectors; offline training on window features (section 8) with window labels (section 9.1 rule 2); scheduled windows only (section 5.2), at most 30 labelled windows per session, shuffled with a seed before `learn_one`; no concurrent-goodware windows (rule 9). Model `20261011T202925Z`: 1,971 labelled windows (513 ransomware, 1,458 goodware); 200 ransomware windows without sample events are dropped. `model-meta.json` stores the feature list and the river version; the service refuses a mismatching model (section 9.2).

### 5.2 Windows the model scores
The model is trained on scheduled windows (section 4.0), whose `end` lies on the 10 s grid, and scores every window the service closes, early ones included. An early window has the same 60 s span and the same 37 features as a scheduled one; only its `end` is the time of an event. Evaluation replays sessions through the service's `Pipeline`, so the figures of section 6 include early windows (labels as in section 9.1 rule 2). The score of a window depends only on its own events: no per-host history enters the model score or the confidence.

### 5.3 Combining scores
```
confidence_score = (w1 * indicator_score + w2 * global_model_score) / (w1 + w2)
```
Implementation (`scoring.py`): weighted mean of the components that exist. The service always has a model, so both exist; a missing component is left out, not counted as 0, so gate and suppression tests run without a model. The model score is computed for every window and stored in the window score (section 7); only gated windows use it, for `confidence_score` and the label. Weights w1 = 0.5, w2 = 0.3 (`config.yaml`); only their ratio matters (62.5 % indicator, 37.5 % model). No weight search has been run on this mean: the tuned quantity is the threshold, chosen by `training/evaluate.py` (section 6), stored in `model-meta.json` and overridable in the config.

### 5.4 Operating mode
Monitor-only, no online learning: the Global Model changes only with an offline retrain (`make model`). Not implemented: true/false-positive feedback (relabelling detections for further learning).

---

## 6. Evaluation

Metrics: **F2** (β=2; a missed ransomware is worse than a false alarm) and **MCC** (balanced view on imbalanced classes).

### Results (model `20261011T202925Z`, `artifacts/evaluation.json`)
The model version is a UTC stamp `YYYYMMDDTHHMMSSZ` (`../AGENTS.md` section 11.3).

- **Data:** run 2026-10-01 (50 ransomware, 50 installer goodware) and 20 admin-scenario goodware sessions captured 2026-10-08/09 (section 9.5): 120 sessions, 20.4 hours of goodware. The held-out runs `20261009T033557Z` and `20261009T120629Z` (the same 15 new ransomware samples captured twice, 5 families not in training) are outside training and threshold selection (section 9.1 rule 10). Indicators include `mass_file_replace` and the Windows servicing exception.
- **Method** (`training/evaluate.py`): family-grouped cross-validation (section 9.1 rule 6). Each ransomware family is a fold; goodware samples (each hash or scenario whole in one fold) are spread over the same 11 folds. A fold's model is trained on the other folds only (`evaluate` stops if no goodware remains outside a fold). Each session is replayed once through the service's `Pipeline` (`replay`): scheduled and early windows, confidence and model score rounded as the service writes them. Session level: detected if at least one gated window has confidence ≥ threshold. Threshold = best session-level F2 (ties: window-level MCC, then the higher threshold): **0.58**. It is selected on the same out-of-fold results the table reports, so the metrics are optimistic.

| | Recall | Precision | F2 | MCC |
|---|---|---|---|---|
| Session level at threshold (TP 48, FN 2, FP 3, TN 67) | 0.96 | 0.94 | 0.96 | 0.91 |
| Session level, Phase 2 gate only (TP 48, FN 2, FP 7, TN 63) | 0.96 | 0.87 | 0.94 | 0.85 |
| Window level at threshold (TP 446, FN 378, FP 29, TN 3,074) | 0.54 | 0.94 | 0.59 | 0.66 |

The window-level row counts every labelled window of the replays, early windows included.

- **Phase 3 removes false alarms:** 7 goodware sessions pass the gate; at the threshold 3 remain — MDaemon `3a60f6dd…`, XAMPP `12e818ce…` and the scenario `deploy-config-files`. Flagged goodware windows drop from 94 to 29.
- **Global Model alone:** AUC 0.937 over all labelled windows (out-of-fold). AUC is unstable between trainings: seeds 1 and 7 give 0.950 and 0.928 (thresholds 0.56 and 0.61, the same session counts), and adding only the column `ind_mass_file_replace` (non-zero in 3 windows of one training session) once moved it from 0.884 to 0.926, so differences of a few percent are not evidence.
- **Cost of the threshold:** 0.54 of ransomware windows reach 0.58 (gate alone: 0.81); the other gated ones are emitted as `indicator_match`. The 2 missed sessions never pass the gate (BlackBasta `17205c43…`, LockBit `032690f1…`, section 4.2).
- **Concurrent goodware** (rule 9; 50 pairs): 47 of 48 sessions detected (alone: 48 of 48). The miss is BlackMatter `9bae897c…` together with goodware `71bcfda9…`: 0.5782 against the threshold 0.58 (alone 0.8038). Ransomware windows detected 528/966 (alone: 446/824); mean model score 0.614 → 0.557.
- **False alarms over time:** 20.38 hours of goodware (4.49 h installers, 15.89 h scenarios), 29 flagged windows (1.42/h). After suppression (`EmissionPolicy`) 25 detections are emitted (all labels), 8 of them `suspicious_ransomware_behavior` (0.39/h). Optimistic: the threshold was chosen on this data.
- **Time to first detection** (48 detected sessions): median 2.6 s, p90 39.1 s, max 186.7 s (event time, from the first event of the sample's process to the end of the first window reaching the threshold; an early window ends at the event that brings the indicator). The service emits an early window at its event and a scheduled one when the next event or `idle_flush_sec` closes it; upstream delay comes on top: Sysmon → Winlogbeat (`pipeline_lag_*` of SentinelCap measures only this hop; run 2026-10-01: median of the per-session maximum 2.2 s, highest 16.2 s) and Kafka/Logstash/service loop (not measured on the real system; simulation in section 9.2).
- **Held-out runs** (`held_out`; 15 samples captured twice = 30 sessions): **30/30 detected** (15/15 per run), including BQTLock, Makop, Nebula, WhiteLock and Yurei (not in training). Time to first detection: median 2.7 s, p90 42.8 s, max 52.6 s (run `20261009T033557Z`: median 3.6 s, max 52.6 s; run `20261009T120629Z`: median 2.4 s, max 42.8 s). Lowest maximum confidence: WhiteLock `a501583b…`, 0.5803 and 0.6539 against the threshold 0.58 (table in section 9.5). Ransomware only, so no false-alarm measurement. Not independent: `mass_file_replace` and its weight were chosen after seeing WhiteLock (section 9.5).
- **The window-sampling seed contains the run name:** `training_rows` seeds with `f"{seed}:{session.key}"` and `session.key` contains the run name, so renaming a run shifts the AUC and the threshold slightly (`../AGENTS.md` section 10).
- **Data still to collect:** (1) a new held-out ransomware batch (unseen samples) to re-check `mass_file_replace` and the 0.8 weight, after which the current 15 samples can join training; (2) new admin/operations goodware not used for the threshold (operations like `deploy-config-files`, service stops, bulk file replacement across directories); (3) long normal-operation captures to measure flagged windows per host per day. After each batch run `make model` (`make evaluate` if only held-out sessions were added) and compare with the tables above.

---

## 7. Output schema

For every scored window the service writes **two streams** from one result (`schema_version` 2; field names follow `../AGENTS.md` section 11.9):

| Stream | Kafka topic → Elasticsearch index | `event.kind` | Content |
|---|---|---|---|
| **detection** | `security.ransomware.detections` → `ransomware-detections-YYYY.MM` | `alert` | Windows that pass the gate and are reported after suppression; no `features` |
| **window score** | `security.ransomware.window-scores` → `ransomware-window-scores-YYYY.MM` | `metric` | **Every** scored window with its feature vector; `logsentinel.verdict.reported` says whether it became a detection |

Both streams carry scheduled and early windows (section 4.0); `logsentinel.window.trigger` tells them apart.

Example: the first reported window of Medusa `49c9b3dd…` (fixture `tests/fixtures/sessions`), an early window, model `20261011T202925Z`, threshold 0.58 (calibrated). The session is in the training set, so the example only illustrates the format (18 windows: 13 scheduled and 5 early; 11 gated; 5 reported, all early). `activity` is laid out several fields per line; `event.created` was set by the script that generated the example.
```json
{
  "@timestamp": "2026-10-01T09:03:18.861Z",
  "ecs": { "version": "8.0.0" },
  "message": "Window 2026-10-01T09:02:18.861Z to 2026-10-01T09:03:18.861Z of host win-en194vl6r3u: suspicious_ransomware_behavior, confidence 0.5886 (threshold 0.58), indicators: service_stop_burst, run_key_persistence",
  "event": {
    "kind": "alert", "module": "logsentinel", "dataset": "logsentinel.detection",
    "category": ["malware"], "type": ["info"],
    "start": "2026-10-01T09:02:18.861Z", "end": "2026-10-01T09:03:18.861Z", "duration": 60000000000,
    "created": "2025-10-09T08:55:00.250Z",
    "risk_score": 0.5886, "risk_score_norm": 58.86
  },
  "host": { "id": "8a1a7c51-9e51-4829-94d7-e8fe2e6c6f02", "name": "win-en194vl6r3u" },
  "service": { "name": "inference", "version": "0.1.0" },
  "logsentinel": {
    "schema_version": 2,
    "window": {
      "id": "01923ff90af3fdaeb4bf4964e8e130e046cda8869ed71d2ca111f230d69eb370",
      "trigger": "indicator",
      "activity": {
        "events": 151, "process_starts": 8, "created_files": 0, "distinct_extensions": 0,
        "max_same_extension": 0, "max_deletes": 85, "max_name_dirs": 0, "max_name_branches": 0,
        "max_replaced_files": 0, "max_cmd_children": 3, "shadow_commands": 0,
        "recovery_commands": 0, "stop_commands": 5, "log_tamper": 0, "lolbin_runs": 0,
        "run_key_writes": 1, "policy_writes": 0, "note_keyword_files": 0, "suspicious_paths": 1,
        "non_system_executables": 1, "command_line_chars": 551, "connections": 0,
        "destination_ips": 0
      }
    },
    "verdict": {
      "gated": true, "suspicious": true, "reported": true,
      "label": "suspicious_ransomware_behavior", "confidence_score": 0.5886, "threshold": 0.58,
      "indicators": ["service_stop_burst", "run_key_persistence"],
      "scores": { "indicator": 0.6, "model": 0.5697 }
    },
    "model": { "name": "adaptive_random_forest", "version": "20261011T202925Z" }
  },
  "process": {
    "entity_id": "{8A1A7C51-21D6-6ABE-AE01-000000001100}",
    "executable": "c:\\windows\\system32\\cmd.exe",
    "name": "cmd.exe",
    "command_line": "c:\\windows\\sysnative\\cmd.exe  /c taskkill -f -im sql writer.exe",
    "parent": { "entity_id": "{8A1A7C51-21D6-6ABE-AC01-000000001100}" }
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "technique": { "id": ["T1489", "T1547"], "subtechnique": { "id": ["T1547.001"] } },
    "tactic": { "name": ["Impact", "Persistence", "Privilege Escalation"] }
  }
}
```
The window closed at the fifth stop command (`stop_commands` 5, the threshold of `service_stop_burst`): `event.end` is 1 ms after that event and `process` is its process. The window score of the same window differs only in: `event.kind` = `metric`, `event.dataset` = `logsentinel.window_score`, no `event.category`/`event.type` (only alerts are classified), and `logsentinel.window.features` — the 37 `ln(1+x)` features the model sees (`events` 5.0239, `code_1` 2.1972, `code_2` 0.0, `code_3` 0.0, …) — next to `activity`. The scheduled window that ends 1.1 s later (`2026-10-01T09:03:20.000Z`, `trigger` `slide`, no `process`) passes the gate with confidence 0.8020, but the early windows have reported its indicators already, so it is only a window score (`reported: false`).

- **Filtering:** `logsentinel.verdict.reported: true` marks detections (in both indices); `suspicious: true` means `confidence_score ≥ threshold`; `gated: true` with `reported: false` passed the gate but was suppressed (`EmissionPolicy`); `gated: false` was not kept by Phase 2: no `confidence_score` or `label`, but `scores.model` is still recorded. `logsentinel.window.trigger: indicator` selects the early windows.
- **One data model:** `score_window` builds a `WindowScore`; `document` derives both documents from it (a detection is the window score without `features`, with another `event.kind`/`event.dataset`, plus `event.category` and `event.type`). Test `test_the_two_documents_of_a_window_cannot_drift_apart`.
- **Identity:** `@timestamp` = `event.end` (event time). `logsentinel.window.id` = SHA-256 of `host.id` and `event.end` is the `_id` in both indices (`document_id` in `logstash-detection-sink`): a replay overwrites the same document and a detection joins its window score by that id. A window can be sent several times with the same id (the idle flush closes it before it is complete and later events of the same bucket close it again: a snapshot; an early window that ends exactly on a boundary has the id of the scheduled window): the later replaces the earlier in both indices and a reported window stays reported (`EmissionPolicy` treats the same `event.end` as the same window), so `verdict.reported` never differs between a detection and the window score of one id (`test_the_records_of_a_window_sent_twice_agree`).
- **`process` (early windows only):** the ECS `process` of the event that closed the window: `entity_id`, `name` (file name of `executable`), `executable`, `command_line` (Event 1 only) and `parent.entity_id`, each only if that event has it. Values are as `events.py` keeps them: case-folded, the command line cut at 32,768 characters. It is the process that brought the new indicator, not necessarily the malicious one. A scheduled window closes on a boundary, not at an event, so it has no `process`. Log records do not carry it (in a log record `process.*` would describe the service itself).
- `verdict.indicators`: strong first, then by weight. `threat`: union of the techniques/tactics of the indicators (`indicators.py`, table `MITRE`); `technique.id` is the parent technique, sub-techniques are in `technique.subtechnique.id`. `event.risk_score` is the raw `confidence_score` (0–1), `risk_score_norm` is ×100. Absent values are omitted, never `null`.
- **Elasticsearch** (mapping, ILM and templates: `../README.md` section 8): `dynamic: false`, `_id` = `logsentinel.window.id`, no data streams (replays must overwrite by `_id`). `process.command_line` is `wildcard` (ECS), the other `process.*` fields are `keyword` with `ignore_above` 1024. An unmapped field stays in `_source` but is not indexed, so tests check every field of every document shape against the joined templates (`test_every_field_is_mapped_in_the_index_template`) and the reverse (`test_the_templates_describe_nothing_the_service_does_not_write`); `tests/test_elasticsearch_config.py` checks that the files reference each other. Retention (delete-only ILM, one policy per index family): 365 days for detections and 90 for window scores, counted from creation of the monthly index; 30 days for `windows-telemetry`, from creation of the daily index.

---

## 8. Features

Input is the event JSON of `telemetry.windows.normalized`; training and inference use the same `logstash-ingest` output, so no schema mapping is needed. The service classifies **each 60 s window** of a host, scheduled or early (section 4.0): `summary.py` (`Summarizer`) counts everything, `features.py` transforms (counts → log1p; ratios and means unchanged); training and service share this code. The column order `FEATURE_NAMES` is part of the model contract (section 5.1). There are 37 features: 24 base features and 13 indicator flags.

| Group | Features | Source |
|---|---|---|
| Volume per event type | `events`, `code_1`, `code_2`, `code_3`, `code_11`, `code_12`, `code_13`, `code_17`, `code_26` | `event.code` (below) |
| File | `max_name_dirs`, `max_name_branches` (one file name in many directories; behind `mass_note_drop`), `distinct_extensions`, `max_same_extension` (behind `new_extension_burst`; feature only, section 4.1), `max_deletes`, `file_name_entropy` (mean; Shannon, base 2, over character frequencies) | Event 11, 23/26 |
| Process | `suspicious_path_ratio`, `non_system_executable_ratio` (keywords `suspicious_path`: Temp/AppData/Roaming/Startup/Downloads/ProgramData/Users; prefixes `system_executable`: C:\Windows\System32, C:\Program Files, C:\Windows), `command_line_length`, `lolbin_runs`, `stop_commands`, `max_cmd_children` | Event 1 |
| Registry, network | `run_key_writes`, `connections`, `destination_ips` | Event 13, 3 |
| Indicator flags | `ind_<indicator>` (0/1) for the 13 indicators of section 4.1 | Phase 2 |

- **Per-`event.code` counts:** 8 types — 1 (Process Create), 2 (File creation time changed), 3 (Network connection; network group, `../README.md` section 4), 11 (File created), 12 (Registry object added or deleted), 13 (Registry value set), 17 (Pipe Created), 26 (File Delete detected). Event 23 is unused: the Sysmon configuration disables it, deletions are Event 26, and the captures contain 0 Event 23. Event 12 is included because it is 15.9% of ransomware events vs 0.2% of goodware (run 2026-10-01).
- **`event.action` is not a feature key:** in SentinelCap data it looks like `<task> (rule: <RuleType>)` (e.g. `File created (rule: FileCreate)`), so matching event-name strings would give an all-zero vector. `event.code` ↔ `event.action` is 1:1 in real data (15 codes ↔ 15 strings over the 100 sessions of 2026-10-01). There is no `event.category` column: it is a function of `event.code` in real data.
- **Not used:** `path_length`, `directory_depth`, `process_vs_parent_freq_ratio`, `executable_depth_diff`, `parent_is_system_executable`, `extension_similarity`. Add one only when a measurement shows it separates the classes on SentinelCap data.

---

## 9. Training data, reliability and harness

### 9.1 SentinelCap loader rules

Rules of the loader (`training/sentinelcap_dataset.py`), derived from run 2026-10-01 (`captures/20261001T011932Z`). SentinelCap itself keeps all data and filters nothing at capture time.

1. **Format:** only `metadata.format = "logsentinel.normalized-sysmon.jsonl/v1"` with an `environment` block (100/100 sessions); others are skipped with a warning.
2. **Labels:** every event in `[t_start, t_end]` carries the session's `label.target_class`, background events included (largest source: Microsoft Edge Update, in 25/50 ransomware and 36/50 goodware sessions). Events from processes in `sample_entity_ids`: median 94.2% (lowest 52.4%) for ransomware, 82.7% (lowest 15.8%) for goodware. **Window label for training:** goodware windows are 0; a ransomware window is 1 only if it contains an event of a process in `sample_entity_ids`; background-only windows are not used (200 windows in run 2026-10-01).
3. **`sample_entity_ids` is for labelling and analysis, never a feature.** It holds the root process, reruns/copies with the same hash, processes started from files the sample's processes wrote (Event 11/29) and all descendants. The service has no such information at inference time, so features are computed per host window.
4. **Encryption without bulk file traces stays in the data:** in 4/50 sessions no file name is created in ≥ 10 directories (Sysmon logs no renames or overwrites): BlackBasta `17205c43…`, Conti `b14cde37…`, LockBit `032690f1…` (note in 9 directories), Medusa `49c9b3dd…`. Only process and command-line traces remain, so detection combines them with file features.
5. **Volume balance:** ransomware 210,730 events, goodware 478,364 (2.3×); one Anaconda session (`b545f4bd…`) is 36.2% of goodware events; events per session: ransomware 65–32,438 (median 1,916), goodware 362–173,058 (median 2,227). Cap windows per session (30) instead of pooling raw events.
6. **Split by family, not by session:** near-duplicates remain (same note name and directory count: Akira 4/5, Conti 2/10, LockBit 2/11, Trigona 2/3 sessions) and sessions per family are skewed (LockBit 11, Conti 10, BlackBasta 6, Akira 5, Medusa 4, BlackMatter 3, Trigona 3; Embargo, HelloKitty, Lynx, Nitrogen 2).
7. **No keyword list for note names:** 3/46 sessions with bulk notes match none (`help.txt`, `conti.txt`, `r3adm3.txt`); "same name in many directories" catches them.
8. **Sysmon event loss (Event 255, `winlog.event_data.ID = "QUEUE"`) is flagged, not dropped:** 1/100 sessions (HelloKitty `10887d13…`; `RegistryEvent` counts 63 … 8,192, so 8,192–16,383 events lost; the counts may be cumulative). The loader flags `events_dropped`, keeps each `<Type>:<count>` pair without summing, keeps the session and lists it in `model-meta.json` (`sessions.events_dropped`). Event 255 with another `ID` (`IMAGE_LOAD`) is not loss. Event 255 has no `process.*` or `event.category`, hence the `Optional` fields in `events.py`.
9. **"Concurrent goodware" test: evaluation only** (`overlay`): each held-out ransomware session is scored again merged by time with a goodware session (outside the fold's training set) shifted to start together; labels follow rule 2. Training on such mixed windows was tried and rejected; all variants detect 48/48 sessions and flag the same 2 goodware sessions (XAMPP, MDaemon) in the measurement below, made before the merged window flow (scheduled windows only, the former baseline in the confidence) and not repeated:

   | Training | Window AUC (seed 42 / 1 / 7) | Ransomware model-score drop with concurrent goodware | Max confidence of the 2 gated goodware |
   |---|---|---|---|
   | **No mixing (used)** | 0.941 / 0.945 / 0.931 | 0.11 – 0.14 | 0.65 – 0.81 |
   | Mixed, ≤ 10 windows/session | 0.915 / 0.907 / — | 0.03 | 0.79 – 0.84 |
   | Mixed, ≤ 30 windows/session | 0.898 / 0.901 / 0.900 | ≤ 0.02 | 0.76 – 0.85 |

   Mixing separates the classes worse and raises the confidence of flagged goodware; session-level results do not change. `evaluate` reports the test (`concurrent_goodware` in `evaluation.json`).
10. **Held-out runs (`--holdout RUN`):** `HOLDOUT` in the `Makefile` = `20261009T033557Z` and `20261009T120629Z` (the same 15 new ransomware samples captured twice). They are outside training, cross-validation and threshold selection; `evaluate` scores them last (`held_out`), only when the model was trained with the same list. A wrong run name, or a training run containing a sample (same hash) of a held-out run, stops `train` and `evaluate`; a run that recaptures held-out samples must go to `--holdout`.

### 9.2 Operational reliability

Each point has a test on real data (`tests/`); ✔ marks behaviour also run on real Kafka (section 9.3).

- **At-least-once delivery with replay ✔** (`offsets.py`, `service.py`). An input offset is committed only when its event is out of every window buffer and every record built from the windows containing it (window score, detection) is acknowledged. After a crash the consumer rereads from the committed offset, rebuilds open windows and resends unacknowledged records with the same `logsentinel.window.id` (one Elasticsearch document per index). Cost: at most one window replayed (longer for hosts that stopped sending, until `host_evict_sec`) and duplicates on the topics. Early windows follow the same rule: the buffer also holds the host's last 60 s, and the early-close decision depends only on those events (section 4.0), so the replay writes every window id again; it may also close an early window the first run did not, which adds a document. Tests: after a replay the ids on both topics cover an uninterrupted run (`test_replay_after_a_restart_loses_no_record`, crashes at seven points of a session), and in the pipeline every window after the crash point is written again (`test_a_restart_reproduces_every_window_that_comes_after_the_crash`).
- **Unscorable window** (`Pipeline._emit`). The exception is caught per window, counted in `internal_errors`, logged as `scoring_error`, the window skipped and no offset held; otherwise the replay would loop on the same window and disable detection for every host. `_shutdown` catches exceptions while emitting the last windows so `producer.flush` and `consumer.close()` always run, then exits with an error.
- **Delivery errors ✔.** No ACK within `delivery_timeout_sec` (60 s) or producer queue full for `produce_timeout_sec` (10 s): `DeliveryError`, exit code 1, Docker restarts, the replay recreates the records. SIGTERM: emit pending windows, flush within `shutdown_timeout_sec` (15 s); unacknowledged records → exit with an error. `stop_grace_period: 30s`.
- **Input boundary ✔** (`events.py`). Payload > 256 KiB, integer > 4,300 digits, JSON nested deeper than the parser handles (≈ 16,900 levels), timestamp outside 2000–2100 or QUEUE count > 18 digits → `InvalidEventError` (counted in `invalid`, the offset advances). Regexes run in linear time: token gap ≤ 256 characters, command lines cut at 32,768 characters (longest in the corpus 4,155, largest gap 16, so no result changes over 9,715 Event 1 command lines).
- **Host clock** (`windowing.py`). Windows follow `@timestamp`; after `late_reset_events` (20) consecutive events older than the window, the host follows the new clock (`clock_resets`), whether a forged future timestamp or a guest clock set back; its early-close state starts again too. The service clock is not used, so old captures replay.
- **Idle flush** (`window.idle_flush_sec`, `Pipeline.tick`). A scheduled window closes when the next event passes its end, so the last window of a burst waits for `idle_flush_sec` of silence; an early window closes at its own event. Default 3 s. Extra records reuse the same window id (one document). `idle_flush_sec` and `host_evict_sec` are not part of the window settings in `model-meta.json` (`WindowConfig.training_fields`): changing them needs no retraining.
- **Delay of the service loop (simulation).** All 150 sessions (120 with fold models, the 30 held-out ones with the full model, threshold 0.58) through the real `Pipeline` and a model of the loop: events arrive in 1 s clumps plus 0.5 s of Kafka/Logstash transport (`floor(event time) + 1.5 s`), `POLL_TIMEOUT_SEC` 1 s, `idle_flush_sec` 3 s. Not measured on real Winlogbeat and Kafka. The script and its output were temporary files and are not kept.

  | | Cross-validation (48 detected sessions) | Held-out (30 sessions) |
  |---|---|---|
  | First alert, first event of the sample's process → record: median / p90 | 2.96 s / 40.1 s | 3.66 s / 40.9 s |
  | First `suspicious` alert, same span: median / p90 | 3.68 s / 40.1 s | 3.66 s / 42.8 s |
  | The first alert is an early window | 48/48 | 30/30 |
  | Event that brings the alert → record: median / p90 / max | 0.89 s / 1.37 s / 1.50 s | 1.06 s / 1.41 s / 1.48 s |
  | Records sent (early windows) | 4,560 (164, 22 on goodware) | 1,050 (81) |

  Records are the window-score documents the service sends: a window sent again after an idle flush is one more record under the same id. The three cross-validation seeds (thresholds 0.58, 0.56, 0.61) give the same goodware result: 7 sessions alerted, 3 `suspicious` (MDaemon, XAMPP, `deploy-config-files`), 8 `suspicious` detection records (0.39/h), 27 detection records of any label (1.32/h; section 6 counts 25 detections in a replay without idle flush).
- **Host lifecycle.** A host silent for `host_evict_sec` gets its last window scored, then its window state, early-close state and suppression state are removed. No limit on host count; the memory of one host is bounded: at most `max_events_per_host` buffered events, plus at most a quarter of that in pushed-out events that the expiry heap of the trailing window still references until it is rebuilt (`test_a_stalled_clock_cannot_make_the_buffer_grow`). Measured on three real sessions (Akira, goodware, Medusa), with all events in one window: parsed event 746–812 bytes plus counting state 145–988 bytes per event, so a host at the limit of 200,000 events holds ≈ 190–350 MB.
- **Artifacts are one set ✔** (`artifacts.py`). Model `version`, window (size, slide), feature names and river version must match; the threshold is used only with the weights it was chosen for (`threshold_basis`). Anything missing, corrupt or inconsistent (including a model that has not been through `evaluate`) → exit code 2: no partial run, no default threshold. `train` writes `model.pkl` first and `model-meta.json` last; `evaluate` writes no threshold for a model trained with other settings. No per-file digests.
- **Healthcheck** (`status.py`, `healthcheck.py`). The loop writes `status.json` every second; unhealthy when it is older than 30 s or when no broker has been reachable for `kafka.down_after_sec` (librdkafka statistics; `GroupCoordinator` is ignored because it does not reflect the cluster). `degraded` only holds `kafka_unreachable`. No detections, or a silent host, is never unhealthy.
- **Known limits.** One instance (no rebalance/scale-out; `sink-inference` partitions by `host.name`, windows by `host.id`); single Kafka broker, replication factor 1, PLAINTEXT; memory queue in `logstash-detection-sink` (`../README.md` section 12); the model is a pickle (trust only `artifacts/` written by `training.train`); `python:3.14-slim` without digest (a model trained with another Python patch only warns); after an idle flush a later snapshot replaces the earlier one in both indices and a reported window stays reported.

### 9.3 Verification on real Kafka (lab stack)

Row 1 ran on real Kafka with the merged window flow (schema 2), on the stack rebuilt clean on 2026-10-12; the other rows ran with the build before it (schema 1) and were not repeated.

Row 2 was measured with a single output topic, so its `produced`/`acked` count detections only.

| Scenario | Result |
|---|---|
| kill -9 mid-stream, restart with the same group (`training/e2e_restart.py`; BlackBasta `11129aad…`, 344 events, own topic; killed at `consumed=206 produced=19 acked=19`) | Uninterrupted run: 21 window scores, 13 detections. Rerun: `consumed=344`, `produced=34`; detections topic 22 messages / 13 distinct ids, window-scores topic 31 / 21; **0 ids missing** |
| Goodware replay, then Conti about 11 h earlier, same host | `late_events=20`, `clock_resets=1`, `produced=2`, `acked=2`: follows the new clock, emits Conti's 2 detections |
| 6 hostile messages: not JSON (16 B); integer > 4,300 digits (6.7 KB); nesting 20,000 levels (40 KB); QUEUE count of 4,301 digits (5.7 KB); 300 KB message; QUEUE text of 200,000 letters (201 KB) | `invalid` 0→5, `consumed` 747→753 (5 of 6 `invalid`, 1 processed); 0 restarts; the goodware batch sent afterwards fully processed (753→1413). QUEUE regex: 0.034 s on 40,000 characters (unbounded: 16.5 s) |
| Undeliverable output topic (`bad topic name!`) | `Broker: Invalid topic` per record, exit code 1 after 3.7 s |
| No artifacts; `weight_global_model: .inf`; threshold chosen for weight 0.3 but config 0.6; missing config file | Exit code 2 after 1.8 s, 1.5 s, 1.7 s and 1.6 s, reason in the log (`Cannot start without a complete model that fits this configuration: …`; `1 validation error for ServiceConfig`; `the model's threshold 0.50 cannot be used: it was chosen for scoring.weight_global_model=0.3 but the service uses 0.6`; `Invalid configuration: Config file not found`) |
| `docker stop` (SIGTERM) while holding a Conti window | 1 s, exit code 0, `Signal 15 received: shutting down` and the final statistics line; after restart `consumed=1` |
| Broker down for over 2 minutes, then back | t+12 s `degraded: [kafka_unreachable]`, `kafka_down_for_sec=13.0`; healthcheck exit 1 from t+65 s (67.1 s; `down_after_sec` 60 s); Docker (interval 30 s, retries 3) reports `unhealthy`; broker back: exit 0 within 9 s, `RestartCount=0`; Medusa replay (697 events) still detects |

librdkafka statistics on a real broker: before any connection only `…/bootstrap` (`nodeid -1`, `CONNECT`) and `GroupCoordinator` (`nodeid -1`, `INIT`) exist; with a live broker `GroupCoordinator` is always `UP`. `KafkaMonitor` counts `…/bootstrap` and ignores `GroupCoordinator` (counting only `nodeid ≥ 0` would report `up` forever without a broker); the real structure is stored in `STATS_*` in `tests/test_service.py`.

**Audit summary** (measured 2026-10-09 UTC on the lab stack, updated 2026-10-10 and 2026-10-12; scope: code quality, configuration and design of the lab). Measurements and scripts were temporary files and are not kept. Re-check with `python scripts/verify_detections.py` and `bash scripts/healthcheck-all.sh`. Performance and the kill -9 result of Reliability were measured with the merged window flow; the other rows describe the build before it.

| Area | Result |
|---|---|
| Performance | Pass. One thread ≈ 21.2 thousand events/s (decode 22.2 µs + pipeline 25.0 µs per event; 689,094 events of run 2026-10-01 in memory, median of 3; measured 2026-10-11 with the merged flow) vs a real peak of 1,875 events/s (≈ 11×). Previous build on the stack: 0.16–0.25 % CPU, 194 MiB. Narrowest point: `logstash-ingest` (one worker for order), ≈ 1.6 thousand events/s with the old filter, an estimated ≈ 2.7 thousand with the cheaper one (`../README.md` section 7.1). Latency: section 9.2 |
| Reliability | Good. kill -9 and rerun on the clean-rebuilt stack lost no id (21 window scores, 13 detections). From `docker compose up -d` the init services exit 0 after about 30 s (4 topics, 8 Elasticsearch resources) and all six services are `healthy` after 77 s; an incomplete or inconsistent model set stops the service (exit 2) |
| Correctness | Pass. 15/15 sessions of run `20261009T120629Z` (5 families not in training) flagged `suspicious`, a median 7.7 s after session start; event order correct; 0 grok failures (previous build). A reported window is no longer overwritten as `reported:false`, and an unscorable window no longer restarts the service; both are locked by tests |
| Stability | Stable. Longest observation over 4 hours: 0 restarts, 0 OOM; after the rebuild six `healthy` containers, 0 restarts. No multi-day soak yet |
| Not verified | Real VM events have not flowed through the rebuilt stack (VM off). The next capture creates `windows-telemetry-*` and the monthly indices from the templates; then run `python scripts/verify_detections.py` (expected: no "no documents yet", no FAIL) |

### 9.4 Logging

- Every module logs through `logging.getLogger(__name__)`; `logs.py` configures logging from environment variables only: `INFERENCE__LOG__LEVEL` (DEBUG, INFO default, WARNING, ERROR, CRITICAL) and `INFERENCE__LOG__FORMAT` (`text` default; `json` set by compose). An invalid value → exit code 2.
- One record per line on stdout, UTC with milliseconds. `json` is ECS with dotted top-level keys: `@timestamp`, `log.level`, `log.logger`, `message`, `service.name`, `service.version`, `event.module` = `logsentinel`, `event.dataset` = `logsentinel.inference`, `ecs.version`, record fields, and `error.type`/`error.message`/`error.stack_trace` (one line). The scoring pipeline logs as `inference.pipeline` (DEBUG window records, `scoring_error`, clock and queue warnings), the Kafka loop as `inference.service`, librdkafka as `inference.librdkafka` and library warnings as `py.warnings`; an unexpected exception is one CRITICAL record, then exit code 1. Messages over 4096 characters are cut.
- Levels: ERROR = unrecoverable or undelivered detection; WARNING = handled anomaly (bad input, clock skew, broker loss); INFO = lifecycle, statistics, delivered detections; DEBUG = one record per scored window.

| `event.action` | Level | When | Main fields |
|---|---|---|---|
| `startup` | INFO | start | `logsentinel.model.version`, `logsentinel.verdict.threshold`, `logsentinel.threshold_source`, `logsentinel.kafka.{input_topic, detections_topic, window_scores_topic, group_id}` |
| `stats` | INFO | every `stats_interval_sec`, at shutdown | `logsentinel.stats.<counter>` cumulative (names as in `status.json`: consumed, invalid, consumer_errors, late_events, clock_resets, overflow_events, windows, early_windows, gated, suppressed, detections, produced, acked, pending_outputs, delivery_errors, internal_errors, sysmon_dropped, hosts), `logsentinel.stats.uptime_sec`, `logsentinel.kafka.down_sec` |
| `detection` | INFO / ERROR | detection acknowledged / delivery failed | `event.outcome`, `event.start`, `event.end`, `logsentinel.window.{id, trigger}`, `logsentinel.verdict.{label, confidence_score, threshold, indicators}`, `logsentinel.model.version`, `logsentinel.monitored_host.{id, name}` (same paths as the document in `ransomware-detections-*`) |
| `window_score` | ERROR | window-score delivery failed (success is not logged) | as `detection` |
| `kafka_connection` | WARNING / INFO | broker lost / back | `logsentinel.kafka.up`, `logsentinel.kafka.down_sec` |
| `scoring_error` | ERROR | a window was skipped (at most one record per `stats_interval_sec`) | `logsentinel.monitored_host.id`, `event.end`, `logsentinel.stats.internal_errors`, `error.*` |
| `shutdown` | INFO / ERROR | stop signal, stopped, stopped with error | `event.outcome` |

The monitored machine is under `logsentinel.monitored_host.*`, not `host.*` (ECS reserves `host.*` for the machine that produced the log). DEBUG window records carry `logsentinel.window.{id, trigger}`, `logsentinel.window.activity.events` and `logsentinel.verdict.{gated, suspicious, reported, indicators, confidence_score}`. Docker keeps 3 files × 10 MB of logs per container (`x-logging` in `docker-compose.yml`); `../scripts/healthcheck-all.sh` also prints service state and consumer-group lag. There is no log index in Elasticsearch (shipping logs there with Filebeat is a separate step).

### 9.5 Admin-scenario goodware and held-out runs

**Data.** 20 `--interactive` goodware sessions in 4 runs (`20261008T013340Z`, `20261008T050249Z`, `20261008T192247Z`, `20261008T195850Z`; 15.89 hours): 15 short admin scenarios and 5 continuous ones (Windows Update 3.9 h, AD DS install 3.7 h, server file download 3.0 h, backup verification 0.8 h, health monitoring 0.4 h). Held-out run `20261009T033557Z`: 15 new ransomware samples, no hash shared with any training run; run `20261009T120629Z` recaptures exactly those 15.

**Scenarios that trigger a strong indicator** (7 of 20; last column: current model, out-of-fold cross-validation):

| Scenario | Strong indicator | Command / activity | Flagged suspicious |
|---|---|---|---|
| boot-config-maintenance | `recovery_disable` | `bcdedit /set {default} recoveryenabled no`, `bootstatuspolicy ignoreallfailures` | no |
| deploy-config-files | `mass_note_drop` (+ `ransom_note_keyword`) | PowerShell writes `project-readme.txt` to 32 directories in 27 branches | **yes** |
| log-archival | `event_log_tamper` | `wevtutil cl application`, `wevtutil cl "windows powershell"` | no |
| service-maintenance | `service_stop_burst` | `net stop spooler/wuauserv/bits /y`, `sc stop wsearch/themes`, repeated | no |
| shadow-copy-cleanup | `shadow_copy_deletion` | `vssadmin delete shadows /oldest`, `vssadmin resize shadowstorage`, `wbadmin delete catalog` | no |
| windows-update-maintenance-continuous | `event_log_tamper` (Event 13) | `TiWorker.exe` registers log channels as disabled | does not pass the gate (section 4.1) |
| ad-install-operations-continuous | `event_log_tamper` (Event 13) | as above | does not pass the gate |
| other 13 scenarios (backup, compress-documents, file-encryption, disk-cleanup, …) | — | — | no |

The first four use exactly the commands ransomware uses, so rules cannot separate them; that is Phase 3's job. Over 20.4 hours of goodware (installers and scenarios): 8 suspicious detections, 3 flagged sessions (`evaluation.json`).

**Decisions in force** (in-memory cross-validation, seed 42, same folds; each scenario whole in one fold, so scored unseen):
- Scenario goodware is trained with all other labelled data except held-out runs, and `evaluate` picks the threshold. Versus a model blind to it with the threshold set from it (0.55): same false-alarm level (0.31 suspicious/hour on scenario goodware), earlier detection (median 8.7 s vs 9.5 s, p90 43.1 s in both). Measured on an earlier build, before `mass_file_replace` existed and before the merged window flow.

**Held-out runs: 15 samples captured twice** (operator confirmed all 15 encrypt; model `20261011T202925Z`, threshold 0.58). Each cell: run `20261009T033557Z` / run `20261009T120629Z`:

| Family | Max confidence | Time to first detection |
|---|---|---|
| Akira `369336e9…` | 0.96 / 0.96 | 2.1 s / 2.1 s |
| BlackBasta `2413841b…` | 0.92 / 0.92 | 3.7 s / 2.7 s |
| BlackMatter `46a9f920…` | 0.96 / 0.95 | 41.7 s / 42.8 s |
| BQTLock (new family) `425b2f28…` | 0.95 / 0.97 | 52.6 s / 39.4 s |
| Conti `248cf7de…` | 0.81 / 0.81 | 5.1 s / 5.1 s |
| HelloKitty `af179b09…` | 0.80 / 0.80 | 2.1 s / 2.1 s |
| LockBit `105912c9…` | 0.99 / 0.96 | 1.3 s / 1.6 s |
| Lynx `b378b7ef…` | 0.80 / 0.80 | 2.2 s / 2.0 s |
| Makop (new family) `f0a17efd…` | 0.99 / 0.99 | 15.6 s / 14.1 s |
| Medusa `6d000a15…` | 0.92 / 0.91 | 3.6 s / 2.4 s |
| Nebula (new family) `112a40f1…` | 0.97 / 0.97 | 1.9 s / 2.0 s |
| Nitrogen `b5189876…` | 0.80 / 0.80 | 0.6 s / 0.6 s |
| Trigona `48877a3a…` | 0.95 / 0.95 | 15.2 s / 15.4 s |
| WhiteLock (new family) `a501583b…` | 0.5803 / 0.6539 | 48.6 s / 16.8 s |
| Yurei (new family) `0303f898…` | 0.95 / 0.99 | 1.3 s / 0.9 s |

Result: **30/30** (15/15 per run), median 2.7 s, p90 42.8 s, max 52.6 s (run `20261009T033557Z`: median 3.6 s, max 52.6 s; run `20261009T120629Z`: median 2.4 s, max 42.8 s). Lowest maximum confidence: WhiteLock (0.5803, 0.6539), against the 0.58 threshold; in the first run its first detection comes at 48.6 s. Not independent: WhiteLock writes a copy `<name>.fbin` and deletes the original, drops no note and touches neither shadow copies nor services, so before `mass_file_replace` (weight 0.8) none of its windows passed the gate and run `20261009T033557Z` detected only 14/15; rule and weight were chosen after seeing it. Both runs are the same samples and ransomware only (no false-alarm measurement), so a new held-out batch is needed.

**Remaining hard case:** `deploy-config-files` spreads one file named `readme` over many directories, exactly like dropping ransom notes. No separating rule can be derived from a single scenario; more goodware of this kind is needed first.

### 9.6 Harness and layout
- `tests/` — `make test` (fast, real data, fake broker that acknowledges immediately, manually or never). Fixtures come from `tests/fixtures/build_fixtures.py`: 6 complete sessions (gzip) and 10 single events chosen by `record_id` from real captures. Counting is checked against `tests/reference_summary.py`, a recount of a window from scratch (section 4.0). Reliability scenarios have their own tests (offsets advance only after ACK, crash/stop + replay loses nothing, delivery failure stops the service, full producer queue, hostile messages, host clock jumps, mismatching artifacts).
- `training/evaluate.py` — indicator coverage over the service's scheduled windows, family-grouped CV on sessions replayed through `Pipeline` (MCC, F2 at window and session level, AUC), threshold selection, concurrent-goodware test, goodware detections per hour after suppression, time to first detection.
- `training/e2e_restart.py` (`make e2e-restart`) — kill -9 the service mid-stream on a real broker and rerun it; nothing may be lost (section 9.3).
- `training/replay_to_kafka.py` — replays the exact payloads of one session into `telemetry.windows.normalized` (key `host.name`, like `sink-inference`); `--realtime` keeps the original spacing (at most 5 s). Timestamps are not changed, so replay only while the victim VM sends no logs (same `host.id`):
  ```bash
  python -m training.replay_to_kafka ../sentinelcap/captures/<run>/conti/<hash> --bootstrap <host>:9092
  docker exec logsentinel-kafka /opt/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server localhost:29092 --topic security.ransomware.detections --from-beginning
  ```
- `artifacts/` — `model.pkl`, `model-meta.json`, `evaluation.json` (`make model`); mounted read-only into the container.

```
inference/
├── AGENTS.md  README.md  config.yaml  Dockerfile  Makefile  pyproject.toml  .pre-commit-config.yaml
├── src/inference/      # the service (table in section 2.1)
├── training/
│   ├── sentinelcap_dataset.py  # loader rules (section 9.1)
│   └── train.py  evaluate.py  e2e_restart.py  replay_to_kafka.py
├── tests/              # tests, real fixtures (tests/fixtures), fake broker (fakes.py)
└── artifacts/          # model.pkl, model-meta.json, evaluation.json
```

---

## References
- River (incremental machine learning, Python): https://riverml.xyz
- MITRE ATT&CK: https://attack.mitre.org/
- Elastic Common Schema (ECS): https://www.elastic.co/guide/en/ecs/current/index.html
- `../sentinelcap/README.md` — source of the training and evaluation data
