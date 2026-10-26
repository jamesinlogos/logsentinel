# AGENTS.md — guide for AI coding agents working on SentinelCap

## Context
`sentinelcap` is the CLI that collects LogSentinel training data: it builds the Windows lab VM via VMware (`build baseline`), captures the original normalized payloads of ransomware and goodware sessions from the Kafka topic `telemetry.windows.normalized`, and writes JSONL with labels in a separate metadata file. This document is the source of truth for its behavior (code: `src/sentinelcap/`); changes must preserve it.

## Required reading before coding
1. `README.md` — usage, output format, goodware scenarios (`scenarios/`); its "Known limitations" section lists what is **deliberately not done**.
2. `src/sentinelcap/{manifest,config,errors,session,capture,orchestrate,baseline,guest_names,cli,vm}.py`.
3. `../README.md` section 3.2 and `../inference/README.md` section 3 — where SentinelCap data goes; normalized event schema.

## Mandatory principles (non-negotiable)
- **Never execute a sample.** The operator double-clicks it in the VM; the tool only opens Explorer (`vm.open_explorer`) and waits. `build baseline` only copies, extracts (7-Zip in the guest) and renames files.
- **Never unpack ransomware on the host;** AES-256 zips are extracted only in the guest.
- **UAC (settled, do not re-propose):** UAC stays enabled (default) in the snapshot, never disabled; the operator always clicks Yes, in both classes. No captured ransomware sample showed a prompt, goodware installers usually do; the resulting `process.integrity_level` difference is kept (using it as a feature is a training-side decision). Never add automatic UAC handling.
- **Lossless:** `session.jsonl` holds each payload byte-for-byte as received from Kafka. Fields may be parsed to find bounds/conditions; **never modify, add or remove one**. Labels live only in `metadata.json`.
- **Labels come only from the manifest `label` column** (`--label`), never from `family` or the presence of `path`.
- **Fail-fast:** an invalid session (no Event 1 of the sample, existing directory, bad manifest) writes nothing and reports a clear error; a failure on any sample in `build baseline` creates no `baseline` snapshot; a failure in `build validate` creates no `validate` snapshot. Never skip silently.
- **Simplicity:** add nothing beyond the behaviors described here (including the "Known limitations" of `README.md`); if a design point is unclear, stop and ask.
- **Test and VM safety:** never write or delete files in the existing `captures/` (user test data; tests use `tmp_path`); tests never run real VMware or Kafka; do not run `sentinelcap build baseline/validate/run/batch` on the real VM unless the user asks.

## Event fields that may be read
Only these (nested ECS paths in the payload):

| Field | Used for |
|---|---|
| `@timestamp` | time bounds (UTC, with timezone) |
| `host.id` | right-VM filter (pre-existing) |
| `event.code` | recognize Event 1 (`"1"`), Event 11/29 |
| `event.created` | pipeline delay (`pipeline_lag_*`); ignored if missing or malformed |
| `process.executable` | match the sample `path` (case-insensitive) |
| `process.hash.sha256` | match the `sample` hash (lower-case SHA-256) |
| `process.entity_id`, `process.parent.entity_id` | the sample's processes and descendants |
| `file.path` | files the sample's processes wrote (Event 11/29), to recognize processes started from them |
| `host.os.build`, `agent.version` | `metadata.environment` (first event in the window only) |

## Behavior
**Manifest** (`manifest.py`): columns `family, sample, path, label`; checked on load:
- `label ∈ {0,1}`; `family`, `sample` non-empty.
- `--execute`: `sample` is 64-character hex, `path` present.
- `--interactive`: `path` empty; `sample` is a free scenario name safe for a directory name (e.g. `backup`, `backup-2`), kept verbatim as `scenario`.
- The CLI flag sets the mode; a non-matching row is an error.

**`build baseline`** (`baseline.py`, `guest_names.py`):
1. Revert `vmware.original_snapshot` → start → wait for VMware Tools and `start_boot_wait_sec`.
2. In the guest, list existing non-hidden sub-directories of `baseline.sample_target_roots` (`vm.list_dirs_in_guest`, PowerShell `-EncodedCommand`); keep only those inside a root with no `setup` in the path (`guest_names.usable_target_dirs`). Create none.
3. Place samples:
   - Host layout: `samples_dir/ransomware/<Family>/<sha256>.zip` (class 1, `family` = lower-cased directory name), `samples_dir/goodware/<sha256>.exe` (class 0, `family = goodware`); other files are ignored.
   - Spread each class over the roots (`guest_names.spread_over_roots`: per-root counts differ by ≤ 1 within a class, whatever the sub-directory count); stop before placing anything if a root has no usable sub-directory.
   - `random.Random(seed)` picks each sample's directory (in its root) and name `<base>_<4 hex>.exe`: no SHA-256, no Sysmon exclude-rule match (`guest_names.is_safe_name`).
   - Ransomware: copy the zip to `C:\Windows\Temp` → `7z x <zip> -p<password> -o<dir> -y` in a PowerShell `-EncodedCommand` script (single-quoted string arguments, not on the vmrun command line; output to `C:\Windows\Temp\sentinelcap-7z.log` and into the error message) → check `<dir>\<sha256>.exe` exists (`fileExistsInGuest`; stop if not) → `vmrun renameFileInGuest` (no guest shell) → delete the zip.
   - Goodware: copy straight to the new path.
   - Never pass paths with spaces on the `runProgramInGuest` command line (vmrun joins arguments into one line); use `vm.run_powershell` or vmrun file commands.
4. Delete, then recreate `vmware.baseline_snapshot` **while the VM is running and logged in**; stop if it still exists after deletion; then power off.
5. Write `manifest.csv` (`family,sample,path,label`); an existing one is always kept as `manifest-<YYYYMMDDTHHMMSSZ>.csv` (UTC).

**`build validate`** (`baseline.py`):
1. Same revert/start/list as `build baseline` from `original`; does **not** modify `baseline` or `manifest.csv`.
2. Pair every ransomware with a goodware from `samples_dir`: both classes required and **equal counts** (fail-fast otherwise); `random.Random(seed)` shuffles each class then zips them into pairs.
3. Place each pair into the **same** usable guest directory (distinct directories for different pairs when enough exist; seeded names); placement mechanics match `build baseline` (7-Zip in guest for ransomware, direct copy for goodware).
4. Delete, then recreate `vmware.validate_snapshot` (default `validate`) while the VM is running and logged in; then power off.
5. Write `manifest-validate.csv` (ransomware then goodware per pair, in pair order); an existing one is kept as `manifest-validate-<YYYYMMDDTHHMMSSZ>.csv`.

**`batch --validate`** (`orchestrate.py`, `manifest.group_validate_pairs`):
1. Load `manifest-validate.csv` with the same row rules as `--execute`; group rows into pairs that share a guest parent directory (exactly one label 1 and one label 0 each).
2. For each pair: revert `vmware.validate_snapshot` → start → wait for VMware Tools → open Explorer once at the shared directory.
3. The operator double-clicks **both** executables. Buffer until Event 1 of each appears within `exec_detect_timeout_sec`; missing either invalidates the pair and writes nothing for it.
4. Two `ExecuteSession`s share the event stream; recording stops when **both** quiet/max-wait rules are met. Then `post_capture_drain_sec`.
5. Export two sessions into the same run directory (`mode = "validate"`, `environment.snapshot` = `validate`); each uses its own `t_exec`/`t_end`, `process_entity_id` and `sample_entity_ids`. A failed pair records an error for both rows and the batch continues.
6. Does not touch the `baseline` snapshot. `run` does not accept `--validate`.

**`--execute`** (`orchestrate.py`):
1. Revert `baseline` → start → wait for VMware Tools → open Explorer at the directory of `path` (PowerShell `Start-Process` in `-EncodedCommand`, so `3D Objects` stays one argument).
2. From consumer readiness, buffer every host event. The first Event 1 matching `path` + `sample` gives `t_exec` (`@timestamp`) and `process_entity_id`; none within `exec_detect_timeout_sec` (default 120) invalidates the session.
3. Recording starts at `t_exec` (earlier events are dropped).
4. Record at least `settle_sec` (120) from `t_exec`, then stop at the first of:
   - **90 continuous seconds** (`quiet_window_sec`) without an event of the sample's processes (step 5), counted from the later of their last event and the end of settle (silence during settle does not count: minimum session 210 s);
   - `max_wait_sec` (300) more seconds (420 s maximum in total).

   No Enter key in this mode.
5. Sample processes (`ExecuteSession`, `session.py`):
   - the root process;
   - any process whose `process.executable` contains the sample hash (reruns, e.g. self-elevation via `dllhost.exe`, or `<hash>_online.paf.exe`);
   - any process with an Event 1 whose `process.hash.sha256` equals the sample hash (renamed copies);
   - any process with an Event 1 whose `process.executable` equals a `file.path` earlier written (Event 11 or 29) by a process in the set (dropped payloads, whoever launches them; case-insensitive, `\\?\` prefix stripped);
   - descendants of all of these (Event 1 with `process.parent.entity_id` in the set).

   A hash on a non-Event 1 event (e.g. Event 23) is not enough. Other processes spawned via WMI/services are not in the set (known limitation). The final list goes to `sample_entity_ids`.
6. Quiet time and the cap use the host monotonic clock from each event's arrival; `t_end` = `t_exec` + elapsed time. After stopping, wait `post_capture_drain_sec` (45), then drop events with `@timestamp > t_end`.

**`capture`** (separate command, no VM control): records `--duration` seconds on the host clock, converts to the guest clock with `clock_offset_sec`, exports in the same directory format with `mode = "capture"`; `sample` is the session name (e.g. `idle-01`, validated like `--interactive`); `environment.snapshot` is `null`.

**`--interactive`**: print the scenario name → wait for Enter (`t_start`) → record → wait for Enter (`t_end`). Enter uses the host clock; `clock_offset_sec` is the median of (host receive time − `@timestamp`) over the first `clock_offset_median_events` (5) events and converts `t_start`/`t_end` to the guest clock. No operator action is verified; no list of expected Event IDs.

**Storage** (`capture.py`):
- Each `run`/`batch`/`capture` creates a run directory `<out_dir>/<YYYYMMDDTHHMMSSZ>/` (UTC; one for all rows of a `batch`); a session is `<run>/<family>/<sample>/` with `session.jsonl` and `metadata.json`.
- `family` is lower-cased and must match `[A-Za-z0-9_-]+`.
- Within a run, the same `sample` under another family is always refused, even with `--force`; an existing directory is refused unless `--force`. Write only valid sessions.
- Safe write: both files go to `<family>/.<sample>.partial/`, renamed to `<sample>` when complete. With `--force` the old session is first renamed `.<sample>.old`, deleted after the swap. The next export of the same family/sample removes a leftover `.partial` and restores `.old` after an interrupted swap. A directory starting with `.` is unfinished.
- If `pipeline_lag_max_sec ≥ post_capture_drain_sec`, warn (the session is not cancelled).

**Metadata** (`metadata.json`): `format = "logsentinel.normalized-sysmon.jsonl/v1"`, `session_id`, `source`, `label` (`target_class`, `target_class_name`) and:
```json
{
  "mode": "execute",
  "t_start": "...Z", "t_end": "...Z",
  "process_entity_id": "{...}",
  "sample_entity_ids": ["{root}", "{...}"],
  "scenario": null,
  "clock_offset_sec": 0.0,
  "event_count": 0,
  "pipeline_lag_max_sec": 12.3, "pipeline_lag_p50_sec": 1.2,
  "skipped_other_hosts": 0, "skipped_invalid": 0, "skipped_outside_session": 0,
  "environment": {
    "sentinelcap_version": "1.0.0",
    "snapshot": "baseline",
    "windows_build": "20348.587",
    "winlogbeat_version": "9.5.4"
  }
}
```
- `mode` is `execute`, `interactive`, `capture` or `validate`. `process_entity_id` and `sample_entity_ids` exist for `execute` and `validate`, `scenario` (verbatim) only for `interactive`; `label.target_class` comes from the `label` column.
- `pipeline_lag_*`: max/median of `event.created − @timestamp` over the selected events; `null` if none has `event.created`.
- `environment.snapshot` is `vmware.baseline_snapshot` (`execute`/`interactive`), `vmware.validate_snapshot` (`validate`), or `null` (`capture`); `windows_build` and `winlogbeat_version` come from the first event in the window (`null` if missing). No configuration-file hashes.
- `skipped_invalid` counts messages that are not a JSON object (host unknown: skipped with a warning, session not cancelled). For another host's message only `host.id` is read; it counts in `skipped_other_hosts`. Victim-VM events are still read strictly (a bad `@timestamp` cancels the session).

**CLI** (`cli.py`):
- `run` takes exactly one of `--execute`/`--interactive`.
- `batch` takes exactly one of `--execute`/`--interactive`/`--validate`.
- `batch` prints a per-row result table (success or failure with the reason) and exits non-zero if any row failed.
- `capture` takes `--family`, `--sample`, `--label`, `--duration`, `--force`; `build baseline` and `build validate` take `--samples-dir`, `--seed`; the `vm` group only controls the VM manually.

**Config** (`config.py`, `config.yaml`): precedence CLI > `SENTINELCAP__…` environment variables > YAML > defaults.
- `vmware.original_snapshot` `original`, `vmware.baseline_snapshot` `baseline`, `vmware.validate_snapshot` `validate`; `kafka.post_capture_drain_sec` 45 (under `kafka`, not `capture`).
- `capture.exec_detect_timeout_sec` 120, `quiet_window_sec` 90, `settle_sec` 120, `max_wait_sec` 300, `clock_offset_median_events` 5.
- `baseline.samples_dir` `samples`, `sample_target_roots`, `sample_zip_password` `infected`, `sevenzip_guest_path` `C:\Program Files\7-Zip\7z.exe`, `seed`.
- Unknown YAML keys are rejected (as in inference); empty environment variables are ignored. Do not touch `guest_password`.

## Code layout
| File | Role |
|---|---|
| `manifest.py` | Read and validate the manifest per mode; `group_validate_pairs` for `--validate` |
| `config.py` | VMware, Kafka, capture and baseline settings |
| `errors.py` | `SentinelcapError` (root; `VMwareError` derives from it) |
| `guest_names.py` | Sample names, forbidden tokens, target-directory filter |
| `session.py` | Pure functions: event fields, `t_exec`, the sample's process set, quiet rule |
| `capture.py` | Kafka consumer, host event buffer, clock offset, `prepare_session_dir`, safe session write, pipeline lag |
| `baseline.py` | `build baseline` / `build validate`: find samples, place, snapshot, manifest |
| `orchestrate.py` | `execute`, `interactive`, `validate` pair, `capture`, `batch` flows; run directory |
| `cli.py` | Commands `run`, `batch`, `capture`, `build baseline`, `build validate`, `config`, `vm` |
| `vm.py` | VMware control via `vmrun` (snapshots, guest file/program operations); `run_in_guest` rejects arguments with whitespace, pass such values through `run_powershell` |

## Testing and quality
- From `sentinelcap/`: `..\.venv\Scripts\python.exe -m pytest tests -q` (Python 3.10+, `pythonpath = ["src"]`). Quality (`pip install -e .[dev]`): `ruff format --check src tests`, `ruff check src tests` (line length 100, `E501` enforced; `B008` ignored in `cli.py`, Typer's API), `mypy` (config in `pyproject.toml`). Full type hints on public functions. Version declared only in `pyproject.toml`.
- Unit tests need no Kafka/VM (fake consumer, `unittest.mock` or fake controller); fake events need only the fields in the table above. Real events for field-reading tests: `../inference/tests/fixtures/sentinelcap-normalized-events.json`.
- Required tests:
  - Manifest: `family` lower-cased; rejected: a `family` unsafe for a directory name, `label` outside {0,1}, no `path` with `--execute`, `path` with `--interactive`, a `sample` that is not 64-character hex, a session name unsafe for a directory name; scenario names kept verbatim (including `backup-2`).
  - `t_exec`: path matched case-insensitively, sha256 matched; no valid Event 1 means an invalid session and no file written.
  - Sample processes. Counted: a rerun (parent `dllhost.exe`), a path containing the hash, a copy with the same sha256, a payload written by a sample process then run (Event 11 and 29, `\\?\` prefix), their descendants. Not counted: a file written by an unrelated process, an Event 1 before the file was written, an unrelated process, a process spawned via WMI, a hash on a non-Event 1 event.
  - Quiet rule: stops at the right threshold and cap.
  - Export: writes `<run>/<family>/<sample>/`; an existing directory is refused, `--force` overwrites; the same sample under another family is always refused; `session.jsonl` bytes unchanged; metadata has `environment`, `sample_entity_ids`, `pipeline_lag_*`; a failure mid-write leaves no target directory; an interrupted `--force` swap restores the old session; a `.partial` under another family does not block `sample`; the lag warning fires at the right threshold.
  - Clock offset: median over the first N events.
  - `capture`: writes the run-directory format with `mode = "capture"`; rejects bad input.
  - `batch`: a failing row does not stop the rest; result table; non-zero exit code; one shared run directory.
  - `batch --validate`: pairs by shared guest directory; revert to `validate`; both Event 1s required; stop when both quiet; two exports with `mode = validate`; a failed pair marks both rows and continues.
  - `vm`: correct `vmrun` arguments per operation; arguments with spaces quoted; `delete_snapshot` errors if the snapshot remains after deletion.
  - `guest_names`: forbidden tokens rejected; generated names safe; seeded selection reproducible; directories containing `setup` or outside the root excluded.
  - `build baseline`: order revert/start/list/place/snapshot/power off; 7-Zip with `x -p -o -y`; zip extracted then renamed; extraction failure creates no snapshot and writes no manifest; the manifest re-reads with `Mode.EXECUTE`.
  - `build validate`: every ransomware/goodware pair shares a guest directory; equal counts required; `validate` snapshot (not `baseline`); `manifest-validate.csv`; unequal counts or a missing class is an error before placement.

## Definition of done
- New and updated tests pass; type hints and lint are clean.
- Each item under "Behavior" has a test or is explicitly noted as untestable without a real VM/Kafka.
- No change beyond this document's scope; unclear points were raised with the user.
- `AGENTS.md` and `README.md` describe the behavior correctly after the change.
