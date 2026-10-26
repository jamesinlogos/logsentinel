# SentinelCap

SentinelCap collects labeled, normalized Windows Sysmon sessions (ransomware and goodware) for LogSentinel training and evaluation. `build baseline` prepares a VMware Workstation victim VM; the operator launches each sample by hand in the guest and SentinelCap captures the original normalized Kafka messages.

**SentinelCap never executes a sample.** `build baseline` only copies, extracts and renames sample files in the guest. A session reads only a few event fields (timestamp, host, event code, process path/hash/entity ids, file path, `event.created`) to find its bounds; it never modifies, maps, flattens or enriches telemetry, so `session.jsonl` is the exact normalized payload the inference service consumes.

See also: `AGENTS.md`, `../README.md` sections 3.2 and 10.4, `../inference/README.md` section 4.1.

## Architecture

```text
Winlogbeat -> telemetry.windows.sysmon.raw -> logstash-ingest (pipeline "ingest")
                                                 |-> sink-es -> Elasticsearch (audit/hunting)
                                                 `-> sink-inference -> telemetry.windows.normalized
                                                                   |-> inference
                                                                   `-> SentinelCap capture
```

Logstash owns Sysmon parsing, ECS normalization, hash extraction and MITRE enrichment. SentinelCap only applies session bounds (`host.id`, `t0`, `t1`) and stores the original JSON payload; labels go to a metadata sidecar, so the model input schema is untouched.

## Prerequisites

- VMware Workstation and `vmrun.exe` on the host; victim VM with VMware Tools, host time sync and an interactive guest session for the user in `config.yaml`.
- Snapshots of the victim VM:
  - `original`: clean Windows, decoy folder tree, 7-Zip at `baseline.sevenzip_guest_path`, Defender disabled, no samples.
  - `baseline`: made from `original` by `sentinelcap build baseline` with the VM running and the guest user logged in; every collection session reverts to it.
  - `validate`: made from `original` by `sentinelcap build validate` with every ransomware/goodware pair sharing a guest folder; does not replace `baseline`.
- Samples under `baseline.samples_dir`: `ransomware/<Family>/<sha256>.zip` (WinZip AES-256, password `infected`, one `<sha256>.exe` inside; never extracted on the host) and `goodware/<sha256>.exe`.
- Topic `telemetry.windows.normalized` exists (`docker compose up -d` creates it via `kafka-init`; otherwise capture fails with `UNKNOWN_TOPIC_OR_PART`) and Logstash produces to it.
- Winlogbeat in the snapshots sets `key` on `output.kafka` (`config/winlogbeat/winlogbeat.yml`); re-take the snapshots after changing it on the guest.
- `kafka.host_id` is the ECS `host.id` of the dedicated victim VM.
- UAC stays at the Windows default (enabled) in the snapshots; do not disable it.

### UAC convention

The operator always clicks **Yes** on a UAC prompt, for both classes; it is the only operator decision about elevation. Samples that elevate without a prompt (e.g. a payload relaunched through `dllhost.exe`) must keep doing so. No collected ransomware sample showed a prompt; goodware installers usually do. The resulting `process.integrity_level` difference (more `High` in goodware) comes from the samples and is kept on purpose; using it as a model feature is a training-side decision.

## Installation and configuration

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e .

sentinelcap config init
sentinelcap config show
```

- Set the VM details, Kafka bootstrap address, normalized topic and victim `host.id` in `config.yaml`; the Kafka address must match the broker's advertised address as reachable from the SentinelCap host.
- `SENTINELCAP__<SECTION>__<FIELD>` environment variables override the YAML file; set the guest password via `SENTINELCAP__VMWARE__GUEST_PASSWORD`, not in a shared file.
- Copy `host.id` from one victim-VM event on `telemetry.windows.normalized`; it is an input boundary that SentinelCap never derives or changes.

## Collection workflow

### `build baseline` (once per sample set)

1. Reverts to `original`, starts the VM, waits for VMware Tools.
2. Lists non-hidden sub-directories under `baseline.sample_target_roots` in the guest (creates none), skipping paths containing `setup` (Sysmon `Image contains setup` exclude). A root without a usable sub-directory stops the command before anything is placed.
3. Spreads each class evenly over the roots (counts differ by at most 1 per class). Per sample, picks a directory in its root and a business-like name such as `invoice_a7f3.exe` (no SHA-256, no name matched by a Sysmon exclude rule), seeded by `--seed`/`baseline.seed`:
   - ransomware: copies the zip to `C:\Windows\Temp`, extracts it in the guest with 7-Zip (encoded PowerShell script), checks that `<sha256>.exe` exists, renames it with vmrun `renameFileInGuest` (no guest shell), deletes the zip;
   - goodware: copies the executable to the new path.
4. Replaces the `baseline` snapshot with the VM running (old one deleted first; stops if it still exists), then powers off.
5. Writes `manifest.csv` (`family,sample,path,label`); an existing one is kept as `manifest-<YYYYMMDDTHHMMSSZ>.csv` (UTC).

Any failure stops the command before the snapshot, so the previous `baseline` stays. The session mode comes from `--execute` or `--interactive`, never from the manifest.

### `build validate` (stack-validation pairs)

Pairs **every** ransomware sample with a goodware sample and places each pair into the **same** guest directory so the operator can later launch both together against a live stack. Ransomware and goodware counts must be equal.

1. Reverts to `original`, starts the VM, lists usable directories (same rules as `build baseline`).
2. Seed-shuffles each class and zips them into pairs; stops if either class is missing or the counts differ.
3. Places each pair into one directory with distinct safe names (different pairs get different directories when enough exist; same copy/extract/rename mechanics as `build baseline`).
4. Replaces the `validate` snapshot while the VM is running (does **not** touch `baseline` or `manifest.csv`), then powers off.
5. Writes `manifest-validate.csv` (ransomware then goodware per pair); an existing file is kept as `manifest-validate-<YYYYMMDDTHHMMSSZ>.csv`.

### `batch --validate` (simultaneous pair capture)

Runs each pair from `manifest-validate.csv` against the live stack: both samples in one Explorer window, one Kafka capture, two session exports.

1. Groups rows that share a guest parent directory (exactly one ransomware and one goodware each).
2. Per pair: reverts to `validate`, starts the VM, opens Explorer at the shared folder.
3. The operator double-clicks **both** executables. Both Sysmon Event 1s must appear within `exec_detect_timeout_sec`.
4. Records until **both** samples meet the usual quiet/max-wait rule, then drains and writes two sessions (`mode = validate`, snapshot `validate`) into one run directory.
5. A failed pair fails both rows in the result table; the batch continues with the next pair. Does not touch `baseline`.

```powershell
sentinelcap batch manifest-validate.csv --validate --config config.yaml
```

### `--execute` (ransomware and goodware executables)

1. Reverts to `baseline`, starts the VM, subscribes a fresh consumer group at the topic tail and opens File Explorer at the executable's directory (encoded PowerShell `Start-Process`).
2. The operator double-clicks the executable. SentinelCap buffers all events of the host and waits up to `exec_detect_timeout_sec` (120) for the first Sysmon Event 1 with `process.executable` equal to `path` (case-insensitive) and `process.hash.sha256` equal to `sample`; its `@timestamp` is `t_exec` and its `process.entity_id` goes to the metadata. If not seen, the session is invalid and nothing is written.
3. Records at least `settle_sec` (120) from `t_exec`, then stops after `quiet_window_sec` (90) without a sample-process event, counted from the later of the last such event and the end of settle (a session lasts at least 210 s), or after `max_wait_sec` (300) more (at most 420 s). Timing uses the host monotonic clock.
4. Waits `post_capture_drain_sec` (45) for late events, keeps events with `t_exec <= @timestamp <= t_end`, stops the VM.

Sample processes: the root; processes whose executable path contains the sample SHA-256 (relaunches, e.g. UAC elevation through `dllhost.exe`) or whose Event 1 carries it (renamed copies); processes whose Event 1 executable is a file a sample process wrote earlier (Event 11/29 `file.path`: dropped payloads); and descendants (`process.parent.entity_id` of Event 1). Processes spawned via WMI/services are not tracked for the quiet rule (their events are still recorded).

### `--interactive` (goodware scenarios)

- Prompts for Enter to start and Enter to end while the operator performs the scenario in the VM console; nothing the operator does is verified.
- Enter uses the host clock; the offset to the guest clock (median of host receive time minus `@timestamp` over the first `clock_offset_median_events` events) is saved as `clock_offset_sec` and applied to `t_start`/`t_end`.
- `sample` is a free scenario name (`backup`, `compress-documents`, `active-directory-setup`), stored verbatim as `metadata.scenario`; use distinct names (`backup`, `backup-2`) to collect a scenario twice in one run.
- Goodware executables (installers, portable applications) are collected with `--execute` and their SHA-256, like ransomware.

### `capture` (no VM control)

Records the victim host for `--duration` seconds without reverting or starting the VM (e.g. background activity of an idle VM). Writes the same session directory and metadata as `run`, with `mode = "capture"`; the window is measured on the host clock and converted with `clock_offset_sec`. `environment.snapshot` is null because the VM is not managed.

### Continuous scenarios in an interactive batch

The long-running rows of `manifest-scenarios.csv` run with one `sentinelcap batch manifest-scenarios.csv --interactive --config config.yaml`; each row reverts to the bare `baseline` first. After Enter to START, run the row's script in an elevated Windows PowerShell 5.1 console in the guest (it must be in the snapshot or copied in after the revert), stop it as described below, then press Enter to END on the host.

#### AD installation and operations in one interactive batch session

The `baseline` snapshot is a bare Windows Server: no AD DS/DNS role or other added server role; only the Windows Server Backup feature is installed. Row `ad-install-operations-continuous` covers installation, the promotion reboot and AD operations in **one session**; only these two scripts add and use AD DS/DNS and GPMC. Keep Sysmon and Winlogbeat running, confirm `kafka.host_id` matches this VM, press Enter to START before installing AD, and do not press Enter to END during the reboot.

```powershell
# Guest, elevated Windows PowerShell, after Enter to START on the AD row.
powershell.exe -NoProfile -File C:\Users\Public\scenarios\install-ad-domain-controller.ps1 `
  -DomainName ad.logsentinel.test -DomainNetBIOSName LOGSENTINEL

# After automatic reboot, sign in as domain administrator and run:
powershell.exe -NoProfile -File C:\Users\Public\scenarios\ad-domain-operations-continuous.ps1 `
  -IntervalSeconds 60 -ExpectedDomainName ad.logsentinel.test

# After the desired time, press Enter in the guest PowerShell console.
# Check completed.txt in the run directory, then press Enter to END on the host.
```

- Installer: adds AD DS/DNS and GPMC, prompts securely for the DSRM password, reboots. If feature installation asks for an earlier reboot, reboot and rerun it in the same session. It warns about a missing static IPv4 address; the AD DS prerequisite checks decide whether promotion proceeds.
- Operations: waits up to 20 minutes after the reboot for AD services, DNS and SYSVOL, then works on a run-specific OU, disabled lab users, a security group and a GPO linked only to that OU (GPO and OU are deleted on exit). It refuses to run if the domain differs from `-ExpectedDomainName`; pass the same name to both scripts.
- Results: `%ProgramData%\SentinelCap\ad-domain-operations\<run-time>\`; `completed.txt` appears only after the operator stops the script and no cycle or cleanup has failed. No fixed duration and no stop after 125 minutes: allow at least two hours for two hours of DC activity.
- After the reboot, re-check Winlogbeat and the host ID; discard the class-0 session if promotion or operations fail or telemetry is missing.
- The session includes installation and reboot, so it is **not** a steady-state DC idle baseline; a single DC also has no client logons or multi-DC replication.
- Reference: [Microsoft's AD DS guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-).

#### Windows Update maintenance on the bare baseline

The `windows-update-maintenance-continuous` row starts from a fresh bare `baseline`, before the AD row, and needs no AD role, AD module, DNS role or SYSVOL.

```powershell
# Guest, after Enter to START on the Windows Update row.
powershell.exe -NoProfile -File C:\Users\Public\scenarios\windows-update-maintenance-continuous.ps1 `
  -UpdateIntervalMinutes 90 -HealthIntervalMinutes 10
```

- Enables local Automatic Updates (notify before download/install), re-enables `wuauserv` and `BITS` if disabled, starts `UsoSvc` when present.
- Every 60-120 minutes (90 by default) installs assigned updates from the configured Windows Update or WSUS source, skipping those that need new license acceptance or interactive input. The 10-minute health check reads only standard OS, disk, service and System event-log information. Results: `%ProgramData%\SentinelCap\windows-update-maintenance\<run-time>\activity.jsonl`.
- The script never reboots; if an install requires one, update cycles stop while health checks continue. Do not reboot during this row.
- To stop, let any active update cycle finish, press Ctrl+C in the guest, then Enter to END on the host. Patching may raise CPU, disk and network load; Windows Server Backup is not used.
- References: [Windows Update policy values](https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings), [Windows Update Agent API](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/searching--downloading--and-installing-updates).

#### Other continuous Windows Server goodware scenarios

Independent rows; the scripts run until Ctrl+C and need no AD DS role, file share, backup volume or additional server feature.

| Script | Default cycle | Activity |
|---|---:|---|
| `server-file-workload-continuous.ps1` | 1 s pause after each batch | Process 200 CSV files of 32 rows each; create a working copy and temporary JSON receipt per input, then archive the CSV. Keeps at most 2,000 archived CSVs. |
| `server-backup-verify-continuous.ps1` | 60 min | Copy five generated lab files, compare SHA-256 hashes, and keep the latest six copies. It never backs up real server data. |
| `server-health-monitor-continuous.ps1` | 15 min | Read OS, disk, process, service and System event-log health; it does not change those resources. |

```powershell
# Guest: run for the desired time, then press Ctrl+C and Enter to END on the host.
powershell.exe -NoProfile -File C:\Users\Public\scenarios\server-file-workload-continuous.ps1 `
  -IntervalSeconds 1 -FilesPerCycle 200 -RowsPerFile 32 -MaxArchivedFiles 2000
```

For the other scenarios use `server-backup-verify-continuous.ps1 -IntervalMinutes 60` or `server-health-monitor-continuous.ps1 -IntervalMinutes 15`.

- Heavier file workload: `-IntervalSeconds 0 -FilesPerCycle 1000`. `IntervalSeconds` is the pause **after** processing, so batch time also affects throughput. Each input creates three files (input CSV, working CSV, JSON receipt): 600 file creations per default batch, excluding summary/log writes. Raise `FilesPerCycle` or lower the pause to create more; `RowsPerFile` mostly enlarges CSVs and processing work. The old `-IntervalMinutes 10` is still accepted for a slow workload but cannot be combined with `-IntervalSeconds`.
- Workload files live under the run's `Documents\inbox`, `Documents\working` and `Documents\archive` (the `Documents` component matches the Sysmon FileCreate include rule). Temporary input and receipt files are deleted after each input; FIFO pruning keeps archived CSVs at the cap; the workload stops if it cannot remove temporary files.
- `activity.jsonl` holds workload counters (files/rows, creates/deletes, work time, approximate creations per second including the pause), **not measured Sysmon events/sec**; it rotates at 16 MiB and keeps one previous segment.
- Each script creates one run directory below `%ProgramData%\SentinelCap\` with a small `activity.jsonl` of cycle outcomes; the file and backup scenarios prune only their own generated archives. None executes samples or changes AD, Windows Update, security agents or event logs. Verify that `metadata.json` holds the expected events before using the session as class 0.

### Commands

```powershell
# Place the samples and (re)create the baseline snapshot; writes manifest.csv.
sentinelcap build baseline --seed 42 --config config.yaml

# Every ransomware/goodware pair in a shared folder; validate snapshot + manifest-validate.csv.
sentinelcap build validate --seed 42 --config config.yaml

# Run each validate pair simultaneously (both double-clicks in one Explorer window).
sentinelcap batch manifest-validate.csv --validate --config config.yaml

# One session. --execute: click the executable when prompted.
sentinelcap run --execute --family Akira --sample <sha256> `
  --path "C:\Users\Public\Documents\invoice_a7f3.exe" --label 1 --config config.yaml

# One interactive scenario (sample = scenario name).
sentinelcap run --interactive --family goodware --sample backup --label 0 --config config.yaml

# Every manifest row; prints a result table and exits 1 if any row failed.
sentinelcap batch manifest.csv --execute --config config.yaml
sentinelcap batch manifest-scenarios.csv --interactive --config config.yaml
sentinelcap batch manifest-validate.csv --validate --config config.yaml

# Record the host without controlling the VM (sample = session name).
sentinelcap capture --family idle --sample idle-01 --label 0 --duration 300 --config config.yaml
```

Each `run`, `batch` or `capture` writes into a new run directory `<out_dir>/<YYYYMMDDTHHMMSSZ>/` (UTC; one per batch). Inside it, an existing `<family>/<sample>/` is refused before recording unless `--force` is given; a sample that already exists under another family is always refused, even with `--force`.

## Goodware scenarios

Every scenario is a **normal Windows administration task** that touches one or a few of the indicators `inference` uses to detect ransomware (`../inference/README.md` section 4.1): the goal is goodware (class 0) containing these behaviors, so the model learns they also occur in legitimate activity and **does not raise false alarms**. The scripts run in the victim VM console between the two Enter presses; they only simulate admin work, never run samples and do not touch `samples/`.

Long-running rows have their own guides: [AD session guide](#ad-installation-and-operations-in-one-interactive-batch-session), [Windows Update guide](#windows-update-maintenance-on-the-bare-baseline), [long-running workload guide](#other-continuous-windows-server-goodware-scenarios).

### Collecting a scenario

On the host, from `sentinelcap/`, run `sentinelcap batch manifest-scenarios.csv --interactive --config config.yaml`, then:

1. Wait for `Press Enter to START`, switch to the **VM console**, open PowerShell **as Administrator** (click Yes at the UAC prompt) and `cd` to the scripts directory.
2. In the sentinelcap terminal **press Enter (START)** and wait for `Recording...`.
3. In the VM console run the script, e.g. `.\backup.ps1`, and wait for `=== DONE ===`.
4. Wait about 10 more seconds (covers `clock_offset` and the pipeline delay), then **press Enter (END)** in the sentinelcap terminal. The batch reverts to `baseline` before the next row.

The scripts must be in the `baseline` snapshot, or copied into the guest after the batch reverts and before START. For the AD and continuous rows follow the guides above.

### Scenario list

| `sample` | Targeted indicator (`../inference/README.md` section 4.1) | Simulated admin work |
|---|---|---|
| `backup` | backup tooling, bulk copy | Nightly server backup (`wbadmin`, `robocopy`) |
| `shadow-copy-cleanup` | `shadow_copy_deletion` | Reclaim disk space from old restore points |
| `service-maintenance` | `service_stop_burst` | Stop and start a batch of services in a maintenance window |
| `log-archival` | `event_log_tamper` | Log rotation for compliance |
| `deploy-startup-app` | `run_key_persistence` | Deploy an agent that starts with Windows |
| `certificate-management` | `lolbins_execution` (`certutil`) | Install and verify certificates |
| `scripted-admin` | `lolbins_execution` (`wmic`/`cscript`/`regsvr32`) | Machine inventory and component registration |
| `deploy-config-files` | `mass_note_drop` | Push one config/README file to every project directory |
| `compress-documents` | burst of encryption-like file creation | Quarterly compression of project directories |
| `bulk-report-export` | Phase 3 features `distinct_extensions`, `max_same_extension` | Nightly report export to many files |
| `boot-config-maintenance` | `recovery_disable` | Preparing a controlled restart test |
| `provision-directory-users` | admin provisioning background | Onboarding a batch of users |
| `scheduled-task-setup` | legitimate persistence background | Scheduling maintenance jobs |
| `disk-cleanup` | bulk file deletion + `cipher` | Cleanup and wipe of free space |
| `file-encryption` | encryption + new file extension | EFS encryption of sensitive directories |
| `windows-update-maintenance-continuous` | Windows Update and server health | Periodic scan, download and install of patches, plus status checks |
| `server-file-workload-continuous` | continuous file processing | Per cycle: 200 CSVs of 32 rows, a copy and a temporary JSON for each, archive the CSV, pause 1 s; keeps at most 2,000 CSVs |
| `server-backup-verify-continuous` | background copy/verification | Copies lab data and compares SHA-256 |
| `server-health-monitor-continuous` | idle monitoring | Periodically reads OS, disk, service and System event-log state |
| `ad-install-operations-continuous` | legitimate AD administration | Installs a DC, then creates, edits and deletes lab OUs, users, groups and GPOs until the operator stops |

### Sysmon coverage

The Sysmon configuration covers **more** than `../README.md` section 10.4 describes:

- System32 tools are all logged as Event 1 with the full `command_line`: `vssadmin`, `wevtutil`, `sc`, `net`, `net1`, `wmic`, `bcdedit`, `wbadmin`, `cipher`, `certutil`, `regsvr32`, `cscript`, `schtasks`, `reg`.
- `powershell.exe` (System32) is logged for Event 11 (file creation) and Event 13 (writes to the `Run`/`RunOnce` keys).

Scripts therefore run tools straight from System32 and never copy a binary to `C:\Users\Public`: the copy would put `command_line` in a user directory (the LOLBin/ransomware pattern, making the goodware less realistic) and breaks the binary (`vssadmin` cannot delete, `certutil`/`schtasks` print `(null)`).

### Safety (observed by every script)

- **Never** stop `Winlogbeat`, `Sysmon64`/`SysmonDrv` or network services.
- **Never** delete or clear the `Microsoft-Windows-Sysmon/Operational` or `Security` log channels (only export, then clear `Application` and `Windows PowerShell`).
- **Never** modify `EnableLUA`/`ConsentPromptBehaviorAdmin` (keeps the UAC convention).
- **Never** touch `samples/` or run any sample.
- Every system change (bcdedit, services, shadow copies) is undone at the end of the script, and the VM reverts to `baseline` after each session: two layers of safety.
- Working data lives under `C:\Users\Public\sc-work\<scenario>` and is deleted at the end of the script.

### Scenarios that need particular care

- **`provision-directory-users`**: creates **local users/groups** (`New-LocalUser`...); it installs no RSAT, AD DS or other feature. The real AD session is `install-ad-domain-controller.ps1`, then `ad-domain-operations-continuous.ps1` after the reboot, in the same `batch --interactive` row; do not add AD to the `baseline` snapshot.
- **`shadow-copy-cleanup`**, **`disk-cleanup`**: delete shadow copies and files; legitimate admin behavior, safe because the VM reverts.

## Manifest

```csv
family,sample,path,label
akira,4afda03d...,C:\Users\Public\Documents\invoice_a7f3.exe,1
goodware,backup,,0
```

`label` (0 or 1) is the only source of the label. `--execute` rows need a 64-hex `sample` and a guest `path`; `--interactive` rows need a scenario name as `sample` and an empty `path`; rows that do not match the mode are rejected. `build baseline` writes the training `--execute` rows; `build validate` writes `manifest-validate.csv` (two rows per pair).

## Output

Each session (all modes) writes `<out_dir>/<run>/<family>/<sample>/`; `<run>` is the UTC run start, `YYYYMMDDTHHMMSSZ`. `family` is lower-cased (`LockBit` and `Lockbit` share a directory); `family` and `sample` allow only letters, digits, `-` and `_`.

| File | Contents |
|---|---|
| `session.jsonl` | Original JSON messages from `telemetry.windows.normalized` inside `[t_start, t_end]`, byte for byte, in arrival order; no added label. |
| `metadata.json` | Format `logsentinel.normalized-sysmon.jsonl/v1`, session ID, source, label (`target_class`, `target_class_name`), `mode` (`execute`, `interactive`, `capture` or `validate`), `t_start`, `t_end`, `clock_offset_sec`, counters (`event_count`, `skipped_other_hosts`, `skipped_invalid`: messages that are not a JSON object, `skipped_outside_session`), `pipeline_lag_max_sec`/`pipeline_lag_p50_sec` (`event.created - @timestamp`; null without `event.created`), `environment` (`sentinelcap_version`, `snapshot`, `windows_build`, `winlogbeat_version`), plus `process_entity_id` and `sample_entity_ids` (`execute` / `validate`) or `scenario` (`interactive`). |

**Partial directories.** Both files are written to `<family>/.<sample>.partial/`, renamed to `<sample>` only when complete (`--force` moves the previous session to `.<sample>.old` during the swap). Directories whose name starts with `.` are unfinished and must be skipped by loaders; the next export of the same family/sample cleans them up (or restores `.old` after an interrupted swap).

**Lag warning.** A warning is logged when `pipeline_lag_max_sec >= post_capture_drain_sec`: the session may miss its last events.

**Loader contract.** Accept only this `format` value and read `<out_dir>/*/<family>/<sample>/`; `sample_entity_ids` separates the sample's own events from background events. Events are those `config/logstash/ingest` emits (ECS fields, MITRE as `threat.*`, no Logstash `@version`). The training loader joins the label from metadata with the JSONL events and must not use `target_class_name`, the sample or collection metadata as model features.

## Project layout

```text
src/sentinelcap/
  cli.py            Command-line interface
  config.py         VMware, Kafka, capture and baseline configuration
  errors.py         SentinelcapError (VMwareError derives from it)
  vm.py             VMware Workstation control (vmrun)
  guest_names.py    Sample names and guest target directories
  baseline.py       build baseline / build validate
  orchestrate.py    execute / interactive / validate / capture / batch workflows
  capture.py        Lossless normalized Kafka capture and session export
  session.py        Pure logic: t_exec detection, sample processes, quiet-window rule
  manifest.py       Manifest validation
```

`scenarios/` holds the goodware scenario scripts (PowerShell, run in the victim VM); `manifest-scenarios.csv` lists their rows. The version is defined once, in `pyproject.toml`; `sentinelcap.__version__` reads it from the installed package metadata.

Development checks (from `sentinelcap/`, `pip install -e .[dev]`):

```powershell
..\.venv\Scripts\python.exe -m pytest tests -q
..\.venv\Scripts\python.exe -m ruff format --check src tests
..\.venv\Scripts\python.exe -m ruff check src tests
..\.venv\Scripts\python.exe -m mypy
```

## Known limitations

Deliberately left undone; `AGENTS.md` treats this list as out of scope.

- `guest_password` in `config.yaml` is stored in clear text (prefer `SENTINELCAP__VMWARE__GUEST_PASSWORD`).
- Not done on purpose: pre-run checks, hashes of the Logstash/Sysmon/Winlogbeat configuration files (collection runs are separated by the `<run>` directory instead), finer label granularity. `environment.snapshot` records only the configured name, not what the snapshot contains.
- `clock_offset_sec` still includes the pipeline delay; the median only removes the effect of a single late event.
- `pipeline_lag_*` covers only Sysmon -> Winlogbeat (both stamps from the guest clock); the Kafka/Logstash part of the delay is not visible in the payload.
- `build baseline` / `build validate` do not recompute the SHA-256 of the extracted executable (the manifest `sample` is the zip file name); a mismatch shows up at collection time as "No Sysmon Event 1".
- `sample_entity_ids` is incomplete by design (see Sample processes under `--execute`): code injected into other processes (e.g. a new `explorer.exe`), files written through SMB (process `System`) and payloads written without an Event 11/29 of a sample process are not tracked. Their events are still in `session.jsonl` with the session label.
- The unit tests use fakes for VMware and Kafka; `build baseline`, `build validate`, `run`, `batch` and live polling run against the real VM only in the collection runs themselves.
