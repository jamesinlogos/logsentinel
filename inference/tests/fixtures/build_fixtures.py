"""Rebuild the test fixtures from real sentinelcap captures.

    python tests/fixtures/build_fixtures.py [--captures ../sentinelcap/captures]

Nothing is generated or edited: whole sessions of run 2026-10-01 are copied
(gzip-compressed, with their metadata.json) and single events are picked by
winlog.record_id, from that run unless an entry names another one.
"""

from __future__ import annotations

import argparse
import gzip
import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CAPTURES = HERE.parents[2] / "sentinelcap" / "captures"
SESSION_RUN = "20261001T011932Z"

SESSIONS = (
    # shadow_copy_deletion + service_stop_burst + run_key_persistence; no mass note
    "conti/b14cde376a8a7a9d7ad34cdfd07108c132ad8be7f60c5c0a0f17b6b63eb28b49",
    # mass_note_drop + shadow_copy_deletion
    "blackbasta/11129aad3b5baa1d118ec0ee3922278c194e43f6e2f0fcef221c65e5f4490d3b",
    # recovery_disable (and the misspelled "recoverynabled"), cmd_burst, service stops
    "medusa/49c9b3ddbce1f77a7f01a660c56f48c0d733a7e807f95caca2dee12a204974ef",
    # note in only 9 directories: no strong indicator
    "lockbit/032690f113289d50b672fb3e95b64c801454e8e07fe3cdcb072efeaabcc7a374",
    # goodware (KeePass installer): run_key_persistence + lolbins_execution only
    "goodware/9923a8b228fe3d8fbe46979991f45d7e0d63f649766596da191eb879b293d38d",
    # mass_file_replace: <file>.crinal written and <file> deleted, 2,569 files in 78 directories
    "akira/c974d8c6a1ce2eb12f0eca40e8782dea046d707f04ad65aae98af3c1b4ca6ce6",
)

# name -> (family/hash, winlog.record_id[, run when not SESSION_RUN])
SINGLE_EVENTS: dict[str, tuple[str, int] | tuple[str, int, str]] = {
    "wmic_shadowcopy_delete": (
        "blackbasta/a120203700369c2bb7ca8abd7d49a89070d73b4c0625203539c4fd47dc2231b9",
        226943,
    ),
    "wevtutil_clear_log": (
        "blackbasta/a120203700369c2bb7ca8abd7d49a89070d73b4c0625203539c4fd47dc2231b9",
        227103,
    ),
    "sysmon_channel_disabled": (
        "blackmatter/8c047ba01ef0db2b2057190d6c35a7c0e6965f465b0015d17b8c59c3767b2cf1",
        231293,
    ),
    "enable_linked_connections": (
        "lockbit/13849c0c923bfed5ab37224d59e2d12e3e72f97dc7f539136ae09484cbe8e5e0",
        227031,
    ),
    "create_remote_thread": (
        "goodware/0b3731c524e6ba716f15087d85eae7e6225b6b51d4ae2fa6c142ff1523f57046",
        227037,
    ),
    "sysmon_queue_drop": (
        "hellokitty/10887d13dba1f83ef34e047455a04416d25a83079a7f3798ce3483e0526e3768",
        233086,
    ),
    "sysmon_image_load_error": (
        "goodware/8cb072ed7149f6eb49e38c93d035fb40703ad213f7b818d2b01f227430745ff6",
        229218,
    ),
    "parent_unresolved": (
        "goodware/12c19ac8fe2c601222c091cdb41e8f8d3b7dae7ab342b4b2f47a159bbbdc879f",
        227649,
    ),
    "network_connection": (
        "akira/0ab9e88f2135f7fbd439435f0ff4da887bbfb1cae67ccc8209aac22e75e3486f",
        228151,
    ),
    # Windows servicing (TiWorker.exe) registering an event log channel as disabled
    "servicing_channel_disabled": (
        "goodware/windows-update-maintenance-continuous",
        231516,
        "20261008T050249Z",
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--captures", type=Path, default=DEFAULT_CAPTURES)
    args = parser.parse_args()
    run = args.captures / SESSION_RUN

    sessions_dir = HERE / "sessions"
    shutil.rmtree(sessions_dir, ignore_errors=True)
    for relative in SESSIONS:
        source = run / relative
        target = sessions_dir / relative
        target.mkdir(parents=True)
        shutil.copyfile(source / "metadata.json", target / "metadata.json")
        with (
            open(source / "session.jsonl", "rb") as src,
            # mtime=0: the same capture always gives the same bytes.
            gzip.GzipFile(target / "session.jsonl.gz", "wb", mtime=0) as dst,
        ):
            shutil.copyfileobj(src, dst)

    picked: dict[str, dict[str, object]] = {}
    for name, (relative, record_id, *other_run) in SINGLE_EVENTS.items():
        source = args.captures / (other_run[0] if other_run else SESSION_RUN) / relative
        with open(source / "session.jsonl", encoding="utf-8") as lines:
            for line in lines:
                doc = json.loads(line)
                if doc["winlog"]["record_id"] == record_id:
                    picked[name] = doc
                    break
        if name not in picked:
            raise SystemExit(f"record_id {record_id} not found in {relative}")
    (HERE / "single-events.json").write_text(
        json.dumps(picked, indent=1), encoding="utf-8", newline="\n"
    )
    print(f"{len(SESSIONS)} sessions, {len(picked)} single events written to {HERE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
