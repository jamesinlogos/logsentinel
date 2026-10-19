"""Check the Logstash pipelines without touching the running stack.

    python scripts/check_logstash_config.py

Starts throw-away containers (``docker run --rm``) from the Logstash image the stack uses:

1. ``logstash -t`` on every pipeline file (syntax and plugin options);
2. the whole ``filter`` of ``ingest.conf`` on a few raw Sysmon events, comparing the MITRE
   annotation (ECS ``threat.*``), the registry value, the executable flag and the ECS
   classification with what they must be, and checking that Logstash's ``@version`` is
   gone;
3. an event through the ingest-to-sink pipeline fork, checking that neither output regains
   ``@version`` and that only the Kafka branch drops ``message``;
4. the ``filter`` of the two detection-sink pipelines on a document and on one without
   ``logsentinel.window.id``: the ``document_id`` must be the window id, and ``@version``
   and ``event.original`` must be gone.

Each Logstash start takes about 40 s. Exit code 0: every check passed. Only the standard
library is used; Docker and the image pulled by ``docker compose`` are needed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

PIPELINES = (
    "ingest/ingest.conf",
    "ingest/sink-es.conf",
    "ingest/sink-inference.conf",
    "detection-sink/detections.conf",
    "detection-sink/window-scores.conf",
)
SYSMON = {
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider_name": "Microsoft-Windows-Sysmon",
}
FRAMEWORK = {"framework": "MITRE ATT&CK"}
POWERSHELL = {
    **FRAMEWORK,
    "technique": {"id": "T1059", "subtechnique": {"id": "T1059.001", "name": "PowerShell"}},
}
RULES = [
    # (RuleName of the Sysmon rule, expected threat.*, expected rule.* fields)
    ("technique_id=T1059.001,technique_name=PowerShell", POWERSHELL, {}),
    (
        "technique_id=T1490,technique_name=Inhibit System Recovery",
        {**FRAMEWORK, "technique": {"id": "T1490", "name": "Inhibit System Recovery"}},
        {},
    ),
    (
        "technique_id=T1059.001,technique_name=PowerShell,rule=AI agent hooks: Cursor scripts",
        POWERSHELL,
        {"description": "AI agent hooks: Cursor scripts"},
    ),
    ("Mission-important Credential Access", None, {"category": "mission-important"}),
    ("Executables", None, {}),
    ("-", None, {}),
]
ABSENT = "<absent>"
"""Expected value of a field that must not be in the event."""


def raw_event(
    rule_name: str = "-", *, code: str = "1", event_data: dict[str, str] | None = None
) -> dict[str, Any]:
    """The part of a Winlogbeat Sysmon event that the ingest filter reads."""
    return {
        "event": {"code": code, "action": "Sysmon event"},
        "host": {"id": "h", "name": "host"},
        "winlog": {
            **SYSMON,
            "event_id": int(code),
            "event_data": {
                "RuleName": rule_name,
                "Image": "C:\\Users\\x\\a.exe",
                **(event_data or {}),
            },
        },
    }


REGISTRY_KEY = "HKU\\S-1\\Software\\x\\setting"
FILE_PATH = "C:\\Users\\x\\a.tmp"
HASHES = "SHA1=AA,MD5=BB,SHA256=CC,IMPHASH=DD"
FIELDS: list[tuple[str, dict[str, Any], dict[str, Any]]] = [
    # (label, raw event, expected fields of the filtered event by dotted path)
    (
        "registry value: the string false",
        raw_event(code="13", event_data={"TargetObject": REGISTRY_KEY, "Details": "false"}),
        {"registry.data.strings": "false"},
    ),
    (
        "registry value: the string 0",
        raw_event(code="13", event_data={"TargetObject": REGISTRY_KEY, "Details": "0"}),
        {"registry.data.strings": "0"},
    ),
    (
        "registry value: a DWORD",
        raw_event(
            code="13",
            event_data={"TargetObject": REGISTRY_KEY, "Details": "DWORD (0x00000000)"},
        ),
        {"registry.data.strings": "DWORD (0x00000000)"},
    ),
    (
        "registry value: empty",
        raw_event(code="13", event_data={"TargetObject": REGISTRY_KEY, "Details": ""}),
        {"registry.data.strings": ABSENT},
    ),
    (
        "deleted file: IsExecutable false",
        raw_event(code="26", event_data={"TargetFilename": FILE_PATH, "IsExecutable": "false"}),
        {"sysmon.file.is_executable": False},
    ),
    (
        "deleted file: IsExecutable true",
        raw_event(code="26", event_data={"TargetFilename": FILE_PATH, "IsExecutable": "true"}),
        {"sysmon.file.is_executable": True},
    ),
    (
        "file event without IsExecutable",
        raw_event(code="11", event_data={"TargetFilename": FILE_PATH}),
        {"sysmon.file.is_executable": ABSENT},
    ),
    (
        "FileCreate is classified",
        raw_event(code="11", event_data={"TargetFilename": FILE_PATH}),
        {"event.category": ["file"], "event.type": ["creation"]},
    ),
    (
        "Sysmon error is not classified",
        raw_event(code="255", event_data={"ID": "QUEUE"}),
        {"event.category": ABSENT},
    ),
    # --- names derived from paths (section 10)
    (
        "file name and extension: the last dot of the name",
        raw_event(code="11", event_data={"TargetFilename": "C:\\Users\\x\\Report.final.docx"}),
        {"file.name": "Report.final.docx", "file.extension": "docx", "process.name": "a.exe"},
    ),
    (
        "file without an extension",
        raw_event(code="11", event_data={"TargetFilename": "C:\\Users\\x\\README"}),
        {"file.name": "README", "file.extension": ABSENT},
    ),
    (
        "a dot in a directory is not an extension",
        raw_event(code="11", event_data={"TargetFilename": "C:\\Users\\x.v2\\README"}),
        {"file.name": "README", "file.extension": ABSENT},
    ),
    (
        "a name that ends with a dot has no extension",
        raw_event(code="11", event_data={"TargetFilename": "C:\\Users\\x\\file."}),
        {"file.name": "file.", "file.extension": ABSENT},
    ),
    (
        "a hidden file: the extension is what follows the dot",
        raw_event(code="11", event_data={"TargetFilename": "C:\\Users\\x\\.gitignore"}),
        {"file.name": ".gitignore", "file.extension": "gitignore"},
    ),
    (
        "a path that ends with a backslash has no name",
        raw_event(code="11", event_data={"TargetFilename": "C:\\Users\\x\\"}),
        {"file.name": ABSENT, "file.extension": ABSENT},
    ),
    (
        "a file called false keeps its name",
        raw_event(code="11", event_data={"TargetFilename": "C:\\Users\\x\\false"}),
        {"file.name": "false"},
    ),
    (
        "the pipe name is not overwritten",
        raw_event(code="17", event_data={"PipeName": "\\PSHost.1", "Image": "C:\\Windows\\a.exe"}),
        {"file.name": "\\PSHost.1", "file.path": ABSENT, "process.name": "a.exe"},
    ),
    (
        "process and parent names",
        raw_event(
            code="1",
            event_data={
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "ParentImage": "C:\\Windows\\explorer.exe",
            },
        ),
        {"process.name": "cmd.exe", "process.parent.name": "explorer.exe"},
    ),
    (
        "an image without a directory",
        raw_event(code="3", event_data={"Image": "<unknown process>"}),
        {"process.name": "<unknown process>"},
    ),
    # --- user (section 3)
    (
        "user DOMAIN\\name",
        raw_event(event_data={"User": "WORKSTATION\\alice"}),
        {"user.domain": "WORKSTATION", "user.name": "alice"},
    ),
    (
        "user: split at the first backslash",
        raw_event(event_data={"User": "A\\B\\C"}),
        {"user.domain": "A", "user.name": "B\\C"},
    ),
    (
        "user: a dash is no user",
        raw_event(code="3", event_data={"User": "-"}),
        {"user.name": ABSENT, "user.domain": ABSENT},
    ),
    (
        "user: an empty domain keeps the whole value",
        raw_event(event_data={"User": "\\alice"}),
        {"user.name": "\\alice", "user.domain": ABSENT},
    ),
    (
        "user: an empty name keeps the whole value",
        raw_event(event_data={"User": "WORKSTATION\\"}),
        {"user.name": "WORKSTATION\\", "user.domain": ABSENT},
    ),
    # --- registry hive (section 6)
    (
        "registry hive",
        raw_event(code="12", event_data={"TargetObject": REGISTRY_KEY}),
        {"registry.hive": "HKU", "registry.path": REGISTRY_KEY},
    ),
    (
        "registry path without a backslash has no hive",
        raw_event(code="12", event_data={"TargetObject": "HKLM"}),
        {"registry.hive": ABSENT, "registry.path": "HKLM"},
    ),
    (
        "registry path that starts with a backslash has no hive",
        raw_event(code="12", event_data={"TargetObject": "\\SOFTWARE\\x"}),
        {"registry.hive": ABSENT},
    ),
    # --- hashes (section 9)
    (
        "process hashes are lower case",
        raw_event(code="1", event_data={"Hashes": HASHES}),
        {
            "process.hash.sha1": "aa",
            "process.hash.md5": "bb",
            "process.hash.sha256": "cc",
            "process.pe.imphash": "dd",
            "file.hash.sha1": ABSENT,
            "tags": ABSENT,
        },
    ),
    (
        "file hashes (image load) are lower case",
        raw_event(code="7", event_data={"Hashes": HASHES, "ImageLoaded": "C:\\Windows\\x.dll"}),
        {
            "file.hash.sha1": "aa",
            "file.hash.md5": "bb",
            "file.hash.sha256": "cc",
            "file.pe.imphash": "dd",
            "process.hash.sha1": ABSENT,
        },
    ),
    (
        "hashes in another layout are tagged, not guessed",
        raw_event(code="1", event_data={"Hashes": "SHA256=CC"}),
        {"process.hash.sha256": ABSENT, "tags": ["_hash_parse_failure"]},
    ),
    # --- "-" placeholders (section 11b)
    (
        "dashes are removed, real values stay",
        raw_event(
            code="1",
            event_data={
                "ParentImage": "-",
                "ParentCommandLine": "-",
                "Company": "-",
                "Product": "-",
                "OriginalFileName": "-",
                "FileVersion": "-",
                "Description": "Windows Command Processor",
            },
        ),
        {
            "process.parent.executable": ABSENT,
            "process.parent.name": ABSENT,
            "process.parent.command_line": ABSENT,
            "process.pe.company": ABSENT,
            "process.pe.product": ABSENT,
            "process.pe.original_file_name": ABSENT,
            "process.pe.file_version": ABSENT,
            "process.pe.description": "Windows Command Processor",
        },
    ),
    (
        "dashes of an image load are removed",
        raw_event(
            code="7",
            event_data={"ImageLoaded": "C:\\Windows\\x.dll", "Company": "-", "Description": "-"},
        ),
        {"file.pe.company": ABSENT, "file.pe.description": ABSENT},
    ),
]


def stack_image() -> str:
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith("LOGSENTINEL_ELASTIC_STACK_VERSION="):
            return f"docker.elastic.co/logstash/logstash:{line.split('=', 1)[1].strip()}"
    raise SystemExit("LOGSENTINEL_ELASTIC_STACK_VERSION is not set in .env")


def docker_logstash(
    image: str, mount: Path, args: list[str], stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    command = ["docker", "run", "--rm", "-i", "-v", f"{mount}:/cfg:ro", image, *args]
    return subprocess.run(
        command, input=stdin or "", capture_output=True, text=True, encoding="utf-8", check=False
    )


def check_syntax(image: str, config_dir: Path) -> list[str]:
    failures = []
    for pipeline in PIPELINES:
        result = docker_logstash(image, config_dir, ["-t", "-f", f"/cfg/{pipeline}"])
        ok = "Configuration OK" in result.stdout + result.stderr
        print(f"  {'OK    ' if ok else 'FAILED'} logstash -t {pipeline}")
        if not ok:
            failures.append(f"{pipeline}: {(result.stdout + result.stderr)[-600:]}")
    return failures


def filter_block(conf: str) -> str:
    """The ``filter { ... }`` block of a pipeline file (up to its ``output`` block)."""
    match = re.search(
        r"^filter \{\n.*?^\}\n(?=\n*^output \{)", conf, flags=re.MULTILINE | re.DOTALL
    )
    if match is None:
        raise SystemExit("cannot find the filter block of a pipeline file")
    return match.group(0)


def dig(event: dict[str, Any], dotted: str) -> Any:
    """The value at a dotted path of ``event``, or ``ABSENT``."""
    value: Any = event
    for key in dotted.split("."):
        if not isinstance(value, dict) or key not in value:
            return ABSENT
        value = value[key]
    return value


def rule_case(
    rule_name: str, threat: dict[str, Any] | None, rule_extra: dict[str, str]
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    expected: dict[str, Any] = {"threat": ABSENT if threat is None else threat}
    expected.update({f"rule.{key}": value for key, value in rule_extra.items()})
    return rule_name, raw_event(rule_name), expected


def check_ingest_filter(image: str, config_dir: Path) -> list[str]:
    conf = (config_dir / "ingest" / "ingest.conf").read_text(encoding="utf-8")
    pipeline = (
        "input { stdin { codec => json_lines } }\n"
        f"{filter_block(conf)}\n"
        "output { stdout { codec => json_lines } }\n"
    )
    cases = [*(rule_case(*rule) for rule in RULES), *FIELDS]
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "ingest-filter.conf").write_text(pipeline, encoding="utf-8")
        stdin = "".join(json.dumps(raw) + "\n" for _, raw, _ in cases)
        result = docker_logstash(
            image,
            Path(tmp),
            ["-f", "/cfg/ingest-filter.conf", "--pipeline.workers", "1", "--log.level", "error"],
            stdin,
        )
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    if len(events) != len(cases):
        return [
            f"expected {len(cases)} events, got {len(events)}: "
            f"{(result.stdout + result.stderr)[-800:]}"
        ]
    failures = []
    for event, (label, _, expected) in zip(events, cases, strict=True):
        problems = [
            f"{dotted} is {dig(event, dotted)!r}, expected {want!r}"
            for dotted, want in expected.items()
            if dig(event, dotted) != want
        ]
        if "@version" in event:
            problems.append("still has @version")
        print(f"  {'FAILED' if problems else 'OK    '} {label}")
        if problems:
            failures.append(f"{label}: {'; '.join(problems)}")
    return failures


def check_ingest_fork(image: str, config_dir: Path) -> list[str]:
    """Exercise the pipeline inputs, which create new events after ingest filtering."""
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        (directory / "pipelines.yml").write_text(
            "- pipeline.id: probe-ingest\n"
            '  path.config: "/cfg/probe-ingest.conf"\n'
            "- pipeline.id: probe-es\n"
            '  path.config: "/cfg/probe-es.conf"\n'
            "- pipeline.id: probe-inference\n"
            '  path.config: "/cfg/probe-inference.conf"\n',
            encoding="utf-8",
        )
        (directory / "probe-ingest.conf").write_text(
            "input { stdin { codec => json_lines } }\n"
            'filter { mutate { remove_field => ["@version"] } }\n'
            'output { pipeline { send_to => ["probe-es", "probe-inference"] } }\n',
            encoding="utf-8",
        )
        for branch in ("es", "inference"):
            conf = (config_dir / "ingest" / f"sink-{branch}.conf").read_text(encoding="utf-8")
            (directory / f"probe-{branch}.conf").write_text(
                f'input {{ pipeline {{ address => "probe-{branch}" }} }}\n'
                f"{filter_block(conf)}\n"
                "output { stdout { codec => json_lines } }\n",
                encoding="utf-8",
            )
        command = [
            "docker",
            "run",
            "--rm",
            "-i",
            "-v",
            f"{directory}:/cfg:ro",
            "--entrypoint",
            "/usr/bin/timeout",
            image,
            "60s",
            "/usr/share/logstash/bin/logstash",
            "--path.settings",
            "/cfg",
            "--log.level",
            "error",
        ]
        payload = json.dumps({"@timestamp": "2026-10-09T00:00:00Z", "message": "fork-probe"})
        result = subprocess.run(
            command,
            input=payload + "\n",
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    problems = []
    if len(events) != 2:
        problems.append(f"expected two fork outputs, got {len(events)}")
    else:
        if any("@version" in event for event in events):
            problems.append("@version reappeared after the pipeline fork")
        if sorted("message" in event for event in events) != [False, True]:
            problems.append("the Kafka branch did not drop only its message field")
    print(f"  {'FAILED' if problems else 'OK    '} ingest -> sink-es / sink-inference")
    if problems:
        return [f"ingest fork: {'; '.join(problems)} {(result.stdout + result.stderr)[-500:]}"]
    return []


SINK_EVENTS = [
    {"@timestamp": "2026-10-01T09:03:30.000Z", "logsentinel": {"window": {"id": "abc123"}}},
    {"@timestamp": "2026-10-01T09:03:30.000Z", "message": "no window id"},
]
"""A document with ``logsentinel.window.id`` and one without."""
SHOW_DOCUMENT_ID = """
filter {
  # @metadata is never printed: copy the document_id where the test can read it
  if [@metadata][document_id] {
    mutate { add_field => { "id_seen" => "%{[@metadata][document_id]}" } }
  }
}
"""


def check_sinks(image: str, config_dir: Path) -> list[str]:
    failures = []
    for name in ("detections", "window-scores"):
        conf = (config_dir / "detection-sink" / f"{name}.conf").read_text(encoding="utf-8")
        pipeline = (
            "input { stdin { codec => json_lines } }\n"
            f"{filter_block(conf)}\n"
            f"{SHOW_DOCUMENT_ID}\n"
            "output { stdout { codec => json_lines } }\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "sink-filter.conf").write_text(pipeline, encoding="utf-8")
            stdin = "".join(json.dumps(event) + "\n" for event in SINK_EVENTS)
            command = ["-f", "/cfg/sink-filter.conf", "--pipeline.workers", "1"]
            result = docker_logstash(image, Path(tmp), [*command, "--log.level", "error"], stdin)
        events = [json.loads(ln) for ln in result.stdout.splitlines() if ln.startswith("{")]
        problems = []
        if len(events) != len(SINK_EVENTS):
            problems.append(f"expected {len(SINK_EVENTS)} events, got {len(events)}")
        else:
            if events[0].get("id_seen") != "abc123":
                problems.append(f"document_id {events[0].get('id_seen')!r}, expected 'abc123'")
            if "id_seen" in events[1]:
                problems.append("a document without a window id got a document_id")
            if any("@version" in e or "original" in e.get("event", {}) for e in events):
                problems.append("@version or event.original is still there")
        print(f"  {'FAILED' if problems else 'OK    '} {name}")
        if problems:
            failures.append(f"{name}: {'; '.join(problems)} {result.stderr[-300:]}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--image", default=None, help="Logstash image (default: the stack's)")
    args = parser.parse_args(argv)
    image = args.image or stack_image()
    config_dir = (ROOT / "config" / "logstash").resolve()
    failures: list[str] = []
    print(f"image {image}")
    print("syntax:")
    failures += check_syntax(image, config_dir)
    print("ingest filter on sample events:")
    failures += check_ingest_filter(image, config_dir)
    print("ingest pipeline fork:")
    failures += check_ingest_fork(image, config_dir)
    print("detection-sink filters on sample documents:")
    failures += check_sinks(image, config_dir)
    for failure in failures:
        print("FAILURE:", failure)
    print("all checks passed" if not failures else f"{len(failures)} check(s) failed")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
