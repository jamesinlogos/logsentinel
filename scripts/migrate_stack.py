"""Move the stack and its data to another machine (the VMware VM is set up there already).

    python scripts/migrate_stack.py export --out <new directory> [--images]
                                           [--leave-stopped] [--force]
    python scripts/migrate_stack.py import --source <export directory>
                                           --target <new project directory> --kafka-host <ip>
                                           [--replace-volumes] [--no-start]
    python scripts/migrate_stack.py verify <export directory>

``export`` (source machine, stack running, VM off) records the document count of every
Elasticsearch data index and the end offset of every Kafka topic, stops the stack, writes the
three Docker volumes (``logsentinel_kafka-data``, ``logsentinel_elasticsearch-data``,
``logsentinel_logstash-ingest-data``) as gzip-compressed tar streams through a throwaway
container, archives the project, copies the two scripts to ``tools/`` (the
target has no project yet), writes ``MANIFEST.json`` and ``SHA256SUMS``, and starts the stack
again (unless ``--leave-stopped``). The project archive holds code, configuration, ``.env``
``sentinelcap/config.yaml`` and the model artifacts; it leaves out ``.venv``, caches,
``sentinelcap/captures``, ``sentinelcap/samples`` (malware) and ``archives``. The config goes
along as it is, VMware paths and ``guest_password`` of the source machine included: keep the
export private and adjust the paths on the target.

``import`` (target machine, Docker running) checks the sums, extracts the project into an
empty directory, sets ``LOGSENTINEL_KAFKA_ADVERTISED_HOST`` in ``.env``, loads the images (or
lets Compose pull and build them), lets Compose create the containers and volumes, fills the
volumes, starts the stack and compares the document counts and Kafka offsets with the
manifest. Consumer-group offsets live in the Kafka volume, so the services go on where they
stopped.

The helper container is the Kafka image of the stack (busybox ``tar``; the Elasticsearch image
has no ``tar``). Only the standard library is used.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import backup_project

ROOT = Path(__file__).resolve().parent.parent
FORMAT = "logsentinel.stack-migration/v1"
PROJECT = "logsentinel"
VOLUMES = ("kafka-data", "elasticsearch-data", "logstash-ingest-data")
KAFKA_CONTAINER = "logsentinel-kafka"
KAFKA_BIN = "/opt/kafka/bin"
KAFKA_BOOTSTRAP = "localhost:29092"
TOPIC_VARIABLES = (
    "LOGSENTINEL_TOPIC_RAW_TELEMETRY",
    "LOGSENTINEL_TOPIC_NORMALIZED_TELEMETRY",
    "LOGSENTINEL_TOPIC_DETECTIONS",
    "LOGSENTINEL_TOPIC_WINDOW_SCORES",
)
HEALTHY_SERVICES = (
    "logsentinel-kafka",
    "logsentinel-elasticsearch",
    "logsentinel-kibana",
    "logsentinel-logstash-ingest",
    "logsentinel-logstash-detection-sink",
    "logsentinel-inference",
    "logsentinel-notifications",
)
INIT_SERVICES = (
    "logsentinel-kafka-init",
    "logsentinel-elasticsearch-init",
    "logsentinel-kibana-init",
)
CHUNK = 4 * 1024 * 1024
MIN_FREE_BYTES = 5 * 1024**3
KAFKA_HOST_VARIABLE = "LOGSENTINEL_KAFKA_ADVERTISED_HOST"


class MigrationError(RuntimeError):
    """A precondition or a step failed; the message says what to do."""


# ------------------------------------------------------------------ docker and the host
def docker(
    *args: str, check: bool = True, timeout: float | None = 600
) -> subprocess.CompletedProcess[str]:
    done = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if check and done.returncode != 0:
        raise MigrationError(f"docker {' '.join(args[:3])}: {done.stderr.strip()[:400]}")
    return done


def compose(
    project: Path, *args: str, timeout: float | None = 900
) -> subprocess.CompletedProcess[str]:
    return docker("compose", "-f", str(project / "docker-compose.yml"), *args, timeout=timeout)


def vm_running() -> bool:
    """Whether VMware Workstation has a virtual machine running on this machine."""
    if os.name == "nt":
        shown = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq vmware-vmx.exe", "/NH"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        return "vmware-vmx.exe" in shown.lower()
    return (
        subprocess.run(["pgrep", "-x", "vmware-vmx"], capture_output=True, check=False).returncode
        == 0
    )


def service_states() -> dict[str, str]:
    """``{container name: status text}`` of the compose project."""
    shown = docker(
        "ps",
        "-a",
        "--filter",
        f"label=com.docker.compose.project={PROJECT}",
        "--format",
        "{{.Names}}|{{.Status}}",
    ).stdout
    return dict(line.split("|", 1) for line in shown.splitlines() if "|" in line)


def stack_is_up(states: dict[str, str]) -> bool:
    return all("(healthy)" in states.get(name, "") for name in HEALTHY_SERVICES) and all(
        states.get(name, "").startswith("Exited (0)") for name in INIT_SERVICES
    )


def wait_until_up(timeout_sec: float) -> dict[str, str]:
    deadline = time.monotonic() + timeout_sec
    states = service_states()
    while not stack_is_up(states):
        if time.monotonic() > deadline:
            raise MigrationError(f"the stack is not healthy after {timeout_sec:.0f} s: {states}")
        time.sleep(5)
        states = service_states()
    return states


# ------------------------------------------------------------------ .env
def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, value = stripped.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def set_env_value(path: Path, key: str, value: str) -> str:
    """Set ``key`` in the ``.env`` file, keeping its line endings; returns the previous value."""
    raw = path.read_bytes().decode("utf-8")
    pattern = re.compile(rf"^{re.escape(key)}=(.*?)(\r?)$", re.MULTILINE)
    found = pattern.search(raw)
    if found is None:
        raise MigrationError(f"{path} has no {key}")
    previous = found.group(1)
    path.write_bytes(
        pattern.sub(lambda m: f"{key}={value}{m.group(2)}", raw, count=1).encode("utf-8")
    )
    return previous


# ------------------------------------------------------------------ facts that must survive
def parse_offsets(output: str) -> dict[str, int]:
    """``kafka-get-offsets.sh`` lines ``topic:partition:offset`` -> ``{partition: offset}``."""
    offsets: dict[str, int] = {}
    for line in output.splitlines():
        parts = line.strip().rsplit(":", 2)
        if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
            offsets[parts[1]] = int(parts[2])
    return offsets


def collect_facts(es: str, topics: Sequence[str]) -> dict[str, Any]:
    """Document counts of the data indices and end offsets of the topics."""
    with urllib.request.urlopen(
        f"{es}/_cat/indices?format=json&h=index,docs.count", timeout=60
    ) as response:
        rows = json.load(response)
    indices = {
        row["index"]: int(row["docs.count"]) for row in rows if not row["index"].startswith(".")
    }
    offsets = {}
    for topic in topics:
        shown = docker(
            "exec",
            KAFKA_CONTAINER,
            f"{KAFKA_BIN}/kafka-get-offsets.sh",
            "--bootstrap-server",
            KAFKA_BOOTSTRAP,
            "--topic",
            topic,
        ).stdout
        offsets[topic] = parse_offsets(shown)
    return {"indices": indices, "offsets": offsets}


def compare_facts(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """Differences between the facts of the source and of the target (empty: the same)."""
    problems = []
    for name in sorted(set(expected["indices"]) | set(actual["indices"])):
        before, after = expected["indices"].get(name), actual["indices"].get(name)
        if before != after:
            problems.append(f"index {name}: {before} documents at the source, {after} here")
    for topic in sorted(set(expected["offsets"]) | set(actual["offsets"])):
        before, after = expected["offsets"].get(topic), actual["offsets"].get(topic)
        if before != after:
            problems.append(f"topic {topic}: offsets {before} at the source, {after} here")
    return problems


# ------------------------------------------------------------------ volumes as tar streams
def volume_command(
    helper: str, volume: str, *tar_args: str, read_only: bool, interactive: bool = False
) -> list[str]:
    mount = f"{volume}:/data" + (":ro" if read_only else "")
    return [
        "docker",
        "run",
        "--rm",
        *(["-i"] if interactive else []),
        "--user",
        "0",
        "--entrypoint",
        "tar",
        "-v",
        mount,
        helper,
        *tar_args,
    ]


def volume_bytes(helper: str, volume: str) -> int:
    shown = docker(
        "run",
        "--rm",
        "--user",
        "0",
        "--entrypoint",
        "du",
        "-v",
        f"{volume}:/data:ro",
        helper,
        "-sk",
        "/data",
    ).stdout
    return int(shown.split()[0]) * 1024


def export_volume(helper: str, volume: str, target: Path) -> None:
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(
            volume_command(helper, volume, "cf", "-", "-C", "/data", ".", read_only=True),
            stdout=subprocess.PIPE,
            stderr=errors,
        )
        assert process.stdout is not None
        with gzip.open(target, "wb", compresslevel=3) as out:
            for block in iter(lambda: process.stdout.read(CHUNK), b""):  # type: ignore[union-attr]
                out.write(block)
        if process.wait() != 0:
            errors.seek(0)
            raise MigrationError(
                f"reading volume {volume} failed: {errors.read().decode(errors='replace')[:400]}"
            )


def import_volume(helper: str, volume: str, source: Path, *, replace: bool) -> None:
    listing = [
        "run",
        "--rm",
        "--user",
        "0",
        "--entrypoint",
        "sh",
        "-v",
        f"{volume}:/data",
        helper,
        "-c",
    ]
    if docker(*listing, "ls -A /data").stdout.strip():
        if not replace:
            raise MigrationError(
                f"volume {volume} is not empty; --replace-volumes empties it first"
            )
        docker(*listing, "rm -rf /data/* /data/.[!.]* /data/..?*")
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(
            volume_command(
                helper, volume, "xf", "-", "-C", "/data", read_only=False, interactive=True
            ),
            stdin=subprocess.PIPE,
            stderr=errors,
        )
        assert process.stdin is not None
        try:
            with gzip.open(source, "rb") as stream:
                for block in iter(lambda: stream.read(CHUNK), b""):
                    process.stdin.write(block)
            process.stdin.close()
        except BrokenPipeError:
            pass  # tar stopped early; its exit code and message follow
        if process.wait() != 0:
            errors.seek(0)
            raise MigrationError(
                f"writing volume {volume} failed: {errors.read().decode(errors='replace')[:400]}"
            )


# ------------------------------------------------------------------ files, manifest, sums
def project_files(root: Path) -> list[Path]:
    """The project archive: what ``backup_project`` keeps (no captures, samples, archives)."""
    return list(backup_project.iter_files(root, root))


def nested_exports(root: Path) -> list[Path]:
    """Exports sitting directly in the project: ``project_files`` would take their volumes along."""
    found = []
    for child in sorted(root.iterdir()):
        manifest = child / "MANIFEST.json"
        if not child.is_dir() or not manifest.is_file():
            continue
        try:
            if json.loads(manifest.read_text(encoding="utf-8")).get("format") == FORMAT:
                found.append(child)
        except (OSError, ValueError, AttributeError):
            continue
    return found


def write_manifest(directory: Path, info: dict[str, Any]) -> None:
    files = {
        path.relative_to(directory).as_posix(): {
            "sha256": backup_project.sha256_of(path),
            "bytes": path.stat().st_size,
        }
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.name not in {"MANIFEST.json", "SHA256SUMS"}
    }
    manifest = {"format": FORMAT, **info, "files": files}
    (directory / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    sums = "".join(f"{entry['sha256']}  {name}\n" for name, entry in files.items())
    (directory / "SHA256SUMS").write_text(sums, encoding="utf-8")


def verify_export(directory: Path) -> list[str]:
    """Problems found when re-reading an export (empty: every file matches the manifest)."""
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"MANIFEST.json unreadable: {exc}"]
    if manifest.get("format") != FORMAT:
        return [f"MANIFEST.json: format {manifest.get('format')!r}, expected {FORMAT!r}"]
    problems = []
    for name, entry in manifest["files"].items():
        path = directory / name
        if not path.is_file():
            problems.append(f"{name}: missing")
        elif (
            path.stat().st_size != entry["bytes"]
            or backup_project.sha256_of(path) != entry["sha256"]
        ):
            problems.append(f"{name}: differs from the manifest")
        elif name.endswith(".gz") and not gzip_is_intact(path):
            problems.append(f"{name}: not a complete gzip stream")
    for volume in VOLUMES:
        if f"volumes/{volume}.tar.gz" not in manifest["files"]:
            problems.append(f"volumes/{volume}.tar.gz: not in the manifest")
    return problems


def gzip_is_intact(path: Path) -> bool:
    try:
        with gzip.open(path, "rb") as stream:
            while stream.read(CHUNK):
                pass
    except (OSError, EOFError):
        return False
    return True


def extract(archive: Path, target: Path) -> int:
    """Unpack a tar.gz below ``target``; a member outside it is refused (``data`` filter)."""
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        tar.extractall(target, members=members, filter="data")
    return len(members)


# ------------------------------------------------------------------ export
def export_stack(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    env = read_env(root / ".env")
    out = Path(args.out).resolve()
    if out.exists() and any(out.iterdir()):
        raise MigrationError(f"{out} exists and is not empty")
    if root in out.parents:
        raise MigrationError(f"{out} is inside the project: export to a directory outside {root}")
    if nested := nested_exports(root):
        raise MigrationError(
            f"{', '.join(path.name for path in nested)} is an export inside the project, so"
            " project.tar.gz would carry its volumes: move it out of the project first"
        )
    if vm_running() and not args.force:
        raise MigrationError(
            "a VMware VM is running: stop the capture and the VM first (--force overrides)"
        )
    docker("version", "--format", "{{.Server.Version}}")
    states = service_states()
    if not stack_is_up(states):
        raise MigrationError(
            f"the stack must be up and healthy to record its counts first: {states}"
        )
    helper = f"apache/kafka:{env['LOGSENTINEL_KAFKA_IMAGE_TAG']}"
    facts = collect_facts(
        f"http://localhost:{env['LOGSENTINEL_ES_PORT']}", [env[key] for key in TOPIC_VARIABLES]
    )
    files = project_files(root)
    sizes = {volume: volume_bytes(helper, f"{PROJECT}_{volume}") for volume in VOLUMES}
    needed = max(
        MIN_FREE_BYTES,
        (sum(sizes.values()) + sum(p.stat().st_size for p in files)) // 2,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(out.parent).free
    if free < needed:
        raise MigrationError(
            f"not enough free space: {free // 1024**2} MB free, need {needed // 1024**2} MB"
        )
    partial = out.with_name(out.name + ".partial")
    shutil.rmtree(partial, ignore_errors=True)
    (partial / "volumes").mkdir(parents=True)
    stopped = False
    try:
        print("stopping the stack (the volumes must not change while they are read) ...")
        compose(root, "stop", "-t", "60")
        stopped = True
        for volume in VOLUMES:
            print(f"volume {PROJECT}_{volume}: {sizes[volume] / 1024**2:.0f} MB ...")
            export_volume(helper, f"{PROJECT}_{volume}", partial / "volumes" / f"{volume}.tar.gz")
        print("project ...")
        (partial / "tools").mkdir()
        for script in ("migrate_stack.py", "backup_project.py"):
            shutil.copy2(Path(__file__).resolve().parent / script, partial / "tools" / script)
        backup_project.write_archive(partial / "project.tar.gz", root, files, 6)
        if args.images:
            images = sorted(set(compose(root, "config", "--images").stdout.split()))
            print(f"images: {', '.join(images)} ...")
            docker("save", "-o", str(partial / "images.tar"), *images, timeout=None)
        model = json.loads(
            (root / "inference" / "artifacts" / "model-meta.json").read_text(encoding="utf-8")
        )
        write_manifest(
            partial,
            {
                "created_utc": backup_project.utc_stamp(),
                "source": {
                    "host": platform.node(),
                    "system": platform.platform(),
                    "kafka_host": env[KAFKA_HOST_VARIABLE],
                },
                "model_version": model.get("version"),
                "helper_image": helper,
                "volume_bytes": sizes,
                "facts": facts,
            },
        )
        partial.rename(out)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)  # a half-written export must not look like one
        raise
    finally:
        if stopped and not args.leave_stopped:
            print("starting the stack again ...")
            compose(root, "up", "-d", "--no-build")
    print(f"export written: {out}")
    print(
        f"on the target: python <copy of {out.name}>/tools/migrate_stack.py import "
        f"--source <copy of {out.name}> --target <new project directory> "
        "--kafka-host <ip of that machine>"
    )
    return 0


# ------------------------------------------------------------------ import
def import_stack(args: argparse.Namespace) -> int:
    source, target = Path(args.source).resolve(), Path(args.target).resolve()
    problems = verify_export(source)
    if problems:
        raise MigrationError("the export is damaged: " + "; ".join(problems))
    manifest = json.loads((source / "MANIFEST.json").read_text(encoding="utf-8"))
    docker("version", "--format", "{{.Server.Version}}")
    if target.exists() and any(target.iterdir()):
        raise MigrationError(f"{target} exists and is not empty")
    if service_states():
        raise MigrationError(
            "containers of this stack exist here already: docker compose down first"
        )
    known = docker("volume", "ls", "-q").stdout.split()
    present = [v for v in VOLUMES if f"{PROJECT}_{v}" in known]
    if present and not args.replace_volumes:
        raise MigrationError(
            f"volumes exist here already: {', '.join(present)} (--replace-volumes empties them)"
        )
    target.mkdir(parents=True, exist_ok=True)
    print(f"project: {extract(source / 'project.tar.gz', target)} entries ...")
    previous = set_env_value(target / ".env", KAFKA_HOST_VARIABLE, args.kafka_host)
    print(f"{KAFKA_HOST_VARIABLE}: {previous} -> {args.kafka_host}")
    env = read_env(target / ".env")
    helper = manifest["helper_image"]
    if (source / "images.tar").is_file():
        print("loading images ...")
        docker("load", "-i", str(source / "images.tar"), timeout=None)
    print("creating containers and volumes (missing images are pulled or built here) ...")
    build = (
        []
        if docker("image", "inspect", "logsentinel-inference", check=False).returncode == 0
        else ["--build"]
    )
    compose(target, "up", "--no-start", *build, timeout=3600)
    for volume in VOLUMES:
        print(f"volume {PROJECT}_{volume} ...")
        import_volume(
            helper,
            f"{PROJECT}_{volume}",
            source / "volumes" / f"{volume}.tar.gz",
            replace=args.replace_volumes,
        )
    if args.no_start:
        print(f"data restored; start with: docker compose -f {target / 'docker-compose.yml'} up -d")
        return 0
    print("starting the stack ...")
    compose(target, "up", "-d")
    wait_until_up(args.wait_sec)
    differences = compare_facts(
        manifest["facts"],
        collect_facts(
            f"http://localhost:{env['LOGSENTINEL_ES_PORT']}", [env[key] for key in TOPIC_VARIABLES]
        ),
    )
    for line in differences:
        print(f"DIFFERENT {line}", file=sys.stderr)
    counts = manifest["facts"]["indices"]
    print(
        f"stack is up; {len(counts)} data indices and {len(manifest['facts']['offsets'])} topics "
        f"{'differ from' if differences else 'match'} the source"
    )
    print(
        "still to do by hand: the Winlogbeat output host in the VM snapshots must reach "
        f"{args.kafka_host}:{env['LOGSENTINEL_KAFKA_PORT']}"
        + "; sentinelcap/config.yaml still has the VMware paths of the source machine"
    )
    return 1 if differences else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser(
        "export", help="write the volumes and the project of the running stack"
    )
    export.add_argument("--out", required=True, help="new directory for the export")
    export.add_argument(
        "--images", action="store_true", help="also save the Docker images (offline target)"
    )
    export.add_argument("--leave-stopped", action="store_true", help="do not start the stack again")
    export.add_argument("--force", action="store_true", help="export although a VM is running")
    imported = commands.add_parser("import", help="rebuild the stack and its data from an export")
    imported.add_argument("--source", required=True, help="the export directory")
    imported.add_argument("--target", required=True, help="new project directory")
    imported.add_argument(
        "--kafka-host", required=True, help="IP of this machine as the VM reaches it"
    )
    imported.add_argument(
        "--replace-volumes", action="store_true", help="empty existing stack volumes first"
    )
    imported.add_argument(
        "--no-start", action="store_true", help="restore the data but do not start"
    )
    imported.add_argument("--wait-sec", type=float, default=300)
    verify = commands.add_parser("verify", help="check an export against its manifest")
    verify.add_argument("directory")
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            problems = verify_export(Path(args.directory))
            for problem in problems:
                print(problem, file=sys.stderr)
            print("export intact" if not problems else f"{len(problems)} problem(s)")
            return 1 if problems else 0
        return export_stack(args) if args.command == "export" else import_stack(args)
    except (MigrationError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
