"""Back up the project before a refactor (rule in AGENTS.md: always back up first).

    python scripts/backup_project.py --label <kebab-case-label> [--captures] [--stack]
    python scripts/backup_project.py --verify archives/backups/<directory>

Writes ``archives/backups/<UTC>-<label>/`` with:

* ``repo.tar.gz``: sources, configuration, documents, ``.env``, model artifacts and test
  fixtures (not ``.venv``, caches, ``sentinelcap/captures``, ``sentinelcap/samples`` or
  ``archives``);
* ``captures.tar.gz`` (``--captures``): every capture run;
* ``stack/`` (``--stack``): Elasticsearch templates, pipelines, ILM policies, index mappings
  and settings, the documents of the small ``ransomware-*`` indices (one JSON object per
  line, ready for ``_bulk``), Kibana saved objects, Docker state and Kafka topic/offset
  descriptions;
* ``SHA256SUMS`` and ``MANIFEST.json``.

Elasticsearch and Kafka *data* is not copied: it stays in the Docker volumes. Only the
standard library is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_NAMES = {
    ".venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".git",
}
EXCLUDED_SUFFIXES = (".egg-info",)
EXCLUDED_PATHS = (
    "sentinelcap/captures",
    "sentinelcap/samples",  # malware samples: not source, and antivirus blocks reading them
    "archives",
)
LABEL_RE = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
MIN_FREE_BYTES = 5 * 1024**3
KAFKA_CONTAINER = "logsentinel-kafka"
MAX_EXPORTED_DOCUMENTS = 10_000
"""The ransomware-* indices hold one document per window; a bigger one is not exported."""
KAFKA_BIN = "/opt/kafka/bin"
KAFKA_BOOTSTRAP = "localhost:29092"
KIBANA_TYPES = [
    "index-pattern",
    "dashboard",
    "visualization",
    "search",
    "lens",
    "tag",
    "query",
]


def utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def iter_files(base: Path, root: Path) -> Iterator[Path]:
    """Files below ``base`` that belong to the repository backup (``root`` fixes the paths)."""
    for path in sorted(base.iterdir()):
        relative = path.relative_to(root).as_posix()
        if path.name in EXCLUDED_NAMES or path.name.endswith(EXCLUDED_SUFFIXES):
            continue
        if relative in EXCLUDED_PATHS:
            continue
        if path.is_dir():
            yield from iter_files(path, root)
        elif path.is_file():
            yield path


def write_archive(target: Path, base: Path, files: list[Path], level: int = 6) -> int:
    with tarfile.open(target, "w:gz", compresslevel=level) as archive:
        for path in files:
            archive.add(path, arcname=path.relative_to(base).as_posix(), recursive=False)
    return len(files)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def http(url: str, *, method: str = "GET", body: dict[str, Any] | None = None) -> bytes:
    request = urllib.request.Request(url, method=method)
    request.add_header("kbn-xsrf", "true")
    data = None
    if body is not None:
        request.add_header("Content-Type", "application/json")
        data = json.dumps(body).encode("utf-8")
    with urllib.request.urlopen(request, data=data, timeout=60) as response:
        payload: bytes = response.read()
    return payload


def run(command: list[str]) -> str:
    done = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"{' '.join(command[:3])}...: {done.stderr.strip()[:200]}")
    return done.stdout


def export_stack(target: Path, es: str, kibana: str) -> dict[str, str]:
    """Write the stack description files; returns ``{file: error}`` for the ones that failed."""
    target.mkdir()
    errors: dict[str, str] = {}

    def save(name: str, produce: Any) -> None:
        try:
            content = produce()
            (target / name).write_bytes(content if isinstance(content, bytes) else content.encode())
        except (OSError, RuntimeError, urllib.error.URLError, ValueError) as exc:
            errors[name] = str(exc)[:300]

    for name, path in (
        ("es-index-templates.json", "_index_template"),
        ("es-component-templates.json", "_component_template"),
        ("es-ingest-pipelines.json", "_ingest/pipeline"),
        ("es-ilm-policies.json", "_ilm/policy"),
        ("es-cluster-health.json", "_cluster/health"),
        ("es-indices.json", "_cat/indices?format=json&bytes=b"),
    ):
        save(name, lambda path=path: http(f"{es}/{path}"))

    def index_descriptions(kind: str) -> bytes:
        listing = json.loads(http(f"{es}/_cat/indices?format=json&h=index"))
        names = [row["index"] for row in listing if not row["index"].startswith(".")]
        return http(f"{es}/{','.join(names)}/{kind}") if names else b"{}"

    def ransomware_documents() -> str:
        found = json.loads(
            http(
                f"{es}/ransomware-*/_search",
                method="POST",
                body={"size": MAX_EXPORTED_DOCUMENTS, "sort": ["_doc"]},
            )
        )["hits"]
        if found["total"]["value"] > len(found["hits"]):
            raise ValueError(f"more than {MAX_EXPORTED_DOCUMENTS} ransomware-* documents")
        return "".join(
            json.dumps({"_index": h["_index"], "_id": h["_id"], "_source": h["_source"]}) + "\n"
            for h in found["hits"]
        )

    save("es-ransomware-documents.ndjson", ransomware_documents)
    save("es-index-mappings.json", lambda: index_descriptions("_mapping"))
    save("es-index-settings.json", lambda: index_descriptions("_settings"))
    save(
        "kibana-saved-objects.ndjson",
        lambda: http(
            f"{kibana}/api/saved_objects/_export",
            method="POST",
            body={"type": KIBANA_TYPES, "includeReferencesDeep": True},
        ),
    )
    docker = ["docker"]
    save("docker-ps.txt", lambda: run([*docker, "ps", "-a", "--format", "{{json .}}"]))
    save(
        "docker-volumes.txt",
        lambda: run([*docker, "volume", "ls", "--format", "{{json .}}"]),
    )
    save(
        "docker-networks.txt",
        lambda: run([*docker, "network", "ls", "--format", "{{json .}}"]),
    )
    save("docker-images.txt", lambda: run([*docker, "images", "--format", "{{json .}}"]))

    def inspect() -> str:
        names = run([*docker, "ps", "-a", "--format", "{{.Names}}"]).split()
        mine = [n for n in names if n.startswith("logsentinel-")]
        return run([*docker, "inspect", *mine])

    save("docker-inspect.json", inspect)
    kafka = [*docker, "exec", KAFKA_CONTAINER]
    save(
        "kafka-topics.txt",
        lambda: run(
            [
                *kafka,
                f"{KAFKA_BIN}/kafka-topics.sh",
                "--bootstrap-server",
                KAFKA_BOOTSTRAP,
            ]
            + ["--describe"]
        ),
    )
    save(
        "kafka-consumer-groups.txt",
        lambda: run(
            [*kafka, f"{KAFKA_BIN}/kafka-consumer-groups.sh", "--bootstrap-server"]
            + [KAFKA_BOOTSTRAP, "--describe", "--all-groups"]
        ),
    )
    return errors


def create_backup(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    if not LABEL_RE.fullmatch(args.label):
        print(
            f"label must be kebab-case (a-z, 0-9, '-'), got {args.label!r}",
            file=sys.stderr,
        )
        return 2
    files = list(iter_files(root, root))
    capture_files: list[Path] = []
    captures = root / "sentinelcap" / "captures"
    if args.captures:
        capture_files = sorted(p for p in captures.rglob("*") if p.is_file())
    raw_bytes = sum(p.stat().st_size for p in [*files, *capture_files])
    needed = max(int(args.min_free_gb * 1024**3), raw_bytes // 3 * 2)
    out_root = Path(args.out) if args.out else root / "archives" / "backups"
    out_root.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(out_root).free
    if free < needed:
        print(
            f"not enough free space: {free // 1024**2} MB free, need {needed // 1024**2} MB",
            file=sys.stderr,
        )
        return 2
    target = out_root / f"{utc_stamp()}-{args.label}"
    target.mkdir()
    try:
        return write_backup(args, root, target, files, capture_files, captures)
    except BaseException:
        shutil.rmtree(target, ignore_errors=True)  # a half-written backup must not look like one
        raise


def write_backup(
    args: argparse.Namespace,
    root: Path,
    target: Path,
    files: list[Path],
    capture_files: list[Path],
    captures: Path,
) -> int:
    manifest: dict[str, Any] = {
        "label": args.label,
        "created_utc": utc_stamp(),
        "files": {},
    }
    manifest["files"]["repo.tar.gz"] = {
        "entries": write_archive(target / "repo.tar.gz", root, files)
    }
    if args.captures:
        count = write_archive(target / "captures.tar.gz", captures, capture_files, level=5)
        manifest["files"]["captures.tar.gz"] = {"entries": count}
    errors: dict[str, str] = {}
    if args.stack:
        errors = export_stack(target / "stack", args.es, args.kibana)
        for stack_file in sorted((target / "stack").iterdir()):
            manifest["files"][f"stack/{stack_file.name}"] = {}
    for name, info in manifest["files"].items():
        path = target / name
        info["bytes"] = path.stat().st_size
        info["sha256"] = sha256_of(path)
    manifest["errors"] = errors
    (target / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    sums = "".join(f"{i['sha256']}  {n}\n" for n, i in manifest["files"].items())
    (target / "SHA256SUMS").write_text(sums, encoding="utf-8")
    problems = verify_backup(target)
    print(f"backup written: {target}")
    for name, info in manifest["files"].items():
        print(f"  {name}: {info['bytes'] / 1024**2:.1f} MB")
    print(f"restore the repository: tar -xzf {target / 'repo.tar.gz'} -C <target directory>")
    for name, message in errors.items():
        print(f"  stack export failed: {name}: {message}", file=sys.stderr)
    for problem in problems:
        print(f"  VERIFY FAILED: {problem}", file=sys.stderr)
    return 1 if problems or errors else 0


def verify_backup(directory: Path) -> list[str]:
    """Problems found when re-reading a backup (empty list: sums and archives are intact)."""
    problems: list[str] = []
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"MANIFEST.json unreadable: {exc}"]
    for name, info in manifest["files"].items():
        path = directory / name
        if not path.is_file():
            problems.append(f"{name}: missing")
            continue
        if sha256_of(path) != info["sha256"]:
            problems.append(f"{name}: SHA-256 differs from the manifest")
            continue
        if name.endswith(".tar.gz"):
            try:
                with tarfile.open(path, "r:gz") as archive:
                    members = sum(1 for _ in archive)
            except (tarfile.TarError, OSError, EOFError) as exc:
                problems.append(f"{name}: not readable ({exc})")
                continue
            if members != info["entries"]:
                problems.append(f"{name}: {members} entries, manifest says {info['entries']}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--label", help="kebab-case name of the refactor step")
    parser.add_argument("--captures", action="store_true", help="include sentinelcap/captures")
    parser.add_argument(
        "--stack", action="store_true", help="export Elasticsearch/Docker/Kafka state"
    )
    parser.add_argument("--verify", metavar="DIR", help="verify an existing backup and exit")
    parser.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    parser.add_argument("--out", help="backup parent directory (default archives/backups)")
    parser.add_argument("--es", default="http://localhost:9200")
    parser.add_argument("--kibana", default="http://localhost:5601")
    parser.add_argument("--min-free-gb", type=float, default=MIN_FREE_BYTES / 1024**3)
    args = parser.parse_args(argv)
    if args.verify:
        problems = verify_backup(Path(args.verify))
        for problem in problems:
            print(problem, file=sys.stderr)
        print("backup intact" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    if not args.label:
        parser.error("--label is required")
    return create_backup(args)


if __name__ == "__main__":
    raise SystemExit(main())
