"""Check the repository against the naming rules (AGENTS.md section 11).

    python scripts/check_naming.py [--root DIR]

Checks what a machine can check; the rest of AGENTS.md section 11 is for people and reviews:

* ``file-name``: files and directories (kebab-case; snake_case for Python);
* ``document``: the markdown files are ``README.md`` and ``AGENTS.md`` only;
* ``env-name``: variables of ``.env``, ``${...}`` in Compose and Logstash files, and the
  ``environment:`` entries of Compose (``LOGSENTINEL_*``, ``INFERENCE__*`` or an
  upstream name);
* ``topic-name``: Kafka topics in ``.env`` (``<domain>.<subject>.<dataset>``);
* ``metadata-key``: keys of the capture ``metadata.json`` files (snake_case, format ``v1``);
* ``template-field``: top-level fields of the Elasticsearch templates (ECS or ``logsentinel``).

Exit code 0: no violation. Only the standard library is used.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {
    ".venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".git",
    "node_modules",
}
DATA_DIRS = (
    "archives",
    "sentinelcap/captures",
    "sentinelcap/samples",
    "inference/tests/fixtures/sessions",
)
"""Data, not project files: their names are the data's own (AGENTS.md section 11.13)."""

CONVENTIONAL_FILES = {
    "README.md",
    "AGENTS.md",
    "LICENSE",
    "Makefile",
    "Dockerfile",
    ".env",
    ".gitkeep",
    ".gitignore",
    ".gitattributes",
    ".dockerignore",
    ".editorconfig",
    ".pre-commit-config.yaml",
}
DOCUMENTS = {"README.md", "AGENTS.md"}
"""The only markdown file names of the project (AGENTS.md section 11.3)."""
PYTHON_FILE = re.compile(r"[a-z_][a-z0-9_]*\.py")
WORD = r"(?:[a-z0-9]+|\d{8}T\d{6}Z)"
"""A lower-case word, or the UTC stamp of AGENTS.md section 11.3."""
OTHER_FILE = re.compile(rf"{WORD}(-{WORD})*(\.[a-z0-9]+)+")
DIRECTORY = re.compile(rf"{WORD}([-_]{WORD})*")

ENV_KEY = re.compile(r"LOGSENTINEL_[A-Z0-9]+(_[A-Z0-9]+)*")
CONTAINER_ENV_KEY = re.compile(
    r"LOGSENTINEL_[A-Z0-9_]+|INFERENCE(__[A-Z0-9_]+)+"
    r"|KAFKA_[A-Z0-9_]+|ES_JAVA_OPTS|ELASTICSEARCH_HOSTS"
    r"|XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY|discovery\.type|xpack\.[a-z.]+"
)
TOPIC = re.compile(r"[a-z]+(\.[a-z0-9]+(-[a-z0-9]+)*){2,}")
SNAKE_KEY = re.compile(r"[a-z][a-z0-9_]*")
INTERPOLATION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)")
ECS_ROOTS = {
    "@timestamp", "message", "tags", "ecs", "event", "host", "service", "threat", "user",
    "process", "file", "registry", "network", "dns", "source", "destination", "rule", "log",
    "error", "agent",
}  # fmt: skip
TEMPLATE_ROOTS = ECS_ROOTS | {"logsentinel", "winlog"}
EXPECTED_FORMAT = "logsentinel.normalized-sysmon.jsonl/v1"


@dataclass(frozen=True)
class Violation:
    rule: str
    path: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.rule}] {self.path}: {self.detail}"


def relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def is_data(rel: str) -> bool:
    return any(rel == prefix or rel.startswith(prefix + "/") for prefix in DATA_DIRS)


def walk(root: Path) -> Iterator[tuple[str, bool]]:
    """``(relative path, is directory)`` of every project file and directory."""
    for current, dirs, files in os.walk(root):
        here = Path(current)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in dirs:
            rel = relative(root, here / name)
            if is_data(rel):
                dirs.remove(name)  # the directory itself is checked, not its content
            yield rel, True
        for name in sorted(files):
            rel = relative(root, here / name)
            if not is_data(rel):
                yield rel, False


def check_file_names(root: Path) -> list[Violation]:
    found = []
    for rel, is_dir in walk(root):
        name = rel.rsplit("/", 1)[-1]
        if not is_dir and name in CONVENTIONAL_FILES:
            continue
        if is_dir:
            ok = bool(DIRECTORY.fullmatch(name)) and not is_data(rel)
            if is_data(rel):
                continue
        elif name.endswith(".py"):
            ok = bool(PYTHON_FILE.fullmatch(name))
        else:
            ok = bool(OTHER_FILE.fullmatch(name))
        if not ok:
            kind = "directory" if is_dir else "file"
            found.append(Violation("file-name", rel, f"{kind} name is not kebab-case/snake_case"))
    return found


def check_documents(root: Path) -> list[Violation]:
    """Markdown files other than ``README.md`` and ``AGENTS.md``."""
    return [
        Violation("document", rel, "a markdown file other than README.md and AGENTS.md")
        for rel, is_dir in walk(root)
        if not is_dir and rel.endswith(".md") and rel.rsplit("/", 1)[-1] not in DOCUMENTS
    ]


def compose_environment(text: str) -> list[tuple[int, str]]:
    """``(line number, variable name)`` of every ``environment:`` entry of a Compose file."""
    lines = text.splitlines()
    entries: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        header = re.match(r"^(\s+)environment:\s*$", lines[index])
        index += 1
        if header is None:
            continue
        indent = len(header.group(1))
        while index < len(lines) and (
            not lines[index].strip() or len(lines[index]) - len(lines[index].lstrip()) > indent
        ):
            entry = lines[index].strip()
            if entry and not entry.startswith("#"):
                entry = entry.removeprefix("-").strip().strip("\"'")
                entries.append((index + 1, re.split(r"[=:]", entry, maxsplit=1)[0].strip()))
            index += 1
    return entries


def check_env_names(root: Path) -> list[Violation]:
    found = []
    env_file = root / ".env"
    if env_file.is_file():
        for number, line in enumerate(env_file.read_text(encoding="utf-8").splitlines(), start=1):
            key = line.split("=", 1)[0].strip()
            if line.strip() and not line.lstrip().startswith("#") and not ENV_KEY.fullmatch(key):
                found.append(
                    Violation("env-name", f".env:{number}", f"{key} lacks the LOGSENTINEL_ prefix")
                )
    compose = root / "docker-compose.yml"
    if compose.is_file():
        text = compose.read_text(encoding="utf-8")
        for number, key in compose_environment(text):
            if not CONTAINER_ENV_KEY.fullmatch(key):
                found.append(
                    Violation(
                        "env-name",
                        f"docker-compose.yml:{number}",
                        f"{key} is not a LOGSENTINEL_, INFERENCE__ or upstream name",
                    )
                )
    for path in [compose, *sorted((root / "config" / "logstash").rglob("*.conf"))]:
        rel = relative(root, path)
        if not path.is_file():
            continue
        for name in INTERPOLATION.findall(path.read_text(encoding="utf-8")):
            if not name.startswith("LOGSENTINEL_"):
                found.append(
                    Violation("env-name", rel, f"${{{name}}} lacks the LOGSENTINEL_ prefix")
                )
    return found


def check_topic_names(root: Path) -> list[Violation]:
    env_file = root / ".env"
    found = []
    if env_file.is_file():
        for number, line in enumerate(env_file.read_text(encoding="utf-8").splitlines(), start=1):
            key, _, value = line.partition("=")
            if key.startswith("LOGSENTINEL_TOPIC_") and not TOPIC.fullmatch(value.strip()):
                found.append(
                    Violation(
                        "topic-name",
                        f".env:{number}",
                        f"{value.strip()!r} is not <domain>.<subject>.<dataset>",
                    )
                )
    return found


def check_metadata_keys(root: Path) -> list[Violation]:
    found = []
    captures = root / "sentinelcap" / "captures"
    for path in sorted(captures.glob("*/*/*/metadata.json")) if captures.is_dir() else []:
        rel = relative(root, path)
        meta = json.loads(path.read_text(encoding="utf-8"))
        if meta.get("format") != EXPECTED_FORMAT:
            found.append(
                Violation(
                    "metadata-key",
                    rel,
                    f"format {meta.get('format')!r}, expected {EXPECTED_FORMAT}",
                )
            )
        for key in _keys(meta):
            if not SNAKE_KEY.fullmatch(key):
                found.append(Violation("metadata-key", rel, f"key {key!r} is not snake_case"))
        if not re.fullmatch(r"\d{8}T\d{6}Z", path.parts[-4]):
            found.append(
                Violation("metadata-key", rel, "the run directory is not a UTC YYYYMMDDTHHMMSSZ")
            )
    return found


def _keys(value: object) -> Iterator[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _keys(item)


def check_template_fields(root: Path) -> list[Violation]:
    found = []
    folder = root / "config" / "elasticsearch"
    for path in sorted(folder.glob("*-templates/*.json")):
        template = json.loads(path.read_text(encoding="utf-8")).get("template", {})
        properties = template.get("mappings", {}).get("properties", {})
        for name in properties:
            if name not in TEMPLATE_ROOTS:
                found.append(
                    Violation(
                        "template-field",
                        relative(root, path),
                        f"top-level field {name!r} is neither ECS nor logsentinel.*",
                    )
                )
    return found


def check_tree(root: Path) -> list[Violation]:
    checks = (
        check_file_names,
        check_documents,
        check_env_names,
        check_topic_names,
        check_metadata_keys,
        check_template_fields,
    )
    return [violation for check in checks for violation in check(root)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the repository against the naming rules (AGENTS.md section 11)."
    )
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    violations = check_tree(args.root.resolve())
    for violation in violations:
        print(violation)
    print(f"{len(violations)} violation(s)" if violations else "naming: clean")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
