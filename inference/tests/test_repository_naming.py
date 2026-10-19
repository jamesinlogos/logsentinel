"""The naming rules (AGENTS.md section 11) as a test.

The repository follows them, and the checker catches what it should.
"""

from __future__ import annotations

import json
from pathlib import Path

import check_naming
import pytest

ROOT = Path(__file__).resolve().parents[2]


def messages(violations: list[check_naming.Violation]) -> str:
    return "\n".join(str(v) for v in violations)


def test_the_repository_follows_the_naming_rules() -> None:
    violations = check_naming.check_tree(ROOT)
    assert violations == [], "\n" + messages(violations)


def write(base: Path, name: str, content: str = "") -> Path:
    path = base / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_an_empty_tree_and_a_conventional_one_are_clean(tmp_path: Path) -> None:
    assert check_naming.check_tree(tmp_path) == []
    for name in ("README.md", "Makefile", "src/pkg_name/__init__.py", "scripts/create-topics.sh"):
        write(tmp_path, name)
    write(tmp_path, "sentinelcap/manifest-20261009T033003Z.csv", "x")
    assert check_naming.check_tree(tmp_path) == []


def test_file_and_directory_names(tmp_path: Path) -> None:
    write(tmp_path, "Bad_Name.json")
    write(tmp_path, "camelCase.py")
    write(tmp_path, "snake_case.json")
    write(tmp_path, "Upper/ok.md")
    write(tmp_path, "src/Fine_Module.py")
    found = {v.path for v in check_naming.check_file_names(tmp_path)}
    assert found == {
        "Bad_Name.json",
        "camelCase.py",
        "snake_case.json",
        "Upper",
        "src/Fine_Module.py",
    }


def test_markdown_files_are_readme_and_agents_only(tmp_path: Path) -> None:
    for name in ("README.md", "AGENTS.md", "inference/README.md", "inference/AGENTS.md"):
        write(tmp_path, name)
    assert check_naming.check_documents(tmp_path) == []
    write(tmp_path, "architecture.md")
    write(tmp_path, "inference/audit.md")
    write(tmp_path, "sentinelcap/samples/ransomware/Akira/notes.md")  # data keeps its own names
    found = {v.path for v in check_naming.check_documents(tmp_path)}
    assert found == {"architecture.md", "inference/audit.md"}


def test_data_directories_keep_their_own_names(tmp_path: Path) -> None:
    write(tmp_path, "sentinelcap/samples/ransomware/BlackMatter/abc.zip")
    write(tmp_path, "sentinelcap/captures/20261009T033557Z/akira/S_1/session.jsonl")
    assert check_naming.check_file_names(tmp_path) == []


def test_environment_variables(tmp_path: Path) -> None:
    write(tmp_path, ".env", "LOGSENTINEL_ES_PORT=9200\nES_PORT=9200\n# a comment\n")
    write(
        tmp_path,
        "docker-compose.yml",
        "services:\n"
        "  kafka:\n"
        "    environment:\n"
        "      KAFKA_NODE_ID: ${LOGSENTINEL_KAFKA_NODE_ID:-1}\n"
        "      SOMETHING: x\n"
        "  elasticsearch:\n"
        "    environment:\n"
        "      - discovery.type=single-node\n"
        '      - "ES_JAVA_OPTS=${ES_JAVA_OPTS:--Xms1g}"\n'
        "      - INFERENCE__KAFKA__INPUT_TOPIC=t\n"
        "    ports:\n"
        "      - 9200:9200\n",
    )
    found = messages(check_naming.check_env_names(tmp_path))
    assert ".env:2" in found and "ES_PORT" in found
    assert "SOMETHING" in found and "${ES_JAVA_OPTS}" in found
    assert "KAFKA_NODE_ID" not in found.replace("${LOGSENTINEL_KAFKA_NODE_ID", "")
    assert "discovery.type" not in found and "INFERENCE__KAFKA__INPUT_TOPIC" not in found


def test_the_compose_environment_parser_reads_both_styles() -> None:
    text = (
        "x:\n  environment:\n    A: 1\n    - B=2\n    - 'C: 3'\n  other:\n    D: 4\n"
        "  environment:\n    # comment\n    E: 5\n"
    )
    assert [key for _, key in check_naming.compose_environment(text)] == ["A", "B", "C", "E"]


def test_logstash_variables_need_the_prefix(tmp_path: Path) -> None:
    write(
        tmp_path,
        "config/logstash/ingest/ok.conf",
        'topics => ["${LOGSENTINEL_TOPIC_RAW_TELEMETRY:t}"]',
    )
    write(tmp_path, "config/logstash/ingest/bad.conf", 'topics => ["${RAW_TOPIC:t}"]')
    found = messages(check_naming.check_env_names(tmp_path))
    assert "bad.conf" in found and "ok.conf" not in found


def test_topic_names(tmp_path: Path) -> None:
    write(
        tmp_path,
        ".env",
        "LOGSENTINEL_TOPIC_A=telemetry.windows.normalized\n"
        "LOGSENTINEL_TOPIC_B=security.ransomware.window-scores\n"
        "LOGSENTINEL_TOPIC_C=Bad_Topic\n"
        "LOGSENTINEL_TOPIC_D=only.two\n",
    )
    found = check_naming.check_topic_names(tmp_path)
    assert [v.path for v in found] == [".env:3", ".env:4"]


def test_capture_metadata(tmp_path: Path) -> None:
    good = {"format": check_naming.EXPECTED_FORMAT, "label": {"target_class": 1}}
    write(
        tmp_path, "sentinelcap/captures/20261009T033557Z/akira/s1/metadata.json", json.dumps(good)
    )
    assert check_naming.check_metadata_keys(tmp_path) == []
    bad = {"format": "logsentinel.normalized-sysmon.jsonl/v9", "label": {"target-name": 1}}
    write(tmp_path, "sentinelcap/captures/20261009-103557/akira/s2/metadata.json", json.dumps(bad))
    found = messages(check_naming.check_metadata_keys(tmp_path))
    assert "expected" in found and "'target-name' is not snake_case" in found
    assert "not a UTC" in found


def test_template_top_level_fields(tmp_path: Path) -> None:
    properties: dict[str, dict[str, str]] = {"event": {}, "logsentinel": {}, "detection": {}}
    body = {"template": {"mappings": {"properties": properties}}}
    write(tmp_path, "config/elasticsearch/component-templates/x.json", json.dumps(body))
    found = check_naming.check_template_fields(tmp_path)
    assert [v.detail for v in found] == [
        "top-level field 'detection' is neither ECS nor logsentinel.*"
    ]


def test_main_reports_and_sets_the_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert check_naming.main(["--root", str(tmp_path)]) == 0
    assert "naming: clean" in capsys.readouterr().out
    write(tmp_path, "Bad_Name.json")
    assert check_naming.main(["--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "[file-name] Bad_Name.json" in out and "1 violation(s)" in out
