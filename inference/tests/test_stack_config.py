"""docker-compose.yml: ``docker compose up -d`` leaves a stack that is ready, and no default drifts.

The init services run ``scripts/create-topics.sh`` and ``scripts/init-elasticsearch.sh`` once; the
services that need the topics or the Elasticsearch configuration wait for them. Only a real
``docker compose up`` shows the whole sequence; these tests keep the pieces consistent.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from inference.config import ServiceConfig, apply_env_overrides

ROOT = Path(__file__).resolve().parents[2]
SERVICES: dict[str, dict[str, Any]] = yaml.safe_load(
    (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
)["services"]
INIT_SERVICES = {"kafka-init": "create-topics.sh", "elasticsearch-init": "init-elasticsearch.sh"}
DEFAULT = re.compile(r"\$\{(LOGSENTINEL_[A-Z0-9_]+):-([^}]*)\}")
TOPIC_VARIABLES = {
    "LOGSENTINEL_TOPIC_RAW_TELEMETRY",
    "LOGSENTINEL_TOPIC_NORMALIZED_TELEMETRY",
    "LOGSENTINEL_TOPIC_DETECTIONS",
    "LOGSENTINEL_TOPIC_WINDOW_SCORES",
}


def environment(service: str) -> dict[str, str]:
    declared = SERVICES[service].get("environment", {})
    if isinstance(declared, dict):
        return {key: "" if value is None else str(value) for key, value in declared.items()}
    return {item.partition("=")[0]: item.partition("=")[2] for item in declared}


def env_file() -> dict[str, str]:
    """``.env`` as docker compose reads it: ``NAME=value`` lines, comments and blanks skipped."""
    values = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            name, _, value = line.partition("=")
            values[name.strip()] = value.strip()
    return values


def mounts(service: str) -> set[str]:
    return set(SERVICES[service]["volumes"])


@pytest.mark.parametrize(("service", "script"), INIT_SERVICES.items())
def test_an_init_service_runs_its_script_once(service: str, script: str) -> None:
    definition = SERVICES[service]
    assert definition["restart"] == "no"
    assert definition["container_name"] == f"logsentinel-{service}"
    assert definition["entrypoint"] == ["bash", f"/scripts/{script}"]
    assert (ROOT / "scripts" / script).is_file()
    assert "./scripts:/scripts:ro" in mounts(service)


def test_elasticsearch_init_reads_the_repository_configuration() -> None:
    assert "./config/elasticsearch:/config/elasticsearch:ro" in mounts("elasticsearch-init")
    assert (ROOT / "config" / "elasticsearch").is_dir()
    # init-elasticsearch.sh reads ../config/elasticsearch next to the script: /scripts/../config.
    host = "http://elasticsearch:9200"
    assert environment("elasticsearch-init") == {"LOGSENTINEL_ES_HOST": host}


def test_kafka_init_uses_the_internal_listener_of_the_broker() -> None:
    advertised = environment("kafka")["KAFKA_ADVERTISED_LISTENERS"]
    internal = re.search(r"INTERNAL://([^,]+)", advertised)
    assert internal is not None
    env = environment("kafka-init")
    assert env["LOGSENTINEL_KAFKA_BOOTSTRAP"] == internal.group(1)
    assert env["LOGSENTINEL_KAFKA_EXEC"] == ""  # no `docker exec`: the script is inside the image
    assert TOPIC_VARIABLES <= set(env)


@pytest.mark.parametrize(
    ("service", "needs"),
    [
        ("logstash-ingest", {"kafka-init", "elasticsearch-init"}),
        ("logstash-detection-sink", {"kafka-init", "elasticsearch-init"}),
        ("inference", {"kafka-init"}),
        ("notifications", {"elasticsearch-init"}),  # it writes receipts into a templated index
    ],
)
def test_services_wait_for_the_init_services_they_need(service: str, needs: set[str]) -> None:
    depends = SERVICES[service]["depends_on"]
    for init in needs:
        assert depends[init]["condition"] == "service_completed_successfully", (service, init)


def test_an_init_service_waits_for_its_server_to_be_healthy() -> None:
    for init, server in (("kafka-init", "kafka"), ("elasticsearch-init", "elasticsearch")):
        assert SERVICES[init]["depends_on"][server]["condition"] == "service_healthy"
        assert "healthcheck" in SERVICES[server]


def test_every_long_running_service_has_a_healthcheck() -> None:
    for service in (
        "kafka",
        "elasticsearch",
        "kibana",
        "logstash-ingest",
        "logstash-detection-sink",
        "notifications",
    ):
        assert "healthcheck" in SERVICES[service], service
    # inference has its own, in its Dockerfile (notifications repeats its own in Compose).
    for component in ("inference", "notifications"):
        dockerfile = (ROOT / component / "Dockerfile").read_text(encoding="utf-8")
        assert "HEALTHCHECK" in dockerfile, component


def test_services_that_keep_state_get_time_to_stop() -> None:
    """Docker's default of 10 s may cut the final write of a broker, an index or a queue."""
    stateful = (
        "kafka",
        "elasticsearch",
        "logstash-ingest",
        "logstash-detection-sink",
        "inference",
        "notifications",  # a stop between a send and its receipt sends the notice again
    )
    for service in stateful:
        assert int(SERVICES[service]["stop_grace_period"].removesuffix("s")) >= 30, service


def test_every_service_variable_of_the_compose_file_names_a_configuration_key() -> None:
    """The service has one start-up (a complete model or exit code 2): nothing to switch on."""
    merged = apply_env_overrides({}, environment("inference"))
    ServiceConfig.model_validate(merged)  # an unknown key would raise


def test_logstash_inputs_use_no_deprecated_option() -> None:
    for path in sorted((ROOT / "config" / "logstash").rglob("*.conf")):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"decorate_events\s*=>\s*true", text), path


def test_every_parsing_plugin_of_the_ingest_pipeline_has_a_unique_id() -> None:
    """The monitoring API names a plugin by its id: without one the time per filter is unreadable"""
    conf = (ROOT / "config" / "logstash" / "ingest" / "ingest.conf").read_text(encoding="utf-8")
    plugins = re.findall(r"^\s*(grok|dissect|translate|kv|ruby)\s*\{", conf, flags=re.MULTILINE)
    with_id = re.findall(
        r'^\s*(?:grok|dissect|translate|kv|ruby)\s*\{\s*\n\s*id => "[a-z0-9-]+"',
        conf,
        flags=re.MULTILINE,
    )
    assert plugins and len(with_id) == len(plugins)
    ids = re.findall(r'\bid => "([a-z0-9-]+)"', conf)
    assert len(ids) == len(set(ids))


def test_the_telemetry_document_id_has_the_metadata_it_names() -> None:
    sink = (ROOT / "config" / "logstash" / "ingest" / "sink-es.conf").read_text(encoding="utf-8")
    ingest = (ROOT / "config" / "logstash" / "ingest" / "ingest.conf").read_text(encoding="utf-8")
    assert "[@metadata][kafka][offset]" in sink
    assert re.search(r'decorate_events\s*=>\s*"basic"', ingest)


def test_compose_defaults_equal_the_env_file() -> None:
    """A missing or older .env must not change what is deployed (an image downgrade, a topic)."""
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    found = DEFAULT.findall(text)
    assert found
    env = env_file()
    for name, default in found:
        if name in env:
            assert default == env[name], f"{name}: compose says {default}, .env says {env[name]}"
    assert {name for name, _ in found} >= TOPIC_VARIABLES


def test_the_env_file_declares_what_compose_interpolates_without_a_default() -> None:
    """Names only: the test never reads or prints a credential."""
    needed = {
        match.group(1)
        for service in ("kibana", "notifications")
        for value in environment(service).values()
        if (match := re.search(r"\$\{(LOGSENTINEL_[A-Z0-9_]+)(?:\}|:\?)", value))
    }
    assert {"LOGSENTINEL_KIBANA_ENCRYPTION_KEY", "LOGSENTINEL_TELEGRAM_BOT_TOKEN"} <= needed
    declared = set(env_file())
    assert needed <= declared, sorted(needed - declared)


TOPIC = re.compile(r"\b(?:telemetry|security)\.[a-z]+\.[a-z0-9]+(?:[.-][a-z0-9]+)*")
ALL_TOPICS = ("RAW_TELEMETRY", "NORMALIZED_TELEMETRY", "DETECTIONS", "WINDOW_SCORES")
SERVICE_TOPICS = ("NORMALIZED_TELEMETRY", "DETECTIONS", "WINDOW_SCORES")
TOPIC_USERS = {
    # file -> the topics it must spell (it may mention others in comments, never another name)
    "config/winlogbeat/winlogbeat.yml": ("RAW_TELEMETRY",),
    "config/logstash/ingest/ingest.conf": ("RAW_TELEMETRY",),
    "config/logstash/ingest/sink-inference.conf": ("NORMALIZED_TELEMETRY",),
    "config/logstash/detection-sink/detections.conf": ("DETECTIONS",),
    "config/logstash/detection-sink/window-scores.conf": ("WINDOW_SCORES",),
    "inference/config.yaml": SERVICE_TOPICS,
    "inference/src/inference/config.py": SERVICE_TOPICS,
    "sentinelcap/src/sentinelcap/config.py": ("NORMALIZED_TELEMETRY",),
    "scripts/create-topics.sh": ALL_TOPICS,
    "scripts/verify_detections.py": ALL_TOPICS,
}


def test_every_place_that_spells_a_topic_spells_the_one_of_the_env_file() -> None:
    """The topic names live in .env; the defaults that repeat them cannot drift."""
    env = env_file()
    known = {env[f"LOGSENTINEL_TOPIC_{key}"] for key in ALL_TOPICS}
    for relative, users in TOPIC_USERS.items():
        spelled = set(TOPIC.findall((ROOT / relative).read_text(encoding="utf-8")))
        assert spelled <= known, f"{relative} spells {sorted(spelled - known)}"
        wanted = {env[f"LOGSENTINEL_TOPIC_{key}"] for key in users}
        assert wanted <= spelled, f"{relative} does not spell {sorted(wanted - spelled)}"


def bash_that_sees(directory: Path) -> str | None:
    """A bash that can open ``directory`` by its POSIX-style path (not the WSL launcher)."""
    bash = shutil.which("bash")
    if bash is None:
        return None
    try:
        probe = subprocess.run(
            [bash, "-c", 'test -d "$1"', "_", directory.as_posix()], timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return bash if probe.returncode == 0 else None


def test_create_topics_runs_kafka_topics_directly_when_it_is_inside_the_broker_image(
    tmp_path: Path,
) -> None:
    """What kafka-init does, with a kafka-topics.sh that only records its arguments."""
    bash = bash_that_sees(tmp_path)
    if bash is None:
        pytest.skip("no bash that can open the temporary directory")
    calls = tmp_path / "calls.log"
    fake = tmp_path / "kafka-topics.sh"
    fake.write_text('#!/bin/bash\necho "$*" >> "$FAKE_CALLS"\n', encoding="utf-8", newline="\n")
    fake.chmod(0o755)
    environ = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("LOGSENTINEL_")  # the topic names come from .env, like by hand
    }
    environ.update(
        FAKE_CALLS=calls.as_posix(),
        LOGSENTINEL_KAFKA_EXEC="",
        LOGSENTINEL_KAFKA_BIN=tmp_path.as_posix(),
        LOGSENTINEL_KAFKA_BOOTSTRAP="kafka:29092",
    )
    script = ROOT / "scripts" / "create-topics.sh"
    result = subprocess.run(
        [bash, script.as_posix()],
        env=environ,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    lines = calls.read_text(encoding="utf-8").splitlines()
    created = [line for line in lines if "--create" in line]
    expected = [env_file()[name] for name in sorted(TOPIC_VARIABLES, key=topic_order)]
    assert [re.search(r"--topic (\S+)", line).group(1) for line in created] == expected  # type: ignore[union-attr]
    assert all("--if-not-exists" in line and "--partitions 3" in line for line in created)
    assert all("--bootstrap-server kafka:29092" in line for line in lines)
    assert any(line.startswith("--list") for line in lines)


def topic_order(name: str) -> int:
    """The order create-topics.sh creates them in."""
    return [
        "LOGSENTINEL_TOPIC_RAW_TELEMETRY",
        "LOGSENTINEL_TOPIC_NORMALIZED_TELEMETRY",
        "LOGSENTINEL_TOPIC_DETECTIONS",
        "LOGSENTINEL_TOPIC_WINDOW_SCORES",
    ].index(name)
