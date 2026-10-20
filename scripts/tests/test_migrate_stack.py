"""Check migration readiness without calling Docker or touching stack data."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import migrate_stack as migration

RUNTIME = (
    "kafka",
    "elasticsearch",
    "kibana",
    "logstash-ingest",
    "logstash-detection-sink",
    "inference",
    "notifications",
)
INIT = ("kafka-init", "elasticsearch-init", "kibana-init")


def ready_states() -> dict[str, str]:
    return {
        **{f"logsentinel-{name}": "Up 2 minutes (healthy)" for name in RUNTIME},
        **{f"logsentinel-{name}": "Exited (0) 2 minutes ago" for name in INIT},
    }


def test_migration_accepts_all_named_services_ready() -> None:
    assert migration.stack_is_up(ready_states())


@pytest.mark.parametrize("name", INIT)
def test_failed_init_cannot_be_hidden_by_another_successful_container(
    name: str,
) -> None:
    states = ready_states()
    states[f"logsentinel-{name}"] = "Exited (1) 2 minutes ago"
    states["logsentinel-old-init"] = "Exited (0) 2 minutes ago"

    assert not migration.stack_is_up(states)


@pytest.mark.parametrize("name", RUNTIME)
def test_unhealthy_runtime_cannot_be_hidden_by_another_healthy_container(
    name: str,
) -> None:
    states = ready_states()
    states[f"logsentinel-{name}"] = "Up 2 minutes (unhealthy)"
    states["logsentinel-old-service"] = "Up 2 minutes (healthy)"

    assert not migration.stack_is_up(states)


def test_missing_named_container_is_not_ready() -> None:
    states = ready_states()
    del states["logsentinel-kibana-init"]

    assert not migration.stack_is_up(states)
