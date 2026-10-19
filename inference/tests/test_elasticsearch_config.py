"""config/elasticsearch: the files name each other consistently (AGENTS.md section 11.8).

A resource is named after its file (``ransomware-detections.json`` is the index template
``ransomware-detections``), so ``scripts/init-elasticsearch.sh`` needs no table of names.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from inference.documents import SCHEMA_VERSION

ES_CONFIG = Path(__file__).resolve().parents[2] / "config" / "elasticsearch"
FOLDERS = ("component-templates", "index-templates", "ilm-policies", "ingest-pipelines")
KEBAB = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")


def names(folder: str) -> set[str]:
    return {path.stem for path in (ES_CONFIG / folder).glob("*.json")}


def load(folder: str, name: str) -> dict[str, Any]:
    return json.loads((ES_CONFIG / folder / f"{name}.json").read_text(encoding="utf-8"))


def meta_of(folder: str, document: dict[str, Any]) -> dict[str, Any]:
    """Where Elasticsearch keeps ``_meta`` in each kind of resource."""
    return document["policy"]["_meta"] if folder == "ilm-policies" else document["_meta"]


@pytest.mark.parametrize("folder", FOLDERS)
def test_every_resource_is_kebab_case_and_marked_with_our_schema_version(
    folder: str,
) -> None:
    assert names(folder)
    for name in names(folder):
        assert KEBAB.fullmatch(name), f"{folder}/{name}"
        meta = meta_of(folder, load(folder, name))
        assert meta["managed_by"] == "logsentinel", f"{folder}/{name}"
        assert meta["schema_version"] == SCHEMA_VERSION, f"{folder}/{name}"


def test_index_templates_use_resources_that_exist() -> None:
    for name in names("index-templates"):
        template = load("index-templates", name)
        settings = template.get("template", {}).get("settings", {}).get("index", {})
        assert set(template.get("composed_of", [])) <= names("component-templates"), name
        if "lifecycle" in settings:
            assert settings["lifecycle"]["name"] in names("ilm-policies"), name
        for component in template.get("composed_of", []):
            shared = load("component-templates", component)["template"]["settings"]["index"]
            if "default_pipeline" in shared:
                assert shared["default_pipeline"] in names("ingest-pipelines"), component


def test_an_index_template_is_named_after_the_indices_it_matches() -> None:
    for name in names("index-templates"):
        patterns = load("index-templates", name)["index_patterns"]
        assert patterns == [f"{name}-*"], name  # <family>-<period>, the period is the wildcard


def test_two_index_templates_never_match_the_same_index() -> None:
    patterns = {
        name: load("index-templates", name)["index_patterns"][0].rstrip("*")
        for name in names("index-templates")
    }
    for first in patterns:
        for second in patterns:
            if first != second:
                a, b = patterns[first], patterns[second]
                assert not a.startswith(b), f"{first} and {second} overlap"


def test_every_index_template_has_a_retention_policy_of_the_same_name() -> None:
    """No family of indices grows for ever (AGENTS.md section 11.8)."""
    assert names("index-templates") == names("ilm-policies")
    for name in names("index-templates"):
        settings = load("index-templates", name)["template"]["settings"]["index"]
        assert settings["lifecycle"]["name"] == name, name


def test_retention_policies_only_delete() -> None:
    for name in names("ilm-policies"):
        phases = load("ilm-policies", name)["policy"]["phases"]
        assert set(phases) == {"delete"}, name  # one shard, no rollover, nothing to tier
        assert phases["delete"]["min_age"].endswith("d"), name


def test_the_ingest_pipeline_stamps_event_ingested() -> None:
    pipeline = load("ingest-pipelines", "logsentinel-event-ingested")
    (processor,) = pipeline["processors"]
    assert processor["set"]["field"] == "event.ingested"
