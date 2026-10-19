"""Elasticsearch templates as the cluster builds them, and checks of documents against them.

The service writes into indices whose templates say ``dynamic: false``: a field the templates
do not describe stays in ``_source`` but is silently not indexed. These helpers let a test say
which fields a document has that its index would drop.
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any

ES_CONFIG = Path(__file__).resolve().parents[2] / "config" / "elasticsearch"


def template(folder: str, name: str) -> dict[str, Any]:
    return json.loads((ES_CONFIG / folder / f"{name}.json").read_text(encoding="utf-8"))


def merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for name, value in extra.items():
        if isinstance(value, dict) and isinstance(merged.get(name), dict):
            merged[name] = merge(merged[name], value)
        else:
            merged[name] = value
    return merged


def effective_mappings(index_template: str) -> dict[str, Any]:
    """The mappings of an index template with its component templates applied, in order."""
    index = template("index-templates", index_template)
    mappings: dict[str, Any] = {}
    for name in index["composed_of"]:
        mappings = merge(mappings, template("component-templates", name)["template"]["mappings"])
    return merge(mappings, index["template"].get("mappings", {}))


def unmapped_fields(
    value: dict[str, Any], mapping: dict[str, Any], dynamic_templates: list[dict[str, Any]]
) -> list[str]:
    """Fields of ``value`` that ``mapping`` does not describe (or describes with another shape)."""
    problems: list[str] = []

    def walk(item: dict[str, Any], node: dict[str, Any], prefix: str, dynamic: Any) -> None:
        dynamic = node.get("dynamic", dynamic)
        properties = node.get("properties", {})
        for name, content in item.items():
            path = f"{prefix}{name}"
            spec = properties.get(name)
            if spec is None:
                matching = [
                    template
                    for entry in dynamic_templates
                    for template in entry.values()
                    if fnmatch.fnmatch(path, template.get("path_match", ""))
                ]
                if dynamic is not True or not matching:
                    problems.append(path)
            elif isinstance(content, dict):
                if "properties" not in spec and spec.get("type") != "object":
                    problems.append(f"{path} is an object but mapped as {spec.get('type')}")
                else:
                    walk(content, spec, f"{path}.", dynamic)
            elif "properties" in spec or spec.get("type") == "object":
                problems.append(f"{path} is a value but mapped as an object")

    walk(value, mapping, "", mapping.get("dynamic"))
    return problems


def mapped_leaves(node: dict[str, Any], prefix: str = "") -> set[str]:
    leaves: set[str] = set()
    for name, spec in node.get("properties", {}).items():
        if "properties" in spec:
            leaves |= mapped_leaves(spec, f"{prefix}{name}.")
        elif spec.get("type") != "object":
            leaves.add(f"{prefix}{name}")
    return leaves


def document_leaves(doc: dict[str, Any], prefix: str = "") -> set[str]:
    leaves: set[str] = set()
    for name, value in doc.items():
        if isinstance(value, dict):
            leaves |= document_leaves(value, f"{prefix}{name}.")
        else:
            leaves.add(f"{prefix}{name}")
    return leaves
