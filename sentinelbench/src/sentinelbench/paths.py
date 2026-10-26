"""Nested dict accessors shared by metric checks."""

from __future__ import annotations

from typing import Any


def get_path(source: dict[str, Any] | None, path: tuple[str, ...]) -> Any:
    current: Any = source
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def missing_paths(source: dict[str, Any], required: tuple[tuple[str, ...], ...]) -> list[str]:
    return [".".join(path) for path in required if get_path(source, path) is None]
