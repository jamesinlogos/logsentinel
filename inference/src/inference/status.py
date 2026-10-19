"""The service's status file: written by the loop, read by the Docker healthcheck."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def write_status(path: Path, status: Mapping[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(status), encoding="utf-8")
    os.replace(tmp, path)


def read_status(path: Path) -> dict[str, Any] | None:
    """The status, or None when the file is missing or not a JSON object."""
    try:
        status = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return status if isinstance(status, dict) else None
