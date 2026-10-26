"""Run commands inside LogSentinel containers via ``docker exec``."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any


class DockerExec:
    """Thin wrapper; returns None when Docker or the container is unavailable."""

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled

    def exec(self, container: str, *command: str, timeout_sec: float = 60.0) -> str | None:
        if not self.enabled:
            return None
        env = os.environ.copy()
        # Git Bash on Windows rewrites /opt/... paths; keep them literal.
        env["MSYS_NO_PATHCONV"] = "1"
        try:
            result = subprocess.run(
                ["docker", "exec", container, *command],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_sec,
                env=env,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None
        if result.returncode != 0:
            return None
        return result.stdout

    def exec_json(self, container: str, *command: str, timeout_sec: float = 60.0) -> Any | None:
        text = self.exec(container, *command, timeout_sec=timeout_sec)
        if text is None:
            return None
        text = text.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
