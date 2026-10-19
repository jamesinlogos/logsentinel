"""Docker HEALTHCHECK: reads the status file the service loop rewrites every second.

Usage: python -m inference.healthcheck [status-file]

Unhealthy when the file is missing or stale (the loop is stuck or gone) or the
loop reports ``healthy: false`` (no broker reachable for ``kafka.down_after_sec``).
Having no detections or quiet hosts is normal and never unhealthy.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from inference.config import STATUS_PATH
from inference.status import read_status

MAX_AGE_SEC = 30.0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    path = Path(args[0]) if args else STATUS_PATH
    status = read_status(path)
    if status is None:
        print(f"no readable status file at {path}")
        return 1
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        return 1
    if age > MAX_AGE_SEC:
        print(f"status file is {age:.0f} s old: the service loop is not running")
        return 1
    if not status.get("healthy", False):
        print(json.dumps(status))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
