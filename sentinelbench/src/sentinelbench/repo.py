"""Locate the LogSentinel repository root from flags or the working tree."""

from __future__ import annotations

from pathlib import Path


def find_logsentinel_root(explicit: Path | str | None = None) -> Path | None:
    if explicit is not None:
        path = Path(explicit).resolve()
        return path if _looks_like_root(path) else None
    here = Path(__file__).resolve()
    candidates = [Path.cwd().resolve(), *here.parents]
    seen: set[Path] = set()
    for start in candidates:
        for path in (start, *start.parents):
            if path in seen:
                continue
            seen.add(path)
            if _looks_like_root(path):
                return path
    return None


def _looks_like_root(path: Path) -> bool:
    return (
        (path / "docker-compose.yml").is_file()
        and (path / "inference").is_dir()
        and (path / "AGENTS.md").is_file()
    )
