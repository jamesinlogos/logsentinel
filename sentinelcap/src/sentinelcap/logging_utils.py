"""Centralized logging configuration for the sentinelcap CLI.

Provides a single ``configure_logging`` entry point that wires the standard
library ``logging`` module to a Rich-based handler, so every module can use
plain ``logging.getLogger(__name__)`` calls instead of ad-hoc print/console
calls. This keeps log format, verbosity, and (optionally) file output
consistent across the whole application.
"""

from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler

MESSAGE_FORMAT = "%(message)s"


def configure_logging(verbose: bool = False, log_file: Path | None = None) -> None:
    """Configure root logging for the CLI process.

    Args:
        verbose: Enable DEBUG-level output on the console handler.
        log_file: Optional path to also persist logs (always at INFO level,
            with timestamps and logger names, regardless of console verbosity).
    """
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [
        # markup=False: log messages carry guest paths and tool output (7-Zip,
        # vmrun) whose "[...]" must be printed as is, not parsed as Rich markup.
        RichHandler(rich_tracebacks=True, show_path=False, markup=False)
    ]

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        )
        file_handler.setLevel(logging.INFO)
        handlers.append(file_handler)

    logging.basicConfig(level=level, format=MESSAGE_FORMAT, handlers=handlers, force=True)

    # Third-party libraries are noisy at INFO/DEBUG; keep them quiet unless
    # the caller explicitly wants verbose output.
    if not verbose:
        logging.getLogger("confluent_kafka").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Convenience wrapper around ``logging.getLogger`` for consistency."""
    return logging.getLogger(name)
