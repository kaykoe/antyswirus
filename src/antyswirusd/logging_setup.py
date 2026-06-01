"""Logging configuration for the antyswirusd daemon."""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys

from antyswirusd.paths import RuntimePaths

_FMT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%dT%H:%M:%S%z"


def setup_logging(paths: RuntimePaths, level: str = "INFO") -> None:
    """Configure root logging to write to the daemon log file (and stderr
    if attached to a terminal, e.g. when run in the foreground)."""
    paths.ensure()

    root = logging.getLogger()
    root.setLevel(level.upper())
    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter = logging.Formatter(_FMT, _DATEFMT)

    file_handler = logging.handlers.WatchedFileHandler(paths.log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    if sys.stderr is not None and os.isatty(sys.stderr.fileno()):
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        root.addHandler(stream_handler)

    logging.getLogger("asyncio").setLevel(logging.WARNING)
