"""Centralised logging configuration for Ariadne.

The rich console stays the human-facing CLI surface; this configures the standard
``logging`` tree for the *other* audience — an operator running the daemon,
autopilot, or web service in production, who needs levelled, timestamped
diagnostics they can tail, ship to a SIEM, or grep after the fact. Logs go to
**stderr** (and optionally a file) so they never corrupt machine-readable stdout
(e.g. a JSON report piped to another tool).

All Ariadne loggers live under the ``ariadne`` namespace; configuring that one
logger sets policy for the whole package. Configuration is idempotent, so calling
it again (tests, re-entry) does not stack duplicate handlers.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

ROOT = "ariadne"

_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class _JsonFormatter(logging.Formatter):
    """One JSON object per line — the shape a log pipeline wants to ingest."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure(
    level: str = "WARNING",
    log_file: str | Path | None = None,
    json_format: bool = False,
) -> logging.Logger:
    """Configure the ``ariadne`` logger. Returns it. Idempotent."""
    lvl = str(level or "WARNING").upper()
    if lvl not in _LEVELS:
        lvl = "WARNING"

    logger = logging.getLogger(ROOT)
    logger.setLevel(getattr(logging, lvl))
    # Idempotent: drop handlers we installed before re-adding, so repeated calls
    # (or a test harness) never fan a single line out to duplicate sinks.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    logger.propagate = False  # don't double-log through the root logger

    fmt: logging.Formatter = (
        _JsonFormatter()
        if json_format
        else logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(fmt)
    logger.addHandler(stream)

    if log_file:
        path = Path(log_file)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger (``ariadne.<name>``)."""
    if name == ROOT or name.startswith(ROOT + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{ROOT}.{name}")
