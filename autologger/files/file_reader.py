"""Whole-file log reading. Java: LogFileReader.

Java used Files.readString(path, UTF_8): strict UTF-8, line endings kept,
any failure -> ERROR log and "" (the file is then silently not matched).
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def read_log_text(path: str) -> str:
    """Strict UTF-8 read that keeps '\\r\\n' (offsets must match Java). Raises on failure."""
    with open(path, "r", encoding="utf-8", errors="strict", newline="") as fh:
        return fh.read()


def read_log_file(path: str | None) -> str:
    if path is None or path.strip() == "":
        return ""
    try:
        return read_log_text(path)
    except (OSError, UnicodeDecodeError, ValueError, MemoryError):
        log.error("Failed to read file into memory: %s", path, exc_info=True)
        return ""
