"""Log file discovery and oversized-file splitting. Java: LogFileCollector.

Pass 1 splits every file larger than 200000 KB into raw 150 MiB byte chunks named
<path>.0<i> (".00", ".01", ... ".010") and renames the original to <canonical>.old.
Pass 2 lists files recursively. Both passes skip entries (files AND directories)
whose lower-cased name ends with ".old" or ".xlsx"; everything else is scanned,
including .csv and .dat files.
"""

from __future__ import annotations

import logging
import os
import threading

from autologger import constants as C

log = logging.getLogger(__name__)


def canonical_path(path: str) -> str:
    """File.getCanonicalPath(): absolute, normalized, real case. Mapped drives keep their letter."""
    absolute = os.path.abspath(path)
    try:
        real = os.path.realpath(absolute, strict=False)
    except (OSError, ValueError):
        return absolute
    if real.startswith("\\\\") and not absolute.startswith("\\\\"):
        return absolute  # realpath turned a mapped drive into a UNC path; Java keeps the drive
    return real


def _accept(name: str) -> bool:
    lower = name.lower()
    return not lower.endswith(".old") and not lower.endswith(".xlsx")


def _entries(directory: str) -> list[str]:
    try:
        return [os.path.join(directory, n) for n in os.listdir(directory) if _accept(n)]
    except OSError:
        return []  # File.listFiles() returns null


class LogFileCollector:
    def __init__(self, threshold_kb: int = C.SPLIT_THRESHOLD_KB, chunk_mb: int = C.SPLIT_CHUNK_MB,
                 chunk_bytes: int | None = None) -> None:
        self.threshold_kb = threshold_kb
        self.chunk_mb = chunk_mb
        self.chunk_bytes = chunk_bytes  # tests only; Java always used chunk_mb MiB

    def collect(self, folder: str | None) -> list[str]:
        if folder is None or folder.strip() == "" or not os.path.exists(folder):
            return []
        self._split_large(folder)
        files: list[str] = []
        self._list(folder, files)
        return files

    def _list(self, directory: str, out: list[str]) -> None:
        for entry in _entries(directory):
            if os.path.isdir(entry):
                self._list(entry, out)
            else:
                try:
                    out.append(canonical_path(entry))
                except OSError:
                    log.error("Failed to resolve canonical path for file: %s", entry, exc_info=True)

    def _split_large(self, directory: str) -> None:
        for entry in _entries(directory):
            if os.path.isdir(entry):
                self._split_large(entry)
                continue
            try:
                size_kb = os.path.getsize(entry) // 1024
            except OSError:
                continue
            if size_kb <= self.threshold_kb:
                continue
            try:
                canonical = canonical_path(entry)
                log.info("%s File size is greater than %d KB. Splitting file '%s'.",
                         threading.current_thread().name, self.threshold_kb, canonical)
                self.split(canonical, self.chunk_mb, entry, self.chunk_bytes)
                try:
                    os.rename(entry, canonical + ".old")
                except OSError:
                    log.warning("Failed to rename original file to .old: %s", canonical)
            except Exception:  # noqa: BLE001
                log.error("Failed splitting file: %s", entry, exc_info=True)

    @staticmethod
    def split(source: str, chunk_mb: int, target_base: str, chunk_bytes: int | None = None) -> list[str]:
        """Raw byte split. Existing chunk files are overwritten in place (not truncated), like Java."""
        log.debug("%s Splitting file '%s' with mBperSplit=%d in directory '%s'.",
                  threading.current_thread().name, source, chunk_mb, target_base)
        if chunk_mb <= 0:
            log.error("mBperSplit must be more than zero")
            raise ValueError("mBperSplit must be more than zero")
        chunk = chunk_bytes or 1048576 * chunk_mb
        size = os.path.getsize(source)
        count, remainder = divmod(size, chunk)
        written: list[str] = []
        with open(source, "rb") as src:
            for index in range(count + (1 if remainder > 0 else 0)):
                part = f"{target_base}.0{index}"
                length = chunk if index < count else remainder
                src.seek(index * chunk)
                with open(part, "r+b" if os.path.exists(part) else "wb") as dst:
                    remaining = length
                    while remaining > 0:
                        block = src.read(min(remaining, 8 * 1048576))
                        if not block:
                            break
                        dst.write(block)
                        remaining -= len(block)
                written.append(part)
        return written
