"""Where regex matching runs: in the calling thread, or in a pool of worker processes.

Java ran every regex on its own threads. Python's `re` holds the GIL, so the
process backend gives real parallelism: workers re-read the log file themselves
(cached per process) and return plain match tuples. If the file changed on disk
since the scanning thread read it, the worker refuses and matching falls back to
the in-thread content, so results always come from the same text Java would see.

This module is imported by worker processes: keep it free of GUI/JVM imports.
"""

from __future__ import annotations

import multiprocessing
import os
import re
import threading
from collections import OrderedDict
from concurrent.futures import CancelledError, ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass

from autologger.files.file_reader import read_log_text
from autologger.jcompat import java_trim
from autologger.scan.patterns import compile_java
from autologger.scan.regex_engine import RawOccurrence, find_occurrences

PatternResult = tuple[list[RawOccurrence] | None, str | None]  # (occurrences, compile error)


class ScanAborted(Exception):
    """Raised when the run was stopped while matching was in flight."""


@dataclass(frozen=True)
class FileSnapshot:
    path: str
    content: str
    size: int
    mtime_ns: int


def scan_patterns(content: str, patterns: list[str], case_insensitive: bool) -> list[PatternResult]:
    results: list[PatternResult] = []
    for pattern in patterns:
        if content == "" or java_trim(pattern) == "":
            results.append(([], None))  # Java returns an empty map for blank content/regex
            continue
        try:
            regex = compile_java(pattern, case_insensitive)
        except (re.error, ValueError, OverflowError, IndexError) as exc:
            results.append((None, str(exc)))
            continue
        results.append((find_occurrences(content, regex), None))
    return results


class InlineBackend:
    """Runs matching in the calling thread (deterministic; used by tests and small runs)."""

    def scan(self, snapshot: FileSnapshot, patterns: list[str], case_insensitive: bool) -> list[PatternResult]:
        return scan_patterns(snapshot.content, patterns, case_insensitive)

    def shutdown(self, kill: bool = False) -> None:
        pass


# ----------------------------------------------------------------------------- worker side
_WORKER_CACHE: "OrderedDict[tuple[str, int, int], str]" = OrderedDict()
_WORKER_CACHE_CHARS = 400_000_000  # per worker process; the most recent file is always kept


def _worker_scan(path: str, size: int, mtime_ns: int, patterns: list[str], case_insensitive: bool):
    key = (path, size, mtime_ns)
    content = _WORKER_CACHE.get(key)
    if content is None:
        try:
            st = os.stat(path)
            if (st.st_size, st.st_mtime_ns) != (size, mtime_ns):
                return None
            content = read_log_text(path)
            st = os.stat(path)
            if (st.st_size, st.st_mtime_ns) != (size, mtime_ns):
                return None
        except (OSError, UnicodeDecodeError, ValueError, MemoryError):
            return None
        _WORKER_CACHE[key] = content
        while len(_WORKER_CACHE) > 1 and sum(len(v) for v in _WORKER_CACHE.values()) > _WORKER_CACHE_CHARS:
            _WORKER_CACHE.popitem(last=False)
    else:
        _WORKER_CACHE.move_to_end(key)
    return scan_patterns(content, patterns, case_insensitive)


# ----------------------------------------------------------------------------- main side
class ProcessBackend:
    """Matching in worker processes; long pattern lists (BIN scans) are split into chunks."""

    def __init__(self, processes: int, chunk_size: int = 150) -> None:
        self.processes = max(1, processes)
        self.chunk_size = max(1, chunk_size)
        self._pool: ProcessPoolExecutor | None = None
        self._lock = threading.Lock()
        self._closed = False
        self._inline = InlineBackend()

    def _get_pool(self) -> ProcessPoolExecutor:
        with self._lock:
            if self._closed:
                raise ScanAborted("scan backend is shut down")
            if self._pool is None:
                self._pool = ProcessPoolExecutor(max_workers=self.processes,
                                                 mp_context=multiprocessing.get_context("spawn"))
            return self._pool

    def scan(self, snapshot: FileSnapshot, patterns: list[str], case_insensitive: bool) -> list[PatternResult]:
        if not patterns:
            return []
        if snapshot.content == "":
            return scan_patterns("", patterns, case_insensitive)
        pool = self._get_pool()
        chunks = [patterns[i:i + self.chunk_size] for i in range(0, len(patterns), self.chunk_size)]
        try:
            futures = [pool.submit(_worker_scan, snapshot.path, snapshot.size, snapshot.mtime_ns, chunk,
                                   case_insensitive) for chunk in chunks]
            results: list[PatternResult] = []
            stale = False
            for future in futures:
                part = future.result()
                if part is None:
                    stale = True
                elif not stale:
                    results.extend(part)
        except (BrokenProcessPool, CancelledError, RuntimeError) as exc:
            raise ScanAborted(str(exc)) from exc
        if stale:
            return self._inline.scan(snapshot, patterns, case_insensitive)
        return results

    def shutdown(self, kill: bool = False) -> None:
        with self._lock:
            self._closed = True
            pool, self._pool = self._pool, None
        if pool is None:
            return
        if kill:
            for proc in list(getattr(pool, "_processes", {}).values()):
                try:
                    proc.terminate()
                except Exception:  # noqa: BLE001 - best effort during stop
                    pass
        pool.shutdown(wait=not kill, cancel_futures=True)


def create_backend(processes: int) -> InlineBackend | ProcessBackend:
    """processes <= 0 -> in-thread matching; otherwise a process pool of that size."""
    return InlineBackend() if processes <= 0 else ProcessBackend(processes)
