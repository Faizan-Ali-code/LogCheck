"""Field (test case) and regex thread pools. Java: ScanTaskExecutor (u).

Fixes vs Java: pools are created per run (Java used static pools, so Stop
broke the next Start), and pool threads are named after the file worker that
submitted the task (Java froze the prefix of the first worker).
"""

from __future__ import annotations

import itertools
import logging
import threading
from concurrent.futures import CancelledError, Future, ThreadPoolExecutor
from typing import Callable

from autologger.control import clear_interrupt
from autologger.scan.backend import ScanAborted

log = logging.getLogger(__name__)


class _NamedPool:
    def __init__(self, kind: str, size: int) -> None:
        self.kind = kind
        self.size = size
        self._counter = itertools.count(1)
        self._local = threading.local()
        self._pool = ThreadPoolExecutor(max_workers=size, thread_name_prefix=f"{kind}_Thread",
                                        initializer=self._init_thread)

    def _init_thread(self) -> None:
        self._local.index = next(self._counter)

    def submit(self, fn: Callable[[], object]) -> Future:
        parent = threading.current_thread().name.split("_TestCase_Thread_")[0].split("_Regex_Thread_")[0]

        def task() -> object:
            threading.current_thread().name = f"{parent}_{self.kind}_Thread_{self._local.index}"
            clear_interrupt()
            return fn()

        return self._pool.submit(task)

    def shutdown(self, wait: bool) -> None:
        self._pool.shutdown(wait=wait, cancel_futures=True)


class ScanExecutors:
    def __init__(self, field_threads: int, regex_threads: int) -> None:
        self.field_threads = max(1, field_threads)
        self.regex_threads = max(1, regex_threads)
        self._field = _NamedPool("TestCase", self.field_threads)
        self._regex = _NamedPool("Regex", self.regex_threads)
        log.info("Scan parallelism initialized: fieldThreads=%d, regexThreads=%d",
                 self.field_threads, self.regex_threads)

    @property
    def field_parallel(self) -> bool:
        return self.field_threads > 1

    @property
    def regex_parallel(self) -> bool:
        return self.regex_threads > 1

    def run_fields(self, tasks: list[Callable[[], object]], label: str) -> None:
        self.wait_all([self._field.submit(t) for t in tasks], label)

    def run_regexes(self, tasks: list[Callable[[], object]], label: str) -> None:
        self.wait_all([self._regex.submit(t) for t in tasks], label)

    @staticmethod
    def wait_all(futures: list[Future], label: str) -> None:
        """u.a(List<Future>, String): wait for each, log failures, keep going."""
        for future in futures:
            try:
                future.result()
            except (ScanAborted, CancelledError):
                pass  # run is stopping
            except Exception as exc:  # noqa: BLE001 - Java logs and continues
                log.error("A %s task failed: %s", label, exc, exc_info=True)

    def shutdown_now(self) -> None:
        self._field.shutdown(wait=False)
        self._regex.shutdown(wait=False)

    def shutdown(self) -> None:
        self._field.shutdown(wait=True)
        self._regex.shutdown(wait=True)
