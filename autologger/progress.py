"""Run metrics shown by the GUI. Java: ScanProgress (threads.f) and TestCaseInfo (threads.g)."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from autologger import constants as C


@dataclass(frozen=True)
class TestCaseInfo:
    name: str
    active: bool
    custom: bool


class ScanProgress:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_files = 0
        self._files_started = 0
        self._files_finished = 0
        self._findings = 0
        self._vulnerable_cards = 0
        self._total_units = 0
        self._finished_units = 0
        self._active_threads: list[str] = []
        self._tc_started: dict[str, int] = {}
        self._tc_finished: dict[str, int] = {}
        self._infos: tuple[TestCaseInfo, ...] = ()
        self._ai_enabled = False
        self._start: float | None = None
        self._end: float | None = None
        self._status = C.STATUS_READY

    # lifecycle ------------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            self._start, self._end = time.monotonic(), None
            self._files_started = self._files_finished = 0
            self._findings = self._vulnerable_cards = 0
            self._total_units = self._finished_units = 0
            self._tc_started.clear()
            self._tc_finished.clear()
            self._active_threads.clear()
            self._status = C.STATUS_RUNNING

    def finish(self, status: str) -> None:
        with self._lock:
            self._end = time.monotonic()
            self._status = status
            self._active_threads.clear()

    def set_status(self, status: str) -> None:
        if status and status.strip():
            self._status = status

    # setters --------------------------------------------------------------
    def set_total_files(self, n: int) -> None:
        self._total_files = max(0, n)

    def set_total_units(self, n: int) -> None:
        self._total_units = max(0, n)

    def set_ai_enabled(self, enabled: bool) -> None:
        self._ai_enabled = enabled

    def set_test_case_infos(self, infos: list[TestCaseInfo]) -> None:
        self._infos = tuple(infos)

    # counters -------------------------------------------------------------
    def file_started(self, thread_name: str) -> None:
        with self._lock:
            self._files_started += 1
            if thread_name and thread_name not in self._active_threads:
                self._active_threads.append(thread_name)

    def file_finished(self, thread_name: str) -> None:
        with self._lock:
            self._files_finished += 1
            if thread_name in self._active_threads:
                self._active_threads.remove(thread_name)

    def finding_written(self) -> None:
        with self._lock:
            self._findings += 1

    def vulnerable_card(self) -> None:
        with self._lock:
            self._vulnerable_cards += 1

    def test_case_started(self, name: str) -> None:
        with self._lock:
            self._tc_started[name] = self._tc_started.get(name, 0) + 1

    def test_case_finished(self, name: str) -> None:
        with self._lock:
            self._tc_finished[name] = self._tc_finished.get(name, 0) + 1
            self._finished_units += 1

    # getters --------------------------------------------------------------
    @property
    def total_files(self) -> int:
        return self._total_files

    @property
    def files_started(self) -> int:
        return self._files_started

    @property
    def files_finished(self) -> int:
        return self._files_finished

    @property
    def findings(self) -> int:
        return self._findings

    @property
    def vulnerable_cards(self) -> int:
        return self._vulnerable_cards

    @property
    def ai_enabled(self) -> bool:
        return self._ai_enabled

    @property
    def status(self) -> str:
        return self._status

    @property
    def test_case_infos(self) -> tuple[TestCaseInfo, ...]:
        return self._infos

    def active_threads(self) -> list[str]:
        with self._lock:
            return list(self._active_threads)

    def started_count(self, name: str) -> int:
        return self._tc_started.get(name, 0)

    def finished_count(self, name: str) -> int:
        return self._tc_finished.get(name, 0)

    def completion_percent(self) -> float:
        if self._total_units > 0:
            return self._finished_units * 100.0 / self._total_units
        return 0.0 if self._total_files <= 0 else self._files_finished * 100.0 / self._total_files

    def duration_seconds(self) -> float:
        if self._start is None:
            return 0.0
        end = self._end if self._end is not None else time.monotonic()
        return max(0.0, end - self._start)
