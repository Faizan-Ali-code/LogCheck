"""UI callbacks. Java: ScanListener (threads.c) with the no-op default (threads.d)."""

from __future__ import annotations

from autologger.progress import TestCaseInfo


class ScanListener:
    """All callbacks are no-ops; the GUI overrides the ones it needs."""

    def run_started(self, total_files: int, threads: int, ai_enabled: bool, log_path: str) -> None:
        pass

    def file_started(self, file_path: str, thread_name: str) -> None:
        pass

    def file_finished(self, file_path: str, thread_name: str) -> None:
        pass

    def run_finished(self, stopped: bool, status: str) -> None:
        pass

    def test_cases_loaded(self, infos: list[TestCaseInfo]) -> None:
        pass

    def test_case_started(self, name: str, thread_name: str, file_path: str) -> None:
        pass

    def test_case_finished(self, name: str, thread_name: str, file_path: str) -> None:
        pass


NO_OP_LISTENER = ScanListener()
