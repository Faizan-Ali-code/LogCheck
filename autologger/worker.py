"""One log file. Java: WorkerThread.

Reads the whole file, then runs every active test case (in parallel on the
field pool when there is more than one) and dispatches each to its detector.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from functools import partial

from autologger import constants as C
from autologger.config.db_secret import decrypt_db_string
from autologger.context import ScanContext
from autologger.control import clear_interrupt
from autologger.files.file_reader import read_log_file
from autologger.jcompat import java_parse_int, java_trim
from autologger.scan import patterns as P
from autologger.scan.backend import FileSnapshot
from autologger.scan.card_scan import CardNumberScanner
from autologger.scan.sensitive_scan import SensitiveInfoScanner

log = logging.getLogger(__name__)

_KEYWORDS = {C.SSN: P.SSN_KEYWORDS, C.EXPIRY_DOB: P.EXPIRY_DOB_KEYWORDS, C.PASSWORD: P.PASSWORD_KEYWORDS}


def _int_variable(value: str | None, fallback: int = 0) -> int:
    if value is None:
        return fallback
    try:
        return java_parse_int(java_trim(value))
    except ValueError:
        return fallback


def take_snapshot(path: str) -> FileSnapshot:
    try:
        st = os.stat(path)
        size, mtime = st.st_size, st.st_mtime_ns
    except OSError:
        size, mtime = -1, -1
    return FileSnapshot(path, read_log_file(path), size, mtime)


class WorkerThread:
    def __init__(self, ctx: ScanContext, file_path: str, bins: list[str], thread_name: str,
                 variables: dict[str, str], test_cases: dict[str, str]) -> None:
        self.ctx = ctx
        self.file_path = file_path
        self.bins = bins
        self.thread_name = thread_name
        self.variables = variables
        self.test_cases = test_cases

    def run(self) -> None:
        ctx = self.ctx
        if not ctx.checkpoint():
            return
        threading.current_thread().name = self.thread_name
        clear_interrupt()
        started = time.monotonic()
        name = self.thread_name
        log.info("%s started.", name)
        ctx.progress.file_started(name)
        ctx.listener.file_started(self.file_path, name)
        try:
            snapshot = take_snapshot(self.file_path)
            if not ctx.checkpoint():
                return
            self.scan_file(snapshot)
            log.info("%s finished.", name)
            elapsed = time.monotonic() - started
            log.info("%s execution time in milliseconds: %d for log file '%s'.", name, int(elapsed * 1000),
                     self.file_path)
            log.info("%s execution time in seconds: %d for log file '%s'.", name, int(elapsed), self.file_path)
        except Exception:  # noqa: BLE001 - Java let this kill the thread silently; log it instead
            log.error("%s failed while scanning '%s'.", name, self.file_path, exc_info=True)
        finally:
            ctx.progress.file_finished(name)
            ctx.listener.file_finished(self.file_path, name)

    def scan_file(self, snapshot: FileSnapshot) -> None:
        ctx = self.ctx
        before = _int_variable(self.variables.get(C.VAR_WORDS_BEFORE))
        after = _int_variable(self.variables.get(C.VAR_WORDS_AFTER))
        if not self.test_cases:
            return
        if ctx.executors.field_parallel and len(self.test_cases) > 1:
            tasks = [partial(self.scan_test_case, name, regex, snapshot, before, after)
                     for name, regex in self.test_cases.items()]
            ctx.executors.run_fields(tasks, "field scan")
        else:
            for name, regex in self.test_cases.items():
                if not ctx.checkpoint():
                    return
                self.scan_test_case(name, regex, snapshot, before, after)

    def scan_test_case(self, name: str, sheet_regex: str, snapshot: FileSnapshot, before: int, after: int) -> None:
        if name is None:
            return
        ctx = self.ctx
        ctx.progress.test_case_started(name)
        ctx.listener.test_case_started(name, self.thread_name, self.file_path)
        try:
            if name == C.CARD_NO:
                self._scan_cards(snapshot, before, after)
            else:
                parts = list(P.detector_parts(name, sheet_regex))
                SensitiveInfoScanner(ctx).scan(name, parts, snapshot, before, after, _KEYWORDS.get(name))
        finally:
            ctx.progress.test_case_finished(name)
            ctx.listener.test_case_finished(name, self.thread_name, self.file_path)

    def _scan_cards(self, snapshot: FileSnapshot, before: int, after: int) -> None:
        try:
            db_url = decrypt_db_string(self.variables.get(C.VAR_DB_STRING))
            CardNumberScanner(self.ctx).scan(C.CARD_REGEX_LIST, db_url, snapshot, before, after, self.bins)
        except Exception:  # noqa: BLE001 - Java: any failure here skips the card scan for this file
            log.info("Could not connect to the database. Please check DB String/Username/Password in the "
                     "Default Sheet.")
