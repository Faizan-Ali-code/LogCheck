"""One complete run. Java: ScanOrchestrator.

Reads Default.xls, collects (and splits) log files, fetches BINs when Card No is
active, runs one WorkerThread per file on a pool of 5, then logs the size list,
the OpenAI statistics and the total time.
"""

from __future__ import annotations

import concurrent.futures as cf
import logging
import os
import time

from autologger import PORT_VERSION, VERSION
from autologger import constants as C
from autologger.ai.openai_verifier import HttpPost, OpenAIVerifier
from autologger.config.db_secret import decrypt_db_string
from autologger.config.default_sheet import DefaultSheetReader
from autologger.context import ScanContext
from autologger.control import Interrupted, RunControl, clear_interrupt
from autologger.db.card_database import CardDatabase, DbBackend, DbError, JdbcBackend
from autologger.files.file_collector import LogFileCollector, canonical_path
from autologger.files.size_report import report_sizes
from autologger.listener import NO_OP_LISTENER, ScanListener
from autologger.logging_setup import configure_logging
from autologger.progress import ScanProgress, TestCaseInfo
from autologger.report.excel_writer import ReportWriter
from autologger.scan.backend import create_backend
from autologger.scan.executors import ScanExecutors
from autologger.settings import Settings
from autologger.worker import WorkerThread

log = logging.getLogger(__name__)
_RULE = "=" * 60


def build_test_case_infos(all_cases: dict[str, bool]) -> list[TestCaseInfo]:
    infos = [TestCaseInfo(name, active, name not in C.BUILT_IN_TEST_CASES) for name, active in all_cases.items()]
    infos += [TestCaseInfo(name, False, False) for name in C.BUILT_IN_TEST_CASES if name not in all_cases]
    return infos


class Orchestrator:
    def __init__(self, settings: Settings, db_backend: DbBackend | None = None,
                 http_post: HttpPost | None = None) -> None:
        self.settings = settings
        self.db_backend = db_backend
        self.verifier = OpenAIVerifier(settings.workdir, http_post, legacy=settings.legacy_compat)
        self._ctx: ScanContext | None = None

    def abort(self) -> None:
        """Stop now (GUI window closed): stop flag + kill worker processes."""
        ctx = self._ctx
        if ctx is not None:
            ctx.control.stop()
            ctx.executors.shutdown_now()
            ctx.backend.shutdown(kill=True)

    def run(self, control: RunControl | None = None, progress: ScanProgress | None = None,
            listener: ScanListener | None = None) -> str:
        control = control or RunControl()
        progress = progress or ScanProgress()
        listener = listener or NO_OP_LISTENER
        s = self.settings
        started = time.monotonic()
        clear_interrupt()  # a Java run always started on a fresh thread
        progress.start()
        configure_logging(s.path("log4j.xml"), s.workdir)
        reports = ReportWriter(s.legacy_compat)
        executors = backend = file_pool = None
        try:
            for line in ("", _RULE, f"Auto Logger {VERSION}",
                         f"Engine       : Python port {PORT_VERSION}", _RULE, "Auto Logger started successfully.",
                         f"Configuration: threadPoolSize={s.file_pool_size}, defaultSheet='{C.DEFAULT_SHEET}'"):
                log.info("%s", line)
            self.verifier.initialize_for_new_run()
            progress.set_ai_enabled(self.verifier.is_enabled())

            sheet = s.path(C.DEFAULT_SHEET)
            if not os.path.exists(sheet):
                log.error("####ERROR: '%s' was not found at path: '%s'. AutoLogger cannot proceed. Please check the "
                          "file path.", C.DEFAULT_SHEET, canonical_path(sheet))
                return self._finish(progress, listener, False, C.STATUS_FAILED_NO_SHEET, "Default.xls not found")

            reader = DefaultSheetReader(s.legacy_compat)
            variables = reader.read_variables(sheet) or {}
            log_path = variables.get(C.VAR_LOGS_FOLDER)
            if not log_path or not os.path.exists(log_path):
                log.error("####ERROR: Log folder path does not exist: '%s'. AutoLogger cannot proceed. Please check "
                          "the log path in Default.xls", "null" if log_path is None else log_path)
                return self._finish(progress, listener, False, C.STATUS_FAILED_BAD_PATH, "Invalid log folder path")
            log.info("Log folder path from 'Default.xls': '%s'", log_path)

            files = LogFileCollector().collect(log_path)
            active = reader.read_active_test_cases(sheet) or {}
            progress.set_total_units(len(files) * len(active))
            infos = build_test_case_infos(reader.read_all_test_cases(sheet))
            progress.set_test_case_infos(infos)
            listener.test_cases_loaded(infos)
            progress.set_total_files(len(files))
            listener.run_started(len(files), s.file_pool_size, self.verifier.is_enabled(), log_path)
            log.info("Default sheet config loaded once in main thread and shared with worker threads.")

            card_db = CardDatabase(self.db_backend or JdbcBackend(s.default_jdbc_classpath(), s.jvm_path,
                                                                  s.jvm_options), s.bin_query)
            bins = self._fetch_bins(card_db, variables, active, control)
            if not bins and C.CARD_NO in active:
                log.info("Card Number testcase will proceed without DB BIN verification. Luhn checksum will still be "
                         "applied and 'Verified in DB' will be marked as Unavailable where needed.")

            log.info("Initializing worker threads with thread pool size: %d", s.file_pool_size)
            executors = ScanExecutors(s.field_threads, s.regex_threads)
            backend = create_backend(s.scan_processes)
            ctx = ScanContext(s, control, progress, reports, executors, backend, self.verifier, card_db, listener)
            self._ctx = ctx
            file_pool = cf.ThreadPoolExecutor(max_workers=s.file_pool_size, thread_name_prefix="FileWorker")
            futures = []
            for index, path in enumerate(files, start=1):
                if not control.await_if_paused():
                    break
                worker = WorkerThread(ctx, path, bins, f"Thread_{index}", variables, active)
                futures.append(file_pool.submit(worker.run))
            self._await_workers(futures, control, executors, backend)
            log.info("All worker threads have finished.")
            if os.path.exists(log_path):
                log.info("****Log files with comma-separated sizes (KB)****")
                report_sizes(log_path)
            self.verifier.log_stats()

            total = int(time.monotonic() - started)
            log.info("%s", _RULE)
            log.info("AutoLogger finished | Total execution time: %d hour(s) %d minute(s) %d second(s)",
                     total // 3600, total % 3600 // 60, total % 60)
            log.info("%s", _RULE)
            stopped = control.is_stopped()
            status = C.STATUS_STOPPED if stopped else C.STATUS_COMPLETED
            return self._finish(progress, listener, stopped, status, status)
        finally:
            if file_pool is not None:
                file_pool.shutdown(wait=True, cancel_futures=True)
            if executors is not None:
                executors.shutdown()
            if backend is not None:
                backend.shutdown(kill=control.is_stopped())
            reports.close_all()
            self._ctx = None

    @staticmethod
    def _finish(progress: ScanProgress, listener: ScanListener, stopped: bool, status: str,
                listener_text: str) -> str:
        progress.finish(status)
        listener.run_finished(stopped, listener_text)
        return status

    @staticmethod
    def _await_workers(futures: list[cf.Future], control: RunControl, executors: ScanExecutors, backend) -> None:
        pending = set(futures)
        killed = False
        while pending:
            _done, pending = cf.wait(pending, timeout=1.0)
            if control.is_stopped() and not killed:
                executors.shutdown_now()
                backend.shutdown(kill=True)
                killed = True

    def _fetch_bins(self, card_db: CardDatabase, variables: dict[str, str], active: dict[str, str],
                    control: RunControl) -> list[str]:
        if C.CARD_NO not in active:
            return []
        log.info("Card Number testcase is enabled; checking database connection.")
        try:
            conn = card_db.connect(decrypt_db_string(variables.get(C.VAR_DB_STRING)))
        except Exception:  # noqa: BLE001
            conn = None
            log.error("Failed to connect using the Default Sheet DB string", exc_info=True)
        if conn is None:
            log.info("Could not connect to the database. Please check DB String/Username/Password in the "
                     "Default Sheet.")
            return []
        bins: list[str] = []
        try:
            rows = card_db.fetch_bins(conn)
            attempts = 0
            while rows is None and attempts < C.DB_RETRY_ATTEMPTS:
                try:
                    log.info("Could not fetch BINs from DB. Retrying in 5 seconds.")
                    control.interruptible_sleep(self.settings.db_retry_delay)
                    rows = card_db.fetch_bins(conn)
                    attempts += 1
                except Interrupted:
                    break
            if rows is not None:
                bins = list(rows)
                log.info("BIN query completed successfully. Total BINs fetched: %d", len(bins))
        except DbError:
            log.error("Failed reading BIN result set", exc_info=True)
            bins = []
        finally:
            card_db.close(conn)
        return bins
