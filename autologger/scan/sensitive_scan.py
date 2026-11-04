"""Generic detector. Java: SensitiveInfoScanning.

For each regex part: scan the file, keep matches with a line keyword within 80
chars (SSN / Expiry-DOB / Password), drop masked password values, write one
summary row per occurrence (with the AI verdict) and always one Overall_Status
row per part (even when nothing matched).
"""

from __future__ import annotations

import logging
import threading
from functools import partial

from autologger import constants as C
from autologger.context import ScanContext
from autologger.jcompat import java_trim
from autologger.report.excel_writer import csv_quote
from autologger.report.paths import ReportPaths
from autologger.scan.backend import FileSnapshot, ScanAborted
from autologger.scan.patterns import PASSWORD_AUTH_MASK_JAVA, PASSWORD_VALUE_MASK_JAVA, compile_java
from autologger.scan.regex_engine import Occurrence
from autologger.scan.scan_utils import scan_java_regex, write_occurrences

log = logging.getLogger(__name__)

_VALUE_MASK = compile_java(PASSWORD_VALUE_MASK_JAVA, False)
_AUTH_MASK = compile_java(PASSWORD_AUTH_MASK_JAVA, False)


def _thread() -> str:
    return threading.current_thread().name


def mask_for_log(value: str) -> str:
    """Never write a detected secret into the app log (Java did at DEBUG)."""
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}***{value[-2:]} (len={len(value)})"


def is_masked_value(text: str | None) -> bool:
    """w.d(): blank, '***', 'redacted', 'changeme', ... or 'Authorization: Bearer ***'."""
    if text is None or java_trim(text) == "":
        return True
    return _VALUE_MASK.search(text) is not None or _AUTH_MASK.search(text) is not None


def keyword_near(content: str, pos: int, keywords: tuple[str, ...], window: int) -> bool:
    """w.a(content, pos, keywords, 80): a keyword substring within `window` chars, same line."""
    if not content or not keywords:
        return False
    p = max(0, min(pos, len(content) - 1))
    line_start = content.rfind("\n", 0, p + 1)
    line_start = 0 if line_start == -1 else line_start + 1
    line_end = content.find("\n", p)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].lower()
    rel = p - line_start
    for keyword in keywords:
        if keyword is None or java_trim(keyword) == "":
            continue
        needle = keyword.lower()
        idx = line.find(needle)
        while idx >= 0:
            if abs(rel - idx) <= window:
                return True
            idx = line.find(needle, idx + 1)
    return False


def filter_by_keywords(occurrences: dict[str, list[Occurrence]], content: str,
                       keywords: tuple[str, ...], window: int) -> dict[str, list[Occurrence]]:
    kept: dict[str, list[Occurrence]] = {}
    for key, occs in occurrences.items():
        for occ in occs or []:
            if keyword_near(content, occ.start, keywords, window):
                kept.setdefault(key, []).append(occ)
    return kept


def filter_masked(occurrences: dict[str, list[Occurrence]]) -> dict[str, list[Occurrence]]:
    return {k: v for k, v in occurrences.items() if k is not None and v and not is_masked_value(k)}


class SensitiveInfoScanner:
    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx

    def scan(self, test_case: str, parts: list[str], snapshot: FileSnapshot, before: int, after: int,
             keywords: tuple[str, ...] | None = None) -> None:
        ctx = self.ctx
        before, after = max(0, before), max(0, after)
        file_path = snapshot.path
        paths = ReportPaths.for_test_case(file_path, test_case)
        ctx.reports.ensure_header(paths.summary, csv_quote(test_case) + C.SUMMARY_HEADER_TAIL)
        ctx.reports.ensure_header(paths.overall, C.OVERALL_HEADER)
        ai_flag = "ENABLED" if ctx.verifier.is_enabled() else "DISABLED"
        try:
            log.info("%s Processing '%s' identification in the file '%s'.", _thread(), test_case, file_path)
            if len(parts) > 1 and ctx.executors.regex_parallel:
                tasks = [partial(self._scan_part, test_case, part, snapshot, keywords, paths, before, after, ai_flag)
                         for part in parts]
                ctx.executors.run_regexes(tasks, "regex scan")
            else:
                for part in parts:
                    if not ctx.checkpoint():
                        return
                    self._scan_part(test_case, part, snapshot, keywords, paths, before, after, ai_flag)
        except ScanAborted:
            return
        except Exception as exc:  # noqa: BLE001 - Java: log and abandon the remaining parts
            log.error("%s Regex iteration failed. Exception details: %s", _thread(), exc, exc_info=True)
        finally:
            ctx.reports.flush(paths.summary, paths.overall)

    def _scan_part(self, test_case: str, part: str, snapshot: FileSnapshot, keywords: tuple[str, ...] | None,
                   paths: ReportPaths, before: int, after: int, ai_flag: str) -> None:
        ctx = self.ctx
        if not ctx.checkpoint():
            return
        file_path, content = snapshot.path, snapshot.content
        occurrences = scan_java_regex(ctx, test_case, part, snapshot, case_insensitive=True)
        if keywords:
            occurrences = filter_by_keywords(occurrences, content, keywords, C.KEYWORD_WINDOW_CHARS)
        if test_case.lower() in (n.lower() for n in C.MASKED_TEST_CASES):
            occurrences = filter_masked(occurrences)

        total = confirmed = 0
        if occurrences:
            total = sum(len(v) for v in occurrences.values() if v)
            confirmed_box = [0]

            def formatter(match_text: str, occ: Occurrence, ev: str) -> str:
                log.debug("%s Identified '%s' as '%s' in file '%s' with log level %s.",
                          _thread(), test_case, mask_for_log(match_text), file_path, occ.level)
                if occ.level.upper() in ("DEBUG", "TRACE"):
                    verdict = C.AI_SKIPPED_DEBUG_TRACE
                else:
                    verdict = ctx.verifier.verify(test_case, match_text, ev)
                if verdict == C.AI_CONFIRMED:
                    confirmed_box[0] += 1
                return ",".join((csv_quote(match_text), csv_quote(part), csv_quote(file_path),
                                 csv_quote(occ.level), csv_quote(ev), csv_quote(verdict)))

            write_occurrences(ctx, paths.summary, content, occurrences, before, after, formatter)
            confirmed = confirmed_box[0]

        if total > 0:
            log.info("%s Total of %d occurrences of '%s' identified in file '%s'. AI confirmed %d occurrences.",
                     _thread(), total, test_case, file_path, confirmed)
        else:
            log.info("%s No occurrences of '%s' were identified using the current pattern in file '%s'.",
                     _thread(), test_case, file_path)
        ctx.reports.write(paths.overall, ",".join((csv_quote(test_case), csv_quote(part), csv_quote(file_path),
                                                   str(total), str(confirmed), csv_quote(ai_flag))))
