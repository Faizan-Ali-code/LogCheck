"""Evidence windows and occurrence row writing. Java: ScanUtils (v) and OccurrenceWriter (e)."""

from __future__ import annotations

import logging
import threading
from typing import Callable

from autologger.context import ScanContext
from autologger.jcompat import java_trim
from autologger.scan.backend import FileSnapshot
from autologger.scan.regex_engine import Occurrence, group_occurrences

log = logging.getLogger("autologger.scan.regex_engine")

# (matchText, occurrence, evidence) -> CSV row, or "" to skip
RowFormatter = Callable[[str, Occurrence, str], str]


def scan_java_regexes(ctx: ScanContext, type_name: str, patterns: list[str], snapshot: FileSnapshot,
                      case_insensitive: bool) -> list[dict[str, list[Occurrence]]]:
    """RegexScanEngine.scanOccurrences for each pattern (same order). Invalid regex -> logged, {}."""
    results: list[dict[str, list[Occurrence]]] = []
    live = [p for p in patterns if p is not None and java_trim(p) != ""]
    if not snapshot.content or not live:
        return [{} for _ in patterns]
    scanned = iter(ctx.backend.scan(snapshot, live, case_insensitive))
    for pattern in patterns:
        if pattern is None or java_trim(pattern) == "":
            results.append({})
            continue
        raw, error = next(scanned)
        if error is not None:
            thread = threading.current_thread().name
            log.error("%s The provided regular expression is invalid. Exception details: %s", thread, error)
            log.debug("%s regex causing the issue: %s", type_name, pattern)
            results.append({})
        else:
            results.append(group_occurrences(raw or []))
    return results


def scan_java_regex(ctx: ScanContext, type_name: str, pattern: str, snapshot: FileSnapshot,
                    case_insensitive: bool) -> dict[str, list[Occurrence]]:
    return scan_java_regexes(ctx, type_name, [pattern], snapshot, case_insensitive)[0]


def evidence(content: str, start: int, end: int, before: int, after: int) -> str:
    """content[start-before : end+after] clamped; 'Words Before/After' are characters."""
    if not content:
        return ""
    before, after = max(0, before), max(0, after)
    lo = max(0, start - before)
    hi = min(len(content), end + after)
    return "" if lo >= hi else content[lo:hi]


def write_occurrences(ctx: ScanContext, summary_path: str, content: str,
                      occurrences: dict[str, list[Occurrence]], before: int, after: int,
                      formatter: RowFormatter) -> int:
    """Write one row per occurrence (grouped by match text, first-seen order). Returns rows visited."""
    if not summary_path or not occurrences:
        return 0
    count = 0
    for match_text, occs in occurrences.items():
        for occ in occs:
            if not ctx.checkpoint():
                return count
            count += 1
            ev = evidence(content, occ.start, occ.end, before, after)
            row = formatter(match_text, occ, ev)
            if row:
                ctx.reports.write(summary_path, row)
                ctx.progress.finding_written()
    return count
