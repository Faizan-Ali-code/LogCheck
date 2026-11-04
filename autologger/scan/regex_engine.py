"""Regex occurrence scanning and log-level extraction.

Java: RegexScanEngine (q), MatchOccurrence (k), LogLevelExtractor (r) and
ScanUtils.extractLogLevel (v.a(String, int)).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

RawOccurrence = tuple[str, int, int, str]  # (match text, start, end, log level)

_LEVELS = "INFO|DEBUG|WARN|WARNING|ERROR|TRACE|FATAL|FINEST"
LEVEL_PATTERNS = tuple(
    re.compile(p, re.IGNORECASE | re.ASCII)
    for p in (
        r"\[(" + _LEVELS + r")\s*\]",
        r"\b(" + _LEVELS + r"):",
        r"\[\s*(" + _LEVELS + r")\s*\]",
        r"\b(" + _LEVELS + r")\b",
    )
)


@dataclass(slots=True)
class Occurrence:
    match: str
    start: int
    end: int
    level: str


def extract_level(content: str, pos: int) -> str:
    """Level of the line containing `pos`; first of the 4 patterns wins; FINEST -> TRACE."""
    if content is None or pos < 0 or pos > len(content):
        return "UNKNOWN"
    line_start = content.rfind("\n", 0, max(0, pos - 1) + 1)
    line_start = 0 if line_start == -1 else line_start + 1
    line_end = content.find("\n", pos)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end]
    for pattern in LEVEL_PATTERNS:
        m = pattern.search(line)
        if m:
            level = m.group(1).upper()
            return "TRACE" if level == "FINEST" else level
    return "UNKNOWN"


def find_occurrences(content: str, regex: re.Pattern[str]) -> list[RawOccurrence]:
    return [(m.group(0), m.start(), m.end(), extract_level(content, m.start())) for m in regex.finditer(content)]


def group_occurrences(raw: list[RawOccurrence]) -> dict[str, list[Occurrence]]:
    """LinkedHashMap<matchText, List<Occurrence>> in first-seen order."""
    grouped: dict[str, list[Occurrence]] = {}
    for text, start, end, level in raw:
        grouped.setdefault(text, []).append(Occurrence(text, start, end, level))
    return grouped
