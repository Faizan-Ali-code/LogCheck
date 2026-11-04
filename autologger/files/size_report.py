"""End-of-run "name,KB" listing. Java: LogFileSizeReporter.

Logged on the message-only logger NameAndSizeLogger. Files are grouped by the
name before the first '.', and ".log" is always appended to the group name.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger("NameAndSizeLogger")


def _accept(name: str) -> bool:
    lower = name.lower()
    return not (lower.endswith(".old") or lower.endswith(".csv") or lower.endswith(".dat"))


def _walk(directory: str, out: list[str]) -> None:
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        if not _accept(name):
            continue
        path = os.path.join(directory, name)
        if os.path.isdir(path):
            _walk(path, out)
        else:
            out.append(os.path.realpath(path))


def stem(path: str) -> str:
    name = os.path.basename(path)
    dot = name.find(".")
    return name if dot < 0 else name[:dot]


def report_sizes(folder: str | None) -> None:
    if folder is None or folder.strip() == "":
        return
    files: list[str] = []
    _walk(folder, files)
    totals: dict[str, int] = {}
    for path in files:
        lower = os.path.basename(path).lower()
        if "summary_report" in lower or "overall_status" in lower:
            continue
        try:
            totals[stem(path)] = totals.get(stem(path), 0) + os.path.getsize(path)
        except OSError:
            log.error("Failed processing file: %s", path, exc_info=True)
    names = []
    for name, size in totals.items():
        if size > 0:
            log.info("%s.log,%d", name, size // 1024)
            names.append(name + ".log")
    log.info("All log files (comma-separated): %s", ",".join(names))
