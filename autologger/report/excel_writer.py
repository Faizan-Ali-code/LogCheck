"""Report writing. Java: WriteToResultFile (y), ExcelReportWriter (h), ExcelWorkbookHandle (i)
and ScanUtils.ensureHeaderExists (v.a(y, String, String)).

Rows are produced as CSV text (like Java) and parsed back into cells with the
same quote-aware splitter, so cell contents match Java byte for byte
(including trimming). The xlsx output reproduces POI:
  * every cell is a string (even "=..." and numbers),
  * XML-illegal characters become '?', '\\r' is kept (written as &#13;),
  * one sheet named "Report"; existing files are appended to.
Fixes vs Java: workbooks are saved per test case instead of after every row
(Java was O(n^2)), handles are closed at the end of the run (Java leaked them),
and opening a handle is race-free.
"""

from __future__ import annotations

import io
import logging
import os
import re
import threading
import zipfile

import openpyxl

from autologger import constants as C
from autologger.jcompat import java_trim, utf16_len

log = logging.getLogger(__name__)

_XML_ILLEGAL = re.compile("[^\t\n\r -퟿-�\U00010000-\U0010ffff]")
_CELL_LIMIT_MESSAGE = "The maximum length of cell contents (text) is 32,767 characters"


class CellTooLongError(ValueError):
    """POI's IllegalArgumentException for strings longer than 32,767 characters."""


def csv_quote(value: str | None) -> str:
    """ScanUtils.csv(): '"' + value with doubled quotes + '"'; null -> ''."""
    return "" if value is None else '"' + value.replace('"', '""') + '"'


def parse_csv_cells(line: str | None, legacy: bool = True) -> list[str]:
    """ExcelWorkbookHandle.c() + d(): quote-aware split, trim each cell, unquote."""
    if not line:
        return []
    cells: list[str] = []
    cur: list[str] = []
    in_quotes = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == '"':
            if in_quotes and i + 1 < len(line) and line[i + 1] == '"':
                cur.append('"')
                i += 1
            else:
                in_quotes = not in_quotes
        elif ch == "," and not in_quotes:
            cells.append(java_trim("".join(cur)))
            cur = []
        else:
            cur.append(ch)
        i += 1
    cells.append(java_trim("".join(cur)))
    return [_unquote(c, legacy) for c in cells]


def _unquote(cell: str, legacy: bool) -> str:
    if cell.startswith('"') and cell.endswith('"'):
        if len(cell) == 1:
            if legacy:  # Java: "\"".substring(1, 0) throws
                raise IndexError("begin 1, end 0, length 1")
            return ""
        cell = cell[1:-1]
    return cell.replace('""', '"')


def sanitize_cell(text: str) -> str:
    """What POI/XmlBeans stores: XML-illegal characters are replaced with '?'."""
    return _XML_ILLEGAL.sub("?", text)


class _WorkbookHandle:
    def __init__(self, path: str, legacy: bool) -> None:
        self.path = path
        self.legacy = legacy
        self.lock = threading.RLock()
        self.wb: openpyxl.Workbook | None = None
        self.ws = None
        self.row_count = 0
        self.dirty = False

    def ensure_open(self) -> None:
        with self.lock:
            if self.wb is not None:
                return
            if os.path.exists(self.path) and os.path.getsize(self.path) > 0:
                wb = openpyxl.load_workbook(self.path)
                ws = wb.worksheets[0]
                rows = [r for (r, _c) in ws._cells]  # noqa: SLF001 - only real cells count (POI rows)
                # POI 4.0.1 getLastRowNum() returns 0 for an empty sheet, so the next row is 1
                self.row_count = (max(rows) - 1 if rows else 0) + 1
            else:
                wb = openpyxl.Workbook()
                ws = wb.active
                ws.title = C.REPORT_SHEET_NAME
                self.row_count = 0
            self.wb, self.ws = wb, ws

    def _cells(self, line: str) -> list[str]:
        cells = [sanitize_cell(c) for c in parse_csv_cells(line, self.legacy)]
        for idx, value in enumerate(cells):
            if utf16_len(value) > C.EXCEL_MAX_CELL_CHARS:
                if self.legacy:
                    raise CellTooLongError(_CELL_LIMIT_MESSAGE)
                cells[idx] = value[:C.EXCEL_MAX_CELL_CHARS]
        return cells

    def _put_row(self, index: int, cells: list[str]) -> None:
        for col, value in enumerate(cells, start=1):
            cell = self.ws.cell(row=index + 1, column=col)
            cell.value = value
            cell.data_type = "s"  # POI setCellValue(String): never a formula/number

    def write_header(self, line: str) -> None:
        with self.lock:
            if self.row_count == 0:
                self._put_row(0, self._cells(line))
                self.row_count = 1
                self.dirty = True

    def write_row(self, line: str) -> None:
        with self.lock:
            cells = self._cells(line)
            self._put_row(self.row_count, cells)
            self.row_count += 1
            self.dirty = True

    def save(self) -> None:
        with self.lock:
            if self.wb is None or not self.dirty:
                return
            buffer = io.BytesIO()
            self.wb.save(buffer)
            data = _preserve_carriage_returns(buffer.getvalue())
            with open(self.path, "wb") as fh:
                fh.write(data)
            self.dirty = False

    def close(self) -> None:
        with self.lock:
            self.save()
            if self.wb is not None:
                self.wb.close()
            self.wb = self.ws = None


def _preserve_carriage_returns(xlsx: bytes) -> bytes:
    """Make cell text survive like POI's: '\\r' as &#13;, '\\n' as a plain newline.

    openpyxl (et_xmlfile) writes worksheet XML through a text-mode file, so on
    Windows every '\\n' arrives as '\\r\\n'; undoing that is exact because each
    inserted CR sits directly before an LF. Any CR left over is real cell data and
    is written as &#13;, otherwise XML readers would turn it into '\\n'. Attribute
    values are already escaped, so element text is the only place this touches.
    """
    src = zipfile.ZipFile(io.BytesIO(xlsx))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename.startswith("xl/worksheets/") and item.filename.endswith(".xml"):
                if os.linesep == "\r\n":
                    data = data.replace(b"\r\n", b"\n")
                data = data.replace(b"\r", b"&#13;")
            dst.writestr(item, data)
    return out.getvalue()


class ReportWriter:
    """Per-run registry of report workbooks."""

    def __init__(self, legacy: bool = True) -> None:
        self.legacy = legacy
        self._handles: dict[str, _WorkbookHandle] = {}
        self._handles_lock = threading.Lock()
        self._header_locks: dict[str, threading.Lock] = {}

    def _handle(self, path: str) -> _WorkbookHandle:
        with self._handles_lock:
            handle = self._handles.get(path)
            if handle is None:
                handle = self._handles[path] = _WorkbookHandle(path, self.legacy)
            return handle

    def ensure_header(self, path: str, header: str) -> None:
        """ScanUtils.ensureHeaderExists: header only when the file is missing or empty."""
        if not path or header is None:
            return
        with self._handles_lock:
            lock = self._header_locks.setdefault(path, threading.Lock())
        with lock:
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                if path.endswith(".xlsx"):
                    self._write_xlsx(path, header, header=True)
                else:
                    self._append_text(path, header)

    def write(self, path: str, line: str) -> None:
        """WriteToResultFile.write."""
        if not path or line is None:
            return
        if path.endswith(".xlsx"):
            self._write_xlsx(path, line, header=False)
        else:
            self._append_text(path, line)

    def _write_xlsx(self, path: str, line: str, header: bool) -> None:
        handle = self._handle(path)
        try:
            handle.ensure_open()
            if header:
                handle.write_header(line)
            else:
                handle.write_row(line)
        except OSError:
            what = "header" if header else "row"
            log.error("Error writing %s to Excel file: %s", what, path, exc_info=True)

    def _append_text(self, path: str, line: str) -> None:
        handle = self._handle(path)
        with handle.lock:
            try:
                with open(path, "a", encoding="utf-8", newline="") as fh:
                    fh.write(line + os.linesep)
            except OSError as exc:
                log.error("%s", exc)

    def flush(self, *paths: str) -> None:
        for path in paths:
            handle = self._handles.get(path)
            if handle is None:
                continue
            try:
                handle.save()
            except OSError:
                log.error("Error writing row to Excel file: %s", path, exc_info=True)

    def close_all(self) -> None:
        with self._handles_lock:
            handles = list(self._handles.values())
            self._handles.clear()
        for handle in handles:
            try:
                handle.close()
            except OSError:
                log.error("Error closing Excel file: %s", handle.path, exc_info=True)
