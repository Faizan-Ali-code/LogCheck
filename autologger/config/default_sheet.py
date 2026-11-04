"""Default.xls reader. Java: DefaultSheetReader, Apache POI HSSF.

POI details reproduced:
  * cell text is HSSFCell.toString().trim(): numbers print like Java doubles
    ("100" stored as a number reads "100.0", which then fails Integer.parseInt),
    dates as dd-MMM-yyyy, booleans as TRUE/FALSE; trim() strips chars <= U+0020 only;
  * getSheet(name) is case-insensitive;
  * rowIterator() walks physical rows and the first one is skipped as the header;
  * results are HashMaps: with legacy_compat the iteration order is Java's
    HashMap order (it decides test-case order and the GUI table order).
Formula cells: xlrd only exposes the cached value, POI printed the formula text.
"""

from __future__ import annotations

import logging

import xlrd

from autologger import constants as C
from autologger.jcompat import java_double_to_string, java_hashmap_order, java_trim

log = logging.getLogger(__name__)

_ACTIVE_VALUES = ("y", "yes", "true")


class DefaultSheetReader:
    def __init__(self, legacy: bool = True) -> None:
        self.legacy = legacy

    # ------------------------------------------------------------------ public API (j.a / j.b / j.c)
    def read_active_test_cases(self, path: str) -> dict[str, str] | None:
        """Active rows of 'Test Cases': name -> regex column. None if the sheet is missing/empty."""
        rows = self._rows(path, C.TEST_CASES_SHEET, missing_level=logging.ERROR,
                          missing_msg="Sheet 'Test Cases' not found in default sheet: %s",
                          error_msg="Failed to read 'Test Cases' from default sheet: %s")
        if rows is None:
            return None
        result: dict[str, str] = {}
        for cells in rows:
            name, regex, flag = cells[0], cells[1], cells[2]
            if self.is_active(flag) and len(name) > 0:
                result[name] = regex
                log.debug("Default sheet: active field='%s', regex='%s'.", name, regex)
        if not result:
            log.debug("Default sheet 'Test Cases' is empty; returning null.")
            return None
        log.debug("Default sheet 'Test Cases' contains active entries.")
        return self._ordered(result)

    def read_all_test_cases(self, path: str) -> dict[str, bool]:
        """Every 'Test Cases' row: name -> active flag ({} when unreadable)."""
        rows = self._rows(path, C.TEST_CASES_SHEET, missing_level=logging.WARNING,
                          missing_msg="Sheet 'Test Cases' not found; returning empty map.",
                          error_msg="Failed to read 'Test Cases' (all rows) from: %s")
        result: dict[str, bool] = {}
        for cells in rows or []:
            if len(cells[0]) > 0:
                result[cells[0]] = self.is_active(cells[2])
        return self._ordered(result)

    def read_variables(self, path: str) -> dict[str, str] | None:
        rows = self._rows(path, C.VARIABLES_SHEET, missing_level=logging.ERROR,
                          missing_msg="Sheet 'Variables' not found in default sheet: %s",
                          error_msg="Failed to read 'Variables' from default sheet: %s")
        if rows is None:
            return None
        result: dict[str, str] = {}
        for cells in rows:
            if len(cells[0]) > 0:
                result[cells[0]] = cells[1]
                log.debug("Default sheet variable loaded: name='%s', value='%s'.", cells[0],
                          "<hidden>" if cells[0] == C.VAR_DB_STRING else cells[1])
        if not result:
            log.debug("Default sheet 'Variables' is empty; returning null.")
            return None
        log.debug("Default sheet 'Variables' contains entries.")
        return result

    @staticmethod
    def is_active(flag: str) -> bool:
        return flag.lower() in _ACTIVE_VALUES

    # ------------------------------------------------------------------ internals
    def _ordered(self, mapping: dict) -> dict:
        if not self.legacy:
            return mapping
        return {k: mapping[k] for k in java_hashmap_order(mapping)}

    def _rows(self, path: str, sheet_name: str, missing_level: int, missing_msg: str,
              error_msg: str) -> list[list[str]] | None:
        try:
            book = xlrd.open_workbook(path, formatting_info=True)
        except (OSError, xlrd.XLRDError, ValueError, AssertionError):
            log.error(error_msg, path, exc_info=True)
            return None
        try:
            sheet = next((s for s in book.sheets() if s.name.lower() == sheet_name.lower()), None)
            if sheet is None:
                log.log(missing_level, missing_msg.replace("%s", path) if "%s" in missing_msg else missing_msg)
                return None
            physical = sorted(set(getattr(sheet, "rowinfo_map", {}))
                              | {r for r in range(sheet.nrows)
                                 if any(c.ctype != xlrd.XL_CELL_EMPTY for c in sheet.row(r))})
            return [[self._text(book, sheet, r, col) for col in range(3)] for r in physical[1:]]
        finally:
            book.release_resources()

    def _text(self, book: xlrd.Book, sheet: xlrd.sheet.Sheet, row: int, col: int) -> str:
        if row >= sheet.nrows or col >= sheet.row_len(row):
            return ""
        return java_trim(self.poi_cell_string(book, sheet.cell(row, col)))

    def poi_cell_string(self, book: xlrd.Book, cell: xlrd.sheet.Cell) -> str:
        """HSSFCell.toString()."""
        ctype, value = cell.ctype, cell.value
        if ctype in (xlrd.XL_CELL_EMPTY, xlrd.XL_CELL_BLANK):
            return ""
        if ctype == xlrd.XL_CELL_TEXT:
            return value
        if ctype == xlrd.XL_CELL_NUMBER:
            if not self.legacy and float(value).is_integer():
                return str(int(value))
            return java_double_to_string(float(value))
        if ctype == xlrd.XL_CELL_DATE:
            try:
                return xlrd.xldate.xldate_as_datetime(value, book.datemode).strftime("%d-%b-%Y")
            except (ValueError, OverflowError, xlrd.xldate.XLDateError):
                return java_double_to_string(float(value))
        if ctype == xlrd.XL_CELL_BOOLEAN:
            return "TRUE" if value else "FALSE"
        if ctype == xlrd.XL_CELL_ERROR:
            return xlrd.error_text_from_code.get(value, "#ERR")
        return str(value)
