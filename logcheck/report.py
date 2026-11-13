"""Report files (CSV, JSON, Excel) and the console summary.

Evidence is text copied from logs, which an attacker may control. Spreadsheet programs execute cells
that start with = + - @, so every such cell is written as plain text (CSV: prefixed with an apostrophe;
Excel: stored as a string, never as a formula).
"""

from __future__ import annotations

import csv
import json
import os
from collections import Counter
from dataclasses import asdict
from typing import TextIO

from logcheck.config import SEVERITY_ORDER
from logcheck.engine import Finding, ScanResult

COLUMNS = ["severity", "confidence", "detector", "title", "file", "line", "column", "masked_value", "fingerprint",
           "evidence", "notes", "ai_verdict"]
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def _rows(result: ScanResult, include_values: bool) -> tuple[list[str], list[list[object]]]:
    cols = COLUMNS + (["value"] if include_values else [])
    findings = sorted(result.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line, f.column))
    return cols, [[getattr(f, c) for c in cols] for f in findings]


def summary(result: ScanResult) -> dict:
    findings = result.findings
    return {
        "total_findings": len(findings),
        "by_severity": {s: n for s in SEVERITY_ORDER if (n := sum(f.severity == s for f in findings))},
        "by_detector": dict(Counter(f.detector for f in findings).most_common()),
        "distinct_values": len({(f.detector, f.fingerprint) for f in findings}),
        "files_scanned": sum(r.status == "scanned" for r in result.files),
        "files_with_findings": sum(bool(r.findings) for r in result.files),
        "files_skipped": sum(r.status == "skipped" for r in result.files),
        "files_with_errors": sum(r.status == "error" for r in result.files),
        "files_changed_during_scan": sum(r.changed_during_scan for r in result.files),
        "lines_scanned": sum(r.lines for r in result.files),
        "bytes_scanned": sum(r.size for r in result.files),
    }


def _file_rows(result: ScanResult) -> list[dict]:
    return [{k: v for k, v in asdict(r).items() if k != "findings"} | {"findings": len(r.findings)}
            for r in result.files]


def write_csv(result: ScanResult, path: str, include_values: bool) -> None:
    cols, rows = _rows(result, include_values)
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(cols)
        writer.writerows([[safe_cell(v) for v in row] for row in rows])


def write_json(result: ScanResult, path: str, include_values: bool, extra: dict | None = None) -> None:
    def finding(f: Finding) -> dict:
        d = asdict(f)
        d.pop("ai_input")
        if not include_values:
            d.pop("value")
        return d

    doc = {
        "tool": result.tool, "started": result.started, "finished": result.finished, "seconds": result.seconds,
        "inputs": result.inputs, "missing_inputs": result.missing, "detectors": result.detectors, "notes": result.notes,
        "summary": summary(result), **(extra or {}),
        "files": _file_rows(result),
        "findings": [finding(f) for f in sorted(result.findings, key=lambda f: (f.file, f.line, f.column))],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)


def write_xlsx(result: ScanResult, path: str, include_values: bool) -> bool:
    """False when openpyxl is not installed (Excel output is optional)."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ImportError:
        return False
    wb = Workbook()

    def sheet(ws, header: list[str], rows: list[list[object]], widths: dict[int, int]) -> None:
        ws.append(header)
        for cell in ws[1]:
            cell.font = Font(bold=True)
        for row in rows:
            ws.append(["" if v is None else v for v in row])
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                if cell.data_type == "f" or isinstance(cell.value, str):
                    cell.data_type = "s"  # log text is data, never a formula
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        for idx, width in widths.items():
            ws.column_dimensions[chr(64 + idx)].width = width

    s = summary(result)
    sheet(wb.active, ["Item", "Value"], [[k.replace("_", " "), json.dumps(v) if isinstance(v, dict) else v]
                                        for k, v in s.items()], {1: 28, 2: 80})
    wb.active.title = "Summary"
    cols, rows = _rows(result, include_values)
    sheet(wb.create_sheet("Findings"), cols, rows, {4: 34, 5: 50, 8: 24, 10: 90, 11: 50})
    files = _file_rows(result)
    sheet(wb.create_sheet("Files"), list(files[0]) if files else ["path"], [list(f.values()) for f in files], {1: 70})
    wb.save(path)
    return True


def write_reports(result: ScanResult, out_dir: str, formats: list[str], include_values: bool,
                  extra: dict | None = None) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    if "csv" in formats:
        written.append(os.path.join(out_dir, "findings.csv"))
        write_csv(result, written[-1], include_values)
    if "json" in formats:
        written.append(os.path.join(out_dir, "findings.json"))
        write_json(result, written[-1], include_values, extra)
    if "xlsx" in formats:
        path = os.path.join(out_dir, "findings.xlsx")
        if write_xlsx(result, path, include_values):
            written.append(path)
    return written


def print_summary(result: ScanResult, out: TextIO) -> None:
    s = summary(result)
    out.write(f"\n{result.tool}: {s['files_scanned']} file(s), {s['lines_scanned']:,} lines, "
              f"{s['bytes_scanned'] / 1_048_576:.1f} MB in {result.seconds:.1f} s\n")
    if s["total_findings"]:
        sev = ", ".join(f"{n} {k}" for k, n in s["by_severity"].items())
        out.write(f"Findings: {s['total_findings']} ({sev}); {s['distinct_values']} distinct value(s)\n")
        width = max(len(d) for d in s["by_detector"])
        for det, n in s["by_detector"].items():
            out.write(f"  {det:<{width}}  {n}\n")
    else:
        out.write("Findings: none\n")
    for r in result.files:
        if r.status != "scanned":
            out.write(f"  {r.status.upper()}: {r.path}: {r.reason}\n")
        elif r.changed_during_scan:
            out.write(f"  NOTE: {r.path} changed while it was being scanned (still being written?)\n")
        if r.replaced_chars:
            out.write(f"  NOTE: {r.path}: {r.replaced_chars} undecodable byte sequence(s) replaced ({r.encoding})\n")
    for item in result.missing:
        out.write(f"  NOT FOUND: {item}\n")
    for note in result.notes:
        out.write(f"  NOTE: {note}\n")
