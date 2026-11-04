"""Report file names. Java: ResultFileName (t) and ReportPaths (s).

<dir>\\<file name up to the FIRST '.'>-<Test Case>-Summary_Report.xlsx and
<dir>\\<stem>-Overall_Status.xlsx (shared by every test case of that stem).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from autologger import constants as C


def result_base(file_path: str) -> str:
    directory = os.path.dirname(file_path)
    name = os.path.basename(file_path)
    dot = name.find(".")
    stem = name if dot < 0 else name[:dot]
    return os.path.join(directory, stem)


@dataclass(frozen=True)
class ReportPaths:
    summary: str
    overall: str

    @staticmethod
    def for_test_case(file_path: str, test_case: str) -> "ReportPaths":
        base = result_base(file_path)
        return ReportPaths(f"{base}-{test_case}-{C.SUMMARY_SUFFIX}", f"{base}-{C.OVERALL_SUFFIX}")

    @staticmethod
    def for_cards(file_path: str) -> "ReportPaths":
        return ReportPaths.for_test_case(file_path, C.CARD_NO)
