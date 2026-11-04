"""Objects shared by one run. Java kept these in static fields (RunContext, ScanTaskExecutor,
OpenAIVerifier); the port passes one ScanContext down instead."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from autologger.control import RunControl
from autologger.listener import NO_OP_LISTENER, ScanListener
from autologger.progress import ScanProgress
from autologger.report.excel_writer import ReportWriter
from autologger.settings import Settings

if TYPE_CHECKING:
    from autologger.ai.openai_verifier import OpenAIVerifier
    from autologger.db.card_database import CardDatabase
    from autologger.scan.backend import InlineBackend, ProcessBackend
    from autologger.scan.executors import ScanExecutors


@dataclass
class ScanContext:
    settings: Settings
    control: RunControl
    progress: ScanProgress
    reports: ReportWriter
    executors: "ScanExecutors"
    backend: "InlineBackend | ProcessBackend"
    verifier: "OpenAIVerifier"
    card_db: "CardDatabase"
    listener: ScanListener = NO_OP_LISTENER
    # Java kept DB-verified card offsets in a static set shared by every file and run
    # (bug #1). legacy_compat keeps that; otherwise each card scan gets its own set.
    verified_offsets: set[str] = field(default_factory=set)

    def checkpoint(self) -> bool:
        """RunContext.b(): wait while paused; False once stopped."""
        return self.control.await_if_paused()

    @property
    def legacy(self) -> bool:
        return self.settings.legacy_compat
