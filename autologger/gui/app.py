"""Desktop window. Java: AutoLoggerFxApp (JavaFX) with StatusTableCell, FxScanListener,
TestCaseRow and UiLogAppender.

Fix vs Java: the log console keeps at most MAX_LOG_LINES lines (Java grew forever).
"""

from __future__ import annotations

import logging
import threading
import time

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (QApplication, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel,
                               QPlainTextEdit, QProgressBar, QPushButton, QSplitter, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from autologger import VERSION
from autologger.control import RunControl
from autologger.listener import ScanListener
from autologger.logging_setup import configure_logging, log4j_level_name
from autologger.orchestrator import Orchestrator
from autologger.progress import ScanProgress, TestCaseInfo
from autologger.settings import Settings
from autologger.gui.theme import ThemeManager

MAX_LOG_LINES = 20000
_COLUMNS = ("Test Case", "Type", "Active in Default.xls", "Scan Status", "Files (done/total)")
_WIDTHS = (200, 90, 150, 120, 130)


class _Bridge(QObject):
    log_line = Signal(str, int)
    run_started = Signal(int, int, bool, str)
    test_cases = Signal(list)
    run_finished = Signal(bool, str)


class UiLogHandler(logging.Handler):
    """'yyyy-MM-dd HH:mm:ss [LEVEL] message' lines for the console (root logger only)."""

    def __init__(self, bridge: _Bridge) -> None:
        super().__init__()
        self.bridge = bridge

    def emit(self, record: logging.LogRecord) -> None:
        try:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.created))
            self.bridge.log_line.emit(f"{stamp} [{log4j_level_name(record.levelno)}] {record.getMessage()}",
                                      record.levelno)
        except Exception:  # noqa: BLE001
            self.handleError(record)


class GuiListener(ScanListener):
    def __init__(self, bridge: _Bridge) -> None:
        self.bridge = bridge

    def run_started(self, total_files: int, threads: int, ai_enabled: bool, log_path: str) -> None:
        self.bridge.run_started.emit(total_files, threads, ai_enabled, log_path)

    def test_cases_loaded(self, infos: list[TestCaseInfo]) -> None:
        self.bridge.test_cases.emit(list(infos))

    def run_finished(self, stopped: bool, status: str) -> None:
        self.bridge.run_finished.emit(stopped, status)


class MainWindow(QWidget):
    def __init__(self, settings: Settings, orchestrator_factory=Orchestrator) -> None:
        super().__init__()
        self.settings = settings
        self.orchestrator_factory = orchestrator_factory
        self.theme = ThemeManager()
        self.bridge = _Bridge()
        self.orchestrator: Orchestrator | None = None
        self.control: RunControl | None = None
        self.progress: ScanProgress | None = None
        self.engine: threading.Thread | None = None
        self.rows: dict[str, int] = {}

        self.setWindowTitle(f"AutoLogger {VERSION}")
        self.resize(1200, 820)
        self._build()
        self.bridge.log_line.connect(self._append_log)
        self.bridge.run_started.connect(self._on_run_started)
        self.bridge.test_cases.connect(self._on_test_cases)
        self.bridge.run_finished.connect(self._on_run_finished)
        self.theme.add_listener(lambda _dark: self._apply_theme())
        self._set_running(False)
        self._apply_theme()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(500)

    # ------------------------------------------------------------------ layout
    def _build(self) -> None:
        title = QLabel(f"AutoLogger {VERSION}")
        title.setStyleSheet("font-size: 25px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.btn_start, self.btn_pause = QPushButton("Start"), QPushButton("Pause")
        self.btn_resume, self.btn_stop = QPushButton("Resume"), QPushButton("Stop")
        self.btn_theme = QPushButton(self.theme.toggle_label())
        self.btn_theme.setStyleSheet("font-size: 11px; padding: 6px 12px;")
        self.btn_start.clicked.connect(self.start_run)
        self.btn_pause.clicked.connect(self.pause_run)
        self.btn_resume.clicked.connect(self.resume_run)
        self.btn_stop.clicked.connect(self.stop_run)
        self.btn_theme.clicked.connect(self.theme.toggle)
        controls = QHBoxLayout()
        controls.setSpacing(8)
        for b in (self.btn_start, self.btn_pause, self.btn_resume, self.btn_stop):
            controls.addWidget(b)
        bar = QHBoxLayout()
        bar.setSpacing(15)
        bar.addLayout(controls)
        bar.addWidget(self.btn_theme)
        bar.addStretch(1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedWidth(600)
        self.status_label = QLabel("Ready")
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)

        self.lbl_files, self.lbl_findings, self.lbl_cards = QLabel("0/0"), QLabel("0"), QLabel("0")
        self.lbl_duration, self.lbl_threads = QLabel("00:00:00"), QLabel("-")
        self.lbl_ai, self.lbl_completion = QLabel("Unknown"), QLabel("0.0%")
        grid = QGridLayout()
        grid.setHorizontalSpacing(20)
        grid.setVerticalSpacing(8)
        cells = (("Files Processed:", self.lbl_files, 0, 0), ("Findings (All):", self.lbl_findings, 0, 2),
                 ("Vulnerable Cards:", self.lbl_cards, 0, 4), ("Duration:", self.lbl_duration, 1, 0),
                 ("Active Threads:", self.lbl_threads, 1, 2), ("AI Verification:", self.lbl_ai, 2, 0),
                 ("Completion:", self.lbl_completion, 2, 2))
        for text, value, row, col in cells:
            grid.addWidget(QLabel(text), row, col)
            grid.addWidget(value, row, col + 1)
        grid.setColumnStretch(6, 1)

        top = QVBoxLayout()
        top.setSpacing(10)
        top.setContentsMargins(12, 12, 12, 6)
        top.addWidget(title)
        top.addLayout(bar)
        top.addWidget(self.progress_bar)
        top.addWidget(self.status_label)
        top.addWidget(separator)
        top.addLayout(grid)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(MAX_LOG_LINES)
        self.console.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.console.setFont(QFont("Consolas", 9))

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        for i, w in enumerate(_WIDTHS):
            self.table.setColumnWidth(i, w)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table_title = QLabel("Test Cases")
        table_title.setStyleSheet("font-size: 13px; font-weight: bold; padding: 6px 0 4px 0;")
        self.table_panel = QWidget()
        panel = QVBoxLayout(self.table_panel)
        panel.setSpacing(4)
        panel.setContentsMargins(12, 6, 12, 8)
        panel.addWidget(table_title)
        panel.addWidget(self.table)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.console)
        splitter.addWidget(self.table_panel)
        splitter.setSizes([650, 350])

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addLayout(top)
        root.addWidget(splitter, 1)

    # ------------------------------------------------------------------ actions
    def _set_running(self, running: bool) -> None:
        self.btn_start.setDisabled(running)
        for b in (self.btn_pause, self.btn_resume, self.btn_stop):
            b.setDisabled(not running)

    def start_run(self) -> None:
        if self.engine is not None and self.engine.is_alive():
            return
        self.console.clear()
        self.table.setRowCount(0)
        self.rows.clear()
        self.control, self.progress = RunControl(), ScanProgress()
        self.orchestrator = self.orchestrator_factory(self.settings)
        self._set_running(True)
        listener = GuiListener(self.bridge)
        control, progress, orchestrator = self.control, self.progress, self.orchestrator
        self.engine = threading.Thread(target=lambda: orchestrator.run(control, progress, listener),
                                       name="AutoLogger-Engine", daemon=True)
        self.engine.start()

    def pause_run(self) -> None:
        if self.control is not None:
            self.control.pause()
            self.status_label.setText("Paused")

    def resume_run(self) -> None:
        if self.control is not None:
            self.control.resume()
            self.status_label.setText("Running")

    def stop_run(self) -> None:
        if self.control is not None:
            self.control.stop()
            self.status_label.setText("Stopping...")

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if self.engine is not None and self.engine.is_alive() and self.orchestrator is not None:
            self.orchestrator.abort()
        super().closeEvent(event)

    # ------------------------------------------------------------------ listener slots
    def _on_run_started(self, files: int, threads: int, _ai: bool, path: str) -> None:
        self.status_label.setText(f"Running | Files={files} | Threads={threads} | Path={path}")

    def _on_test_cases(self, infos: list) -> None:
        self.table.setRowCount(0)
        self.rows.clear()
        total = self.progress.total_files if self.progress else "?"
        for info in infos:
            if not info.active:
                continue
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = (f"{info.name} (Others)" if info.custom else info.name,
                      "Custom" if info.custom else "Built-in", "Yes", "Queued", f"0/{total}")
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(value))
            self.rows[info.name] = row
        self._color_status_cells()

    def _on_run_finished(self, _stopped: bool, status: str) -> None:
        self.status_label.setText(status)
        self._set_running(False)
        self.refresh()

    # ------------------------------------------------------------------ refresh
    def refresh(self) -> None:
        p = self.progress
        if p is None:
            return
        total = p.total_files
        self.lbl_files.setText(f"{p.files_finished}/{total}")
        self.lbl_findings.setText(str(p.findings))
        self.lbl_cards.setText(str(p.vulnerable_cards))
        secs = int(p.duration_seconds())
        self.lbl_duration.setText(f"{secs // 3600:02d}:{secs % 3600 // 60:02d}:{secs % 60:02d}")
        self.lbl_ai.setText("Enabled" if p.ai_enabled else "Disabled")
        pct = p.completion_percent()
        self.lbl_completion.setText(f"{pct:.1f}%")
        self.progress_bar.setValue(int(max(0.0, min(100.0, pct)) * 10))
        threads = p.active_threads()
        self.lbl_threads.setText(", ".join(threads) if threads else "-")
        for name, row in self.rows.items():
            started, finished = p.started_count(name), p.finished_count(name)
            self.table.item(row, 4).setText(f"{finished}/{total}")
            status = "Queued" if started == 0 else ("In Progress" if finished < total else "Processed")
            self.table.item(row, 3).setText(status)
        self._color_status_cells()

    def _color_status_cells(self) -> None:
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 3)
            if item is None:
                continue
            color, bold = self.theme.status_color(item.text())
            item.setForeground(QColor(color))
            font = item.font()
            font.setBold(bold)
            item.setFont(font)

    # ------------------------------------------------------------------ console
    def _line_color(self, levelno: int) -> str:
        p = self.theme.palette
        if levelno >= logging.ERROR:
            return p.error
        if levelno >= logging.WARNING:
            return p.warn
        return p.text

    def _append_log(self, text: str, levelno: int) -> None:
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(self._line_color(levelno)))
        cursor = self.console.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if not self.console.document().isEmpty():
            cursor.insertText("\n")
        cursor.insertText(text, fmt)
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    def _apply_theme(self) -> None:
        p = self.theme.palette
        self.console.setStyleSheet(f"QPlainTextEdit {{ background: {p.console_bg}; }}")
        self.table_panel.setStyleSheet(f"background-color: {p.panel_bg}; color: {p.panel_fg};")
        self.btn_theme.setText(self.theme.toggle_label())
        self._color_status_cells()
        # Java recoloured existing lines by their text (error/exception, warn, other)
        doc = self.console.document()
        block = doc.begin()
        while block.isValid():
            lower = block.text().lower()
            color = p.error if ("error" in lower or "exception" in lower) else (p.warn if "warn" in lower else p.text)
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(color))
            cursor = QTextCursor(block)
            cursor.select(QTextCursor.SelectionType.BlockUnderCursor)
            cursor.mergeCharFormat(fmt)
            block = block.next()


def launch(settings: Settings, argv: list[str] | None = None) -> int:
    configure_logging(settings.path("log4j.xml"), settings.workdir)
    app = QApplication.instance() or QApplication(["AutoLogger", *(argv or [])])
    window = MainWindow(settings)
    handler = UiLogHandler(window.bridge)
    logging.getLogger().addHandler(handler)
    try:
        window.show()
        return app.exec()
    finally:
        logging.getLogger().removeHandler(handler)
