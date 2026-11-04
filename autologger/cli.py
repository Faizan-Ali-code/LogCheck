"""Entry point and run-mode selection. Java: AutoLogger3.main.

CLI when: --cli argument, AUTOLOGGER_FORCE_CLI=true|1, -Dautologger.forceCli=true,
or no display is available. Otherwise the GUI starts; if the GUI cannot start,
the same stderr messages as Java are printed and the CLI runs instead.
"""

from __future__ import annotations

import multiprocessing
import os
import sys
import threading

from autologger.settings import Settings, load_settings


def is_headless() -> bool:
    if sys.platform in ("win32", "darwin"):
        return False
    return not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def run_cli(settings: Settings) -> int:
    from autologger.orchestrator import Orchestrator

    threading.current_thread().name = "main"
    Orchestrator(settings).run()
    return 0


def main(argv: list[str] | None = None) -> int:
    multiprocessing.freeze_support()
    argv = sys.argv[1:] if argv is None else argv
    settings = load_settings(argv)
    if settings.force_cli or is_headless():
        return run_cli(settings)
    try:
        from autologger.gui.app import launch
    except Exception as exc:  # noqa: BLE001 - e.g. PySide6 missing
        print("[AutoLogger] GUI launch failed; falling back to CLI mode.", file=sys.stderr)
        print(f"[AutoLogger] Cause: {type(exc).__module__}.{type(exc).__name__}: {exc}", file=sys.stderr)
        return run_cli(settings)
    try:
        return launch(settings, argv)
    except Exception as exc:  # noqa: BLE001
        print("[AutoLogger] GUI launch failed; falling back to CLI mode.", file=sys.stderr)
        print(f"[AutoLogger] Cause: {type(exc).__module__}.{type(exc).__name__}: {exc}", file=sys.stderr)
        return run_cli(settings)
