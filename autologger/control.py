"""Pause / resume / stop control and Java-style thread interruption.

Java: RunControl (threads.b) and RunContext (threads.e).

Java's DB retry code calls Thread.currentThread().interrupt() after its last
failed attempt; every later Thread.sleep() on that thread then fails at once,
which is what makes later DB retries on the same task immediate. The
`interrupt_current_thread` / `interruptible_sleep` pair reproduces that timing.
Unlike Java, the interrupt flag never makes a *paused* worker abort its file
(bug #2 in the analysis), because await_if_paused() ignores it.
"""

from __future__ import annotations

import threading

_tls = threading.local()


class Interrupted(Exception):
    """Equivalent of java.lang.InterruptedException."""


def interrupt_current_thread() -> None:
    _tls.interrupted = True


def clear_interrupt() -> None:
    """ThreadPoolExecutor clears the interrupt flag before running each task (Java semantics)."""
    _tls.interrupted = False


def is_interrupted() -> bool:
    return getattr(_tls, "interrupted", False)


class RunControl:
    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._paused = False
        self._stopped = False
        self._stop_event = threading.Event()

    def pause(self) -> None:
        with self._cond:
            self._paused = True

    def resume(self) -> None:
        with self._cond:
            self._paused = False
            self._cond.notify_all()

    def stop(self) -> None:
        with self._cond:
            self._stopped = True
            self._paused = False
            self._stop_event.set()
            self._cond.notify_all()

    def is_paused(self) -> bool:
        return self._paused

    def is_stopped(self) -> bool:
        return self._stopped

    def await_if_paused(self) -> bool:
        """Block while paused; True = keep working, False = stopped."""
        if self._stopped:
            return False
        with self._cond:
            while self._paused and not self._stopped:
                self._cond.wait()
            return not self._stopped

    def interruptible_sleep(self, seconds: float) -> None:
        """Thread.sleep(): raises Interrupted if the thread is interrupted or the run stops."""
        if is_interrupted():
            raise Interrupted()
        if seconds > 0 and self._stop_event.wait(seconds):
            interrupt_current_thread()
            raise Interrupted()
        if self._stopped:
            interrupt_current_thread()
            raise Interrupted()
