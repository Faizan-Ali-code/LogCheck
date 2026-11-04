"""Colours of the JavaFX theme. Java: ThemeManager. Starts in light mode."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Palette:
    console_bg: str
    panel_bg: str
    panel_fg: str
    queued: str
    in_progress: str
    processed: str
    other: str
    error: str
    warn: str
    text: str


DARK = Palette("#101317", "#1a1f26", "#d9e2ec", "#8899aa", "#ffd166", "#06d6a0", "#556677",
               "#ff6b6b", "#ffd166", "#d9e2ec")
LIGHT = Palette("#ffffff", "#f5f5f5", "#000000", "#555555", "#ff6b00", "#008000", "#999999",
                "#cc0000", "#ff8800", "#333333")


class ThemeManager:
    def __init__(self) -> None:
        self.dark = False
        self._listeners: list = []

    @property
    def palette(self) -> Palette:
        return DARK if self.dark else LIGHT

    def toggle(self) -> None:
        self.dark = not self.dark
        for listener in list(self._listeners):
            listener(self.dark)

    def add_listener(self, fn) -> None:
        self._listeners.append(fn)

    def status_color(self, status: str) -> tuple[str, bool]:
        p = self.palette
        return {"Queued": (p.queued, False), "In Progress": (p.in_progress, True),
                "Processed": (p.processed, False)}.get(status, (p.other, False))

    def toggle_label(self) -> str:
        return "☀ Light Mode" if self.dark else "\U0001F319 Dark Mode"
