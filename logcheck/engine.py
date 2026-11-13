"""Runs the detectors over files: one streaming pass per file, files in parallel processes."""

from __future__ import annotations

import concurrent.futures as cf
import datetime as _dt
from concurrent.futures.process import BrokenProcessPool
import gzip
import os
import re
import secrets
import time
import zlib
from dataclasses import dataclass, field
from typing import Callable

from logcheck import __version__
from logcheck.ai.redaction import redact_evidence, shape
from logcheck.cards import BinList, PanHashList, pan_hash_key
from logcheck.collect import collect
from logcheck.config import CONFIDENCE_ORDER, Config
from logcheck.detectors import PRIORITY, Detector, all_detectors, select
from logcheck.masking import Fingerprinter, evidence_window, mask_spans
from logcheck.reader import FileState, NotText, TextStream, iter_lines

_HAS_DIGIT = re.compile(r"[0-9]")
_RANK = {d: i for i, d in enumerate(PRIORITY)}
# Card data is never sent to the AI service, masked or not (PCI DSS scope stays on this machine).
AI_EXCLUDED = frozenset({"card-number", "card-track-data", "card-security-code", "card-pin", "card-expiry"})


@dataclass
class Finding:
    detector: str
    title: str
    severity: str
    confidence: str
    file: str
    line: int
    column: int
    masked_value: str
    fingerprint: str
    evidence: str
    notes: str
    value: str | None = None  # the raw value, only with include_values
    ai_input: str | None = None  # redacted text for AI triage, only when it is enabled
    ai_verdict: str = ""


@dataclass
class FileResult:
    path: str
    status: str = "scanned"  # scanned | skipped | error
    reason: str = ""
    encoding: str = ""
    size: int = 0
    lines: int = 0
    replaced_chars: int = 0
    changed_during_scan: bool = False
    seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)


@dataclass
class ScanResult:
    started: str
    finished: str
    seconds: float
    inputs: list[str]
    missing: list[str]
    detectors: list[str]
    files: list[FileResult]
    notes: list[str] = field(default_factory=list)
    tool: str = f"LogCheck {__version__}"

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.files for f in r.findings]


@dataclass(frozen=True)
class WorkerSettings:
    """Everything a worker process needs; picklable, so it can be sent to a process pool."""
    enable: tuple[str, ...]
    disable: tuple[str, ...]
    bin_list: str
    pan_hashes: str
    pan_key: bytes | None
    fingerprint_key: bytes
    context_chars: int
    min_confidence: str
    include_values: bool
    ai_input: bool


class FileScanner:
    def __init__(self, ws: WorkerSettings) -> None:
        bins = BinList.load(ws.bin_list) if ws.bin_list else None
        hashes = PanHashList.load(ws.pan_hashes, ws.pan_key) if ws.pan_hashes else None
        self.detectors = select(all_detectors(bins, hashes), list(ws.enable), list(ws.disable))
        self.ws = ws
        self.fingerprint = Fingerprinter(ws.fingerprint_key)
        self.min_rank = CONFIDENCE_ORDER[ws.min_confidence]
        # All detectors' keywords in one pass per line. The lookahead finds overlapping occurrences; a keyword
        # also counts for every detector whose keyword it contains ("password" contains "pass").
        words = sorted({t for d in self.detectors for t in d.triggers}, key=len, reverse=True)
        self._keywords = re.compile("(?=(" + "|".join(map(re.escape, words)) + "))") if words else None
        self._wanted_by = {w: {d.id for d in self.detectors if any(t in w for t in d.triggers)} for w in words}

    def _wanted(self, line: str, lower: str) -> list[Detector]:
        present: set[str] = set()
        if self._keywords is not None:
            for m in self._keywords.finditer(lower):
                present |= self._wanted_by[m.group(1)]
        has_digit = _HAS_DIGIT.search(line) is not None
        return [d for d in self.detectors
                if (not d.triggers or d.id in present) and (has_digit or not d.needs_digit)
                and (d.hint is None or d.hint.search(line) is not None)]

    def scan_line(self, path: str, lineno: int, line: str) -> list[Finding]:
        hits: list[tuple[int, int, int, Detector, object]] = []
        for det in self._wanted(line, line.lower()):
            for h in det.find(line):
                if CONFIDENCE_ORDER[h.confidence] >= self.min_rank:
                    hits.append((_RANK[det.id], h.start - h.end, h.start, det, h))
        if not hits:
            return []
        hits.sort(key=lambda t: t[:3])
        kept: list[tuple[Detector, object]] = []
        for _rank, _neg_len, _start, det, h in hits:  # most specific detector wins an overlap, then the longer hit
            if not any(h.start < k.end and k.start < h.end for _d, k in kept):
                kept.append((det, h))
        kept.sort(key=lambda t: t[1].start)
        masked_line = mask_spans(line, [(h.start, h.end, det.masked(h)) for det, h in kept])
        ctx = self.ws.context_chars
        out = []
        for det, h in kept:
            identity = re.sub(r"[ -]", "", h.value) if det.id == "card-number" else h.value
            ai_input = None
            if self.ws.ai_input and det.id not in AI_EXCLUDED:
                window = evidence_window(line, h.start, h.end, ctx)
                ai_input = f"value format: {shape(h.value)}\nlog text: {redact_evidence(h.value, window)}"
            out.append(Finding(
                detector=det.id, title=det.title, severity=det.severity, confidence=h.confidence, file=path,
                line=lineno, column=h.start + 1, masked_value=det.masked(h), fingerprint=self.fingerprint(identity),
                evidence=evidence_window(masked_line, h.start, h.end, ctx), notes="; ".join(h.notes),
                value=h.value if self.ws.include_values else None, ai_input=ai_input))
        return out

    def scan_file(self, path: str) -> FileResult:
        result = FileResult(path)
        started = time.perf_counter()
        try:
            before = FileState.of(path)
        except OSError as exc:
            return FileResult(path, "error", f"cannot read: {exc.strerror or exc}")
        result.size = before.size
        stream = TextStream("")
        try:
            for lineno, line in iter_lines(path, stream):
                result.lines = lineno
                result.findings.extend(self.scan_line(path, lineno, line))
        except NotText as exc:
            result.status, result.reason = "skipped", f"not a text file ({exc})"
        except (OSError, EOFError, zlib.error, gzip.BadGzipFile) as exc:
            result.status = "error"
            result.reason = f"stopped at line {result.lines}: {exc}"
        result.encoding, result.replaced_chars = stream.encoding, stream.replaced
        try:
            after = FileState.of(path)
            result.changed_during_scan = after != before
        except OSError:
            result.changed_during_scan = True
        result.seconds = round(time.perf_counter() - started, 3)
        return result


_worker: FileScanner | None = None


def _init_worker(ws: WorkerSettings) -> None:
    global _worker
    _worker = FileScanner(ws)


def _scan_in_worker(path: str) -> FileResult:
    assert _worker is not None
    return _worker.scan_file(path)


def worker_settings(cfg: Config) -> WorkerSettings:
    return WorkerSettings(
        enable=tuple(cfg.enable), disable=tuple(cfg.disable), bin_list=cfg.bin_list, pan_hashes=cfg.pan_hashes,
        pan_key=pan_hash_key() if cfg.pan_hashes else None,
        fingerprint_key=(os.environ.get("LOGCHECK_FINGERPRINT_KEY", "").encode("utf-8") or secrets.token_bytes(32)),
        context_chars=cfg.context_chars, min_confidence=cfg.min_confidence, include_values=cfg.include_values,
        ai_input=cfg.ai_enabled)


def run_scan(inputs: list[str], cfg: Config, skip_dirs: list[str] | None = None,
             progress: Callable[[FileResult, int, int], None] | None = None) -> ScanResult:
    started, t0 = _dt.datetime.now().astimezone(), time.perf_counter()
    ws = worker_settings(cfg)
    local = FileScanner(ws)  # also validates detector ids and loads the card lists once, before any work
    found = collect(inputs, cfg.include, cfg.exclude, skip_dirs)
    workers = cfg.workers or os.cpu_count() or 1
    results: list[FileResult] = []
    notes: list[str] = []
    total = len(found.files)
    if workers == 1 or total <= 1:
        for path in found.files:
            results.append(local.scan_file(path))
            if progress:
                progress(results[-1], len(results), total)
    else:
        try:
            with cf.ProcessPoolExecutor(max_workers=min(workers, total), initializer=_init_worker,
                                        initargs=(ws,)) as pool:
                futures = [pool.submit(_scan_in_worker, p) for p in found.files]
                for fut in cf.as_completed(futures):
                    results.append(fut.result())
                    if progress:
                        progress(results[-1], len(results), total)
        except (OSError, BrokenProcessPool) as exc:  # e.g. process creation blocked by policy
            notes.append(f"parallel scanning unavailable ({exc}); the remaining files were scanned in one process")
            done = {r.path for r in results}
            for path in found.files:
                if path not in done:
                    results.append(local.scan_file(path))
                    if progress:
                        progress(results[-1], len(results), total)
    results.sort(key=lambda r: r.path)
    finished = _dt.datetime.now().astimezone()
    return ScanResult(started.isoformat(timespec="seconds"), finished.isoformat(timespec="seconds"),
                      round(time.perf_counter() - t0, 2), list(inputs), found.missing,
                      [d.id for d in local.detectors], results, notes)
