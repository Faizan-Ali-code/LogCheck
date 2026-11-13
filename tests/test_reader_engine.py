"""Reading files safely (review item L6) and the engine around the detectors."""

import gzip
import hashlib
import os

import pytest

from logcheck import engine
from logcheck.config import Config
from logcheck.engine import FileScanner, run_scan
from logcheck.reader import NotText, TextStream, detect_encoding, iter_lines

from conftest import make_settings

PAN = "4539578763621486"


def _write(path, data: bytes) -> str:
    with open(path, "wb") as fh:
        fh.write(data)
    return str(path)


def _digest(path) -> tuple[str, int, int]:
    st = os.stat(path)
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest(), st.st_size, st.st_mtime_ns


# ------------------------------------------------------------------------------------------ reader

def test_invalid_utf8_is_replaced_not_skipped(tmp_path):
    data = "café, naïve, résumé ok ".encode() + b"\xff broken byte card=" + PAN.encode() + b"\nnext\n"
    path = _write(tmp_path / "a.log", data)
    stream = TextStream("")
    lines = list(iter_lines(path, stream))
    assert stream.encoding == "utf-8" and stream.replaced == 1
    assert lines[0][1].startswith("café") and lines[1] == (2, "next")
    result = FileScanner(make_settings()).scan_file(path)
    assert result.status == "scanned" and [f.detector for f in result.findings] == ["card-number"]


def test_single_byte_encoding_is_detected(tmp_path):
    path = _write(tmp_path / "w.log", b"caf\xe9 \xff\xfe card=" + PAN.encode() + b"\n")
    stream = TextStream("")
    assert list(iter_lines(path, stream))[0][1].startswith("café")
    assert stream.encoding == "cp1252" and stream.replaced == 0


def test_multibyte_character_across_the_sample_boundary(tmp_path):
    data = b"x" * 65535 + "é".encode() + b"\npassword=Hunter2Secret!\n"
    path = _write(tmp_path / "big.log", data)
    assert detect_encoding(data[:65536])[0] == "utf-8"
    result = FileScanner(make_settings()).scan_file(path)
    assert result.replaced_chars == 0 and [f.detector for f in result.findings] == ["password"]


def test_cp1252_utf16_and_gzip(tmp_path):
    cp = _write(tmp_path / "cp.log", "café ssn=219-09-9998\r\n".encode("cp1252"))
    u16 = _write(tmp_path / "u16.log", "﻿ssn=219-09-9998\r\n".encode("utf-16-le"))
    gz = tmp_path / "old.log.gz"
    with gzip.open(gz, "wb") as fh:
        fh.write(b"ssn=219-09-9998\n")
    scanner = FileScanner(make_settings())
    for path, encoding in ((cp, "cp1252"), (u16, "utf-16-le"), (str(gz), "utf-8")):
        result = scanner.scan_file(path)
        assert result.encoding == encoding
        assert [f.value for f in result.findings] == ["219-09-9998"]


def test_binary_files_are_skipped_and_reported(tmp_path):
    path = _write(tmp_path / "img.log", b"\x89PNG\x00\x00\x00data")
    with pytest.raises(NotText):
        list(iter_lines(path))
    result = FileScanner(make_settings()).scan_file(path)
    assert result.status == "skipped" and "not a text file" in result.reason


def test_large_file_is_streamed_and_left_untouched(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    line = b"2026-11-13 10:15:32 INFO nothing to see here\n"
    path = _write(logs / "app.log", line * 200_000 + b"late card=" + PAN.encode() + b"\n")
    before = _digest(path)
    result = run_scan([str(logs)], Config(workers=1), skip_dirs=[str(tmp_path / "out")])
    assert [f.line for f in result.findings] == [200_001]
    assert _digest(path) == before  # same bytes, size and modification time
    assert os.listdir(logs) == ["app.log"]  # nothing renamed, split or added


# ------------------------------------------------------------------------------------------ engine

def test_overlaps_keep_the_most_specific_finding():
    scanner = FileScanner(make_settings())
    findings = scanner.scan_line("x", 1, f"swipe ;{PAN}=25121011234567890? and card={PAN}")
    assert [f.detector for f in findings] == ["card-track-data", "card-number"]


def test_reports_hold_masked_values_and_fingerprints():
    scanner = FileScanner(make_settings(include_values=False))
    a = scanner.scan_line("x", 1, f"card={PAN} password=Hunter2Secret!")
    b = scanner.scan_line("y", 7, "card=4539 5787 6362 1486")
    assert a[0].value is None and PAN not in a[0].evidence and "Hunter2Secret!" not in a[1].evidence
    assert a[0].masked_value == "453957******1486" and a[1].masked_value == "*" * 14
    assert a[0].fingerprint == b[0].fingerprint  # same card, different layout
    assert a[0].fingerprint != a[1].fingerprint


def test_min_confidence_and_detector_selection():
    low = FileScanner(make_settings())
    assert [f.confidence for f in low.scan_line("x", 1, "test card 4111111111111111")] == ["low"]
    assert FileScanner(make_settings(min_confidence="medium")).scan_line("x", 1, "test card 4111111111111111") == []
    only = FileScanner(make_settings(enable=("password",)))
    assert [f.detector for f in only.scan_line("x", 1, f"card={PAN} password=Hunter2Secret!")] == ["password"]
    with pytest.raises(ValueError):
        FileScanner(make_settings(disable=("no-such-detector",)))


def test_collection_include_exclude_missing_and_report_folder(tmp_path):
    logs = tmp_path / "logs"
    (logs / "sub").mkdir(parents=True)
    (logs / "report").mkdir()
    for name in ("a.log", "b.txt", "c.bin", "sub/d.log", "sub/e.log.1", "report/findings.json"):
        (logs / name).write_text(f"card={PAN}\n")
    cfg = Config(workers=1, exclude=["*.txt"])
    result = run_scan([str(logs), str(tmp_path / "missing.log")], cfg, skip_dirs=[str(logs / "report")])
    assert sorted(os.path.relpath(r.path, logs) for r in result.files) == ["a.log", os.path.join("sub", "d.log"),
                                                                           os.path.join("sub", "e.log.1")]
    assert result.missing == [str(tmp_path / "missing.log")]


def test_parallel_scan_gives_the_same_findings(tmp_path):
    for i in range(4):
        (tmp_path / f"{i}.log").write_text(f"card={PAN}\npassword=Hunter2Secret!\nssn=219-09-9998\n")
    sequential = run_scan([str(tmp_path)], Config(workers=1))
    parallel = run_scan([str(tmp_path)], Config(workers=3))  # falls back to one process where spawning is blocked

    def key(r):
        return [(f.file, f.line, f.detector, f.fingerprint) for f in r.findings]
    assert len(sequential.findings) == 12
    # fingerprint keys are random per run, so compare everything else
    assert [k[:3] for k in key(sequential)] == [k[:3] for k in key(parallel)]
    # within one run every process uses the same key: one card, one fingerprint, across all four files
    assert len({f.fingerprint for f in parallel.findings if f.detector == "card-number"}) == 1


def test_process_pool_failure_falls_back_to_one_process(tmp_path, monkeypatch):
    for i in range(3):
        (tmp_path / f"{i}.log").write_text(f"card={PAN}\n")

    class Blocked:
        def __init__(self, *a, **k):
            raise PermissionError(5, "Access is denied")
    monkeypatch.setattr(engine.cf, "ProcessPoolExecutor", Blocked)
    result = run_scan([str(tmp_path)], Config(workers=4))
    assert len(result.findings) == 3 and "parallel scanning unavailable" in result.notes[0]


def test_files_changing_during_the_scan_are_flagged(tmp_path, monkeypatch):
    path = _write(tmp_path / "live.log", b"hello\n")
    states = iter([engine.FileState(6, 1), engine.FileState(12, 2)])
    monkeypatch.setattr(engine.FileState, "of", classmethod(lambda cls, p: next(states)))
    assert FileScanner(make_settings()).scan_file(path).changed_during_scan


def test_unreadable_file_is_an_error_not_a_crash(tmp_path):
    result = FileScanner(make_settings()).scan_file(str(tmp_path / "gone.log"))
    assert result.status == "error" and "cannot read" in result.reason
