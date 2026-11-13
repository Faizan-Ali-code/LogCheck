"""Read-only, streaming access to log files.

Rules this module follows, because an audit tool must not damage what it audits:
- files are opened read-only and never renamed, split, truncated or rewritten;
- they are streamed line by line, so file size does not matter and no finding is lost at a chunk edge;
- bytes that do not decode are replaced (U+FFFD) and counted, never a reason to skip the file;
- anything that cannot be read is reported, not silently ignored.
"""

from __future__ import annotations

import codecs
import gzip
import io
import os
from dataclasses import dataclass
from typing import BinaryIO, Iterator

SAMPLE_BYTES = 64 * 1024
_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32-le"), (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be"),
)


class NotText(Exception):
    """The file looks binary, so it is reported as skipped instead of being scanned."""


@dataclass
class FileState:
    size: int
    mtime_ns: int

    @classmethod
    def of(cls, path: str) -> FileState:
        st = os.stat(path)
        return cls(st.st_size, st.st_mtime_ns)


def _open_binary(path: str) -> BinaryIO:
    if path.lower().endswith(".gz"):
        return gzip.open(path, "rb")  # read-only
    return open(path, "rb")  # noqa: SIM115 - closed by the caller


def detect_encoding(sample: bytes) -> tuple[str, int]:
    """(encoding, BOM length).

    A BOM decides. Otherwise the sample is decoded as UTF-8 (an incomplete character at its very end is
    allowed, because the sample can stop in the middle of one): UTF-8 is chosen when it decodes cleanly or
    when correctly encoded non-ASCII characters outnumber the broken byte sequences (a UTF-8 log with a few
    damaged bytes); otherwise the file is read as cp1252, the usual single-byte Windows encoding.
    """
    for bom, name in _BOMS:
        if sample.startswith(bom):
            return name, len(bom)
    if b"\x00" in sample[:8192]:
        raise NotText("contains NUL bytes")
    text = codecs.getincrementaldecoder("utf-8")(errors="replace").decode(sample, final=False)
    broken = text.count("�")
    if broken == 0:
        return "utf-8", 0
    valid_non_ascii = sum(1 for ch in text if ord(ch) > 127 and ch != "�")
    return ("utf-8", 0) if valid_non_ascii > broken else ("cp1252", 0)


@dataclass
class TextStream:
    encoding: str
    replaced: int = 0  # undecodable byte sequences replaced with U+FFFD


def iter_lines(path: str, stream: TextStream | None = None) -> Iterator[tuple[int, str]]:
    """Yield (line number, line without its newline). Fills `stream` with the encoding used."""
    with _open_binary(path) as raw:
        sample = raw.read(SAMPLE_BYTES)
        encoding, bom = detect_encoding(sample)
        if stream is not None:
            stream.encoding = encoding
        raw.seek(bom)
        codec = "utf-8" if encoding == "utf-8-sig" else encoding
        text = io.TextIOWrapper(raw, encoding=codec, errors="replace", newline=None)
        for number, line in enumerate(text, start=1):
            if line.endswith("\n"):
                line = line[:-1]
            if stream is not None and "�" in line:
                stream.replaced += line.count("�")
            yield number, line
