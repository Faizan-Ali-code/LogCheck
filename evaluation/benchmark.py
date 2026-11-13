"""Throughput, and the cost of a card-number BIN check as the BIN list grows.

    python -m evaluation.benchmark

1. Whole-scanner throughput on a generated log (single process, all detectors).
2. BIN-prefixed card matching done two ways over the same text:
   - one regular-expression pass per BIN and card length (cost grows with the BIN list), and
   - LogCheck's approach: one pass for stand-alone digit runs, then a set lookup per candidate.
"""

from __future__ import annotations

import os
import random
import re
import tempfile
import time

from evaluation.corpus import generate
from evaluation.evaluate import scanner
from logcheck.cards import BinList
from logcheck.checks import luhn_valid
from logcheck.detectors import card_candidates


def _corpus_text(target_bytes: int) -> str:
    lines = [line.text for line in generate(2026, 6000)]
    out, size, i = [], 0, 0
    while size < target_bytes:
        line = lines[i % len(lines)]
        out.append(line)
        size += len(line) + 1
        i += 1
    return "\n".join(out) + "\n"


def throughput(mb: int = 20) -> dict:
    text = _corpus_text(mb * 1_048_576)
    fd, path = tempfile.mkstemp(suffix=".log")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    try:
        s = scanner()
        t0 = time.perf_counter()
        result = s.scan_file(path)
        seconds = time.perf_counter() - t0
    finally:
        os.remove(path)
    return {"megabytes": round(result.size / 1_048_576, 1), "lines": result.lines, "findings": len(result.findings),
            "seconds": round(seconds, 2), "mb_per_second": round(result.size / 1_048_576 / seconds, 1)}


def bin_lookup(bin_counts=(10, 100, 1000), mb: int = 1) -> list[dict]:
    text = _corpus_text(mb * 1_048_576)
    lines = text.splitlines()
    rnd = random.Random(7)
    rows = []
    for n in bin_counts:
        bins = sorted({str(rnd.randint(400000, 559999)) for _ in range(n)})
        t0 = time.perf_counter()
        per_bin = 0
        for b in bins:  # one pass per BIN and length
            for length in range(13, 20):
                pattern = re.compile(rf"(?<![0-9]){b}[0-9]{{{length - len(b)}}}(?![0-9])")
                per_bin += sum(luhn_valid(m.group(0)) for m in pattern.finditer(text))
        t_per_bin = time.perf_counter() - t0
        t0 = time.perf_counter()
        bl, single = BinList(bins), 0
        for line in lines:  # one pass, then a set lookup
            for _s, _e, digits in card_candidates(line):
                if luhn_valid(digits) and bl.match(digits):
                    single += 1
        t_single = time.perf_counter() - t0
        rows.append({"bins": len(bins), "regex_passes": len(bins) * 7, "per_bin_seconds": round(t_per_bin, 2),
                     "single_pass_seconds": round(t_single, 2), "per_bin_matches": per_bin, "single_pass_matches": single})
    return rows


def main() -> None:
    t = throughput()
    print(f"Throughput: {t['megabytes']} MB, {t['lines']:,} lines, {t['findings']:,} findings in {t['seconds']} s "
          f"= {t['mb_per_second']} MB/s (one process, all detectors)\n")
    print("| BINs | Regex passes | One pass per BIN and length | One pass + set lookup |")
    print("|---:|---:|---:|---:|")
    for r in bin_lookup():
        print(f"| {r['bins']} | {r['regex_passes']} | {r['per_bin_seconds']} s | {r['single_pass_seconds']} s |")


if __name__ == "__main__":
    main()
