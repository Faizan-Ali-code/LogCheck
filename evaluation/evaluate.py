"""Precision and recall of every detector on the generated corpus, compared with a naive baseline.

    python -m evaluation.evaluate            # Markdown tables on standard output
    python -m evaluation.evaluate --json     # the same numbers as JSON

A finding counts as a true positive when its line carries a label for the same detector. Every other
finding is a false positive; every label without a finding is a false negative.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from evaluation import baseline
from evaluation.corpus import Line, generate
from logcheck.detectors import PRIORITY
from logcheck.engine import FileScanner, WorkerSettings

SEED = 2026


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    def row(self) -> dict:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn,
                "precision": round(self.precision, 3), "recall": round(self.recall, 3)}


@dataclass
class Evaluation:
    lines: int
    labels: int
    per_detector: dict[str, Score]
    overall: Score
    false_positives_by_trap: dict[str, int] = field(default_factory=dict)
    baseline: dict[str, Score] = field(default_factory=dict)
    baseline_fp_by_trap: dict[str, int] = field(default_factory=dict)


def scanner() -> FileScanner:
    ws = WorkerSettings(enable=(), disable=(), bin_list="", pan_hashes="", pan_key=None, fingerprint_key=b"eval",
                        context_chars=40, min_confidence="low", include_values=False, ai_input=False)
    return FileScanner(ws)


def _score(corpus: list[Line], found_per_line: list[set[str]], detectors) -> tuple[dict[str, Score], Counter]:
    scores = {d: Score() for d in detectors}
    traps: Counter = Counter()
    for line, found in zip(corpus, found_per_line):
        for det in found:
            if det not in scores:
                continue
            if det == line.detector:
                scores[det].tp += 1
            else:
                scores[det].fp += 1
                traps[line.trap or ("other labelled line" if line.detector else "ordinary log line")] += 1
        if line.detector in scores and line.detector not in found:
            scores[line.detector].fn += 1
    return scores, traps


def evaluate(seed: int = SEED, noise_lines: int = 6000) -> Evaluation:
    corpus = generate(seed, noise_lines)
    s = scanner()
    found = [{f.detector for f in s.scan_line("corpus", i, line.text)} for i, line in enumerate(corpus, 1)]
    per, traps = _score(corpus, found, PRIORITY)
    overall = Score(sum(x.tp for x in per.values()), sum(x.fp for x in per.values()), sum(x.fn for x in per.values()))
    base_found = [set(baseline.scan_line(line.text)) for line in corpus]
    base, base_traps = _score(corpus, base_found, baseline.DETECTORS)
    return Evaluation(len(corpus), sum(line.detector is not None for line in corpus), per, overall,
                      dict(traps.most_common()), base, dict(base_traps.most_common()))


def to_markdown(ev: Evaluation) -> str:
    out = [f"Corpus: {ev.lines:,} lines, {ev.labels} labelled values, seed {SEED}.", "",
           "| Detector | TP | FP | FN | Precision | Recall |", "|---|---:|---:|---:|---:|---:|"]
    for det, sc in ev.per_detector.items():
        out.append(f"| {det} | {sc.tp} | {sc.fp} | {sc.fn} | {sc.precision:.3f} | {sc.recall:.3f} |")
    o = ev.overall
    out.append(f"| **all** | **{o.tp}** | **{o.fp}** | **{o.fn}** | **{o.precision:.3f}** | **{o.recall:.3f}** |")
    out += ["", "False positives by cause:", ""]
    out += [f"- {trap}: {n}" for trap, n in ev.false_positives_by_trap.items()] or ["- none"]
    out += ["", "Naive baseline on the same corpus (see evaluation/baseline.py):", "",
            "| Detector | Baseline precision | Baseline recall | LogCheck precision | LogCheck recall |",
            "|---|---:|---:|---:|---:|"]
    for det, sc in ev.baseline.items():
        lc = ev.per_detector[det]
        out.append(f"| {det} | {sc.precision:.3f} | {sc.recall:.3f} | {lc.precision:.3f} | {lc.recall:.3f} |")
    out += ["", "Baseline false positives by cause:", ""]
    out += [f"- {trap}: {n}" for trap, n in ev.baseline_fp_by_trap.items()]
    return "\n".join(out)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--json", action="store_true")
    p.add_argument("--seed", type=int, default=SEED)
    args = p.parse_args()
    ev = evaluate(args.seed)
    if args.json:
        doc = {"lines": ev.lines, "labels": ev.labels, "overall": ev.overall.row(),
               "per_detector": {k: v.row() for k, v in ev.per_detector.items()},
               "false_positives_by_trap": ev.false_positives_by_trap,
               "baseline": {k: v.row() for k, v in ev.baseline.items()},
               "baseline_false_positives_by_trap": ev.baseline_fp_by_trap}
        print(json.dumps(doc, indent=2))
    else:
        print(to_markdown(ev))


if __name__ == "__main__":
    main()
