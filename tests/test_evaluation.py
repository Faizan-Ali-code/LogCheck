"""The measured results in docs/EVALUATION.md, kept as a regression check (review item L2)."""

from evaluation.corpus import generate
from evaluation.evaluate import evaluate


def test_corpus_is_reproducible():
    assert [line.text for line in generate(7, 200)] == [line.text for line in generate(7, 200)]


def test_detectors_on_the_corpus():
    ev = evaluate()
    assert ev.labels >= 450
    assert ev.overall.recall >= 0.98 and ev.overall.precision >= 0.98
    for det, score in ev.per_detector.items():
        assert score.recall >= 0.95, det


def test_validation_beats_the_naive_baseline():
    ev = evaluate()
    for det in ("card-number", "us-ssn", "password", "api-token"):
        assert ev.per_detector[det].precision > ev.baseline[det].precision, det
        assert ev.per_detector[det].recall >= ev.baseline[det].recall, det
    assert ev.baseline_fp_by_trap.get("9 digits after 'setting', 'routing', 'testing'", 0) > 0
    assert "9 digits after 'setting', 'routing', 'testing'" not in ev.false_positives_by_trap
