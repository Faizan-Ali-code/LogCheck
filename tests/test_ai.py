"""The optional AI triage must never send a detected value (or other values in the line) off the machine."""

import json

import pytest

from logcheck.ai.redaction import redact_evidence, shape
from logcheck.ai.triage import NOT_SENT, UNAVAILABLE, Triage
from logcheck.engine import FileScanner

from conftest import make_settings

SECRETS = {
    "password": ("Hunter2Secret!", "2026-11-12 INFO login user=alice password=Hunter2Secret! from 10.1.2.3"),
    "us-ssn": ("219-09-9998", "INFO customer ssn: 219-09-9998 verified"),
    "connection-string": ("S3cr3tPw", "ERROR connect postgresql://app:S3cr3tPw@db01:5432/cards failed"),
    "crypto-key": ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                   "WARN aes_key=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 loaded"),
    "api-token": ("9f8e7d6c5b4a39281706f5e4d3c2b1a0Zx", "INFO partner api_key=9f8e7d6c5b4a39281706f5e4d3c2b1a0Zx"),
}


def test_shape_keeps_format_not_content():
    assert shape("Hunter2!") == "Aaaaaa9*"
    assert shape("123-45-6789") == "999-99-9999"
    assert shape("") == ""


def test_redact_evidence_masks_match_and_assigned_values():
    text = redact_evidence("Hunter2Secret!", "user=alice password=Hunter2Secret! pin: 4321")
    assert "Hunter2Secret" not in text and "alice" not in text and "4321" not in text
    assert "password=" in text and "pin:" in text  # key names stay, so the model can still classify


def _findings(ai=True):
    scanner = FileScanner(make_settings(ai_input=ai, include_values=False))
    out = {}
    for detector, (_value, line) in SECRETS.items():
        [finding] = [f for f in scanner.scan_line("x", 1, line) if f.detector == detector]
        out[detector] = finding
    return out


def test_ai_input_never_contains_values():
    for detector, finding in _findings().items():
        value = SECRETS[detector][0]
        for fragment in (value, value[:6], value[-6:]):
            assert fragment not in finding.ai_input, f"{detector}: '{fragment}' would leave the machine"


def test_card_findings_are_never_prepared_for_ai():
    scanner = FileScanner(make_settings(ai_input=True))
    [finding] = scanner.scan_line("x", 1, "card=4539578763621486")
    assert finding.ai_input is None


def test_triage_requests_are_masked_cached_and_bounded():
    sent = []

    def fake_post(url, headers, body, timeout):
        sent.append(body.decode("utf-8"))
        reply = {"choices": [{"message": {"content": json.dumps({"verdict": "likely_real", "reason": "x"})}}]}
        return 200, json.dumps(reply)

    findings = list(_findings().values())
    duplicate = _findings()["password"]  # same masked input as an earlier finding: no second request
    stats = Triage("m", max_calls=4, endpoint="https://example.invalid", api_key="k", post=fake_post).run(
        findings + [duplicate])
    assert stats.sent == 4 and stats.cached == 1 and stats.skipped == 1
    assert [f.ai_verdict for f in findings].count("likely_real") == 4 and NOT_SENT in [f.ai_verdict for f in findings]
    for body, (value, _line) in zip(sent, SECRETS.values()):
        assert value not in body


def test_triage_stops_after_repeated_failures():
    calls = []

    def failing(url, headers, body, timeout):
        calls.append(1)
        return 0, "connection refused"

    findings = list(_findings().values())
    stats = Triage("m", 50, "https://example.invalid", api_key="k", post=failing, max_failures=2).run(findings)
    assert len(calls) == 2 and stats.failed == 2
    assert [f.ai_verdict for f in findings] == [UNAVAILABLE, UNAVAILABLE, NOT_SENT, NOT_SENT, NOT_SENT]


def test_triage_needs_a_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        Triage("m", 1, "https://example.invalid").run([])
