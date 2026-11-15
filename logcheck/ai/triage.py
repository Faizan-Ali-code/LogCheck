"""Experimental second opinion on findings from an OpenAI chat model.

What is sent per finding: the detector's name, the value's *format* (``Aaaaaa9*``) and the evidence
window with every value-like part replaced by its format (see redaction.py). Card findings are never
sent. The verdict is shown in a separate column and never removes or changes a finding.

Its effect on precision has not been measured, so it
is off by default and reported as experimental.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from logcheck.engine import Finding

VERDICTS = ("likely_real", "likely_false", "unsure")
UNAVAILABLE = "unavailable"
NOT_SENT = "not sent"

SYSTEM_PROMPT = (
    "You review findings from a tool that scans application logs for sensitive data. Every value has been "
    "masked: letters are a/A, digits are 9, other symbols are *. Judge from the key names, the format and the "
    "surrounding words whether the log line really contains the kind of data named by the detector. "
    'Answer with JSON only: {"verdict": "likely_real" | "likely_false" | "unsure", "reason": "<one sentence>"}.'
)

Post = Callable[[str, dict, bytes, float], tuple[int, str]]


def _urllib_post(url: str, headers: dict, body: bytes, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoint from config
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:  # DNS, TLS, timeout, connection refused
        return 0, str(exc)


def build_request(model: str, detector_title: str, ai_input: str) -> bytes:
    return json.dumps({
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Detector: {detector_title}\n{ai_input}"},
        ],
    }).encode("utf-8")


def parse_verdict(body: str) -> str:
    try:
        content = json.loads(body)["choices"][0]["message"]["content"]
        verdict = json.loads(content).get("verdict", "")
    except (KeyError, IndexError, TypeError, ValueError):
        return UNAVAILABLE
    return verdict if verdict in VERDICTS else UNAVAILABLE


@dataclass
class TriageStats:
    sent: int = 0
    cached: int = 0
    failed: int = 0
    skipped: int = 0
    verdicts: dict[str, int] = field(default_factory=dict)


class Triage:
    def __init__(self, model: str, max_calls: int, endpoint: str, api_key: str | None = None,
                 post: Post | None = None, timeout: float = 20.0, max_failures: int = 3) -> None:
        self.model, self.max_calls, self.endpoint, self.timeout = model, max_calls, endpoint, timeout
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.post = post or _urllib_post
        self.max_failures = max_failures

    def run(self, findings: list[Finding]) -> TriageStats:
        stats = TriageStats()
        if not self.api_key:
            raise RuntimeError("AI triage needs the OPENAI_API_KEY environment variable")
        cache: dict[tuple[str, str], str] = {}
        failures = 0
        for f in findings:
            if f.ai_input is None:
                f.ai_verdict = NOT_SENT
                continue
            key = (f.title, f.ai_input)  # identical masked input -> identical question, so one call
            if key in cache:
                f.ai_verdict = cache[key]
                stats.cached += 1
            elif stats.sent >= self.max_calls or failures >= self.max_failures:
                f.ai_verdict = NOT_SENT
                stats.skipped += 1
                continue
            else:
                status, body = self.post(self.endpoint, {"Authorization": f"Bearer {self.api_key}",
                                                         "Content-Type": "application/json"},
                                         build_request(self.model, f.title, f.ai_input), self.timeout)
                stats.sent += 1
                verdict = parse_verdict(body) if status == 200 else UNAVAILABLE
                failures = failures + 1 if verdict == UNAVAILABLE else 0
                stats.failed += verdict == UNAVAILABLE
                cache[key] = f.ai_verdict = verdict
            stats.verdicts[f.ai_verdict] = stats.verdicts.get(f.ai_verdict, 0) + 1
        return stats
