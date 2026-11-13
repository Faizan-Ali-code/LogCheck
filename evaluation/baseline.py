"""A deliberately simple scanner, used only as a point of comparison in the evaluation.

It represents the common first attempt at log scanning: contiguous digit runs plus Luhn for cards, a
9-digit or dashed number within 80 characters of a keyword *substring* for SSNs, and "key = anything"
for passwords and tokens. The evaluation shows what the validation in LogCheck's detectors changes.
"""

from __future__ import annotations

import re

from logcheck.checks import luhn_valid

_CARD = re.compile(r"\d{13,19}")
_SSN = re.compile(r"\d{3}-\d{2}-\d{4}|\d{9}")
_SSN_WORDS = ("ssn", "social", "tin", "tax")
_PASSWORD = re.compile(r"(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*\"?([^\s\",;]+)")
_TOKEN = re.compile(r"(?i)(?:api_key|apikey|access_token|token)\s*[=:]\s*\"?([^\s\",;]+)")

DETECTORS = ("card-number", "us-ssn", "password", "api-token")


def scan_line(line: str) -> list[str]:
    found = []
    if any(luhn_valid(m.group(0)) for m in _CARD.finditer(line)):
        found.append("card-number")
    lower = line.lower()
    for m in _SSN.finditer(line):
        window = lower[max(0, m.start() - 80):m.end() + 80]
        if any(w in window for w in _SSN_WORDS):
            found.append("us-ssn")
            break
    if _PASSWORD.search(line):
        found.append("password")
    if _TOKEN.search(line):
        found.append("api-token")
    return found
