"""Masking of detected values before anything is sent to an external AI service.

The AI step only has to judge whether a finding is real, for example "is this a
password being logged, or the word 'password' in a help text?". That judgement
depends on the key names, the format and the surrounding words, not on the
secret itself. So the value is replaced by its *shape* (letters, digits and
separators, same length) before the request is built, and any other value-like
text in the evidence window is masked the same way. Nothing here touches the
local reports, which keep the real evidence.

    shape("Hunter2!")          -> "Aaaaaa9*"
    shape("123-45-6789")       -> "999-99-9999"
"""

from __future__ import annotations

import re

# Separators that describe a format rather than carry secret content.
_KEPT = frozenset(" \t-_.:/@+")

# key=value, key: value, key => value (the value is masked, the key is kept).
_ASSIGNED = re.compile(r"(?P<key>[A-Za-z_][\w.\-]{0,40}\s*(?:=>|=|:)\s*)(?P<quote>[\"']?)(?P<value>[^\s\"',;&<>]{2,})")
# Any remaining run of 4+ digits (card numbers, SSNs, account numbers, PINs).
_DIGITS = re.compile(r"\d{4,}")
# Long tokens that mix letters and digits or use base64/hex alphabets (keys, session ids, JWT parts).
_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")  # '=' only as base64 padding, so "key=" is never swallowed


def shape(value: str | None) -> str:
    """The value's format with its content removed: digits -> 9, letters -> a/A, other symbols -> *."""
    if not value:
        return ""
    out = []
    for ch in value:
        if ch.isdigit():
            out.append("9")
        elif ch.isalpha():
            out.append("A" if ch.isupper() else "a")
        elif ch in _KEPT:
            out.append(ch)
        else:
            out.append("*")
    return "".join(out)


def _looks_like_secret_token(token: str) -> bool:
    has_digit = any(c.isdigit() for c in token)
    has_alpha = any(c.isalpha() for c in token)
    return (has_digit and has_alpha) or any(c in "+/=" for c in token)


def redact_evidence(match: str | None, evidence: str | None) -> str:
    """Evidence text safe to send off-machine: the match and every value-like substring are shaped."""
    text = evidence or ""
    if match:
        text = re.sub(re.escape(match), lambda m: shape(m.group(0)), text, flags=re.IGNORECASE)
    text = _ASSIGNED.sub(lambda m: m.group("key") + m.group("quote") + shape(m.group("value")), text)
    text = _DIGITS.sub(lambda m: "9" * len(m.group(0)), text)
    return _TOKEN.sub(lambda m: shape(m.group(0)) if _looks_like_secret_token(m.group(0)) else m.group(0), text)
