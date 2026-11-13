"""How detected values appear in reports: masked to the same length, plus a keyed fingerprint.

Reports are themselves sensitive files that get emailed and attached to tickets, so by default they
never contain a detected value. Each value is replaced by a mask of the same length (so evidence
lines keep their layout) and identified by an HMAC fingerprint, which lets a reader see that two
findings are the same value without seeing the value.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

MASK = "*"


def _keep_ends(value: str, head: int, tail: int) -> str:
    if len(value) <= head + tail:
        return MASK * len(value)
    return value[:head] + MASK * (len(value) - head - tail) + value[len(value) - tail:]


def mask_digits_keep(value: str, head: int, tail: int) -> str:
    """Mask digits only (separators stay), keeping the first `head` and last `tail` digits."""
    total = sum(c.isdigit() for c in value)
    out, seen = [], 0
    for ch in value:
        if ch.isdigit():
            keep = seen < head or seen >= total - tail
            out.append(ch if keep else MASK)
            seen += 1
        else:
            out.append(ch)
    return "".join(out)


def mask_value(value: str, style: str) -> str:
    """Same-length mask.

    card    first 6 and last 4 digits (the most PCI DSS allows to be displayed)
    last4   last 4 digits (SSNs, account numbers)
    prefix  first 4 characters (keeps a key's type prefix such as 'AKIA' or 'ghp_')
    full    nothing kept (passwords, PINs, security codes)
    default first 2 and last 2 characters when the value is 12+ characters, otherwise nothing
    """
    if style == "card":
        return mask_digits_keep(value, 6, 4)
    if style == "last4":
        return mask_digits_keep(value, 0, 4)
    if style == "prefix":
        return _keep_ends(value, 4, 0) if len(value) > 8 else MASK * len(value)
    if style == "full":
        return MASK * len(value)
    return _keep_ends(value, 2, 2) if len(value) >= 12 else MASK * len(value)


def mask_spans(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Replace each (start, end, masked) span; masks have the span's length, so offsets stay valid."""
    chars = list(text)
    for start, end, masked in spans:
        chars[start:end] = list(masked[: end - start].ljust(end - start, MASK))
    return "".join(chars)


def evidence_window(text: str, start: int, end: int, context: int, limit: int = 400) -> str:
    """`context` characters either side of [start, end), with ellipses where text was cut."""
    lo, hi = max(0, start - context), min(len(text), end + context)
    snippet = text[lo:hi]
    if len(snippet) > limit:
        snippet = snippet[:limit]
        hi = lo + limit
    return ("..." if lo > 0 else "") + snippet + ("..." if hi < len(text) else "")


class Fingerprinter:
    """HMAC-SHA256 of a value, shortened. The key is random per run unless LOGCHECK_FINGERPRINT_KEY is set,
    in which case fingerprints are comparable across runs (keep that key as secret as the logs)."""

    def __init__(self, key: bytes | None = None) -> None:
        env = os.environ.get("LOGCHECK_FINGERPRINT_KEY")
        self.key = key or (env.encode("utf-8") if env else secrets.token_bytes(32))

    def __call__(self, value: str) -> str:
        return hmac.new(self.key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
