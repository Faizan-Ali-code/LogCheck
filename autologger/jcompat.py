"""Helpers that reproduce Java library semantics the original tool relied on.

The Java tool's observable behaviour (report contents, test-case order, how
Excel cells are read) depends on details such as String.trim(), HashMap
iteration order and Double.toString(). These functions copy those details.
"""

from __future__ import annotations

import math
import re
from decimal import Decimal
from typing import Iterable

_INT_RE = re.compile(r"[+-]?\d+")  # Integer.parseInt accepts any Unicode decimal digit
_HEX_INT_RE = re.compile(r"[+-]?[0-9a-fA-F]+")
INT_MIN, INT_MAX = -(2 ** 31), 2 ** 31 - 1


def java_trim(s: str) -> str:
    """String.trim(): strip chars <= U+0020 only (NBSP and other Unicode spaces are kept)."""
    start, end = 0, len(s)
    while start < end and s[start] <= " ":
        start += 1
    while end > start and s[end - 1] <= " ":
        end -= 1
    return s[start:end]


def java_split(pattern: re.Pattern[str], s: str) -> list[str]:
    """String.split(regex): like re.split but trailing empty strings are removed."""
    if s == "":
        return [""]
    parts = pattern.split(s)
    while parts and parts[-1] == "":
        parts.pop()
    return parts


def java_parse_int(s: str | None) -> int:
    """Integer.parseInt(s): raises ValueError like NumberFormatException."""
    if s is None or not _INT_RE.fullmatch(s):
        raise ValueError(f"For input string: \"{s}\"")
    value = int(s)
    if not INT_MIN <= value <= INT_MAX:
        raise ValueError(f"For input string: \"{s}\"")
    return value


def java_parse_hex_byte(s: str) -> int:
    """(byte) Integer.parseInt(s, 16) as used by the Java hex decoders."""
    if not _HEX_INT_RE.fullmatch(s):
        raise ValueError(f"For input string: \"{s}\" under radix 16")
    return int(s, 16) & 0xFF


def java_double_to_string(d: float) -> str:
    """Double.toString(d) (shortest digits, Java's plain/scientific switch at 1e-3 and 1e7)."""
    if math.isnan(d):
        return "NaN"
    if math.isinf(d):
        return "Infinity" if d > 0 else "-Infinity"
    if d == 0:
        return "-0.0" if math.copysign(1.0, d) < 0 else "0.0"
    sign = "-" if d < 0 else ""
    a = abs(d)
    _, digit_tuple, exponent = Decimal(repr(a)).as_tuple()
    digits = "".join(str(x) for x in digit_tuple).rstrip("0") or "0"
    # value = 0.<digits> * 10^point
    point = exponent + len(digit_tuple)
    if 1e-3 <= a < 1e7:
        if point <= 0:
            body = "0." + "0" * (-point) + digits
        elif point >= len(digits):
            body = digits + "0" * (point - len(digits)) + ".0"
        else:
            body = digits[:point] + "." + digits[point:]
    else:
        body = f"{digits[0]}.{digits[1:] or '0'}E{point - 1}"
    return sign + body


def java_string_hash(s: str) -> int:
    """String.hashCode() over UTF-16 code units, as a signed 32-bit int."""
    h = 0
    raw = s.encode("utf-16-le", "surrogatepass")
    for i in range(0, len(raw), 2):
        h = (31 * h + (raw[i] | (raw[i + 1] << 8))) & 0xFFFFFFFF
    return h - (1 << 32) if h >= (1 << 31) else h


def java_hashmap_order(keys: Iterable[str]) -> list[str]:
    """Iteration order of `new HashMap<>()` after put()-ing keys in the given order.

    Order = bucket index in the final table, then insertion order inside a bucket
    (no treeified bins at these sizes). Duplicate keys keep their first position.
    """
    unique = list(dict.fromkeys(keys))
    capacity = 16
    while len(unique) > capacity * 0.75:
        capacity *= 2

    def bucket(key: str) -> int:
        h = java_string_hash(key) & 0xFFFFFFFF
        return (h ^ (h >> 16)) & (capacity - 1)

    indexed = sorted(range(len(unique)), key=lambda i: (bucket(unique[i]), i))
    return [unique[i] for i in indexed]


def java_pattern_quote(s: str) -> str:
    r"""Pattern.quote(s): \Q...\E, splitting any embedded \E."""
    if "\\E" not in s:
        return "\\Q" + s + "\\E"
    return "\\Q" + s.replace("\\E", "\\E\\\\E\\Q") + "\\E"


def utf16_len(s: str) -> int:
    """String.length() (UTF-16 code units)."""
    return len(s) + sum(1 for ch in s if ord(ch) > 0xFFFF)
