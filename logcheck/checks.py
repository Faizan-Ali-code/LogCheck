"""Validation used by the detectors: checksums, public numbering plans, entropy and placeholder values.

A pattern alone only finds *candidates*. These checks decide whether a candidate is plausible enough
to report, which is where most false positives are removed.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import json
import math
import re
from collections import Counter

# --------------------------------------------------------------------------------------------- cards


def luhn_valid(digits: str) -> bool:
    """ISO/IEC 7812-1 check digit (mod 10). Every payment card number satisfies it."""
    if not digits or not digits.isascii() or not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Issuer identification number ranges published by the card schemes:
# (brand, first prefix, last prefix, prefix length, valid card lengths).
_BRANDS: tuple[tuple[str, int, int, int, tuple[int, ...]], ...] = (
    ("Visa", 4, 4, 1, (13, 16, 19)),
    ("Mastercard", 51, 55, 2, (16,)),
    ("Mastercard", 2221, 2720, 4, (16,)),
    ("American Express", 34, 34, 2, (15,)),
    ("American Express", 37, 37, 2, (15,)),
    ("Discover", 6011, 6011, 4, (16, 17, 18, 19)),
    ("Discover", 644, 649, 3, (16, 17, 18, 19)),
    ("Discover", 65, 65, 2, (16, 17, 18, 19)),
    ("Diners Club", 300, 305, 3, (14, 15, 16, 17, 18, 19)),
    ("Diners Club", 36, 36, 2, (14, 15, 16, 17, 18, 19)),
    ("Diners Club", 38, 39, 2, (16, 17, 18, 19)),
    ("JCB", 3528, 3589, 4, (16, 17, 18, 19)),
    ("UnionPay", 62, 62, 2, (16, 17, 18, 19)),
    ("Maestro", 5018, 5018, 4, (13, 14, 15, 16, 17, 18, 19)),
    ("Maestro", 5020, 5020, 4, (13, 14, 15, 16, 17, 18, 19)),
    ("Maestro", 5038, 5038, 4, (13, 14, 15, 16, 17, 18, 19)),
    ("Maestro", 5893, 5893, 4, (13, 14, 15, 16, 17, 18, 19)),
    ("Maestro", 6304, 6304, 4, (13, 14, 15, 16, 17, 18, 19)),
    ("Maestro", 6759, 6763, 4, (13, 14, 15, 16, 17, 18, 19)),
    ("Mir", 2200, 2204, 4, (16, 17, 18, 19)),
)


def card_brand(digits: str) -> str | None:
    """The card scheme whose published range and length fit `digits`, or None."""
    for brand, low, high, plen, lengths in _BRANDS:
        if len(digits) in lengths and low <= int(digits[:plen]) <= high:
            return brand
    return None


# Numbers the schemes and payment gateways publish for testing; seeing them in a log is a
# finding about test data, not about a cardholder.
TEST_CARD_NUMBERS = frozenset({
    "4111111111111111", "4012888888881881", "4222222222222", "4242424242424242", "4000056655665556",
    "4005519200000004", "4009348888881881", "5555555555554444", "5105105105105100", "5200828282828210",
    "2223003122003222", "2223000048400011", "378282246310005", "371449635398431", "378734493671000",
    "6011111111111117", "6011000990139424", "30569309025904", "38520000023237", "3530111333300000",
    "3566002020360505", "6200000000000005", "6759649826438453",
})


def is_test_or_trivial_card(digits: str) -> bool:
    """Published test numbers, or numbers such as 4444...4 that pass the checksum by construction."""
    return digits in TEST_CARD_NUMBERS or len(set(digits[1:-1])) <= 1


# --------------------------------------------------------------------------------------------- identity


def ssn_valid(area: str, group: str, serial: str) -> bool:
    """US Social Security Number rules (SSA): area 001-899 except 666, group 01-99, serial 0001-9999."""
    a = int(area)
    return 0 < a < 900 and a != 666 and int(group) > 0 and int(serial) > 0


# The SSA has publicly invalidated these, and they are used as examples in documentation.
EXAMPLE_SSNS = frozenset({"078051120", "219099999", "123456789"})


def parse_date(text: str) -> _dt.date | None:
    """A calendar date in one of the formats logs commonly use, or None."""
    t = text.strip()
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%m-%d-%Y", "%d.%m.%Y", "%Y%m%d"):
        try:
            return _dt.datetime.strptime(t, fmt).date()
        except ValueError:
            continue
    return None


def plausible_birth_date(text: str, today: _dt.date | None = None) -> bool:
    d = parse_date(text)
    today = today or _dt.date.today()
    return d is not None and 1900 <= d.year and d <= today


# --------------------------------------------------------------------------------------------- banking

# IBAN length per country (ISO 13616 registry).
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
    "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
    "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21,
    "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28,
    "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27,
    "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24,
    "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "TL": 23, "TN": 24, "TR": 26,
    "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}


def iban_valid(iban: str) -> bool:
    """Country length and ISO 7064 mod 97-10 check."""
    s = iban.replace(" ", "").upper()
    if len(s) < 15 or IBAN_LENGTHS.get(s[:2]) != len(s) or not s.isalnum() or not s.isascii():
        return False
    rearranged = s[4:] + s[:4]
    number = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(number) % 97 == 1


def aba_routing_valid(digits: str) -> bool:
    """US ABA routing transit number: valid Federal Reserve prefix and weighted checksum 3-7-1."""
    if len(digits) != 9 or not digits.isdigit():
        return False
    prefix = int(digits[:2])
    if not (prefix <= 12 or 21 <= prefix <= 32 or 61 <= prefix <= 72 or prefix == 80):
        return False
    d = [int(c) for c in digits]
    return (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10 == 0


# --------------------------------------------------------------------------------------------- secrets


def shannon_entropy(value: str) -> float:
    """Bits per character. Random tokens score high; words and repeated characters score low."""
    if not value:
        return 0.0
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())


_PLACEHOLDER = re.compile(
    r"""^(?:
        [*xX#•.\-_?~]+                      # mask characters: ****, xxxx, ####
      | <[^>]*> | \[[^\]]*\] | \([^)]*\)         # <password>, [REDACTED], (hidden)
      | \$\{[^}]*\} | \$\([^)]*\) | (?-i:\$[A-Z_][A-Z0-9_]*) | %\(?\w*\)?[sd] | \{\d*\} | \{\{[^}]*\}\}  # templates
      | redacted | filtered | masked | hidden | protected | removed | omitted | sensitive
      | null | none | nil | undefined | empty | blank | n/?a | true | false
    )$""",
    re.IGNORECASE | re.VERBOSE,
)
_MASK_RUN = re.compile(r"[*•]{3,}|[xX#]{4,}")


def is_placeholder(value: str) -> bool:
    """True when a value is clearly not the real thing: masked, templated or empty."""
    v = value.strip().strip("\"'")
    return not v or _PLACEHOLDER.match(v) is not None or _MASK_RUN.search(v) is not None


# Hash formats: a logged password *hash* is a weaker finding than a plaintext password.
_HASH = re.compile(r"^(?:\$2[abxy]?\$\d\d\$[./A-Za-z0-9]{53}|\$argon2(?:id|i|d)\$\S+|\$[156]\$\S+|[0-9a-fA-F]{32}|"
                   r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$")


def looks_like_hash(value: str) -> bool:
    return _HASH.match(value) is not None


def b64decode_loose(value: str) -> bytes | None:
    """Decode standard or URL-safe base64 with or without padding; None if it is not base64."""
    v = value.strip()
    v += "=" * (-len(v) % 4)
    try:
        return base64.b64decode(v.replace("-", "+").replace("_", "/"), validate=True)
    except (binascii.Error, ValueError):
        return None


def jwt_header(token: str) -> dict | None:
    """The decoded header of a JSON Web Token, or None if the first segment is not a JWT header."""
    raw = b64decode_loose(token.split(".", 1)[0])
    if raw is None:
        return None
    try:
        header = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return header if isinstance(header, dict) and "alg" in header else None
