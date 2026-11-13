"""What LogCheck looks for. Each detector finds candidates with a pattern and then validates them.

Design rules (the reasoning per detector is in docs/DETECTORS.md):
- Numbers are only reported when they pass the relevant check (Luhn, IIN ranges, IBAN mod 97,
  ABA checksum, SSA rules), and digit runs must stand alone: a candidate inside a longer number is
  never reported.
- Keyword-anchored detectors look for a *key* (whole word, optionally with a prefix such as
  ``db.`` or ``user_``) followed by ``=``, ``:`` or ``=>`` and a value, so ``setting`` never counts as
  ``tin`` and ``spin=1234`` never counts as a PIN.
- Placeholders (``****``, ``${DB_PASSWORD}``, ``<redacted>``) and message text (``password: invalid``)
  are not values.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from dataclasses import dataclass
from typing import Iterator

from logcheck import checks
from logcheck.masking import mask_value

SEVERITIES = ("critical", "high", "medium", "low")
CONFIDENCES = ("high", "medium", "low")


@dataclass(frozen=True)
class Hit:
    start: int
    end: int
    value: str
    confidence: str
    notes: tuple[str, ...] = ()
    masked: str | None = None  # set when the detector masks the value itself


@dataclass
class Detector:
    id: str = ""
    title: str = ""
    severity: str = "high"
    mask: str = "default"
    triggers: tuple[str, ...] = ()  # lower-case substrings; the line is skipped unless one occurs
    needs_digit: bool = False
    enabled_by_default: bool = True
    hint: re.Pattern[str] | None = None  # cheap pattern the raw line must contain before find() runs

    def __post_init__(self) -> None:
        self._trigger_re = re.compile("|".join(map(re.escape, self.triggers))) if self.triggers else None

    def applies(self, line: str, lower: str, has_digit: bool) -> bool:
        """Cheap pre-checks so that most lines never reach the full patterns."""
        if self.needs_digit and not has_digit:
            return False
        if self._trigger_re is not None and self._trigger_re.search(lower) is None:
            return False
        return self.hint is None or self.hint.search(line) is not None

    def find(self, line: str) -> Iterator[Hit]:  # pragma: no cover - overridden
        raise NotImplementedError

    def masked(self, hit: Hit) -> str:
        return hit.masked if hit.masked is not None else mask_value(hit.value, self.mask)


# ------------------------------------------------------------------------------------------ key = value

_SEP = r"""["']?[ \t]*(?:=>|->|=|:)[ \t]*"""
_VALUE = r"""(?:"(?P<dq>[^"\r\n]{1,256})"|'(?P<sq>[^'\r\n]{1,256})'|(?P<bare>[^\s,;&"'<>(){}\[\]|]{1,256}))"""


def kv(keys: str, value: str | None = None, *, loose_prefix: bool = False) -> re.Pattern[str]:
    """key <sep> value. The key must start at a word boundary; it may carry a prefix that ends in
    '.', '_' or '-' (``db.password``); with loose_prefix also a camelCase one (``userPassword``)."""
    prefix = r"[A-Za-z0-9._-]*?" if loose_prefix else r"(?:[A-Za-z0-9._-]*[._-])?"
    val = _VALUE if value is None else rf"""["']?(?P<bare>{value})"""
    return re.compile(rf"(?<![A-Za-z0-9._-])(?P<key>{prefix}(?:{keys})){_SEP}{val}", re.IGNORECASE)


def kv_value(m: re.Match[str]) -> tuple[int, int, str]:
    for group in ("dq", "sq", "bare"):
        if m.re.groupindex.get(group) and m.group(group) is not None:
            return m.start(group), m.end(group), m.group(group)
    raise ValueError("pattern has no value group")


def _word(pattern: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![A-Za-z])(?:{pattern})(?![A-Za-z])", re.IGNORECASE)


# ------------------------------------------------------------------------------------------ cards

_DIGIT_RUN = re.compile(r"(?<![A-Za-z0-9_])(?<![0-9]\.)[0-9]+(?:[ -][0-9]+)*(?![A-Za-z0-9_])(?!\.[0-9])")
_GROUP = re.compile(r"[0-9]+")
_LAYOUTS = frozenset({(4, 4, 4, 4), (4, 4, 4, 4, 1), (4, 4, 4, 4, 2), (4, 4, 4, 4, 3), (4, 6, 5), (4, 6, 4),
                      (4, 4, 4, 1), (4, 4, 4, 2), (4, 4, 4, 3)})
_CARD_CONTEXT = _word(r"card|cards|pan|cc|ccn|ccnum|cc[_-]?number|credit|debit|visa|mastercard|amex|cardholder")


def card_candidates(line: str) -> Iterator[tuple[int, int, str]]:
    """(start, end, digits) for every run of 13-19 digits that stands alone, either contiguous or
    written in a card layout with one consistent separator (4111 1111 1111 1111, 3782-822463-10005)."""
    for run in _DIGIT_RUN.finditer(line):
        groups = [(m.start() + run.start(), m.end() + run.start()) for m in _GROUP.finditer(run.group(0))]
        seps = [line[groups[i][1]] for i in range(len(groups) - 1)]
        for i, (s, e) in enumerate(groups):  # contiguous form, not glued to another group by '-'
            joined = (i > 0 and seps[i - 1] == "-") or (i < len(seps) and seps[i] == "-")
            if 13 <= e - s <= 19 and not joined:
                yield s, e, line[s:e]
        for i in range(len(groups)):  # separated form
            for j in range(i + 2, min(len(groups), i + 5) + 1):
                window = groups[i:j]
                layout = tuple(e - s for s, e in window)
                if layout not in _LAYOUTS or len(set(seps[i:j - 1])) != 1:
                    continue
                sep = seps[i]
                before = i > 0 and seps[i - 1] == sep and groups[i - 1][1] - groups[i - 1][0] == 4
                after = j < len(groups) and seps[j - 1] == sep and groups[j][1] - groups[j][0] == 4
                if before or after:  # part of a longer grouped number
                    continue
                s, e = window[0][0], window[-1][1]
                yield s, e, "".join(line[a:b] for a, b in window)


class CardNumber(Detector):
    """Primary account numbers: stand-alone 13-19 digits, Luhn-valid, in a card scheme's IIN range
    (or in the issuer's own BIN list)."""

    def __init__(self, bin_list=None, pan_hashes=None) -> None:
        super().__init__("card-number", "Payment card number (PAN)", "high", "card", needs_digit=True,
                         hint=re.compile(r"[0-9](?:[ -]?[0-9]){12}"))
        self.bin_list = bin_list
        self.pan_hashes = pan_hashes

    def find(self, line: str) -> Iterator[Hit]:
        context = None
        for start, end, digits in card_candidates(line):
            if not checks.luhn_valid(digits):
                continue
            brand = checks.card_brand(digits)
            own_bin = self.bin_list.match(digits) if self.bin_list else None
            if brand is None and own_bin is None:
                continue
            notes = [f"{brand or 'issuer BIN'}, {len(digits)} digits, Luhn valid"]
            if own_bin:
                notes.append(f"matches BIN {own_bin} from the BIN list")
            if self.pan_hashes and self.pan_hashes.contains(digits):
                notes.append("matches a card in the PAN hash list")
                confidence = "high"
            elif checks.is_test_or_trivial_card(digits):
                notes.append("published test card number")
                confidence = "low"
            else:
                if context is None:
                    context = _CARD_CONTEXT.search(line) is not None
                confidence = "high" if (own_bin or context) else "medium"
            yield Hit(start, end, line[start:end], confidence, tuple(notes))


_TRACK1 = re.compile(r"%?B(?P<pan>[0-9]{13,19})\^(?P<name>[A-Za-z0-9 /.'-]{2,26})\^(?P<yy>[0-9]{2})(?P<mm>[0-9]{2})"
                     r"[0-9]{3}[0-9]*\??")
_TRACK2 = re.compile(r"(?<![A-Za-z0-9]);?(?P<pan>[0-9]{13,19})[=D](?P<yy>[0-9]{2})(?P<mm>[0-9]{2})[0-9]{3}[0-9]*(?:F|\?)?")


class CardTrackData(Detector):
    """Magnetic-stripe track 1/2 or EMV track 2 equivalent (tag 57): PAN, expiry and service code."""

    def __init__(self) -> None:
        super().__init__("card-track-data", "Card track data", "critical", "card", needs_digit=True,
                         hint=re.compile(r"[0-9]{13}"))

    def find(self, line: str) -> Iterator[Hit]:
        for pattern, label in ((_TRACK1, "track 1"), (_TRACK2, "track 2")):
            for m in pattern.finditer(line):
                pan = m.group("pan")
                if checks.luhn_valid(pan) and 1 <= int(m.group("mm")) <= 12:
                    p0 = m.start("pan") - m.start()
                    value = m.group(0)
                    masked = "*" * p0 + mask_value(pan, "card") + "*" * (len(value) - p0 - len(pan))
                    yield Hit(m.start(), m.end(), value, "high", (f"{label} format, PAN Luhn valid",), masked)


class CardSecurityCode(Detector):
    def __init__(self) -> None:
        super().__init__("card-security-code", "Card security code (CVV/CVC)", "critical", "full",
                         ("cvv", "cvc", "cvn", "csc", "cav", "cid", "verification", "security", "code"), True)
        self.pattern = kv(r"cvv2?|cvc2?|cvn2?|csc|cav2|cid2|card[_ .-]?verification(?:[_ .-]?(?:value|code|number))?|"
                          r"card[_ .-]?security[_ .-]?code|security[_ .-]?code|card[_ .-]?code",
                          r"[0-9]{3,4}(?![0-9A-Za-z])")

    def find(self, line: str) -> Iterator[Hit]:
        for m in self.pattern.finditer(line):
            s, e, v = kv_value(m)
            yield Hit(s, e, v, "high", (f"key '{m.group('key')}'",))


class CardPin(Detector):
    def __init__(self) -> None:
        super().__init__("card-pin", "Card PIN or clear PIN block", "critical", "full", ("pin",), True)
        self.pin = kv(r"pin|pin[_ .-]?(?:code|number|no|value)|(?:atm|card|new|old|current|confirm)[_ .-]?pin",
                      r"[0-9]{4,12}(?![0-9A-Za-z])")
        self.block = kv(r"(?:clear[_ .-]?)?pin[_ .-]?block", r"[0-9A-Fa-f]{16}(?![0-9A-Za-z])")

    def find(self, line: str) -> Iterator[Hit]:
        for pattern, label in ((self.pin, "PIN"), (self.block, "PIN block")):
            for m in pattern.finditer(line):
                s, e, v = kv_value(m)
                yield Hit(s, e, v, "high", (f"{label}, key '{m.group('key')}'",))


class CardExpiry(Detector):
    def __init__(self) -> None:
        super().__init__("card-expiry", "Card expiry date", "low", "full", ("exp", "valid"), True)
        self.pattern = kv(r"exp|expiry|expiration|exp[_ .-]?date|expiry[_ .-]?date|expiration[_ .-]?date|"
                          r"card[_ .-]?exp(?:iry|iration)?(?:[_ .-]?date)?|valid[_ .-]?(?:thru|through|until)",
                          r"(?:0[1-9]|1[0-2])[ ]?[/-]?[ ]?(?:20[0-9]{2}|[0-9]{2})(?![0-9])")

    def find(self, line: str) -> Iterator[Hit]:
        for m in self.pattern.finditer(line):
            s, e, v = kv_value(m)
            yield Hit(s, e, v, "medium", ("only sensitive together with a card number",))


# ------------------------------------------------------------------------------------------ identity

_SSN_DASHED = re.compile(r"(?<![0-9A-Za-z-])(?P<a>[0-9]{3})-(?P<g>[0-9]{2})-(?P<s>[0-9]{4})(?![0-9A-Za-z-])")
_SSN_SPACED = re.compile(r"(?<![0-9])(?P<a>[0-9]{3}) (?P<g>[0-9]{2}) (?P<s>[0-9]{4})(?![0-9])")
_SSN_CONTEXT = _word(r"ssn|ssns|social[ _-]?security|socialsecurity|taxpayer|itin")


class UsSsn(Detector):
    def __init__(self) -> None:
        super().__init__("us-ssn", "US Social Security Number", "high", "last4", needs_digit=True,
                         hint=re.compile(r"(?<![0-9])[0-9]{3}[- ]?[0-9]{2}[- ]?[0-9]{4}(?![0-9])"))
        self.keyed = kv(r"ssn|ss[_ .-]?no|ssn[_ .-]?(?:no|num|number)|social[_ .-]?security(?:[_ .-]?(?:no|num|number))?|"
                        r"tin|itin|tax[_ .-]?id|taxpayer[_ .-]?id(?:[_ .-]?number)?",
                        r"[0-9]{3}-?[0-9]{2}-?[0-9]{4}(?![0-9A-Za-z])")

    @staticmethod
    def _rated(digits: str, base: str) -> tuple[str, tuple[str, ...]] | None:
        if not checks.ssn_valid(digits[:3], digits[3:5], digits[5:]):
            return None
        if digits in checks.EXAMPLE_SSNS:
            return "low", ("well-known example or invalidated SSN",)
        return base, ()

    def find(self, line: str) -> Iterator[Hit]:
        taken: list[tuple[int, int]] = []
        for m in self.keyed.finditer(line):
            s, e, v = kv_value(m)
            rated = self._rated(v.replace("-", ""), "high")
            if rated:
                taken.append((s, e))
                yield Hit(s, e, v, rated[0], (f"key '{m.group('key')}'", *rated[1]))
        context = _SSN_CONTEXT.search(line) is not None
        for pattern, needs_context in ((_SSN_DASHED, False), (_SSN_SPACED, True)):
            if needs_context and not context:
                continue
            for m in pattern.finditer(line):
                if any(m.start() < e and s < m.end() for s, e in taken):
                    continue
                rated = self._rated(m.group("a") + m.group("g") + m.group("s"), "high" if context else "medium")
                if rated:
                    yield Hit(m.start(), m.end(), m.group(0), rated[0],
                              ("SSN keyword on the line" if context else "SSN format only", *rated[1]))


class DateOfBirth(Detector):
    def __init__(self) -> None:
        super().__init__("date-of-birth", "Date of birth", "medium", "full", ("dob", "d.o.b", "birth"), True)
        self.pattern = kv(r"dob|d\.o\.b|date[_ .-]?of[_ .-]?birth|birth[_ .-]?date|birth[_ .-]?dt|birthday",
                          r"[0-9]{4}[-/][0-9]{2}[-/][0-9]{2}|[0-9]{2}[-/.][0-9]{2}[-/.][0-9]{4}|[0-9]{8}(?![0-9])")

    def find(self, line: str) -> Iterator[Hit]:
        for m in self.pattern.finditer(line):
            s, e, v = kv_value(m)
            if checks.plausible_birth_date(v):
                yield Hit(s, e, v, "high", (f"key '{m.group('key')}'",))


# ------------------------------------------------------------------------------------------ banking

_IBAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])")


class Iban(Detector):
    def __init__(self) -> None:
        super().__init__("iban", "IBAN (international bank account number)", "high", needs_digit=True,
                         hint=re.compile(r"[A-Z]{2}[0-9]{2}"))

    def find(self, line: str) -> Iterator[Hit]:
        for m in _IBAN.finditer(line):
            text = m.group(0)
            cuts = [len(text)] + [i for i in range(len(text) - 1, 14, -1) if text[i] == " "]
            for cut in cuts:  # an IBAN followed by a short word: try shorter group boundaries
                if checks.iban_valid(text[:cut]):
                    yield Hit(m.start(), m.start() + cut, text[:cut], "high", ("IBAN length and mod-97 check valid",))
                    break


class BankAccount(Detector):
    def __init__(self) -> None:
        super().__init__("bank-account", "Bank account or routing number", "medium", "last4",
                         ("acc", "acct", "dda", "routing", "aba", "rtn"), True)
        self.account = kv(r"(?:bank[_ .-]?|beneficiary[_ .-]?|checking[_ .-]?|savings[_ .-]?)?account[_ .-]?(?:no|num|number|nbr)|"
                          r"acct(?:[_ .-]?(?:no|num|number|nbr))?|acc[_ .-]?no|dda(?:[_ .-]?(?:no|num|number|account))?",
                          r"[0-9]{6,17}(?![0-9A-Za-z])")
        self.routing = kv(r"routing(?:[_ .-]?(?:no|num|number|transit(?:[_ .-]?number)?))?|aba(?:[_ .-]?(?:no|num|number|routing))?|rtn",
                          r"[0-9]{9}(?![0-9A-Za-z])")

    def find(self, line: str) -> Iterator[Hit]:
        for m in self.account.finditer(line):
            s, e, v = kv_value(m)
            yield Hit(s, e, v, "medium", (f"account number, key '{m.group('key')}'",))
        for m in self.routing.finditer(line):
            s, e, v = kv_value(m)
            if checks.aba_routing_valid(v):
                yield Hit(s, e, v, "medium", ("ABA routing number, checksum valid",))


# ------------------------------------------------------------------------------------------ credentials

_PW_STOPWORDS = frozenset("""
required invalid incorrect wrong expired expire expires expiring changed change reset missing mismatch policy updated
update is was for not has have should must cannot can too the a an to of user username attempt attempts failed failure
error ok success successful set provided supplied length strength weak strong match matched matches verification
verified complexity rules hash hashed encrypted salt salted protected login valid accepted rejected denied enabled
disabled yes no on off field value parameter param prompt dialog input text characters chars history age rotation
manager store vault file flag form page screen please enter entered new old current confirm confirmation
""".split())
_LOOKS_LIKE_KV = re.compile(r"^[A-Za-z_][\w.-]*=")
_PATH = re.compile(r"^(?:/|\./|\.\./|~/|[A-Za-z]:[\\/]|\\\\)")  # PWD=/opt/app is the working directory
_TOKEN_END = re.compile(r"[\s\"'<>]")


def credential_value_rejected(value: str) -> bool:
    v = value.strip()
    return (len(v) < 4 or checks.is_placeholder(v) or v.lower() in _PW_STOPWORDS
            or _LOOKS_LIKE_KV.match(v) is not None or _PATH.match(v) is not None or len(set(v)) == 1)


class Password(Detector):
    def __init__(self) -> None:
        super().__init__("password", "Password or secret in clear text", "high", "full", ("pass", "pwd", "pw", "secret"))
        self.patterns = (
            kv(r"password|passwd|passphrase|pass[_ .-]?word|secret", loose_prefix=True),
            kv(r"pwd|pass|pw"),
            re.compile(r"(?<![A-Za-z0-9-])--?(?:password|passwd|passphrase|pwd|pass)(?:=|[ \t]+)(?P<bare>[^\s\"']{1,256})",
                       re.IGNORECASE),
            re.compile(r"<(?P<tag>[A-Za-z0-9:_.-]*?(?:password|passwd|pwd|passphrase|secret))>(?P<bare>[^<\r\n]{1,256})"
                       r"</(?P=tag)>", re.IGNORECASE),
        )

    def find(self, line: str) -> Iterator[Hit]:
        seen: set[tuple[int, int]] = set()
        for pattern in self.patterns:
            for m in pattern.finditer(line):
                s, e, v = kv_value(m)
                if (s, e) in seen or credential_value_rejected(v):
                    continue
                seen.add((s, e))
                masked = None
                if m.groupdict().get("bare") is not None and m.re is not self.patterns[3]:
                    # An unquoted value is read up to , ; & and similar, but a password may contain them:
                    # mask through to the end of the token so no part of it survives in the evidence.
                    stop = _TOKEN_END.search(line, e)
                    end = stop.start() if stop else len(line)
                    if end > e:
                        masked, e = "*" * (end - s), end
                key = m.groupdict().get("key") or m.groupdict().get("tag") or "command-line option"
                if checks.looks_like_hash(v):
                    yield Hit(s, e, v, "low", (f"key '{key}'", "looks like a password hash, not plaintext"), masked)
                    continue
                classes = sum(any(f(c) for c in v) for f in (str.islower, str.isupper, str.isdigit))
                classes += any(not c.isalnum() for c in v)
                confidence = "high" if len(v) >= 8 and classes >= 2 else "medium"
                yield Hit(s, e, v, confidence, (f"key '{key}'",), masked)


_URL_CREDENTIALS = re.compile(r"(?<![A-Za-z0-9+.-])(?P<scheme>[A-Za-z][A-Za-z0-9+.-]{1,30})://(?P<user>[^\s:/@?#\"']{1,128}):"
                              r"(?P<pw>[^\s@/?#\"']{1,256})@(?P<host>[A-Za-z0-9._\-\[\]]+)")


class ConnectionString(Detector):
    def __init__(self) -> None:
        super().__init__("connection-string", "Credentials in a connection string or URL", "high", "full", ("://",))

    def find(self, line: str) -> Iterator[Hit]:
        for m in _URL_CREDENTIALS.finditer(line):
            pw = m.group("pw")
            if not checks.is_placeholder(pw):
                yield Hit(m.start("pw"), m.end("pw"), pw, "high",
                          (f"{m.group('scheme')} URL with a password for host {m.group('host')}",))


_AUTH_HEADER = re.compile(r"""(?<![A-Za-z0-9-])(?:proxy-)?authorization["']?[ \t]*[:=][ \t]*["']?(?P<scheme>bearer|basic|"""
                          r"""token|apikey|api-key|sharedkey|sharedaccesssignature|aws4-hmac-sha256|negotiate|ntlm|digest)"""
                          r"""[ \t]+(?P<bare>[^\s"',]{8,})""", re.IGNORECASE)
_BEARER = re.compile(r"(?<![A-Za-z0-9])bearer[ \t]+(?P<bare>[A-Za-z0-9\-._~+/]{20,}=*)", re.IGNORECASE)


class AuthorizationHeader(Detector):
    def __init__(self) -> None:
        super().__init__("authorization-header", "HTTP Authorization credentials", "high", triggers=("authorization", "bearer"))

    def find(self, line: str) -> Iterator[Hit]:
        taken: list[tuple[int, int]] = []
        for m in _AUTH_HEADER.finditer(line):
            v, scheme = m.group("bare"), m.group("scheme").lower()
            if checks.is_placeholder(v):
                continue
            notes, confidence = [f"{m.group('scheme')} credentials"], "high"
            if scheme == "basic":
                decoded = checks.b64decode_loose(v)
                if decoded and b":" in decoded:
                    notes.append("decodes to user:password")
                else:
                    confidence = "medium"
            elif scheme in ("negotiate", "ntlm", "digest"):
                confidence = "medium"
            taken.append(m.span("bare"))
            yield Hit(m.start("bare"), m.end("bare"), v, confidence, tuple(notes))
        for m in _BEARER.finditer(line):
            if not any(m.start("bare") < e and s < m.end("bare") for s, e in taken):
                yield Hit(m.start("bare"), m.end("bare"), m.group("bare"), "medium", ("bearer token",))


class ApiToken(Detector):
    def __init__(self) -> None:
        super().__init__("api-token", "API key or access token", "high", triggers=(
            "api", "token", "secret", "key"))
        self.pattern = kv(r"api[_ .-]?key|apikey|api[_ .-]?secret|api[_ .-]?token|access[_ .-]?token|auth[_ .-]?token|"
                          r"refresh[_ .-]?token|id[_ .-]?token|client[_ .-]?secret|x-api-key|x-auth-token|"
                          r"subscription[_ .-]?key|app[_ .-]?(?:key|secret)|private[_ .-]?token|consumer[_ .-]?secret|"
                          r"webhook[_ .-]?secret|signing[_ .-]?secret|bot[_ .-]?token",
                          r"[A-Za-z0-9\-._~+/:]{16,512}={0,2}(?![A-Za-z0-9\-._~+/=])", loose_prefix=True)

    def find(self, line: str) -> Iterator[Hit]:
        for m in self.pattern.finditer(line):
            s, e, v = kv_value(m)
            entropy = checks.shannon_entropy(v)
            # Random tokens almost always contain a digit; YOUR_API_KEY_HERE and other names do not.
            if checks.is_placeholder(v) or entropy < 3.0 or (len(v) < 32 and not any(c.isdigit() for c in v)):
                continue
            confidence = "high" if entropy >= 3.5 and len(v) >= 20 else "medium"
            yield Hit(s, e, v, confidence, (f"key '{m.group('key')}'", f"entropy {entropy:.1f} bits/char"))


_KNOWN_FORMATS: tuple[tuple[str, re.Pattern[str], str], ...] = tuple(
    (label, re.compile(rx), confidence) for label, rx, confidence in (
        ("AWS access key ID", r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])", "high"),
        ("GitHub token", r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9_])", "high"),
        ("GitHub fine-grained token", r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{60,255}", "high"),
        ("GitLab token", r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}", "high"),
        ("Slack token", r"(?<![A-Za-z0-9-])xox[abposr]-[A-Za-z0-9-]{10,}", "high"),
        ("Slack webhook", r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+", "high"),
        ("Google API key", r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])", "high"),
        ("Stripe live key", r"(?<![A-Za-z0-9_])(?:sk|rk)_live_[0-9A-Za-z]{16,}", "high"),
        ("Stripe test key", r"(?<![A-Za-z0-9_])(?:sk|rk)_test_[0-9A-Za-z]{16,}", "low"),
        ("OpenAI API key", r"(?<![A-Za-z0-9_-])sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}", "high"),
        ("Anthropic API key", r"(?<![A-Za-z0-9_-])sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,}", "high"),
        ("npm token", r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])", "high"),
        ("SendGrid API key", r"(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "high"),
        ("Azure storage account key", r"(?i:AccountKey)=[A-Za-z0-9+/]{86}==", "high"),
    ))
_AWS_SECRET = kv(r"aws[_ .-]?secret[_ .-]?(?:access[_ .-]?)?key", r"[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")


class KnownKeyFormat(Detector):
    def __init__(self) -> None:
        super().__init__("known-key-format", "Cloud or SaaS credential with a known format", "high", "prefix", (
            "akia", "asia", "abia", "acca", "gh", "glpat", "xox", "hooks.slack", "aiza", "sk_", "rk_", "sk-", "npm_",
            "sg.", "accountkey", "aws"))

    def find(self, line: str) -> Iterator[Hit]:
        for label, pattern, confidence in _KNOWN_FORMATS:
            for m in pattern.finditer(line):
                start = m.start()
                if label == "Azure storage account key":
                    start += len("AccountKey=")
                yield Hit(start, m.end(), line[start:m.end()], confidence, (label,))
        for m in _AWS_SECRET.finditer(line):
            s, e, v = kv_value(m)
            yield Hit(s, e, v, "high", ("AWS secret access key",))


_JWT = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


class Jwt(Detector):
    def __init__(self) -> None:
        super().__init__("jwt", "JSON Web Token", "high", triggers=("eyj",))

    def find(self, line: str) -> Iterator[Hit]:
        for m in _JWT.finditer(line):
            token = m.group(0)
            header = checks.jwt_header(token)
            if header is None:
                continue
            notes, confidence = [f"alg {header.get('alg')}"], "high"
            payload = checks.b64decode_loose(token.split(".")[1])
            try:
                claims = json.loads(payload.decode("utf-8")) if payload else {}
            except (UnicodeDecodeError, ValueError):
                claims = {}
            exp = claims.get("exp") if isinstance(claims, dict) else None
            if isinstance(exp, (int, float)):
                expiry = _dt.datetime.fromtimestamp(exp, _dt.timezone.utc)
                notes.append(f"expires {expiry:%Y-%m-%d %H:%M} UTC")
                if expiry < _dt.datetime.now(_dt.timezone.utc):
                    confidence = "medium"
            if not token.split(".")[2]:
                notes.append("unsigned")
            yield Hit(m.start(), m.end(), token, confidence, tuple(notes))


class SessionId(Detector):
    def __init__(self) -> None:
        super().__init__("session-id", "Session identifier", "high", triggers=("sess", "sid"))
        self.pattern = kv(r"jsessionid|phpsessid|asp\.net_sessionid|aspsessionid[a-z]{8}|session[_ .-]?id|sessionid|"
                          r"sess[_ .-]?id|sid|connect\.sid|laravel_session|ci_session|session[_ .-]?token|session[_ .-]?key|"
                          r"x-session-id", r"[A-Za-z0-9%._~+/:-]{16,256}(?![A-Za-z0-9%._~+/:-])")

    def find(self, line: str) -> Iterator[Hit]:
        for m in self.pattern.finditer(line):
            s, e, v = kv_value(m)
            if checks.is_placeholder(v) or checks.shannon_entropy(v) < 3.0 or v.upper().startswith("S-1-"):
                continue
            yield Hit(s, e, v, "medium", (f"key '{m.group('key')}'", "usable by anyone while the session is active"))


_PRIVATE_KEY = re.compile(r"-----BEGIN (?:(?P<kind>RSA|DSA|EC|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----|"
                          r"PuTTY-User-Key-File-[23]:")


class PrivateKey(Detector):
    def __init__(self) -> None:
        super().__init__("private-key", "Private key", "critical", triggers=("private key", "putty-user-key"))

    def masked(self, hit: Hit) -> str:
        return hit.value  # the header names the key type; the key material follows it

    def find(self, line: str) -> Iterator[Hit]:
        for m in _PRIVATE_KEY.finditer(line):
            encrypted = m.group("kind") == "ENCRYPTED"
            yield Hit(m.start(), m.end(), m.group(0), "medium" if encrypted else "high",
                      ("key is passphrase-protected" if encrypted else "key material follows this line",))


class CryptoKey(Detector):
    def __init__(self) -> None:
        super().__init__("crypto-key", "Symmetric or HSM key value", "high", "full", triggers=(
            "key", "zmk", "zpk", "tmk", "tpk", "tak", "zak", "kek", "dek", "cvk", "pvk", "bdk", "ipek", "lmk"))
        self.pattern = kv(r"(?:secret|private|encryption|enc|aes|des|3des|tdes|hmac|signing|master|wrapping|transport|"
                          r"data[_ .-]?encryption|key[_ .-]?encryption)[_ .-]?key|zmk|zpk|tmk|tpk|tak|zak|kek|dek|cvk|pvk|"
                          r"bdk|ipek|lmk|key[_ .-]?material|key[_ .-]?value|clear[_ .-]?key|key[_ .-]?component",
                          r"[UTXY]?(?:[0-9A-Fa-f]{32,128}|[A-Za-z0-9+/]{24,88}={0,2})(?![A-Za-z0-9+/=])")

    def find(self, line: str) -> Iterator[Hit]:
        for m in self.pattern.finditer(line):
            s, e, v = kv_value(m)
            body = v[1:] if v[:1] in "UTXY" and len(v) % 2 else v
            is_hex = all(c in "0123456789abcdefABCDEF" for c in body)
            entropy = checks.shannon_entropy(body)
            if v.isdigit() or entropy < (2.8 if is_hex else 3.5) or (is_hex and len(body) % 2):
                continue
            kind = f"{len(body) * 4}-bit hex value" if is_hex else "base64 value"
            yield Hit(s, e, v, "high", (f"key '{m.group('key')}'", kind))


# ------------------------------------------------------------------------------------------ registry

# When two findings overlap on a line, the earlier detector in this list wins (the more specific one).
PRIORITY = ("private-key", "card-track-data", "card-number", "card-pin", "card-security-code", "known-key-format",
            "connection-string", "authorization-header", "jwt", "crypto-key", "api-token", "password", "session-id",
            "us-ssn", "iban", "bank-account", "date-of-birth", "card-expiry")


def all_detectors(bin_list=None, pan_hashes=None) -> list[Detector]:
    detectors = [PrivateKey(), CardTrackData(), CardNumber(bin_list, pan_hashes), CardPin(), CardSecurityCode(),
                 KnownKeyFormat(), ConnectionString(), AuthorizationHeader(), Jwt(), CryptoKey(), ApiToken(),
                 Password(), SessionId(), UsSsn(), Iban(), BankAccount(), DateOfBirth(), CardExpiry()]
    assert [d.id for d in detectors] == list(PRIORITY)
    return detectors


def select(detectors: list[Detector], enable: list[str] | None = None, disable: list[str] | None = None) -> list[Detector]:
    known = {d.id for d in detectors}
    unknown = sorted((set(enable or []) | set(disable or [])) - known)
    if unknown:
        raise ValueError(f"unknown detector id(s): {', '.join(unknown)}")
    chosen = [d for d in detectors if (d.id in enable if enable else d.enabled_by_default)]
    return [d for d in chosen if d.id not in set(disable or [])]
