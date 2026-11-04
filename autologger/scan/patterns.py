"""Regex catalog, Java regex-list splitting and Java -> Python regex translation.

Java sources: WorkerThread (threads.h) for the built-in constants and the
sheet-value merge rules, SensitiveInfoScanning (w.a / w.b) for list splitting.

All built-in patterns come byte-exact from data/regex_catalog.json (extracted
from the JAR by reflection). Patterns are always handled in *Java syntax* first
(merged and split exactly like Java), then translated to Python syntax.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources

from autologger import constants as C
from autologger.jcompat import java_pattern_quote, java_split, java_trim

_CATALOG = json.loads(resources.files("autologger.data").joinpath("regex_catalog.json").read_text("utf-8"))
_DETECTORS = _CATALOG["detectors"]

# Line keywords used by the proximity filter (Java constants h.u, h.v, h.w).
SSN_KEYWORDS: tuple[str, ...] = tuple(_DETECTORS[C.SSN]["line_keywords"])
EXPIRY_DOB_KEYWORDS: tuple[str, ...] = tuple(_DETECTORS[C.EXPIRY_DOB]["line_keywords"])
PASSWORD_KEYWORDS: tuple[str, ...] = tuple(_DETECTORS[C.PASSWORD]["line_keywords"])

# Built-in Java patterns (constants h.x, h.G, h.K, h.J, h.M, h.C, h.D, h.E, h.F, h.Q).
BUILT_IN_JAVA_PATTERNS: dict[str, str] = {
    name: d["java_pattern"] for name, d in _DETECTORS.items() if "java_pattern" in d
}
SOFTWARE_TERMS: tuple[str, ...] = tuple(_CATALOG["software_terms"])
SOFTWARE_VERSION = _CATALOG["software_version_pattern"]  # h.O
SOFTWARE_VERSION_LABEL = _CATALOG["software_version_label_pattern"]  # h.P
PASSWORD_VALUE_MASK_JAVA = _CATALOG["password_mask_filters"]["value_mask"]  # w.i
PASSWORD_AUTH_MASK_JAVA = _CATALOG["password_mask_filters"]["auth_header_mask"]  # w.j
OPENAI_NORMALIZERS_JAVA: dict[str, str] = _CATALOG["openai_template_normalizers"]  # n.x .. n.A

_SHEET_TERM_SPLIT = re.compile(r"\s*,\s*", re.ASCII)


# --------------------------------------------------------------------------- splitting

def split_top_level(text: str) -> list[str]:
    """w.b(String): split on commas outside (), {}, [] and escapes; trim; drop empties."""
    parts: list[str] = []
    cur: list[str] = []
    escaped = in_class = False
    parens = braces = 0
    for ch in text:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == "\\":
            cur.append(ch)
            escaped = True
        elif in_class:
            if ch == "]":
                in_class = False
            cur.append(ch)
        elif ch == "[":
            in_class = True
            cur.append(ch)
        elif ch == "(":
            parens += 1
            cur.append(ch)
        elif ch == ")" and parens > 0:
            parens -= 1
            cur.append(ch)
        elif ch == "{":
            braces += 1
            cur.append(ch)
        elif ch == "}" and braces > 0:
            braces -= 1
            cur.append(ch)
        elif ch == "," and parens == 0 and braces == 0:
            part = java_trim("".join(cur))
            if part:
                parts.append(part)
            cur = []
        else:
            cur.append(ch)
    part = java_trim("".join(cur))
    if part:
        parts.append(part)
    return parts


def split_regex_list(test_case: str, text: str | None) -> list[str]:
    """w.a(name, text): '~' split for legacy Track Data names, top-level comma split otherwise."""
    if text is None or java_trim(text) == "":
        return []
    if test_case in C.TRACK_DATA_LEGACY_NAMES:
        return java_split(re.compile("~"), text)
    return split_top_level(text)


# --------------------------------------------------------------------------- sheet merges

def _sheet_terms(sheet_value: str | None) -> list[str]:
    if sheet_value is None or java_trim(sheet_value) == "":
        return []
    return [t for t in (java_trim(x) for x in java_split(_SHEET_TERM_SPLIT, sheet_value)) if t]


def _raw_regex_term(term: str) -> str | None:
    """Return the regex after a case-insensitive 're:' prefix, '' if empty, None if not prefixed."""
    if term[:3].lower() == "re:":
        return java_trim(term[3:])
    return None


def password_extra_terms(sheet_value: str | None) -> str:
    """h.a(String): literal -> '(?i)' + Pattern.quote(term); 're:' -> raw regex."""
    out = []
    for term in _sheet_terms(sheet_value):
        raw = _raw_regex_term(term)
        if raw is None:
            out.append("(?i)" + java_pattern_quote(term))
        elif raw:
            out.append(raw)
    return ",".join(out)


def software_term_pattern(term: str) -> str:
    """h.d(String): the software/framework version template for one term (Java syntax)."""
    quoted = java_pattern_quote(term)
    bounded = "(?<![A-Za-z0-9_.$+])" + quoted + "(?![A-Za-z0-9_.$+])"
    loose = "(?:[\\\"']?)" + quoted + "(?:[\\\"']?)"
    ver, lbl = SOFTWARE_VERSION, SOFTWARE_VERSION_LABEL
    return (
        "(?i)(?:" + bounded + "\\s*(?:[\\(\\[]\\s*)?(?:" + lbl + "\\s*)?(?:[:=]|=>|->)?\\s*" + ver
        + "(?:\\s*[\\)\\]])?(?:\\.(?:jar|war|ear|zip|tar|gz|tgz|dll|so|exe))?|"
        + bounded + "(?:[/_-])" + ver
        + "|(?:software|framework|technology|library|component|dependency|artifact|package|module)\\s*[:=]\\s*"
        + loose + "\\s*(?:[,;]\\s*)?(?:" + lbl + ")\\s*[:=]\\s*" + ver
        + "|(?:name|artifactId|groupId)\\s*[:=]\\s*" + loose + "\\s*(?:[,;]\\s*)?(?:" + lbl
        + ")\\s*[:=]\\s*[\\\"']?" + ver + "[\\\"']?)"
    )


def software_extra_terms(sheet_value: str | None) -> str:
    """h.b(String): literal -> software template; 're:' -> raw regex."""
    out = []
    for term in _sheet_terms(sheet_value):
        raw = _raw_regex_term(term)
        if raw is None:
            out.append(software_term_pattern(term))
        elif raw:
            out.append(raw)
    return ",".join(out)


def _join(base: str, extra: str) -> str:
    return base if not extra else base + "," + extra


@lru_cache(maxsize=256)
def detector_regex_text(test_case: str, sheet_value: str | None) -> str:
    """The Java-syntax regex list WorkerThread hands to SensitiveInfoScanning for a test case."""
    if test_case == C.PASSWORD:
        return _join(BUILT_IN_JAVA_PATTERNS[C.PASSWORD], password_extra_terms(sheet_value))
    if test_case == C.SOFTWARE:
        return _join(BUILT_IN_JAVA_PATTERNS[C.SOFTWARE], software_extra_terms(sheet_value))
    if test_case in BUILT_IN_JAVA_PATTERNS:
        return BUILT_IN_JAVA_PATTERNS[test_case]
    return sheet_value or ""


@lru_cache(maxsize=256)
def detector_parts(test_case: str, sheet_value: str | None) -> tuple[str, ...]:
    """Java-syntax regex parts scanned for a test case (one full pass over the file each)."""
    return tuple(split_regex_list(test_case, detector_regex_text(test_case, sheet_value)))


# --------------------------------------------------------------------------- translation

_JAVA_POSIX = {
    "Lower": "a-z", "Upper": "A-Z", "ASCII": "\\x00-\\x7f", "Alpha": "a-zA-Z", "Digit": "0-9",
    "Alnum": "a-zA-Z0-9", "Punct": "!-/:-@\\[-`{-~", "Graph": "!-~", "Print": " -~",
    "Blank": " \\t", "Cntrl": "\\x00-\\x1f\\x7f", "XDigit": "0-9a-fA-F", "Space": " \\t\\n\\x0b\\f\\r",
}
_JAVA_LINE_TERMINATORS = "\\n\\r\\u0085\\u2028\\u2029"
_JAVA_DOT = "[^" + _JAVA_LINE_TERMINATORS + "]"
_JAVA_DOLLAR = "(?:(?=\\r\\n\\Z)|(?<!\\r)(?=\\n\\Z)|(?=[\\r\\u0085\\u2028\\u2029]\\Z)|\\Z)"
_JAVA_UPPER_Z = "(?=(?:\\r\\n|[" + _JAVA_LINE_TERMINATORS + "])?\\Z)"
_INLINE_FLAGS = re.compile(r"\(\?([a-zA-Z]*)(?:-([a-zA-Z]*))?([:)])")
_PY_SCOPED_FLAGS = set("imsx")


def _class_escape(ch: str) -> str:
    return "\\" + ch if ch in "\\]^-[" else re.escape(ch)


class _Translator:
    """Single pass Java regex -> Python `re` translator (see java_to_python)."""

    def __init__(self, pattern: str, case_insensitive: bool) -> None:
        self.p = pattern
        self.ci = case_insensitive
        self.i = 0
        self.out: list[str] = []
        self.in_class = 0
        # one entry per open group: closers of scoped-flag groups to emit when it closes
        self.frames: list[list[str]] = [[]]
        self.dotall = re.search(r"\(\?[a-zA-Z]*s[a-zA-Z]*[:)]", pattern) is not None
        self.multiline = re.search(r"\(\?[a-zA-Z]*m[a-zA-Z]*[:)]", pattern) is not None

    def run(self) -> str:
        p = self.p
        while self.i < len(p):
            ch = p[self.i]
            if ch == "\\":
                self._escape()
            elif self.in_class:
                if ch == "[":
                    # Java nested class = union ([a[bc]] == [abc]); flatten it for Python
                    self.in_class += 1
                    if p.startswith("^", self.i + 1):
                        self.i += 1  # negated nested union is not expressible; approximated
                elif ch == "]":
                    self.in_class -= 1
                    if self.in_class == 0:
                        self.out.append("]")
                else:
                    self.out.append(ch)
                self.i += 1
            elif ch == "[":
                self.in_class = 1
                self.out.append("[")
                self.i += 1
                if p.startswith("^", self.i):
                    self.out.append("^")
                    self.i += 1
                if p.startswith("]", self.i):  # literal ']' first in class
                    self.out.append("\\]")
                    self.i += 1
            elif ch == "(":
                self._group()
            elif ch == ")":
                closers = self.frames.pop() if len(self.frames) > 1 else []
                self.out.append("".join(reversed(closers)) + ")")
                self.i += 1
            elif ch == "." and not self.dotall:
                self.out.append(_JAVA_DOT)
                self.i += 1
            elif ch == "$" and not self.multiline:
                self.out.append(_JAVA_DOLLAR)
                self.i += 1
            else:
                self.out.append(ch)
                self.i += 1
        self.out.append("".join(reversed(self.frames[0])))
        return "".join(self.out)

    # -- groups / inline flags
    def _group(self) -> None:
        p = self.p
        m = _INLINE_FLAGS.match(p, self.i)
        if m and (m.group(1) or m.group(2) is not None):
            on = "".join(f for f in m.group(1) if f in _PY_SCOPED_FLAGS)
            off = "".join(f for f in (m.group(2) or "") if f in _PY_SCOPED_FLAGS)
            if self.ci:
                on = on.replace("i", "")
            flags = on + ("-" + off if off else "")
            at_start = not self.out and len(self.frames) == 1
            self.i = m.end()
            if m.group(3) == ":":
                self.out.append("(?" + flags + ":" if flags else "(?:")
                self.frames.append([])
            elif flags and at_start and not off:
                self.out.append("(?" + flags + ")")  # leading flags are global, as in Java
            elif flags:
                # Java: flags apply to the rest of the enclosing group -> scoped group in Python;
                # in verbose mode a trailing '#' comment would swallow ')', so close on a new line
                self.out.append("(?" + flags + ":")
                self.frames[-1].append("\n)" if "x" in on else ")")
            return
        if p.startswith("(?<", self.i) and not p.startswith("(?<=", self.i) and not p.startswith("(?<!", self.i):
            self.out.append("(?P<")
            self.i += 3
        else:
            self.out.append("(")
            self.i += 1
        self.frames.append([])

    # -- escapes
    def _escape(self) -> None:
        p, i = self.p, self.i
        if i + 1 >= len(p):
            self.out.append("\\\\")
            self.i += 1
            return
        nxt = p[i + 1]
        if nxt == "Q":
            end = p.find("\\E", i + 2)
            literal = p[i + 2:] if end < 0 else p[i + 2:end]
            if self.in_class:
                self.out.append("".join(_class_escape(c) for c in literal))
            else:
                self.out.append(re.escape(literal))
            self.i = len(p) if end < 0 else end + 2
            return
        if nxt == "E":  # stray \E is ignored by Java
            self.i += 2
            return
        self.i += 2
        if nxt == "z":
            self.out.append("\\Z")
        elif nxt == "Z" and not self.in_class:
            self.out.append(_JAVA_UPPER_Z)
        elif nxt == "e":
            self.out.append("\\x1b")
        elif nxt == "c" and self.i < len(p):
            self.out.append(f"\\x{ord(p[self.i]) ^ 64:02x}")
            self.i += 1
        elif nxt == "0":
            m = re.compile(r"[0-3]?[0-7]{1,2}").match(p, self.i)
            if m:
                self.out.append(f"\\x{int(m.group(0), 8):02x}")
                self.i = m.end()
            else:
                self.out.append("\\0")
        elif nxt == "x" and p.startswith("{", self.i):
            end = p.find("}", self.i)
            code = int(p[self.i + 1:end], 16)
            self.out.append(f"\\U{code:08x}")
            self.i = end + 1
        elif nxt == "h":
            body = " \\t\\xa0\\u1680\\u180e\\u2000-\\u200a\\u202f\\u205f\\u3000"
            self.out.append(body if self.in_class else "[" + body + "]")
        elif nxt == "v":
            body = "\\n\\x0b\\f\\r\\x85\\u2028\\u2029"
            self.out.append(body if self.in_class else "[" + body + "]")
        elif nxt == "R" and not self.in_class:
            self.out.append("(?:\\r\\n|[\\n\\x0b\\f\\r\\x85\\u2028\\u2029])")
        elif nxt == "k" and p.startswith("<", self.i):
            end = p.find(">", self.i)
            self.out.append("(?P=" + p[self.i + 1:end] + ")")
            self.i = end + 1
        elif nxt in "pP" and p.startswith("{", self.i):
            end = p.find("}", self.i)
            name = p[self.i + 1:end]
            body = _JAVA_POSIX.get(name[2:] if name.startswith("Is") else name)
            self.i = end + 1
            if body is None or (nxt == "P" and self.in_class):
                self.out.append("\\" + nxt + "{" + name + "}")  # unsupported: Python reports invalid regex
            elif self.in_class:
                self.out.append(body)
            else:
                self.out.append(("[^" if nxt == "P" else "[") + body + "]")
        else:
            self.out.append("\\" + nxt)


@lru_cache(maxsize=65536)
def java_to_python(pattern: str, case_insensitive: bool) -> str:
    r"""Translate a Java regex to an equivalent Python `re` pattern.

    Compile the result with re.ASCII (and re.IGNORECASE when case_insensitive),
    which reproduces Java's default ASCII \b \w \d \s and ASCII-only case folding.
    Handles: \Q..\E, mid-pattern inline flags (made scoped), (?<name>, \k<name>,
    Java '.' and '$' line-terminator semantics, \z \Z \e \cX \0oct \x{..} \h \v \R
    and POSIX \p{..} classes.
    """
    return _Translator(pattern, case_insensitive).run()


def python_flags(case_insensitive: bool) -> int:
    return re.ASCII | (re.IGNORECASE if case_insensitive else 0)


@lru_cache(maxsize=65536)
def compile_java(pattern: str, case_insensitive: bool) -> re.Pattern[str]:
    """Translate + compile a Java regex (raises re.error when Python cannot compile it)."""
    return re.compile(java_to_python(pattern, case_insensitive), python_flags(case_insensitive))
