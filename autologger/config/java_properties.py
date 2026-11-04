"""java.util.Properties.load(InputStream) for the openai-config.properties file.

ISO-8859-1 input; '#'/'!' comments; '\\' line continuation; key ends at the first
unescaped '=', ':' or whitespace; \\t \\n \\r \\f \\uXXXX escapes. Later keys win.
"""

from __future__ import annotations

_WS = " \t\f"
_ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    current: str | None = None
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.lstrip(_WS)
        if current is None and (line == "" or line[0] in "#!"):
            continue
        backslashes = len(line) - len(line.rstrip("\\"))
        if backslashes % 2 == 1:
            current = (current or "") + line[:-1]
            continue
        lines.append((current or "") + line)
        current = None
    if current is not None:
        lines.append(current)
    return lines


def _unescape(s: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= len(s):
            i += 1
            continue
        nxt = s[i + 1]
        if nxt == "u":
            digits = s[i + 2:i + 6]
            if len(digits) < 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                raise ValueError("Malformed \\uxxxx encoding.")
            out.append(chr(int(digits, 16)))
            i += 6
        else:
            out.append(_ESCAPES.get(nxt, nxt))
            i += 2
    return "".join(out)


def parse_properties(text: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in _logical_lines(text):
        i, escaped = 0, False
        while i < len(line):
            ch = line[i]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch in "=:" or ch in _WS:
                break
            i += 1
        rest = line[i:].lstrip(_WS)
        if rest[:1] in ("=", ":"):
            rest = rest[1:].lstrip(_WS)
        props[_unescape(line[:i])] = _unescape(rest)
    return props


def load_properties_file(path: str) -> dict[str, str]:
    with open(path, "rb") as fh:
        return parse_properties(fh.read().decode("iso-8859-1"))
