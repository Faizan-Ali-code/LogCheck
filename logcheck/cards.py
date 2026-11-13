"""Optional issuer data that raises confidence in card findings, without clear card numbers anywhere.

- A BIN list: the issuer's own card number prefixes (6 to 11 digits), one per line. A prefix is not
  cardholder data, so the file is not sensitive.
- A PAN hash list: HMAC-SHA256 digests of the issuer's real card numbers, made on the issuer's side with
  ``logcheck hash-pans``. The scanner hashes each candidate with the same key and looks the digest up,
  so it can confirm "this is one of our cards" without a database query that carries clear PANs.

Both lookups are in memory: one pass over the log finds candidates, then each candidate costs one set
lookup per distinct prefix length, however many BINs the list holds.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sys
from typing import Iterable

PAN_HASH_KEY_ENV = "LOGCHECK_PAN_HASH_KEY"
_DIGITS = re.compile(r"[0-9]+")


class BinList:
    def __init__(self, prefixes: Iterable[str]) -> None:
        self.prefixes = {p for p in prefixes if 6 <= len(p) <= 11}
        self.lengths = sorted({len(p) for p in self.prefixes}, reverse=True)

    @classmethod
    def load(cls, path: str) -> BinList:
        prefixes = []
        with open(path, encoding="utf-8-sig") as fh:
            for line in fh:
                first = line.split(",")[0].strip()
                if _DIGITS.fullmatch(first):
                    prefixes.append(first)
        return cls(prefixes)

    def match(self, pan: str) -> str | None:
        """The longest listed prefix of `pan`, or None."""
        for n in self.lengths:
            if pan[:n] in self.prefixes:
                return pan[:n]
        return None

    def __len__(self) -> int:
        return len(self.prefixes)


def pan_digest(pan: str, key: bytes) -> str:
    return hmac.new(key, pan.encode("ascii"), hashlib.sha256).hexdigest()


def pan_hash_key() -> bytes:
    key = os.environ.get(PAN_HASH_KEY_ENV, "")
    if len(key) < 16:
        raise ValueError(f"set {PAN_HASH_KEY_ENV} to the same secret (16+ characters) used to make the hash list")
    return key.encode("utf-8")


class PanHashList:
    def __init__(self, digests: Iterable[str], key: bytes) -> None:
        self.digests = {d.strip().lower() for d in digests if d.strip()}
        self.key = key

    @classmethod
    def load(cls, path: str, key: bytes | None = None) -> PanHashList:
        with open(path, encoding="utf-8") as fh:
            return cls((line for line in fh if not line.startswith("#")), key or pan_hash_key())

    def contains(self, pan: str) -> bool:
        return pan_digest(pan, self.key) in self.digests

    def __len__(self) -> int:
        return len(self.digests)


def hash_pans_cli(lines: Iterable[str], out=None) -> int:
    """Read card numbers (one per line, separators allowed) and write their digests."""
    out = out or sys.stdout
    key = pan_hash_key()
    count = 0
    out.write("# HMAC-SHA256 PAN digests for logcheck --pan-hashes\n")
    for line in lines:
        pan = "".join(_DIGITS.findall(line))
        if 12 <= len(pan) <= 19:
            out.write(pan_digest(pan, key) + "\n")
            count += 1
    return count
