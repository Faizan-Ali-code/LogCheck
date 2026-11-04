"""DB password encryption. Java: DecryptDBstring and the PasswordEncryption tool.

AES-128/ECB/PKCS5Padding; the ciphertext is uppercase hex placed after
';password=' in the Default.xls DB String. The key is NOT part of the code: it
comes from the AUTOLOGGER_DB_KEY environment variable (32 hex characters), so
every install chooses its own. ECB with a symmetric key keeps the password out
of plain sight in Default.xls; it is obfuscation, not strong protection.
"""

from __future__ import annotations

import logging
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from autologger.jcompat import java_parse_hex_byte

log = logging.getLogger(__name__)

KEY_ENV = "AUTOLOGGER_DB_KEY"
_MARKER = ";password="


class MissingKeyError(RuntimeError):
    """AUTOLOGGER_DB_KEY is not set to 32 hex characters (an AES-128 key)."""

    def __init__(self) -> None:
        super().__init__(
            f"{KEY_ENV} is not set to 32 hex characters. Create a key once with\n"
            '    python -c "import secrets; print(secrets.token_hex(16))"\n'
            f"and set it as the {KEY_ENV} environment variable (the same value on every machine "
            "that reads your Default.xls).")


def _key() -> bytes:
    try:
        key = bytes.fromhex(os.environ.get(KEY_ENV, "").strip())
    except ValueError:
        key = b""
    if len(key) != 16:
        raise MissingKeyError()
    return key


def _hex_to_bytes(hex_text: str) -> bytes:
    """Java g.b(): pairs of hex digits; an odd trailing character is ignored."""
    return bytes(java_parse_hex_byte(hex_text[i * 2:i * 2 + 2]) for i in range(len(hex_text) // 2))


def decrypt_password_hex(hex_text: str) -> str:
    cipher = Cipher(algorithms.AES(_key()), modes.ECB()).decryptor()
    padded = cipher.update(_hex_to_bytes(hex_text)) + cipher.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    raw = unpadder.update(padded) + unpadder.finalize()
    return raw.decode("utf-8", errors="replace")  # new String(bytes) with Java 18+ default UTF-8


def encrypt_password(plain: str) -> str:
    padder = padding.PKCS7(128).padder()
    data = padder.update(plain.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(_key()), modes.ECB()).encryptor()
    return (cipher.update(data) + cipher.finalize()).hex().upper()


def decrypt_db_string(db_string: str | None) -> str | None:
    """Replace the hex after the LAST ';password=' with the plaintext; None (logged) on failure.

    Raises ValueError for a missing DB String, like Java's NullPointerException
    (the card scan then logs 'Could not connect to the database' and is skipped).
    """
    if db_string is None:
        raise ValueError("DB String is missing")
    idx = db_string.rfind(_MARKER)
    cut = idx + len(_MARKER)  # Java: lastIndexOf(...) + 10, also when not found (-1 + 10)
    try:
        plain = decrypt_password_hex(db_string[cut:])
    except MissingKeyError as exc:
        log.error("###ERROR: Unable to decrypt DB password. %s", exc)
        return None
    except Exception:  # noqa: BLE001 - any crypto/hex failure
        log.error("###ERROR: Unable to decrypt DB password because the provided password is invalid.")
        return None
    return db_string[:cut] + plain
