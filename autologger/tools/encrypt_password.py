"""Database password encryption utility. Java: the PasswordEncryption tool.

Usage: python -m autologger.tools.encrypt_password   (needs AUTOLOGGER_DB_KEY)
Fix vs Java: the whole line is read (Java's Scanner.next() stopped at the first
space) and input is not echoed.
"""

from __future__ import annotations

import getpass
import sys

from autologger.config.db_secret import MissingKeyError, encrypt_password


def main() -> int:
    print("\n" * 6)
    print("********************************************************")
    print("**********Database Password Encryption utility**********")
    print("********************************************************\n\n")
    try:
        plain = getpass.getpass("Please Enter Plain Text Password:\n")
    except (EOFError, KeyboardInterrupt):
        return 1
    if plain == "":
        print("No password entered.")
        return 1
    try:
        encrypted = encrypt_password(plain)
    except MissingKeyError as exc:
        print(f"ERROR: {exc}")
        return 1
    print("\n\n")
    print("Encrypted Password:")
    print(encrypted)
    print("\n\n\n")
    print("*Please copy encrypted password and use in Auto Logger 3.0 Default sheet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
