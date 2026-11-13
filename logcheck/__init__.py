"""LogCheck: finds sensitive data (card data, personal data, credentials and keys) written to log files.

The scanner reads logs without modifying them, validates every candidate before reporting it
(checksums, number plans, context), and writes reports that hold masked values only, unless the
user explicitly asks for the raw ones.
"""

__version__ = "2.0.0"
