"""Literal values shared across the tool (names, headers, thresholds).

Every string here is part of the output/config contract of the Java tool, so
changing one changes the reports or the Default.xls format.
"""

DEFAULT_SHEET = "Default.xls"
TEST_CASES_SHEET = "Test Cases"
VARIABLES_SHEET = "Variables"

VAR_LOGS_FOLDER = "Logs Folder Path"
VAR_DB_STRING = "DB String"
VAR_WORDS_BEFORE = "Words Before"
VAR_WORDS_AFTER = "Words After"

# Built-in test-case names (exact, case-sensitive; note no space in "Session IDs,Tokens").
CARD_NO = "Card No"
SSN = "SSN"
EXPIRY_DOB = "Expiry Date, DOB"
PASSWORD = "Password"
PIN_CVC = "PIN, AccessCode, CVC"
DB_STRING = "DB String"
CARD_TRACK = "Card Track"
CRYPTO_KEYS = "Cryptographic Keys"
DDA = "DDA No, Account No"
SESSION_TOKENS = "Session IDs,Tokens"
SOFTWARE = "Software, Framework"

BUILT_IN_TEST_CASES = (
    CARD_NO, SSN, EXPIRY_DOB, PASSWORD, PIN_CVC, DB_STRING,
    CARD_TRACK, CRYPTO_KEYS, DDA, SESSION_TOKENS, SOFTWARE,
)

# Report files and headers.
SUMMARY_SUFFIX = "Summary_Report.xlsx"
OVERALL_SUFFIX = "Overall_Status.xlsx"
SUMMARY_HEADER_TAIL = ",Regular Expression,Log File,Log Level, Evidence,Vulnerability confirm with AI"
OVERALL_HEADER = "Sensitive Info,Regular Expression,Log File,Total Occurrences,AI Confirmed Occurrences,AI Verification"
CARD_SUMMARY_HEADER = ("Card Number,Card Length,Log File,Log Level,Evidence,Luhn Checksum,"
                       "Verified in DB,Vulnerability Status")
REPORT_SHEET_NAME = "Report"
EXCEL_MAX_CELL_CHARS = 32767

# Scanning.
FILE_POOL_SIZE = 5
SPLIT_THRESHOLD_KB = 200000
SPLIT_CHUNK_MB = 150
KEYWORD_WINDOW_CHARS = 80
CARD_REGEX_LIST = "T,[0-9]{19},[0-9]{18},[0-9]{17},[0-9]{16},[0-9]{15},[0-9]{14},[0-9]{13}"
TOKENIZED_CARD_REGEX = r"\d{2}T\d{16}"
TRACK_DATA_LEGACY_NAMES = ("Track Data1", "Track Data2")
MASKED_TEST_CASES = ("Password", "Passphrase")

# Database.
DB_RETRY_ATTEMPTS = 3
DB_RETRY_DELAY_SECONDS = 5.0
INFORMIX_DRIVER_CLASS = "com.informix.jdbc.IfxDriver"
# Example only: point it at your own schema with AUTOLOGGER_BIN_QUERY (see settings.py).
# It must return one BIN (card number prefix) per row in its first column.
BIN_QUERY = "select distinct bin from card_bin_ranges where length(bin) > 4 and length(bin) < 16;"

# AI verification results.
AI_CONFIRMED = "AI_CONFIRMED"
AI_NOT_CONFIRMED = "AI_NOT_CONFIRMED"
AI_UNAVAILABLE = "AI_UNAVAILABLE"
AI_SKIPPED_DEBUG_TRACE = "AI_SKIPPED_DEBUG_TRACE"

# Card verification values.
LUHN_PASSED = "Passed"
LUHN_FAILED = "Failed"
DB_VERIFIED = "Verified"
DB_NOT_VERIFIED = "Not Verified"
DB_UNAVAILABLE = "Unavailable"
DB_VERIFIED_TOKENIZED = "Verified-Tokenized"
STATUS_VULNERABLE = "Vulnerable"
STATUS_NOT_VULNERABLE = "Not Vulnerable"
STATUS_REVIEW = "Review Manually"

# Run status texts shown in the GUI.
STATUS_READY = "Ready"
STATUS_RUNNING = "Running"
STATUS_COMPLETED = "Completed"
STATUS_STOPPED = "Stopped by user"
STATUS_FAILED_NO_SHEET = "Failed: Default.xls not found"
STATUS_FAILED_BAD_PATH = "Failed: Invalid log path"
