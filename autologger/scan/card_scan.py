"""Card number pipeline. Java: CardNumberScanner with b, c, d.

Per card length (19 -> 13): BIN-prefixed (or generic) digit scans, overlap
filter against longer cards already found in the file, de-duplication by
position, Luhn check, DB verification (`cards` table), tokenized lookups
(first2 + 'T%' + last4) and the Vulnerable / Not Vulnerable / Review Manually
decision. Card rows never go to OpenAI.
"""

from __future__ import annotations

import logging
import re
import threading
import unicodedata
from functools import partial

from autologger import constants as C
from autologger.context import ScanContext
from autologger.control import Interrupted, interrupt_current_thread
from autologger.db.card_database import DbError
from autologger.jcompat import java_parse_int, java_split, java_trim
from autologger.report.excel_writer import csv_quote
from autologger.report.paths import ReportPaths
from autologger.scan.backend import FileSnapshot, ScanAborted
from autologger.scan.regex_engine import Occurrence
from autologger.scan.scan_utils import evidence, scan_java_regexes, write_occurrences

log = logging.getLogger(__name__)

_SPEC_SPLIT = re.compile(r"\s*,\s*", re.ASCII)
_LENGTH_IN_SPEC = re.compile(r"\{(\d+)\}", re.ASCII)
_PAN_RUN = re.compile(r"\d{10,}")
IN_QUERY_CHUNK = 500  # non-legacy only


def _thread() -> str:
    return threading.current_thread().name


def mask_pans(text: str) -> str:
    """Mask card-like digit runs before they reach the app log (Java logged full PANs)."""
    def repl(m: re.Match[str]) -> str:
        s = m.group(0)
        keep_head, keep_tail = (6, 4) if len(s) >= 13 else (2, 2)
        return s[:keep_head] + "*" * (len(s) - keep_head - keep_tail) + s[-keep_tail:]
    return _PAN_RUN.sub(repl, text)


def parse_spec(spec: str) -> tuple[bool, int]:
    """CardRegexSpec: 'T' -> tokenized length 19; else the first {n}; else length 0."""
    if spec == "T":
        return True, 19
    m = _LENGTH_IN_SPEC.search(spec)
    if m:
        try:
            return False, java_parse_int(m.group(1))
        except ValueError:
            pass
    return False, 0


def luhn_ok(number: str | None) -> bool:
    if not number:
        return False
    total, double = 0, False
    for ch in reversed(number):
        if unicodedata.category(ch) != "Nd":  # Character.isDigit
            return False
        digit = ord(ch) - 48
        if double:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        double = not double
    return total % 10 == 0


def vulnerability_status(luhn: str, db: str) -> str:
    if db == C.DB_VERIFIED:
        return C.STATUS_VULNERABLE
    if db == C.DB_VERIFIED_TOKENIZED:
        return C.STATUS_VULNERABLE if luhn == C.LUHN_PASSED else C.STATUS_REVIEW
    return C.STATUS_NOT_VULNERABLE if luhn == C.LUHN_FAILED else C.STATUS_REVIEW


def in_query(cards: list[str]) -> str:
    if not cards:
        return "select card_no from cards where 1=0;"
    return "select card_no from cards where card_no in ('" + "','".join(cards) + "');"


def like_query(patterns: list[str]) -> str:
    return "select card_no from cards where " + " or ".join(f"card_no like '{p}'" for p in patterns) + ";"


def token_like_patterns(cards: list[str]) -> list[str]:
    return [c[:2] + "T%" + c[-4:] for c in cards if c is not None and len(c) >= 6]


class OverlapTracker:
    """Spans of cards already reported in this file, per length (Java c/d)."""

    def __init__(self) -> None:
        self._spans: dict[int, list[tuple[int, int]]] = {}
        self._lock = threading.Lock()

    def add(self, length: int, occurrences: list[Occurrence]) -> None:
        with self._lock:
            self._spans.setdefault(length, []).extend((o.start, o.end) for o in occurrences)

    def overlaps(self, start: int, end: int) -> bool:
        with self._lock:
            return any(s_end > start and s_start < end
                       for spans in self._spans.values() for s_start, s_end in spans)


class CardNumberScanner:
    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx

    # ------------------------------------------------------------------ entry
    def scan(self, card_regex_list: str, db_url: str | None, snapshot: FileSnapshot,
             before: int, after: int, bins: list[str]) -> None:
        ctx = self.ctx
        before, after = max(0, before), max(0, after)
        paths = ReportPaths.for_cards(snapshot.path)
        ctx.reports.ensure_header(paths.summary, C.CARD_SUMMARY_HEADER)
        ctx.reports.ensure_header(paths.overall, C.OVERALL_HEADER)
        specs = (java_split(_SPEC_SPLIT, card_regex_list)
                 if card_regex_list is not None and java_trim(card_regex_list) != "" else [])
        tracker = OverlapTracker()
        verified = ctx.verified_offsets if ctx.legacy else set()
        scan_spec = partial(self._scan_spec, db_url=db_url, snapshot=snapshot, before=before, after=after,
                            bins=bins, paths=paths, tracker=tracker, verified=verified)
        try:
            by_length: dict[int, list[str]] = {}
            for spec in specs:
                by_length.setdefault(parse_spec(spec)[1], []).append(spec)
            if len(specs) > 1 and ctx.executors.regex_parallel:
                for length in sorted(by_length, reverse=True):
                    if not ctx.checkpoint():
                        return
                    group = by_length[length]
                    if len(group) == 1:
                        scan_spec(group[0])
                    else:
                        ctx.executors.run_regexes([partial(scan_spec, s) for s in group],
                                                  f"card regex scan (length: {length} digits)")
            else:
                for spec in specs:
                    if not ctx.checkpoint():
                        return
                    scan_spec(spec)
        except ScanAborted:
            return
        except Exception as exc:  # noqa: BLE001
            log.error("%s ####ERROR: Regex iteration failed. Details: %s", _thread(), exc, exc_info=True)
        finally:
            ctx.reports.flush(paths.summary, paths.overall)

    # ------------------------------------------------------------------ one card regex
    def _scan_spec(self, spec: str, *, db_url: str | None, snapshot: FileSnapshot, before: int, after: int,
                   bins: list[str], paths: ReportPaths, tracker: OverlapTracker, verified: set[str]) -> None:
        ctx = self.ctx
        if not ctx.checkpoint() or spec is None or java_trim(spec) == "":
            return
        file_path, content = snapshot.path, snapshot.content
        tokenized, length = parse_spec(spec)
        if tokenized:
            log.info("%s Processing tokenized card, length:%d in file '%s'.", _thread(), length, file_path)
        log.info("%s Processing cards, length:%d in file '%s'.", _thread(), length, file_path)

        cards: list[str] = []
        occs: list[Occurrence] = []
        try:
            if tokenized:
                patterns = [C.TOKENIZED_CARD_REGEX]
            elif bins:
                patterns = [b + "\\d{" + str(length - len(b)) + "}" for b in bins
                            if b is not None and length - len(b) > 0]
            else:
                log.warning("%s BIN list is empty for file '%s'. Falling back to generic %d-digit scan and "
                            "marking DB verification as Unavailable if DB checks fail.", _thread(), file_path, length)
                patterns = ["\\d{" + str(length) + "}"] if length > 0 else []
            for grouped in scan_java_regexes(ctx, C.CARD_NO, patterns, snapshot, case_insensitive=False):
                for key, found in grouped.items():
                    cards.append(key)
                    occs.extend(found)
        except ScanAborted:
            raise
        except Exception as exc:  # noqa: BLE001
            log.error("####ERROR: BIN iteration failed. Exception details: %s", exc, exc_info=True)

        if not tokenized:
            kept = [o for o in occs if not tracker.overlaps(o.start, o.end)]
            if len(kept) < len(occs):
                log.debug("%s Filtered out %d overlapping matches for %d-digit cards.",
                          _thread(), len(occs) - len(kept), length)
            occs = kept

        unique_positions: dict[str, Occurrence] = {}
        for occ in occs:
            unique_positions.setdefault(f"{occ.start}-{occ.end}", occ)
        if len(unique_positions) < len(occs):
            log.debug("%s Removed %d duplicate position matches for %d-digit cards (matched by multiple BINs at "
                      "same location).", _thread(), len(occs) - len(unique_positions), length)
        occs = list(unique_positions.values())

        sorted_cards = sorted(set(cards))
        verified_cards = self._verify_cards(sorted_cards, db_url)
        if verified_cards is None:
            verified_cards = self._verify_cards_with_retry(sorted_cards, db_url)
        db_available = verified_cards is not None
        verified_set = set(verified_cards or [])
        tokens: list[str] = []
        if db_available:
            unverified = [c for c in sorted_cards if c not in verified_set]
            tokens = self._lookup_tokens(token_like_patterns(unverified), db_url) or []

        grouped: dict[str, list[Occurrence]] = {}
        for occ in occs:
            grouped.setdefault(occ.match, []).append(occ)
        vulnerable = [0]

        def formatter(match_text: str, occ: Occurrence, ev: str) -> str:
            luhn = C.LUHN_PASSED if luhn_ok(match_text) else C.LUHN_FAILED
            if not db_available:
                db = C.DB_UNAVAILABLE
            elif match_text in verified_set:
                db = C.DB_VERIFIED
                verified.add(str(occ.start))
            else:
                db = C.DB_NOT_VERIFIED
            status = vulnerability_status(luhn, db)
            if status == C.STATUS_VULNERABLE:
                vulnerable[0] += 1
                ctx.progress.vulnerable_card()
            return ",".join((csv_quote(match_text), str(length), csv_quote(file_path), csv_quote(occ.level),
                             csv_quote(ev), csv_quote(luhn), csv_quote(db), csv_quote(status)))

        if grouped:
            write_occurrences(ctx, paths.summary, content, grouped, before, after, formatter)
        else:
            log.info("%s No card number with length %d was identified in file '%s'.", _thread(), length, file_path)

        if not tokenized and occs:
            tracker.add(length, occs)

        for token in tokens:
            if not ctx.checkpoint():
                return
            if token is None or len(token) < 6:
                continue
            prefix, suffix = token[:2], token[-4:]
            for occ in occs:
                match = occ.match
                if match is None or len(match) < 6:
                    continue
                if str(occ.start) not in verified and match.startswith(prefix) and match.endswith(suffix):
                    if not ctx.checkpoint():
                        return
                    ev = evidence(content, occ.start, occ.end, before, after)
                    status = vulnerability_status("N/A", C.DB_VERIFIED_TOKENIZED)
                    ctx.reports.write(paths.summary, ",".join((
                        csv_quote(token), str(length), csv_quote(file_path), csv_quote(occ.level), csv_quote(ev),
                        csv_quote("N/A"), csv_quote(C.DB_VERIFIED_TOKENIZED), csv_quote(status))))
                    ctx.progress.finding_written()

        label = f"{length} digits Tokenized regex" if tokenized else f"{length} digits regex"
        ctx.reports.write(paths.overall, ",".join((csv_quote(f"Card Number {length} Digits"), csv_quote(label),
                                                   csv_quote(file_path), str(vulnerable[0]), "0", csv_quote("N/A"))))

    # ------------------------------------------------------------------ DB flows
    def _connect_with_retry(self, db_url: str | None, sql_for_log: str) -> object | None:
        """Shared retry loop of a.c(List) / a.b(List): 3 x 5 s, then interrupt the thread."""
        ctx = self.ctx
        conn = ctx.card_db.connect(db_url, log_errors=True)
        attempts = 0
        while conn is None and attempts < C.DB_RETRY_ATTEMPTS:
            try:
                log.info("%s Could not get a DB connection. Retrying in 5 seconds.", _thread())
                ctx.control.interruptible_sleep(ctx.settings.db_retry_delay)
                conn = ctx.card_db.connect(db_url, log_errors=False)
                attempts += 1
                if conn is None:
                    log.info("%s Retry %d failed to get a DB connection.", _thread(), attempts)
                if conn is None and attempts == C.DB_RETRY_ATTEMPTS:
                    log.error("%s Stopping retries after %d attempts because a DB connection could not be "
                              "established.", _thread(), attempts)
                    log.error("%s ####ERROR: Could not verify the following cards from DB due to DB connection "
                              "unavailability: %s", _thread(), mask_pans(sql_for_log))
                    interrupt_current_thread()
            except Interrupted:
                interrupt_current_thread()
                return None
        return conn

    def _run_queries(self, conn: object, queries: list[str]) -> list[str]:
        rows: list[str] = []
        for sql in queries:
            rows.extend(self.ctx.card_db.query(conn, sql))
        return rows

    def _verify_cards(self, cards: list[str], db_url: str | None) -> list[str] | None:
        """a.c(List, String): cards found in `cards`; [] for no cards; None if the DB is unavailable."""
        if not cards:
            return []
        sql = in_query(cards)
        conn = self._connect_with_retry(db_url, sql)
        if conn is None:
            log.warning("%s Skipping card DB verification because DB connection is unavailable.", _thread())
            return None
        queries = ([sql] if self.ctx.legacy else
                   [in_query(cards[i:i + IN_QUERY_CHUNK]) for i in range(0, len(cards), IN_QUERY_CHUNK)])
        try:
            rows = self._run_queries(conn, queries)
            log.debug("%s Verifying cards from DB using query: %s", _thread(), mask_pans(sql))
            return rows
        except DbError as exc:
            log.error("%s ####ERROR: Could not verify following cards from DB: %s", _thread(), mask_pans(sql))
            log.error("Exception details: %s", exc)
            return None
        finally:
            self.ctx.card_db.close_quietly(conn)

    def _verify_cards_with_retry(self, cards: list[str], db_url: str | None) -> list[str] | None:
        """a.a(List, String)."""
        ctx = self.ctx
        attempts = 0
        result: list[str] | None = None
        while result is None and attempts < C.DB_RETRY_ATTEMPTS:
            try:
                log.info("%s Could not verify cards from DB. Retrying in 5 seconds.", _thread())
                ctx.control.interruptible_sleep(ctx.settings.db_retry_delay)
                result = self._verify_cards(cards, db_url)
                attempts += 1
                if result is None:
                    log.info("%s Retry %d failed to verify cards from DB.", _thread(), attempts)
                if result is None and attempts == C.DB_RETRY_ATTEMPTS:
                    log.error("%s Stopping retries after %d attempts because cards could not be verified from DB.",
                              _thread(), attempts)
                    log.error("%s ####ERROR: Could not verify the following cards from DB: %s",
                              _thread(), mask_pans(in_query(cards)))
                    interrupt_current_thread()
            except Interrupted:
                interrupt_current_thread()
                return None
        return result

    def _lookup_tokens(self, patterns: list[str], db_url: str | None) -> list[str] | None:
        """a.b(List, String): tokenized card numbers matching first2 + 'T%' + last4."""
        if not patterns:
            return []
        sql = like_query(patterns)
        conn = self._connect_with_retry(db_url, sql)
        if conn is None:
            log.warning("%s Skipping token DB verification because DB connection is unavailable.", _thread())
            return None
        try:
            rows = self.ctx.card_db.query(conn, sql)
            log.debug("%s Verifying tokens from DB using query: %s", _thread(), mask_pans(sql))
            return rows
        except DbError as exc:
            log.error("%s ####ERROR: Could not verify following cards from DB: %s", _thread(), mask_pans(sql))
            log.error("Exception details: %s", exc)
            return None
        finally:
            self.ctx.card_db.close_quietly(conn)
