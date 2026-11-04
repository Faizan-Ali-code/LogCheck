"""OpenAI evidence verification. Java: OpenAIVerifier and type stats (o).

Flow per finding: blank evidence -> AI_NOT_CONFIRMED; disabled -> AI_UNAVAILABLE;
exact cache; template cache (volatile numbers/tokens replaced); then type
cooldown / open circuit / budget -> AI_UNAVAILABLE (cached for the run);
otherwise one Responses API call with retries.

Fixes vs Java: the request payload (it contains the evidence) is never logged,
and concurrent identical requests wait for one in-flight call instead of
holding a map lock during HTTP. With legacy_compat=False the verdict is read
from the response's output text instead of a substring search of the raw JSON.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Callable

from autologger import constants as C
from autologger.config.openai_config import OpenAIConfig, load_openai_config
from autologger.jcompat import java_trim
from autologger.scan.patterns import OPENAI_NORMALIZERS_JAVA, compile_java

log = logging.getLogger(__name__)

SYSTEM_PROMPT = ("Security evidence validator. Return only CONFIRMED or NOT_CONFIRMED. Require clear evidence. "
                 "Partial match in larger value=NOT_CONFIRMED. Wrong category=NOT_CONFIRMED. "
                 "Unclear evidence=NOT_CONFIRMED.")

_NUM_OR_HEX = compile_java(OPENAI_NORMALIZERS_JAVA["num_or_hex"], False)
_TOKEN = compile_java(OPENAI_NORMALIZERS_JAVA["token"], False)
_NUM = compile_java(OPENAI_NORMALIZERS_JAVA["num"], False)
_WHITESPACE = compile_java(OPENAI_NORMALIZERS_JAVA["whitespace"], False)
_LINE_BREAKS = re.compile(r"\r\n|\r|\n")
_RETRYABLE_MESSAGES = ("timed out", "timeout", "connection reset", "upstream connect error", "disconnect/reset")

HttpPost = Callable[[str, dict, bytes, "float | None"], tuple[int, str]]


class _NotSent(Exception):
    """The request never reached the server (Java: exception before the body was written)."""


def requests_post(url: str, headers: dict, body: bytes, timeout_s: float | None) -> tuple[int, str]:
    import requests

    try:
        resp = requests.post(url, data=body, headers=headers,
                             timeout=None if timeout_s is None else (timeout_s, timeout_s))
    except requests.exceptions.ConnectionError as exc:  # includes ConnectTimeout; ReadTimeout passes through
        raise _NotSent(str(exc)) from exc
    return resp.status_code, resp.text


@dataclass
class TypeStats:
    requests: int = 0
    cache_hits: int = 0
    template_cache_hits: int = 0
    cache_misses: int = 0
    api_calls: int = 0
    api_failures: int = 0
    circuit_skips: int = 0
    budget_skips: int = 0
    type_cooldown_skips: int = 0


def json_escape(s: str | None) -> str:
    """n.g(): Java's hand-written JSON string escaping."""
    if s is None:
        return ""
    out = []
    for ch in s:
        if ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch < " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def build_payload(model: str, type_key: str, match: str, evidence: str, include_temperature: bool) -> str:
    user = "C=" + java_trim(type_key or "") + "\nM=" + java_trim(match or "") + "\nE=" + java_trim(evidence or "")
    body = ('{"model":"' + json_escape(model) + '","input":[{"role":"system","content":"'
            + json_escape(SYSTEM_PROMPT) + '"},{"role":"user","content":"' + json_escape(user) + '"}]')
    if include_temperature:
        body += ',"temperature":0'
    return body + "}"


def map_verdict(text: str | None) -> str:
    upper = (text or "").upper()
    if "NOT_CONFIRMED" in upper:
        return C.AI_NOT_CONFIRMED
    return C.AI_CONFIRMED if "CONFIRMED" in upper else C.AI_UNAVAILABLE


def output_text(body: str) -> str | None:
    """Text of the Responses API output (output[].content[] items of type output_text)."""
    try:
        data = json.loads(body)
    except ValueError:
        return None
    parts = [c.get("text", "") for item in data.get("output", []) if isinstance(item, dict)
             for c in item.get("content", []) or [] if isinstance(c, dict) and c.get("type") == "output_text"]
    return " ".join(parts) if parts else None


class OpenAIVerifier:
    def __init__(self, workdir: str = ".", http_post: HttpPost | None = None, legacy: bool = True,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.time) -> None:
        self.workdir = workdir
        self.legacy = legacy
        self._post = http_post or requests_post
        self._sleep = sleep
        self._clock = clock
        self._lock = threading.Lock()
        self.config = OpenAIConfig.disabled()
        self._reset()

    # ------------------------------------------------------------------ lifecycle
    def _reset(self) -> None:
        self._exact: dict[str, str] = {}
        self._template: dict[str, str] = {}
        self._type_cooldown_until: dict[str, float] = {}
        self._stats: dict[str, TypeStats] = {}
        self._logged_first_call: set[str] = set()
        self._inflight: dict[str, threading.Event] = {}
        self.requests = self.cache_hits = self.cache_misses = self.template_cache_hits = 0
        self.api_calls = self.api_failures = self.circuit_skips = self.budget_skips = 0
        self.type_cooldown_skips = self.circuit_trips = self.consecutive_failures = 0
        self._request_seq = 0
        self._circuit_open_until = 0.0

    def initialize_for_new_run(self, config: OpenAIConfig | None = None) -> None:
        with self._lock:
            self._reset()
            self.config = config if config is not None else load_openai_config(self.workdir)
        log.info("OpenAI verifier cache initialized for a new application run.")

    def is_enabled(self) -> bool:
        return self.config.enabled

    def _now_ms(self) -> float:
        return self._clock() * 1000.0

    def _type_stats(self, type_key: str) -> TypeStats:
        stats = self._stats.get(type_key)
        if stats is None:
            stats = self._stats.setdefault(type_key, TypeStats())
        return stats

    # ------------------------------------------------------------------ verify
    def verify(self, type_name: str | None, match: str | None, evidence: str | None) -> str:
        if evidence is None or java_trim(evidence) == "":
            return C.AI_NOT_CONFIRMED
        type_key = java_trim(type_name or "") or "UNKNOWN"
        with self._lock:
            stats = self._type_stats(type_key)
            self.requests += 1
            stats.requests += 1
        cfg = self.config
        if not cfg.enabled:
            return C.AI_UNAVAILABLE

        exact_key = (java_trim(type_name or "").lower() + "|" + java_trim(match or "").lower() + "|"
                     + java_trim(evidence))
        template_key = self.template_key(type_key, match, evidence)
        with self._lock:
            cached = self._exact.get(exact_key)
            if cached is not None:
                self.cache_hits += 1
                stats.cache_hits += 1
                return cached
            cached = self._template.get(template_key)
            if cached is not None:
                self.cache_hits += 1
                self.template_cache_hits += 1
                stats.cache_hits += 1
                stats.template_cache_hits += 1
                self._exact.setdefault(exact_key, cached)
                return cached
            self.cache_misses += 1
            stats.cache_misses += 1
            skip = None
            if self._type_cooldown_until.get(type_key, 0) > self._now_ms():
                self.type_cooldown_skips += 1
                stats.type_cooldown_skips += 1
                skip = C.AI_UNAVAILABLE
            elif self._circuit_open_until > self._now_ms():
                self.circuit_skips += 1
                stats.circuit_skips += 1
                skip = C.AI_UNAVAILABLE
            elif self._budget_exceeded(cfg, stats):
                self.budget_skips += 1
                stats.budget_skips += 1
                skip = C.AI_UNAVAILABLE
            if skip is not None:
                self._exact.setdefault(exact_key, skip)
                self._template.setdefault(template_key, skip)
                return skip
            event = self._inflight.get(exact_key)
            owner = event is None
            if owner:
                event = self._inflight[exact_key] = threading.Event()

        if not owner:
            event.wait()
            with self._lock:
                return self._exact.get(exact_key, C.AI_UNAVAILABLE)
        verdict = C.AI_UNAVAILABLE
        try:
            verdict = self._call_api(cfg, type_key, match or "", evidence)
        finally:
            with self._lock:
                verdict = self._exact.setdefault(exact_key, verdict)
                self._template.setdefault(template_key, verdict)
                self._inflight.pop(exact_key, None)
            event.set()
        return verdict

    @staticmethod
    def template_key(type_key: str, match: str | None, evidence: str) -> str:
        text = java_trim(evidence).lower()
        m = java_trim(match or "").lower()
        if m:
            text = text.replace(m, "<match>")
        text = _NUM_OR_HEX.sub("<num_or_hex>", text)
        text = _TOKEN.sub("<token>", text)
        text = _NUM.sub("<num>", text)
        text = java_trim(_WHITESPACE.sub(" ", text))
        return type_key.lower() + "|" + text[:320]

    def _budget_exceeded(self, cfg: OpenAIConfig, stats: TypeStats) -> bool:
        """a(m, o): per-run budget on all API calls, per-type budget on that type's calls (0 = unlimited)."""
        if cfg.max_calls_per_run > 0 and self.api_calls >= cfg.max_calls_per_run:
            return True
        return cfg.max_calls_per_type > 0 and stats.api_calls >= cfg.max_calls_per_type

    # ------------------------------------------------------------------ HTTP
    def _verdict(self, body: str) -> str:
        if not self.legacy:
            text = output_text(body)
            if text is not None:
                return map_verdict(text)
        return map_verdict(body)

    def _call_api(self, cfg: OpenAIConfig, type_key: str, match: str, evidence: str) -> str:
        thread = threading.current_thread().name
        timeout = cfg.timeout_ms / 1000.0 if cfg.timeout_ms > 0 else None
        headers = {"Authorization": "Bearer " + cfg.api_key, "Content-Type": "application/json"}
        include_temp = not java_trim(cfg.model).lower().startswith("gpt-5")
        for attempt in range(1, cfg.max_attempts + 1):
            with self._lock:
                self._request_seq += 1
                req_id = self._request_seq
                first = f"{type_key}|{cfg.model}|{include_temp}" not in self._logged_first_call
                self._logged_first_call.add(f"{type_key}|{cfg.model}|{include_temp}")
            started = time.monotonic()
            body = build_payload(cfg.model, type_key, match, evidence, include_temp)
            log.debug("%s [OpenAI][reqId=%d] Request -> endpoint=%s, type=%s, model=%s, includeTemperature=%s, "
                      "attempt=%d, payloadChars=%d", thread, req_id, cfg.endpoint, type_key, cfg.model,
                      str(include_temp).lower(), attempt, len(body))
            if first:
                log.info("%s [OpenAI][reqId=%d] Calling API for type='%s' model='%s' includeTemperature=%s",
                         thread, req_id, type_key, cfg.model, str(include_temp).lower())
            try:
                status, text = self._send(cfg, type_key, headers, body, timeout)
                elapsed = int((time.monotonic() - started) * 1000)
                text = "".join(_LINE_BREAKS.split(text or ""))
                log.info("%s [OpenAI][reqId=%d] event=httpResponse, status=%d, responseTimeMs=%d, attempt=%d, "
                         "includeTemperature=%s", thread, req_id, status, elapsed, attempt, str(include_temp).lower())
                if 200 <= status < 300:
                    with self._lock:
                        self.consecutive_failures = 0
                    return self._verdict(text)
                if status == 400 and "unsupported parameter" in text.lower() and "temperature" in text.lower():
                    log.info("%s [OpenAI][reqId=%d] temperatureUnsupported=true, status=%d, responseTimeMs=%d. "
                             "Retrying without temperature.", thread, req_id, status, elapsed)
                    return self._call_without_temperature(cfg, type_key, match, evidence)
                if (status in (408, 429) or status >= 500) and attempt < cfg.max_attempts:
                    log.warning("%s [OpenAI][reqId=%d] retryableHttpFailure=true, status=%d, responseTimeMs=%d, "
                                "attempt=%d/%d. Retrying.", thread, req_id, status, elapsed, attempt,
                                cfg.max_attempts)
                    self._backoff(attempt, cfg)
                    continue
                self._record_failure(type_key, cfg)
                log.warning("%s [OpenAI][reqId=%d] verificationFailed=true, status=%d, responseTimeMs=%d, "
                            "response=%s", thread, req_id, status, elapsed, text)
                return C.AI_UNAVAILABLE
            except Exception as exc:  # noqa: BLE001
                if self._retryable(exc) and attempt < cfg.max_attempts:
                    log.warning("[OpenAI][reqId=%d] retryableException=true, attempt=%d/%d, message=%s. Retrying.",
                                req_id, attempt, cfg.max_attempts, exc)
                    self._backoff(attempt, cfg)
                    continue
                self._record_failure(type_key, cfg)
                elapsed = int((time.monotonic() - started) * 1000)
                log.warning("[OpenAI][reqId=%d] verificationFailed=true, exception=true, responseTimeMs=%d, "
                            "message=%s", req_id, elapsed, exc)
                return C.AI_UNAVAILABLE
        self._record_failure(type_key, cfg)
        return C.AI_UNAVAILABLE

    def _call_without_temperature(self, cfg: OpenAIConfig, type_key: str, match: str, evidence: str) -> str:
        thread = threading.current_thread().name
        with self._lock:
            self._request_seq += 1
            req_id = self._request_seq
        started = time.monotonic()
        timeout = cfg.timeout_ms / 1000.0 if cfg.timeout_ms > 0 else None
        headers = {"Authorization": "Bearer " + cfg.api_key, "Content-Type": "application/json"}
        body = build_payload(cfg.model, type_key, match, evidence, False)
        log.info("%s [OpenAI][reqId=%d] Retrying API call without temperature for type='%s' model='%s'",
                 thread, req_id, type_key, cfg.model)
        try:
            status, text = self._send(cfg, type_key, headers, body, timeout)
            elapsed = int((time.monotonic() - started) * 1000)
            text = "".join(_LINE_BREAKS.split(text or ""))
            log.info("%s [OpenAI][reqId=%d] event=httpResponse, status=%d, responseTimeMs=%d, withoutTemperature=true",
                     thread, req_id, status, elapsed)
            if 200 <= status < 300:
                with self._lock:
                    self.consecutive_failures = 0
                return self._verdict(text)
            self._record_failure(type_key, cfg)
            log.warning("[OpenAI][reqId=%d] verificationFailed=true, withoutTemperature=true, status=%d, "
                        "responseTimeMs=%d, response=%s", req_id, status, elapsed, text)
        except Exception as exc:  # noqa: BLE001
            self._record_failure(type_key, cfg)
            elapsed = int((time.monotonic() - started) * 1000)
            log.warning("[OpenAI][reqId=%d] verificationFailed=true, withoutTemperature=true, exception=true, "
                        "responseTimeMs=%d, message=%s", req_id, elapsed, exc)
        return C.AI_UNAVAILABLE

    def _send(self, cfg: OpenAIConfig, type_key: str, headers: dict, body: str,
              timeout: float | None) -> tuple[int, str]:
        try:
            status, text = self._post(cfg.endpoint, headers, body.encode("utf-8"), timeout)
        except _NotSent:
            raise
        except Exception:
            self._count_call(type_key)  # body was written (e.g. read timeout)
            raise
        self._count_call(type_key)
        return status, text

    def _count_call(self, type_key: str) -> None:
        with self._lock:
            self.api_calls += 1
            self._type_stats(type_key).api_calls += 1

    def _backoff(self, attempt: int, cfg: OpenAIConfig) -> None:
        self._sleep(cfg.base_delay_ms * attempt / 1000.0)

    @staticmethod
    def _retryable(exc: Exception) -> bool:
        import requests

        if isinstance(exc, (OSError, requests.exceptions.RequestException, _NotSent)):
            return True
        message = str(exc).lower()
        return any(m in message for m in _RETRYABLE_MESSAGES)

    def _record_failure(self, type_key: str, cfg: OpenAIConfig) -> None:
        with self._lock:
            self.api_failures += 1
            self._type_stats(type_key).api_failures += 1
            if cfg.type_failure_cooldown_ms > 0:
                self._type_cooldown_until[type_key] = self._now_ms() + cfg.type_failure_cooldown_ms
            self.consecutive_failures += 1
            if self.consecutive_failures >= cfg.failure_threshold and cfg.circuit_cooldown_ms > 0:
                until = self._now_ms() + cfg.circuit_cooldown_ms
                if until > self._circuit_open_until:
                    self._circuit_open_until = until
                    self.circuit_trips += 1
                    log.warning("%s OpenAI circuit opened due to repeated failures. Cooldown=%dms.",
                                threading.current_thread().name, cfg.circuit_cooldown_ms)

    # ------------------------------------------------------------------ stats
    def log_stats(self) -> None:
        log.info("\n\n")
        log.info("OpenAI (Overall Stats) -> requests=%d, cacheHits=%d, cacheMisses=%d, templateCacheHits=%d, "
                 "apiCalls=%d, apiFailures=%d, circuitSkips=%d, circuitTrips=%d, budgetSkips=%d, "
                 "typeCooldownSkips=%d, consecutiveFailures=%d, cacheSize=%d, templateCacheSize=%d",
                 self.requests, self.cache_hits, self.cache_misses, self.template_cache_hits, self.api_calls,
                 self.api_failures, self.circuit_skips, self.circuit_trips, self.budget_skips,
                 self.type_cooldown_skips, self.consecutive_failures, len(self._exact), len(self._template))
        for type_key in sorted(self._stats):
            s = self._stats[type_key]
            log.info("OpenAI ('%s' Stats) -> type=%s, requests=%d, cacheHits=%d, templateCacheHits=%d, "
                     "cacheMisses=%d, apiCalls=%d, apiFailures=%d, circuitSkips=%d, budgetSkips=%d, "
                     "typeCooldownSkips=%d", type_key, type_key, s.requests, s.cache_hits, s.template_cache_hits,
                     s.cache_misses, s.api_calls, s.api_failures, s.circuit_skips, s.budget_skips,
                     s.type_cooldown_skips)
