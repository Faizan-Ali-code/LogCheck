"""OpenAI verifier settings. Java: OpenAIConfig.

File: $OPENAI_CONFIG_FILE or openai-config.properties in the working directory.
Missing/invalid numbers fall back to Java's defaults and are clamped the same way.
Addition vs Java: a value written as ${ENV_VAR} is read from the environment,
so the API key does not have to sit in the file.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass

from autologger.config.java_properties import load_properties_file
from autologger.jcompat import java_parse_int

log = logging.getLogger(__name__)

CONFIG_FILE = "openai-config.properties"
CONFIG_ENV = "OPENAI_CONFIG_FILE"
_PLACEHOLDER = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


@dataclass(frozen=True)
class OpenAIConfig:
    enabled: bool
    api_key: str
    model: str
    endpoint: str
    timeout_ms: int
    max_attempts: int
    base_delay_ms: int
    failure_threshold: int
    circuit_cooldown_ms: int
    max_calls_per_run: int
    max_calls_per_type: int
    type_failure_cooldown_ms: int

    @staticmethod
    def disabled() -> "OpenAIConfig":
        return OpenAIConfig(False, "", "", "", 0, 1, 0, 1, 0, 0, 0, 0)


def _clean(value: str | None) -> str:
    value = "" if value is None else value.strip()
    m = _PLACEHOLDER.match(value)
    return os.environ.get(m.group(1), "").strip() if m else value


def _int(value: str, fallback: int) -> int:
    if value.strip() == "":
        return fallback
    try:
        return java_parse_int(value.strip())
    except ValueError:
        return fallback


def config_path(workdir: str) -> str:
    env_path = (os.environ.get(CONFIG_ENV) or "").strip()
    return env_path if env_path else os.path.join(workdir, CONFIG_FILE)


def load_openai_config(workdir: str = ".") -> OpenAIConfig:
    path = config_path(workdir)
    if not os.path.exists(path):
        log.info("OpenAI config file not found at path: %s", os.path.abspath(path))
        return OpenAIConfig.disabled()
    try:
        props = load_properties_file(path)
    except Exception:  # noqa: BLE001
        log.error("Failed loading OpenAI config file: %s", os.path.abspath(path), exc_info=True)
        return OpenAIConfig.disabled()

    get = lambda key: _clean(props.get(key))  # noqa: E731
    key = get("openai.api.key")
    model = get("openai.model") or "gpt-4.1-mini"
    endpoint = get("openai.endpoint") or "https://api.openai.com/v1/responses"
    timeout = _int(get("openai.timeout.ms"), 15000)
    attempts = max(1, _int(get("openai.retry.max.attempts"), 3))
    delay = max(0, _int(get("openai.retry.base.delay.ms"), 700))
    threshold = max(1, _int(get("openai.circuit.failure.threshold"), 4))
    cooldown = max(0, _int(get("openai.circuit.cooldown.ms"), 60000))
    per_run = max(0, _int(get("openai.max.calls.per.run"), 60))
    per_type = max(0, _int(get("openai.max.calls.per.type"), 12))
    type_cooldown = max(0, _int(get("openai.type.failure.cooldown.ms"), 120000))

    enabled = get("openai.enabled").lower() == "true"
    if enabled and key == "":
        log.warning("OpenAI is enabled in config but openai.api.key is empty.")
        enabled = False
    if not enabled:
        return OpenAIConfig.disabled()
    return OpenAIConfig(True, key, model, endpoint, timeout, attempts, delay, threshold, cooldown,
                        per_run, per_type, type_cooldown)
