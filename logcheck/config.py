"""Settings: built-in defaults, optionally overridden by a TOML file, then by command-line options.

See logcheck.example.toml for every key with its default.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields

DEFAULT_INCLUDE = ["*.log", "*.log.*", "*.txt", "*.out", "*.err", "*.json", "*.gz"]
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
REPORT_FORMATS = ("csv", "json", "xlsx")

# TOML section -> {key in the file: attribute of Config}
_SECTIONS = {
    "scan": {"include": "include", "exclude": "exclude", "workers": "workers", "context_chars": "context_chars",
             "min_confidence": "min_confidence"},
    "detectors": {"enable": "enable", "disable": "disable"},
    "cards": {"bin_list": "bin_list", "pan_hashes": "pan_hashes"},
    "report": {"formats": "formats", "output_dir": "output_dir", "include_values": "include_values"},
    "ai": {"enabled": "ai_enabled", "model": "ai_model", "max_calls": "ai_max_calls", "endpoint": "ai_endpoint"},
}


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    include: list[str] = field(default_factory=lambda: list(DEFAULT_INCLUDE))
    exclude: list[str] = field(default_factory=list)
    workers: int = 0  # 0 = one per CPU
    context_chars: int = 60
    min_confidence: str = "low"
    enable: list[str] = field(default_factory=list)  # empty = every detector that is on by default
    disable: list[str] = field(default_factory=list)
    bin_list: str = ""
    pan_hashes: str = ""
    formats: list[str] = field(default_factory=lambda: ["csv", "json", "xlsx"])
    output_dir: str = ""  # empty = ./logcheck-report-<timestamp>
    include_values: bool = False
    ai_enabled: bool = False
    ai_model: str = "gpt-4.1-mini"
    ai_max_calls: int = 50
    ai_endpoint: str = "https://api.openai.com/v1/chat/completions"

    def validate(self) -> Config:
        if self.min_confidence not in CONFIDENCE_ORDER:
            raise ConfigError(f"min_confidence must be one of {', '.join(CONFIDENCE_ORDER)}")
        bad = [f for f in self.formats if f not in REPORT_FORMATS]
        if bad:
            raise ConfigError(f"unknown report format(s): {', '.join(bad)} (use {', '.join(REPORT_FORMATS)})")
        if self.workers < 0 or self.context_chars < 0 or self.ai_max_calls < 0:
            raise ConfigError("workers, context_chars and ai max_calls cannot be negative")
        return self


def load_config(path: str | None) -> Config:
    cfg = Config()
    if not path:
        return cfg
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    types = {f.name: f.type for f in fields(Config)}
    for section, values in data.items():
        if section not in _SECTIONS or not isinstance(values, dict):
            raise ConfigError(f"{path}: unknown section [{section}]")
        for key, value in values.items():
            attr = _SECTIONS[section].get(key)
            if attr is None:
                raise ConfigError(f"{path}: unknown key '{key}' in [{section}]")
            expected = types[attr]
            ok = {"int": isinstance(value, int) and not isinstance(value, bool), "bool": isinstance(value, bool),
                  "str": isinstance(value, str),
                  "list[str]": isinstance(value, list) and all(isinstance(v, str) for v in value)}[expected]
            if not ok:
                raise ConfigError(f"{path}: [{section}] {key} must be of type {expected}")
            setattr(cfg, attr, value)
    return cfg.validate()
