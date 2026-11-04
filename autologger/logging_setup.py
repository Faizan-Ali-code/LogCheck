"""Logging configured from log4j.xml (the same file the Java tool used).

Supported subset: Console/File/RollingFileAppender, PatternLayout with
%d{SimpleDateFormat} %p (with padding) %m %n %c %t %%, logger/root levels,
additivity and appender-refs. Level names are log4j's (WARN, FATAL).

Fixes vs Java: appenders that point at the same file share one handle, so the
10 MB rollover works (log4j opened the file twice and never rolled on Windows),
and configuration happens once per process (Java re-ran it on every Start,
which removed the GUI log appender).
"""

from __future__ import annotations

import logging
import os
import re
import sys
import threading
import time
import xml.etree.ElementTree as ET

DEFAULT_PATTERN = "%d{yyyy-MM-dd HH:mm:ss}-%-5p - %m%n"
_LOG4J_LEVELS = {"ALL": logging.NOTSET, "TRACE": 5, "DEBUG": logging.DEBUG, "INFO": logging.INFO,
                 "WARN": logging.WARNING, "ERROR": logging.ERROR, "FATAL": logging.CRITICAL,
                 "OFF": logging.CRITICAL + 10}
_LEVEL_NAMES = {5: "TRACE", logging.DEBUG: "DEBUG", logging.INFO: "INFO", logging.WARNING: "WARN",
                logging.ERROR: "ERROR", logging.CRITICAL: "FATAL"}
_SIZE = re.compile(r"^\s*(\d+)\s*(KB|MB|GB)?\s*$", re.IGNORECASE)
_configured = False
_config_lock = threading.Lock()


def log4j_level_name(levelno: int) -> str:
    return _LEVEL_NAMES.get(levelno, logging.getLevelName(levelno))


def _java_date(fmt: str, ts: float) -> str:
    t = time.localtime(ts)
    millis = int((ts - int(ts)) * 1000)
    tokens = {"yyyy": f"{t.tm_year:04d}", "yy": f"{t.tm_year % 100:02d}", "MM": f"{t.tm_mon:02d}",
              "dd": f"{t.tm_mday:02d}", "HH": f"{t.tm_hour:02d}", "mm": f"{t.tm_min:02d}",
              "ss": f"{t.tm_sec:02d}", "SSS": f"{millis:03d}"}
    return re.sub(r"yyyy|yy|MM|dd|HH|mm|ss|SSS", lambda m: tokens[m.group(0)], fmt)


class PatternLayout(logging.Formatter):
    """log4j PatternLayout. %n is the platform line separator (CRLF on Windows), as in log4j."""

    _TOKEN = re.compile(r"%(-?\d+)?([dpmnctr%])(\{[^}]*\})?")

    def __init__(self, pattern: str = DEFAULT_PATTERN) -> None:
        super().__init__()
        self.pattern = pattern

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        if record.exc_info:
            message += os.linesep + self.formatException(record.exc_info).replace("\n", os.linesep)

        def render(m: re.Match[str]) -> str:
            width, conv, arg = m.group(1), m.group(2), m.group(3)
            if conv == "d":
                value = _java_date(arg[1:-1] if arg else "yyyy-MM-dd HH:mm:ss,SSS", record.created)
            elif conv == "p":
                value = log4j_level_name(record.levelno)
            elif conv == "m":
                value = message
            elif conv == "n":
                value = os.linesep
            elif conv == "c":
                value = record.name
            elif conv == "t":
                value = record.threadName or ""
            elif conv == "r":
                value = str(int((record.created - logging._startTime) * 1000))  # noqa: SLF001
            else:
                value = "%"
            if width:
                w = int(width)
                value = value.ljust(-w) if w < 0 else value.rjust(w)
            return value

        return self._TOKEN.sub(render, self.pattern)


class SharedLogFile:
    """One open file per path, with log4j-style size rollover (file -> file.1 -> ... file.N)."""

    _registry: dict[str, "SharedLogFile"] = {}

    def __init__(self, path: str, append: bool, max_bytes: int, backups: int) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.backups = backups
        self.lock = threading.RLock()
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.stream = open(path, "a" if append else "w", encoding="utf-8", newline="")

    @classmethod
    def get(cls, path: str, append: bool, max_bytes: int, backups: int) -> "SharedLogFile":
        key = os.path.normcase(os.path.abspath(path))
        existing = cls._registry.get(key)
        if existing is None:
            existing = cls._registry[key] = SharedLogFile(path, append, max_bytes, backups)
        else:
            if max_bytes and (not existing.max_bytes or max_bytes < existing.max_bytes):
                existing.max_bytes = max_bytes
            existing.backups = max(existing.backups, backups)
        return existing

    def write(self, text: str) -> None:
        with self.lock:
            self.stream.write(text)
            self.stream.flush()
            if self.max_bytes and self.stream.tell() >= self.max_bytes:
                self._roll_over()

    def _roll_over(self) -> None:
        self.stream.close()
        try:
            if self.backups > 0:
                oldest = f"{self.path}.{self.backups}"
                if os.path.exists(oldest):
                    os.remove(oldest)
                for i in range(self.backups - 1, 0, -1):
                    if os.path.exists(f"{self.path}.{i}"):
                        os.replace(f"{self.path}.{i}", f"{self.path}.{i + 1}")
                os.replace(self.path, f"{self.path}.1")
                mode = "w"
            else:
                mode = "w"
        except OSError:
            mode = "a"  # could not rename; keep appending rather than lose logs
        self.stream = open(self.path, mode, encoding="utf-8", newline="")


class _FileAppender(logging.Handler):
    def __init__(self, shared: SharedLogFile, layout: PatternLayout) -> None:
        super().__init__()
        self.shared = shared
        self.setFormatter(layout)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.shared.write(self.format(record))
        except Exception:  # noqa: BLE001
            self.handleError(record)


class _ConsoleAppender(logging.Handler):
    def __init__(self, layout: PatternLayout) -> None:
        super().__init__()
        self.setFormatter(layout)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            text = self.format(record).replace(os.linesep, "\n")
            stream = sys.stdout
            if stream is not None:
                try:
                    stream.write(text)
                except UnicodeEncodeError:
                    stream.write(text.encode(stream.encoding or "utf-8", "replace").decode(stream.encoding or "utf-8"))
                stream.flush()
        except Exception:  # noqa: BLE001
            self.handleError(record)


def _size(value: str | None, default: int) -> int:
    m = _SIZE.match(value or "")
    if not m:
        return default
    mult = {"KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}.get((m.group(2) or "").upper(), 1)
    return int(m.group(1)) * mult


def _params(el: ET.Element) -> dict[str, str]:
    return {p.get("name", "").lower(): p.get("value", "") for p in el.findall("param")}


def _build_appender(el: ET.Element, base_dir: str) -> logging.Handler | None:
    cls = el.get("class", "")
    params = _params(el)
    layout_el = el.find("layout")
    pattern = _params(layout_el).get("conversionpattern", DEFAULT_PATTERN) if layout_el is not None else "%m%n"
    layout = PatternLayout(pattern)
    if cls.endswith("ConsoleAppender"):
        return _ConsoleAppender(layout)
    if cls.endswith("FileAppender"):
        path = params.get("file", "")
        if not path:
            return None
        if not os.path.isabs(path):
            path = os.path.join(base_dir, path)
        rolling = cls.endswith("RollingFileAppender")
        shared = SharedLogFile.get(path, params.get("append", "true").lower() != "false",
                                   _size(params.get("maxfilesize"), 10 * 1024 * 1024) if rolling else 0,
                                   int(params.get("maxbackupindex", "1") or 1) if rolling else 0)
        return _FileAppender(shared, layout)
    return None


def _default_config_xml() -> str:
    return ("<configuration><appender name='console' class='org.apache.log4j.ConsoleAppender'><layout>"
            f"<param name='ConversionPattern' value='{DEFAULT_PATTERN}'/></layout></appender>"
            "<appender name='file' class='org.apache.log4j.RollingFileAppender'>"
            "<param name='file' value='Applogs/autologger3.log'/><param name='maxFileSize' value='10MB'/>"
            f"<param name='maxBackupIndex' value='10'/><layout><param name='ConversionPattern' value='{DEFAULT_PATTERN}'/>"
            "</layout></appender><appender name='messageOnlyConsole' class='org.apache.log4j.ConsoleAppender'>"
            "<layout><param name='ConversionPattern' value='%m%n'/></layout></appender>"
            "<appender name='messageOnlyFile' class='org.apache.log4j.FileAppender'>"
            "<param name='file' value='Applogs/autologger3.log'/><layout><param name='ConversionPattern' value='%m%n'/>"
            "</layout></appender><logger name='NameAndSizeLogger' additivity='false'><level value='INFO'/>"
            "<appender-ref ref='messageOnlyFile'/><appender-ref ref='messageOnlyConsole'/></logger>"
            "<root><level value='INFO'/><appender-ref ref='console'/><appender-ref ref='file'/></root>"
            "</configuration>")


def reset_logging() -> None:
    """Remove the handlers configure_logging() added and close the log files."""
    global _configured
    with _config_lock:
        for logger in [logging.getLogger()] + [logging.getLogger(n) for n in list(logging.root.manager.loggerDict)]:
            for handler in list(getattr(logger, "handlers", [])):
                if isinstance(handler, (_FileAppender, _ConsoleAppender)):
                    logger.removeHandler(handler)
        for shared in SharedLogFile._registry.values():
            try:
                shared.stream.close()
            except OSError:
                pass
        SharedLogFile._registry.clear()
        _configured = False


def configure_logging(config_path: str = "log4j.xml", base_dir: str | None = None, force: bool = False) -> None:
    """Configure once per process from log4j.xml (falls back to the shipped defaults)."""
    global _configured
    with _config_lock:
        if _configured and not force:
            return
        base_dir = base_dir or os.path.dirname(os.path.abspath(config_path))
        logging.addLevelName(5, "TRACE")
        try:
            root_el = ET.parse(config_path).getroot()
        except (OSError, ET.ParseError) as exc:
            print(f"log4j:WARN Could not read {config_path} ({exc}); using built-in defaults.", file=sys.stderr)
            root_el = ET.fromstring(_default_config_xml())

        appenders: dict[str, logging.Handler] = {}
        for el in root_el.iter("appender"):
            handler = _build_appender(el, base_dir)
            if handler is not None:
                appenders[el.get("name", "")] = handler

        def apply(logger: logging.Logger, el: ET.Element) -> None:
            for h in list(logger.handlers):
                if isinstance(h, (_FileAppender, _ConsoleAppender)):
                    logger.removeHandler(h)
            level_el = el.find("level")
            if level_el is not None:
                logger.setLevel(_LOG4J_LEVELS.get(level_el.get("value", "INFO").upper(), logging.INFO))
            for ref in el.findall("appender-ref"):
                handler = appenders.get(ref.get("ref", ""))
                if handler is not None:
                    logger.addHandler(handler)

        for el in root_el.iter("logger"):
            logger = logging.getLogger(el.get("name", ""))
            logger.propagate = el.get("additivity", "true").lower() != "false"
            apply(logger, el)
        root = root_el.find("root")
        if root is not None:
            apply(logging.getLogger(), root)
        _configured = True
