"""Runtime settings (Java: JVM system properties + hard-coded constants).

Resolution order: defaults <- environment variables <- command-line arguments.
Java-style "-Dname=value" arguments are accepted, so existing habits keep working.

| Setting          | -D property / CLI                     | Environment variable        | Default                     |
|------------------|---------------------------------------|-----------------------------|-----------------------------|
| field_threads    | -Dautologger.scan.fieldThreads=N      | AUTOLOGGER_FIELD_THREADS    | max(2, min(max(1,CPU-2),8))  |
| regex_threads    | -Dautologger.scan.regexThreads=N      | AUTOLOGGER_REGEX_THREADS    | same as field_threads       |
| scan_processes   | -Dautologger.scan.processes=N         | AUTOLOGGER_SCAN_PROCESSES   | max(1, CPU-1); 0 = in-thread |
| legacy_compat    | -Dautologger.legacyCompat=true|false  | AUTOLOGGER_LEGACY_COMPAT    | true                        |
| force_cli        | --cli / -Dautologger.forceCli=true    | AUTOLOGGER_FORCE_CLI        | false                       |
| jvm_path         | -Dautologger.jvmPath=...              | AUTOLOGGER_JVM_PATH         | JAVA_HOME / registry        |
| bin_query        | -Dautologger.db.binQuery=...          | AUTOLOGGER_BIN_QUERY        | constants.BIN_QUERY example |
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from autologger import constants as C

_TRUE = ("true", "1")


def _cpus() -> int:
    return os.cpu_count() or 2


def default_scan_threads() -> int:
    return max(2, min(max(1, _cpus() - 2), 8))


@dataclass
class Settings:
    workdir: str = field(default_factory=os.getcwd)
    field_threads: int = field(default_factory=default_scan_threads)
    regex_threads: int = field(default_factory=default_scan_threads)
    scan_processes: int = field(default_factory=lambda: max(1, _cpus() - 1))
    legacy_compat: bool = True
    force_cli: bool = False
    jvm_path: str | None = None
    jdbc_classpath: list[str] = field(default_factory=list)
    jvm_options: list[str] = field(default_factory=list)
    bin_query: str = C.BIN_QUERY
    file_pool_size: int = C.FILE_POOL_SIZE
    db_retry_delay: float = C.DB_RETRY_DELAY_SECONDS

    def path(self, name: str) -> str:
        """Config files are resolved against the working directory, like Java's CWD."""
        return os.path.join(self.workdir, name)

    def default_jdbc_classpath(self) -> list[str]:
        if self.jdbc_classpath:
            return self.jdbc_classpath
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates = [os.path.join(self.workdir, "lib", "jdbc-4.10.12.jar"),
                      os.path.join(here, "lib", "jdbc-4.10.12.jar")]
        return [next((c for c in candidates if os.path.exists(c)), candidates[0])]


def _int(value: str | None, fallback: int, minimum: int = 1) -> int:
    if value is None or value.strip() == "":
        return fallback
    try:
        return max(minimum, int(value.strip()))
    except ValueError:
        return fallback


def _bool(value: str | None, fallback: bool) -> bool:
    if value is None or value.strip() == "":
        return fallback
    return value.strip().lower() in _TRUE


def load_settings(argv: list[str] | None = None, env: dict[str, str] | None = None) -> Settings:
    env = dict(os.environ) if env is None else env
    props: dict[str, str] = {}
    force_cli = False
    for arg in argv or []:
        if arg.lower() == "--cli":
            force_cli = True
        elif arg.startswith("-D") and "=" in arg:
            key, value = arg[2:].split("=", 1)
            props[key] = value

    s = Settings()
    s.field_threads = _int(props.get("autologger.scan.fieldThreads", env.get("AUTOLOGGER_FIELD_THREADS")),
                           s.field_threads)
    s.regex_threads = _int(props.get("autologger.scan.regexThreads", env.get("AUTOLOGGER_REGEX_THREADS")),
                           s.regex_threads)
    s.scan_processes = _int(props.get("autologger.scan.processes", env.get("AUTOLOGGER_SCAN_PROCESSES")),
                            s.scan_processes, minimum=0)
    s.legacy_compat = _bool(props.get("autologger.legacyCompat", env.get("AUTOLOGGER_LEGACY_COMPAT")), True)
    s.force_cli = (force_cli or _bool(env.get("AUTOLOGGER_FORCE_CLI"), False)
                   or _bool(props.get("autologger.forceCli"), False))
    s.jvm_path = props.get("autologger.jvmPath") or env.get("AUTOLOGGER_JVM_PATH") or None
    s.bin_query = props.get("autologger.db.binQuery") or env.get("AUTOLOGGER_BIN_QUERY") or s.bin_query
    return s
