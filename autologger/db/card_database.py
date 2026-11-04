"""Informix access for card verification.

Java: the connection/BIN helpers inside CardNumberScanner (a.a(String),
a.a(Connection), a.b(Connection)). The same JDBC driver (lib/jdbc-4.10.12.jar)
is used through JPype, so the DB String in Default.xls stays unchanged and rows
are read exactly as Java read them (getObject(1).toString()).

DbBackend is the seam for other drivers (e.g. pyodbc + Informix CSDK) and for tests.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Protocol

from autologger import constants as C

log = logging.getLogger(__name__)


class DbError(Exception):
    """A java.sql.SQLException. phase='execute' (statement failed) or 'read' (failed mid-result)."""

    def __init__(self, message: str, phase: str = "execute") -> None:
        super().__init__(message)
        self.phase = phase


class DbBackend(Protocol):
    def load_driver(self) -> None: ...

    def connect(self, url: str | None) -> Any: ...

    def query(self, conn: Any, sql: str, scrollable: bool = False) -> list[str]: ...

    def close(self, conn: Any) -> None: ...


def _java_message(exc: BaseException) -> str:
    getter = getattr(exc, "getMessage", None)
    if callable(getter):
        try:
            msg = getter()
            return "null" if msg is None else str(msg)
        except Exception:  # noqa: BLE001
            pass
    return str(exc)


class JdbcBackend:
    """Informix JDBC through an in-process JVM (JPype). The JVM starts once, on first use."""

    _jvm_lock = threading.Lock()

    def __init__(self, classpath: list[str], jvm_path: str | None = None, jvm_options: list[str] | None = None):
        self.classpath = list(classpath)
        self.jvm_path = jvm_path
        self.jvm_options = list(jvm_options or [])
        self._driver_manager = None

    def load_driver(self) -> None:
        import jpype  # imported lazily: worker processes and non-card runs never need a JVM

        with self._jvm_lock:
            if not jpype.isJVMStarted():
                jvm = self.jvm_path or jpype.getDefaultJVMPath()
                jpype.startJVM(jvm, "--enable-native-access=ALL-UNNAMED", *self.jvm_options,
                               classpath=self.classpath, convertStrings=False)
            if self._driver_manager is None:
                jpype.JClass(C.INFORMIX_DRIVER_CLASS)  # Class.forName -> registers the driver
                self._driver_manager = jpype.JClass("java.sql.DriverManager")

    def connect(self, url: str | None) -> Any:
        import jpype

        try:
            return self._driver_manager.getConnection(url)
        except jpype.JException as exc:
            raise DbError(_java_message(exc)) from None

    def query(self, conn: Any, sql: str, scrollable: bool = False) -> list[str]:
        import jpype

        rows: list[str] = []
        phase = "execute"
        try:
            # 1005/1007 = TYPE_SCROLL_INSENSITIVE / CONCUR_READ_ONLY (Java used them for the BIN query)
            stmt = conn.createStatement(1005, 1007) if scrollable else conn.createStatement()
            try:
                rs = stmt.executeQuery(sql)
                phase = "read"
                try:
                    while rs.next():
                        value = rs.getObject(1)
                        if value is None:  # Java: NullPointerException on .toString()
                            raise RuntimeError("null value in first column")
                        rows.append(str(value.toString()))
                finally:
                    rs.close()
            finally:
                stmt.close()
        except jpype.JException as exc:
            raise DbError(_java_message(exc), phase) from None
        return rows

    def close(self, conn: Any) -> None:
        conn.close()


class CardDatabase:
    """Connection helpers with the Java tool's log messages."""

    def __init__(self, backend: DbBackend, bin_query: str = C.BIN_QUERY) -> None:
        self.backend = backend
        self.bin_query = bin_query

    def connect(self, url: str | None, log_errors: bool = True) -> Any | None:
        try:
            self.backend.load_driver()
        except Exception:  # noqa: BLE001 - Java: Class.forName failure
            log.error("####ERROR: failed to load Informix JDBC driver.")
            return None
        try:
            return self.backend.connect(url)
        except DbError as exc:
            if log_errors:
                log.error("####ERROR: Failed to connect to the database.")
                log.error("####ERROR: %s", exc)
            return None

    def query(self, conn: Any, sql: str) -> list[str]:
        return self.backend.query(conn, sql)

    def fetch_bins(self, conn: Any) -> list[str] | None:
        """a(Connection): None when the statement fails (caller retries); DbError(phase='read') propagates."""
        log.info("Database connection established successfully.")
        log.info("Executing BIN query to fetch distinct BIN values.")
        try:
            return self.backend.query(conn, self.bin_query, scrollable=True)
        except DbError as exc:
            if exc.phase == "read":
                raise
            log.error("%s ####ERROR: Could not fetch BINs from DB: %s", threading.current_thread().name, exc)
            return None

    def close(self, conn: Any) -> None:
        """b(Connection) - logs success like Java."""
        try:
            self.backend.close(conn)
            log.info("Database connection closed successfully.")
        except Exception:  # noqa: BLE001
            log.error("%s ####ERROR: failed to close the connection!", threading.current_thread().name)

    def close_quietly(self, conn: Any) -> None:
        try:
            self.backend.close(conn)
        except Exception:  # noqa: BLE001
            pass
